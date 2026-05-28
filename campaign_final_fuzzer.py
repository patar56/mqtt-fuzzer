#!/usr/bin/env python3
"""
Campaign FINAL — Stateful, Multi-Client, Differential MQTT Fuzzer
UCLA ECE 202C — IoT Security Final Project
Patrick Argento

This is the definitive campaign fuzzer. It improves on Campaigns 1-3
in five fundamental ways:

  1. COORDINATED MULTI-CLIENT SCENARIOS
     Most interesting MQTT bugs involve 2+ clients (publisher, subscriber,
     attacker, observer). We script roles that act in parallel via threads
     and barriers, capturing emergent behaviors.

  2. STATEFUL ATTACK SEQUENCES
     Vulnerabilities are described as ordered chains of primitives, not
     single packets. The same primitives (Will, retain, hijack, QoS 2)
     compose differently to expose new bugs.

  3. RACE-CONDITION / TIMING MODULE
     Barrier-synchronized concurrent operations probe for windows where
     the broker's session table, in-flight QoS table, or retained map is
     inconsistent across connections.

  4. DIFFERENTIAL TESTING ACROSS 4 BROKERS
     Every test is dispatched in parallel against Mosquitto, NanoMQ,
     HiveMQ CE, and EMQX. Behavioral divergence is automatically flagged
     as a candidate finding.

  5. STATE-FEEDBACK MUTATION
     A small coverage-proxy (response signature → seen_set) guides
     mutation toward inputs that produce previously-unseen broker
     responses, mimicking AFLNET coverage feedback without instrumentation.

  Plus: deep QoS 2 state-machine fuzzing, MQTT v5 feature abuse on
  v5-capable brokers, and version-mixing (v3 publisher + v5 subscriber)
  to expose downgrade paths.

Usage:
    python3 campaign_final_fuzzer.py [--quick] [--out PATH]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("final")

# ─────────────────────────────────────────────────────────────
# Broker registry — all four targets
# ─────────────────────────────────────────────────────────────
BROKERS: Dict[str, Dict[str, Any]] = {
    "mosquitto": {"host": "127.0.0.1", "port": 1883, "v5": False, "container": "mqtt_target_broker"},
    "emqx":      {"host": "127.0.0.1", "port": 1884, "v5": True,  "container": "emqx_broker"},
    "nanomq":    {"host": "127.0.0.1", "port": 1885, "v5": True,  "container": "nanomq_broker"},
    "hivemq":    {"host": "127.0.0.1", "port": 1886, "v5": True,  "container": "hivemq_broker"},
}

# ═════════════════════════════════════════════════════════════
# SECTION 1 — Raw MQTT packet construction
# (We avoid paho-mqtt entirely so we have byte-level control,
#  including malformed packets that no library would emit.)
# ═════════════════════════════════════════════════════════════

def encode_remaining_length(length: int) -> bytes:
    """MQTT variable byte integer (§1.5.5)."""
    out = bytearray()
    while True:
        b = length % 128
        length //= 128
        if length > 0:
            b |= 0x80
        out.append(b)
        if length == 0:
            break
    return bytes(out)

def encode_utf8(s: Any) -> bytes:
    """UTF-8 string with 2-byte length prefix (§1.5.4)."""
    if isinstance(s, bytes):
        b = s
    else:
        b = str(s).encode("utf-8", errors="replace")
    return struct.pack("!H", len(b)) + b

def u16(v: int) -> bytes:
    return struct.pack("!H", v & 0xFFFF)

# ── CONNECT (v3.1.1 and v5) ─────────────────────────────────
def build_connect(
    *,
    client_id: str = "fc",
    clean_session: bool = True,
    keepalive: int = 60,
    username: Optional[str] = None,
    password: Optional[bytes] = None,
    will_topic: Optional[str] = None,
    will_payload: bytes = b"",
    will_qos: int = 0,
    will_retain: bool = False,
    protocol_level: int = 0x04,  # 0x04 = v3.1.1; 0x05 = v5
    properties: bytes = b"",     # MQTT v5 properties block (already encoded)
    will_properties: bytes = b"",
) -> bytes:
    vh = encode_utf8("MQTT") + bytes([protocol_level])
    flags = 0x02 if clean_session else 0
    if will_topic is not None:
        flags |= 0x04 | ((will_qos & 3) << 3)
        if will_retain:
            flags |= 0x20
    if password is not None:
        flags |= 0x40
    if username is not None:
        flags |= 0x80
    vh += bytes([flags])
    vh += u16(keepalive)

    if protocol_level == 0x05:
        vh += encode_remaining_length(len(properties)) + properties

    payload = encode_utf8(client_id)
    if will_topic is not None:
        if protocol_level == 0x05:
            payload += encode_remaining_length(len(will_properties)) + will_properties
        payload += encode_utf8(will_topic)
        payload += struct.pack("!H", len(will_payload)) + will_payload
    if username is not None:
        payload += encode_utf8(username)
    if password is not None:
        payload += struct.pack("!H", len(password)) + password

    body = vh + payload
    return bytes([0x10]) + encode_remaining_length(len(body)) + body

# ── PUBLISH ─────────────────────────────────────────────────
def build_publish(
    topic: str,
    payload: bytes = b"",
    qos: int = 0,
    retain: bool = False,
    dup: bool = False,
    packet_id: int = 0,
    protocol_level: int = 0x04,
    properties: bytes = b"",
) -> bytes:
    flags = 0
    if dup:    flags |= 0x08
    flags |= (qos & 0x03) << 1
    if retain: flags |= 0x01
    fh1 = 0x30 | flags

    body = encode_utf8(topic)
    if qos > 0:
        body += u16(packet_id)
    if protocol_level == 0x05:
        body += encode_remaining_length(len(properties)) + properties
    body += payload
    return bytes([fh1]) + encode_remaining_length(len(body)) + body

def build_puback(packet_id: int, protocol_level: int = 0x04) -> bytes:
    body = u16(packet_id)
    if protocol_level == 0x05:
        body += b"\x00\x00"  # reason code 0, empty properties
    return bytes([0x40]) + encode_remaining_length(len(body)) + body

def build_pubrec(packet_id: int, protocol_level: int = 0x04) -> bytes:
    body = u16(packet_id)
    if protocol_level == 0x05:
        body += b"\x00\x00"
    return bytes([0x50]) + encode_remaining_length(len(body)) + body

def build_pubrel(packet_id: int, protocol_level: int = 0x04) -> bytes:
    body = u16(packet_id)
    if protocol_level == 0x05:
        body += b"\x00\x00"
    return bytes([0x62]) + encode_remaining_length(len(body)) + body

def build_pubcomp(packet_id: int, protocol_level: int = 0x04) -> bytes:
    body = u16(packet_id)
    if protocol_level == 0x05:
        body += b"\x00\x00"
    return bytes([0x70]) + encode_remaining_length(len(body)) + body

# ── SUBSCRIBE / UNSUBSCRIBE ─────────────────────────────────
def build_subscribe(
    topics: List[Tuple[str, int]],
    packet_id: int = 1,
    protocol_level: int = 0x04,
    properties: bytes = b"",
) -> bytes:
    body = u16(packet_id)
    if protocol_level == 0x05:
        body += encode_remaining_length(len(properties)) + properties
    for topic, qos in topics:
        body += encode_utf8(topic)
        body += bytes([qos & 0x03])
    return bytes([0x82]) + encode_remaining_length(len(body)) + body

def build_unsubscribe(
    topics: List[str],
    packet_id: int = 1,
    protocol_level: int = 0x04,
) -> bytes:
    body = u16(packet_id)
    if protocol_level == 0x05:
        body += b"\x00"  # empty properties
    for t in topics:
        body += encode_utf8(t)
    return bytes([0xA2]) + encode_remaining_length(len(body)) + body

def build_disconnect(reason: int = 0x00, protocol_level: int = 0x04) -> bytes:
    if protocol_level == 0x05:
        return bytes([0xE0, 0x02, reason, 0x00])
    return bytes([0xE0, 0x00])

def build_pingreq() -> bytes:
    return bytes([0xC0, 0x00])

# ── MQTT v5 properties helpers ──────────────────────────────
def v5_prop_topic_alias(alias: int) -> bytes:
    """Property 0x23 — TopicAlias (§3.3.2.3.4)."""
    return bytes([0x23]) + u16(alias)

def v5_prop_session_expiry(secs: int) -> bytes:
    """Property 0x11 — SessionExpiryInterval (4-byte int)."""
    return bytes([0x11]) + struct.pack("!I", secs)

def v5_prop_receive_maximum(n: int) -> bytes:
    """Property 0x21 — ReceiveMaximum."""
    return bytes([0x21]) + u16(n)

def v5_prop_maximum_packet_size(n: int) -> bytes:
    """Property 0x27 — MaximumPacketSize."""
    return bytes([0x27]) + struct.pack("!I", n)

def v5_prop_user_property(key: str, value: str) -> bytes:
    """Property 0x26 — UserProperty (key, value pair)."""
    return bytes([0x26]) + encode_utf8(key) + encode_utf8(value)

def v5_prop_subscription_identifier(sub_id: int) -> bytes:
    """Property 0x0B — SubscriptionIdentifier (variable byte int)."""
    return bytes([0x0B]) + encode_remaining_length(sub_id)

def encode_v5_props(*props: bytes) -> bytes:
    return b"".join(props)

# ═════════════════════════════════════════════════════════════
# SECTION 2 — Connection wrapper with protocol-aware reads
# ═════════════════════════════════════════════════════════════

class MQTTSession:
    """Raw MQTT TCP session with protocol-aware framing.

    This wrapper intentionally does NOT enforce MQTT semantics —
    callers pass arbitrary bytes. It only handles socket I/O and
    decodes the MQTT remaining-length varint when reading frames.
    """

    def __init__(self, host: str, port: int, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.recv_buf = bytearray()
        self.received_frames: List[bytes] = []  # parsed frames during life

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            log.debug(f"connect failed {self.host}:{self.port} {e}")
            return False

    def send(self, data: bytes) -> bool:
        try:
            assert self.sock is not None
            self.sock.sendall(data)
            return True
        except Exception as e:
            log.debug(f"send failed: {e}")
            return False

    def _read_n(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes from socket, buffering."""
        while len(self.recv_buf) < n:
            try:
                chunk = self.sock.recv(4096)  # type: ignore
                if not chunk:
                    return None
                self.recv_buf.extend(chunk)
            except socket.timeout:
                return None
            except Exception:
                return None
        out = bytes(self.recv_buf[:n])
        del self.recv_buf[:n]
        return out

    def read_frame(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Read one complete MQTT frame (fixed header + body)."""
        if self.sock is None:
            return None
        prev = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            fh = self._read_n(1)
            if fh is None:
                return None
            # decode varint remaining length
            length = 0
            multiplier = 1
            for _ in range(4):
                b = self._read_n(1)
                if b is None:
                    return None
                length += (b[0] & 0x7F) * multiplier
                if (b[0] & 0x80) == 0:
                    rl_bytes = bytes(b)  # last byte
                    break
                multiplier *= 128
                rl_bytes = bytes(b)
            else:
                return None
            body = self._read_n(length) if length > 0 else b""
            if body is None:
                return None
            # Reconstruct: we need full RL bytes — easiest: rebuild
            full = bytes([fh[0]]) + encode_remaining_length(length) + body
            self.received_frames.append(full)
            return full
        finally:
            try:
                self.sock.settimeout(prev)
            except Exception:
                pass

    def read_all_available(self, max_wait: float = 0.6) -> List[bytes]:
        """Read frames until timeout."""
        frames: List[bytes] = []
        deadline = time.time() + max_wait
        while time.time() < deadline:
            remaining = max(0.05, deadline - time.time())
            f = self.read_frame(timeout=remaining)
            if f is None:
                break
            frames.append(f)
        return frames

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None


# ═════════════════════════════════════════════════════════════
# SECTION 3 — Frame parsing (decode CONNACK, PUBLISH, etc.)
# ═════════════════════════════════════════════════════════════

def parse_frame(frame: bytes) -> Dict[str, Any]:
    """Decode top-level MQTT frame into a dict of fields."""
    if not frame:
        return {"type": "EMPTY"}
    pt = (frame[0] >> 4) & 0x0F
    flags = frame[0] & 0x0F
    # find body offset
    i = 1
    multiplier = 1
    rl = 0
    for _ in range(4):
        b = frame[i]; i += 1
        rl += (b & 0x7F) * multiplier
        if (b & 0x80) == 0:
            break
        multiplier *= 128
    body = frame[i:i+rl]

    type_names = {
        1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
        5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
        9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
        12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH",
    }
    out: Dict[str, Any] = {
        "type": type_names.get(pt, f"UNKNOWN_{pt}"),
        "flags": flags,
        "rl": rl,
        "raw_hex": frame.hex(),
    }
    try:
        if pt == 2 and len(body) >= 2:  # CONNACK
            out["session_present"] = bool(body[0] & 0x01)
            out["return_code"] = body[1]
        elif pt == 3:  # PUBLISH
            tlen = (body[0] << 8) | body[1]
            out["topic"] = body[2:2+tlen].decode("utf-8", errors="replace")
            out["qos"] = (flags >> 1) & 0x03
            out["retain"] = bool(flags & 0x01)
            after_topic = 2 + tlen
            if out["qos"] > 0 and len(body) >= after_topic + 2:
                out["packet_id"] = (body[after_topic] << 8) | body[after_topic+1]
                after_topic += 2
            out["payload"] = bytes(body[after_topic:])[:200]  # truncate
        elif pt == 9 and len(body) >= 2:  # SUBACK
            out["packet_id"] = (body[0] << 8) | body[1]
            out["reason_codes"] = list(body[2:])
        elif pt in (4, 5, 6, 7) and len(body) >= 2:  # PUBACK/PUBREC/PUBREL/PUBCOMP
            out["packet_id"] = (body[0] << 8) | body[1]
        elif pt == 14 and len(body) >= 1:  # DISCONNECT v5
            out["reason_code"] = body[0]
    except Exception as e:
        out["parse_error"] = str(e)
    return out

# ═════════════════════════════════════════════════════════════
# SECTION 4 — Test result dataclasses
# ═════════════════════════════════════════════════════════════

@dataclass
class BrokerResult:
    broker: str
    success: bool
    response_signature: str       # short fingerprint of broker response
    frames_received: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0

@dataclass
class FinalTestResult:
    test_id: str
    category: str
    description: str
    cwe: str = ""
    spec_ref: str = ""
    severity_hint: str = "info"
    results: Dict[str, BrokerResult] = field(default_factory=dict)
    differential_signature: str = ""    # hash over all broker sigs
    is_anomaly: bool = False
    anomaly_reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # frames are bytes-heavy; truncate raw_hex if too long
        for r in d["results"].values():
            for fr in r["frames_received"]:
                if isinstance(fr.get("raw_hex"), str) and len(fr["raw_hex"]) > 400:
                    fr["raw_hex"] = fr["raw_hex"][:400] + "...trunc"
        return d


# ═════════════════════════════════════════════════════════════
# SECTION 5 — Differential test runner
# ═════════════════════════════════════════════════════════════

def response_signature(frames: List[Dict[str, Any]]) -> str:
    """Fingerprint a broker's response set as a short string.

    Includes packet types and key fields (CONNACK return code,
    SUBACK reason codes) so that semantically-different responses
    yield different signatures.
    """
    parts: List[str] = []
    for f in frames:
        t = f.get("type", "?")
        if t == "CONNACK":
            parts.append(f"CONNACK(rc={f.get('return_code')},sp={int(bool(f.get('session_present')))})")
        elif t == "SUBACK":
            parts.append(f"SUBACK({','.join(str(r) for r in f.get('reason_codes', []))})")
        elif t == "PUBLISH":
            parts.append(f"PUBLISH(topic={f.get('topic')!r},qos={f.get('qos')},retain={int(bool(f.get('retain')))})")
        elif t == "DISCONNECT":
            parts.append(f"DISCONNECT(rc={f.get('reason_code')})")
        elif t in ("PUBACK", "PUBREC", "PUBREL", "PUBCOMP"):
            parts.append(f"{t}(pid={f.get('packet_id')})")
        else:
            parts.append(t)
    return "|".join(parts) if parts else "NO_RESPONSE"


def run_differential(test_fn: Callable[[Dict[str, Any]], BrokerResult],
                     test_id: str,
                     category: str,
                     description: str,
                     cwe: str = "",
                     spec_ref: str = "",
                     severity_hint: str = "info") -> FinalTestResult:
    """Run test_fn against every broker in parallel and aggregate."""
    res = FinalTestResult(
        test_id=test_id, category=category, description=description,
        cwe=cwe, spec_ref=spec_ref, severity_hint=severity_hint,
    )
    with ThreadPoolExecutor(max_workers=len(BROKERS)) as pool:
        futs = {pool.submit(test_fn, {"name": name, **info}): name
                for name, info in BROKERS.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                br = fut.result(timeout=30)
            except Exception as e:
                br = BrokerResult(broker=name, success=False,
                                  response_signature="EXCEPTION",
                                  error=str(e))
            res.results[name] = br
    sigs = sorted(set(r.response_signature for r in res.results.values()))
    res.differential_signature = hashlib.sha1("||".join(sigs).encode()).hexdigest()[:12]
    if len(sigs) > 1:
        res.is_anomaly = True
        res.anomaly_reason = f"divergent: {sigs}"
    return res


# Helper: run a small protocol script against one broker, returning a BrokerResult
def run_script(broker_info: Dict[str, Any],
               script: Callable[[MQTTSession, Dict[str, Any]], Dict[str, Any]],
               timeout: float = 3.0) -> BrokerResult:
    name = broker_info["name"]
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=timeout)
    t0 = time.time()
    if not s.connect():
        return BrokerResult(broker=name, success=False,
                            response_signature="TCP_FAIL",
                            error="tcp_connect_failed",
                            duration_ms=(time.time()-t0)*1000)
    try:
        artifacts = script(s, broker_info)
        frames = [parse_frame(f) for f in s.received_frames]
        sig = response_signature(frames)
        return BrokerResult(broker=name, success=True,
                            response_signature=sig,
                            frames_received=frames,
                            artifacts=artifacts,
                            duration_ms=(time.time()-t0)*1000)
    except Exception as e:
        frames = [parse_frame(f) for f in s.received_frames]
        return BrokerResult(broker=name, success=False,
                            response_signature=response_signature(frames),
                            frames_received=frames,
                            error=f"{type(e).__name__}: {e}",
                            duration_ms=(time.time()-t0)*1000)
    finally:
        s.close()


# ═════════════════════════════════════════════════════════════
# SECTION 6 — Module: Multi-Client Coordinated Scenarios (M-1..M-5)
# ═════════════════════════════════════════════════════════════
#
# These scenarios spawn multiple clients with distinct roles
# (Publisher P, Subscriber S, Attacker A, Observer O) and use
# Python threading.Barrier to synchronize their actions.
#
# A coordinated scenario produces ONE BrokerResult per broker
# that aggregates the observations across all client roles.

def _do_simple_connect(s: MQTTSession, client_id: str, clean: bool = True,
                       v5: bool = False) -> bool:
    pl = 0x05 if v5 else 0x04
    props = b"" if not v5 else b""  # empty v5 props
    s.send(build_connect(client_id=client_id, clean_session=clean,
                         protocol_level=pl,
                         properties=props if v5 else b""))
    f = s.read_frame(timeout=2.0)
    if f and f[0] >> 4 == 2:
        return True
    return False


def scenario_M1_will_observer(broker_info) -> BrokerResult:
    """M-1: Will-message cross-client injection observed in real time.

    Roles:
      - Observer O: connects, subscribes to will/+
      - Attacker A: connects with will_topic=will/inject, then drops abruptly
      - Observer waits for Will message arrival
    """
    name = broker_info["name"]
    t0 = time.time()
    artifacts: Dict[str, Any] = {"observer_received": False, "topic_seen": None}
    obs = MQTTSession(broker_info["host"], broker_info["port"], timeout=4.0)
    atk = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.0)
    try:
        if not obs.connect():
            return BrokerResult(name, False, "TCP_FAIL", error="obs_tcp", duration_ms=0)
        if not _do_simple_connect(obs, f"obs_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "OBS_NO_CONNACK", error="obs_no_connack", duration_ms=0)
        obs.send(build_subscribe([("will/#", 0)], packet_id=1))
        obs.read_frame(timeout=1.5)  # SUBACK

        if not atk.connect():
            return BrokerResult(name, False, "ATK_TCP", error="atk_tcp", duration_ms=0)
        atk.send(build_connect(client_id=f"atk_{random.randint(0,9999)}",
                               will_topic="will/inject",
                               will_payload=b"WILL-FROM-ATK",
                               will_qos=0, will_retain=False))
        atk.read_frame(timeout=1.5)
        # Abrupt close (no DISCONNECT) → broker should publish will
        atk.close()

        # Observer waits up to 2.5s for the Will message
        deadline = time.time() + 2.5
        while time.time() < deadline:
            f = obs.read_frame(timeout=1.0)
            if f is None:
                continue
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH" and pf.get("topic") == "will/inject":
                artifacts["observer_received"] = True
                artifacts["topic_seen"] = pf.get("topic")
                artifacts["payload"] = pf.get("payload", b"")[:80].hex()
                break

        frames = [parse_frame(f) for f in obs.received_frames]
        sig = "WILL_DELIVERED" if artifacts["observer_received"] else "WILL_NOT_DELIVERED"
        return BrokerResult(name, True, sig, frames_received=frames,
                            artifacts=artifacts, duration_ms=(time.time()-t0)*1000)
    finally:
        obs.close(); atk.close()


def scenario_M2_session_hijack_with_inflight(broker_info) -> BrokerResult:
    """M-2: ClientID hijack while victim has an in-flight QoS 1 PUBLISH.

    Roles:
      - Victim V: CONNECT clean=False clientid=X, PUBLISH qos=1 (no PUBACK awaited)
      - Attacker A: connects with same clientid=X, observes session_present=1
      - Verify the broker hands the in-flight PUBACK to A or drops V
    """
    name = broker_info["name"]
    t0 = time.time()
    cid = f"hijack_{random.randint(0,9999)}"
    art: Dict[str, Any] = {}
    vic = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    atk = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not vic.connect():
            return BrokerResult(name, False, "VIC_TCP", error="vic_tcp", duration_ms=0)
        vic.send(build_connect(client_id=cid, clean_session=False))
        vic.read_frame(timeout=1.5)
        # In-flight: PUBLISH qos=1 then DON'T await PUBACK
        vic.send(build_publish("hijack/test", b"in-flight", qos=1, packet_id=42))
        time.sleep(0.1)

        if not atk.connect():
            return BrokerResult(name, False, "ATK_TCP", error="atk_tcp", duration_ms=0)
        atk.send(build_connect(client_id=cid, clean_session=False))
        f = atk.read_frame(timeout=2.0)
        if f and (f[0] >> 4) == 2 and len(f) >= 4:
            art["session_present"] = bool(f[2] & 0x01) if len(f) >= 4 else None
            art["connack_rc"] = f[3] if len(f) >= 4 else None
        else:
            art["connack_rc"] = None

        # Attacker checks for any redelivered queued messages
        atk.send(build_subscribe([("hijack/+", 1)], packet_id=2))
        atk.read_frame(timeout=1.5)
        time.sleep(0.4)
        leaked = []
        while True:
            f = atk.read_frame(timeout=0.5)
            if f is None:
                break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH":
                leaked.append(pf.get("topic"))
        art["leaked_topics"] = leaked

        frames = [parse_frame(f) for f in atk.received_frames]
        sig = f"SESSION_PRESENT={art.get('session_present')}|RC={art.get('connack_rc')}|LEAKED={len(leaked)}"
        return BrokerResult(name, True, sig, frames_received=frames,
                            artifacts=art, duration_ms=(time.time()-t0)*1000)
    finally:
        vic.close(); atk.close()


def scenario_M3_retain_poison_chain(broker_info) -> BrokerResult:
    """M-3: Retain → New Subscriber chain.

    Attacker publishes retained malicious payload to sensors/critical.
    Then a fresh subscriber connects and subscribes — does it
    receive the retained payload?
    """
    name = broker_info["name"]
    t0 = time.time()
    a = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {"retained_received": False}
    try:
        if not a.connect():
            return BrokerResult(name, False, "TCP", error="a_tcp", duration_ms=0)
        _do_simple_connect(a, f"poison_{random.randint(0,9999)}")
        a.send(build_publish("sensors/critical", b"FAKE_TEMP=999",
                             qos=0, retain=True))
        time.sleep(0.2)

        if not s.connect():
            return BrokerResult(name, False, "TCP2", error="s_tcp", duration_ms=0)
        _do_simple_connect(s, f"sub_{random.randint(0,9999)}")
        s.send(build_subscribe([("sensors/critical", 0)], packet_id=1))
        s.read_frame(timeout=1.0)
        time.sleep(0.4)
        # Look for retained PUBLISH
        while True:
            f = s.read_frame(timeout=0.5)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH" and pf.get("retain"):
                art["retained_received"] = True
                art["payload_hex"] = pf.get("payload", b"")[:50].hex()

        frames = [parse_frame(f) for f in s.received_frames]
        sig = "POISON_PERSISTED" if art["retained_received"] else "NO_RETAINED"
        return BrokerResult(name, True, sig, frames_received=frames, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        # Cleanup: clear retained
        try:
            a.send(build_publish("sensors/critical", b"", qos=0, retain=True))
        except Exception:
            pass
        a.close(); s.close()


def scenario_M4_wildcard_eavesdrop(broker_info) -> BrokerResult:
    """M-4: Anonymous '#' wildcard subscription receives all topic traffic.

    Roles:
      - Eavesdropper E: subscribes to '#'
      - Publisher P: publishes 5 messages on disjoint topics
      - Confirm E sees all 5
    """
    name = broker_info["name"]
    t0 = time.time()
    e = MQTTSession(broker_info["host"], broker_info["port"], timeout=4.0)
    p = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    try:
        if not e.connect() or not _do_simple_connect(e, f"eve_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "E_FAIL", error="e_fail", duration_ms=0)
        e.send(build_subscribe([("#", 0)], packet_id=1))
        suback = e.read_frame(timeout=1.5)
        sa = parse_frame(suback) if suback else {}
        art["suback_rc"] = sa.get("reason_codes")

        if not p.connect() or not _do_simple_connect(p, f"pub_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "P_FAIL", error="p_fail", duration_ms=0)
        topics = ["a/1", "b/2", "c/3/d", "secret/admin", "telemetry/x"]
        for t in topics:
            p.send(build_publish(t, b"DATA", qos=0))
        time.sleep(0.6)

        seen = set()
        while True:
            f = e.read_frame(timeout=0.5)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH":
                seen.add(pf.get("topic"))
        art["topics_seen"] = sorted(seen)
        art["topics_published"] = topics
        sig = f"WILDCARD_COVERAGE={len(seen)}/{len(topics)}"
        frames = [parse_frame(f) for f in e.received_frames]
        return BrokerResult(name, True, sig, frames_received=frames, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        e.close(); p.close()


def scenario_M5_concurrent_clientid_race(broker_info) -> BrokerResult:
    """M-5: Two clients race to grab the SAME persistent ClientID.

    Both threads call CONNECT(clientid=Z, clean=False) at the same
    barrier. The broker spec says the second one disconnects the
    first; we measure the actual ordering / ambiguity window.
    """
    name = broker_info["name"]
    t0 = time.time()
    cid = f"race_{random.randint(0,99999)}"
    barrier = threading.Barrier(2, timeout=3)
    results: Dict[str, Any] = {}
    lock = threading.Lock()

    def role(tag: str):
        s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
        try:
            if not s.connect():
                with lock: results[tag] = {"err": "tcp"}
                return
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            ts = time.time()
            s.send(build_connect(client_id=cid, clean_session=False))
            f = s.read_frame(timeout=2.0)
            with lock:
                results[tag] = {
                    "connack_at": ts,
                    "connack": parse_frame(f) if f else None,
                }
            # hold connection briefly, see if forced disconnect
            time.sleep(0.6)
            try:
                extra = s.read_frame(timeout=0.3)
            except Exception:
                extra = None
            with lock:
                results[tag]["post_extra"] = parse_frame(extra) if extra else None
        finally:
            s.close()

    t1 = threading.Thread(target=role, args=("A",))
    t2 = threading.Thread(target=role, args=("B",))
    t1.start(); t2.start(); t1.join(); t2.join()
    sigs = []
    for tag in ("A", "B"):
        r = results.get(tag, {})
        ck = r.get("connack") or {}
        sigs.append(f"{tag}(rc={ck.get('return_code')},sp={int(bool(ck.get('session_present')))})")
    sig = "RACE|" + "|".join(sigs)
    return BrokerResult(name, True, sig, frames_received=[],
                        artifacts=results, duration_ms=(time.time()-t0)*1000)


# ═════════════════════════════════════════════════════════════
# SECTION 7 — Module: Race conditions & timing attacks (R-1..R-4)
# ═════════════════════════════════════════════════════════════

def scenario_R1_qos2_pubrel_dup_race(broker_info) -> BrokerResult:
    """R-1: Race PUBREL with a duplicate PUBLISH (same PID).

    QoS 2 sequence: PUBLISH → PUBREC → PUBREL → PUBCOMP.
    We send PUBLISH(qos=2,pid=N), wait PUBREC, send DUP PUBLISH(qos=2,pid=N)
    AND PUBREL(pid=N) virtually simultaneously. Spec says broker must
    deliver exactly once. We watch a separate observer client.
    """
    name = broker_info["name"]
    t0 = time.time()
    obs = MQTTSession(broker_info["host"], broker_info["port"], timeout=4.0)
    pub = MQTTSession(broker_info["host"], broker_info["port"], timeout=4.0)
    art: Dict[str, Any] = {}
    try:
        if not obs.connect() or not _do_simple_connect(obs, f"obsq_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "OBS", error="obs_fail", duration_ms=0)
        obs.send(build_subscribe([("qos2/race", 2)], packet_id=1))
        obs.read_frame(timeout=1.5)

        if not pub.connect() or not _do_simple_connect(pub, f"pubq_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "PUB", error="pub_fail", duration_ms=0)
        # PUBLISH qos=2 first time
        pub.send(build_publish("qos2/race", b"PAY", qos=2, packet_id=77))
        rec = pub.read_frame(timeout=1.5)
        art["pubrec_seen"] = rec is not None and (rec[0] >> 4) == 5

        # Now race: send DUP PUBLISH and PUBREL very close together
        dup = build_publish("qos2/race", b"PAY", qos=2, packet_id=77, dup=True)
        rel = build_pubrel(77)
        pub.send(dup + rel)
        # Read whatever comes back
        deadline = time.time() + 1.5
        responses = []
        while time.time() < deadline:
            f = pub.read_frame(timeout=0.5)
            if f is None: break
            responses.append(parse_frame(f))
        art["responses"] = responses

        # Observer counts deliveries
        time.sleep(0.5)
        delivered = 0
        while True:
            f = obs.read_frame(timeout=0.5)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH" and pf.get("topic") == "qos2/race":
                delivered += 1
        art["delivered_count"] = delivered
        sig = f"QOS2_RACE_DELIVERED={delivered}"
        frames = [parse_frame(f) for f in obs.received_frames]
        return BrokerResult(name, True, sig, frames_received=frames,
                            artifacts=art, duration_ms=(time.time()-t0)*1000)
    finally:
        obs.close(); pub.close()


def scenario_R2_disconnect_during_pubrec(broker_info) -> BrokerResult:
    """R-2: Disconnect publisher right after sending PUBLISH qos=2.

    Did the broker still queue the message? We check by reconnecting
    with the same session and seeing if the message progresses.
    """
    name = broker_info["name"]
    t0 = time.time()
    cid = f"r2_{random.randint(0,99999)}"
    pub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    obs = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    try:
        if not obs.connect() or not _do_simple_connect(obs, f"r2obs_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "OBS", error="obs", duration_ms=0)
        obs.send(build_subscribe([("r2/topic", 2)], packet_id=1))
        obs.read_frame(timeout=1.5)

        if not pub.connect():
            return BrokerResult(name, False, "PUB_TCP", error="pub_tcp", duration_ms=0)
        pub.send(build_connect(client_id=cid, clean_session=False))
        pub.read_frame(timeout=1.0)
        pub.send(build_publish("r2/topic", b"WILL_BE_ABANDONED", qos=2, packet_id=99))
        pub.close()  # abrupt — before PUBREL

        time.sleep(0.5)
        recv_count = 0
        while True:
            f = obs.read_frame(timeout=0.5)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH" and pf.get("topic") == "r2/topic":
                recv_count += 1
        art["delivered_after_abort"] = recv_count
        sig = f"ABORT_DELIVERED={recv_count}"

        # Now reconnect publisher with same session
        pub2 = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
        pub2.connect()
        pub2.send(build_connect(client_id=cid, clean_session=False))
        f2 = pub2.read_frame(timeout=1.5)
        ck = parse_frame(f2) if f2 else {}
        art["resume_session_present"] = ck.get("session_present")
        # Did broker resend PUBREC?
        time.sleep(0.4)
        resumed = []
        while True:
            f = pub2.read_frame(timeout=0.4)
            if f is None: break
            resumed.append(parse_frame(f).get("type"))
        art["resumed_frames"] = resumed
        pub2.close()

        frames = [parse_frame(f) for f in obs.received_frames]
        return BrokerResult(name, True, sig, frames_received=frames, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        pub.close(); obs.close()


def scenario_R3_keepalive_timing_window(broker_info) -> BrokerResult:
    """R-3: Probe the keepalive enforcement window.

    Connect with keepalive=2s. Don't send PINGREQ. Wait 5.0s.
    If broker still answers a PINGREQ, it has not enforced
    1.5x grace window per §3.1.2.10.
    """
    name = broker_info["name"]
    t0 = time.time()
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=8.0)
    art: Dict[str, Any] = {}
    try:
        if not s.connect():
            return BrokerResult(name, False, "TCP", error="tcp", duration_ms=0)
        s.send(build_connect(client_id=f"r3_{random.randint(0,9999)}",
                             keepalive=2))
        s.read_frame(timeout=1.5)
        time.sleep(5.0)
        # Try PINGREQ
        s.send(build_pingreq())
        f = s.read_frame(timeout=2.0)
        if f and (f[0] >> 4) == 13:
            art["enforced"] = False
            sig = "KEEPALIVE_NOT_ENFORCED"
        else:
            art["enforced"] = True
            sig = "KEEPALIVE_ENFORCED"
        return BrokerResult(name, True, sig, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        s.close()


def scenario_R4_concurrent_retain_clear(broker_info) -> BrokerResult:
    """R-4: Race retain set vs retain clear.

    One thread continually publishes retained=True payload X to topic;
    another thread continually publishes retained=True empty payload
    (which clears retain). A third client subscribes once and observes
    what it gets. Inconsistency would suggest a race in the retained
    map.
    """
    name = broker_info["name"]
    t0 = time.time()
    a = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    b = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    sub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    stop = threading.Event()

    def setter():
        try:
            _do_simple_connect(a, f"setter_{random.randint(0,9999)}")
            for _ in range(40):
                if stop.is_set(): return
                a.send(build_publish("race/retain", b"SET", qos=0, retain=True))
                time.sleep(0.02)
        except Exception: pass

    def clearer():
        try:
            _do_simple_connect(b, f"clearer_{random.randint(0,9999)}")
            for _ in range(40):
                if stop.is_set(): return
                b.send(build_publish("race/retain", b"", qos=0, retain=True))
                time.sleep(0.02)
        except Exception: pass

    try:
        a.connect(); b.connect(); sub.connect()
        ts = threading.Thread(target=setter)
        tc = threading.Thread(target=clearer)
        ts.start(); tc.start()
        time.sleep(0.4)
        _do_simple_connect(sub, f"r4sub_{random.randint(0,9999)}")
        sub.send(build_subscribe([("race/retain", 0)], packet_id=1))
        sub.read_frame(timeout=1.0)
        time.sleep(0.4)
        seen_payloads = []
        while True:
            f = sub.read_frame(timeout=0.4)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH":
                seen_payloads.append((pf.get("retain"), pf.get("payload", b"")[:5]))
        stop.set(); ts.join(timeout=2); tc.join(timeout=2)
        art["payloads_seen"] = [(int(bool(r)), p.hex()) for r, p in seen_payloads]
        sig = f"RETAIN_RACE_OBSERVED={len(seen_payloads)}"
        return BrokerResult(name, True, sig, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        stop.set()
        try:
            a.send(build_publish("race/retain", b"", qos=0, retain=True))
        except Exception: pass
        a.close(); b.close(); sub.close()


# ═════════════════════════════════════════════════════════════
# SECTION 8 — Module: MQTT v5 feature abuse (V5-1..V5-4)
# ═════════════════════════════════════════════════════════════

def scenario_V5_1_topic_alias_oob(broker_info) -> BrokerResult:
    """V5-1: Send TopicAlias > broker's TopicAliasMaximum.

    For brokers that don't advertise v5, this should TCP-drop.
    For v5-capable brokers, this should disconnect with reason 0x94
    (Topic Alias Invalid) per §3.3.4.
    """
    name = broker_info["name"]
    if not broker_info.get("v5"):
        # Just record that we did not test v5 here
        return BrokerResult(name, True, "V5_NOT_SUPPORTED",
                            artifacts={"skipped": True}, duration_ms=0)
    t0 = time.time()
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    try:
        if not s.connect():
            return BrokerResult(name, False, "TCP", error="tcp", duration_ms=0)
        s.send(build_connect(client_id=f"v51_{random.randint(0,9999)}",
                             protocol_level=0x05,
                             properties=b""))
        ck = s.read_frame(timeout=2.0)
        art["connack"] = parse_frame(ck) if ck else None
        # Send PUBLISH with topic alias 0xFFFF and empty topic
        props = v5_prop_topic_alias(0xFFFF)
        s.send(build_publish("", b"PAY", qos=0, protocol_level=0x05,
                             properties=props))
        time.sleep(0.5)
        responses = []
        while True:
            f = s.read_frame(timeout=0.5)
            if f is None: break
            responses.append(parse_frame(f))
        art["responses"] = responses
        rcs = [r.get("reason_code") for r in responses if r.get("type") == "DISCONNECT"]
        sig = f"V5_TOPIC_ALIAS_OOB|disc_rc={rcs}"
        return BrokerResult(name, True, sig, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        s.close()


def scenario_V5_2_session_expiry_overflow(broker_info) -> BrokerResult:
    """V5-2: SessionExpiryInterval = 0xFFFFFFFF (max).

    This should be accepted as 'session never expires' per §3.1.2.11.4.
    But unbounded session retention is a memory-pressure DoS surface.
    """
    name = broker_info["name"]
    if not broker_info.get("v5"):
        return BrokerResult(name, True, "V5_NOT_SUPPORTED",
                            artifacts={"skipped": True}, duration_ms=0)
    t0 = time.time()
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not s.connect():
            return BrokerResult(name, False, "TCP", error="tcp", duration_ms=0)
        props = v5_prop_session_expiry(0xFFFFFFFF)
        s.send(build_connect(client_id=f"v52_{random.randint(0,9999)}",
                             clean_session=False, protocol_level=0x05,
                             properties=props))
        ck = s.read_frame(timeout=2.0)
        ckp = parse_frame(ck) if ck else {}
        sig = f"V5_INF_SESSION_RC={ckp.get('return_code')}"
        return BrokerResult(name, True, sig, artifacts={"connack": ckp},
                            duration_ms=(time.time()-t0)*1000)
    finally:
        s.close()


def scenario_V5_3_user_property_flood(broker_info) -> BrokerResult:
    """V5-3: PUBLISH with 100 UserProperty entries.

    UserProperty (0x26) is unlimited per spec — abused for amplification
    or memory pressure. We send 100 Key/Value pairs of 200 bytes each.
    Total ~ 40KB of properties.
    """
    name = broker_info["name"]
    if not broker_info.get("v5"):
        return BrokerResult(name, True, "V5_NOT_SUPPORTED",
                            artifacts={"skipped": True}, duration_ms=0)
    t0 = time.time()
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=4.0)
    try:
        if not s.connect():
            return BrokerResult(name, False, "TCP", error="tcp", duration_ms=0)
        s.send(build_connect(client_id=f"v53_{random.randint(0,9999)}",
                             protocol_level=0x05))
        ck = s.read_frame(timeout=2.0)
        if not ck or (ck[0] >> 4) != 2:
            return BrokerResult(name, False, "NO_CONNACK", error="no_ck", duration_ms=0)
        big_props = b"".join(
            v5_prop_user_property(f"k{i:03}", "v" * 200) for i in range(100)
        )
        # subscribe so we can observe broker echo
        s.send(build_subscribe([("v53/topic", 0)], packet_id=1, protocol_level=0x05))
        s.read_frame(timeout=1.5)
        s.send(build_publish("v53/topic", b"x", qos=0,
                             protocol_level=0x05, properties=big_props))
        time.sleep(0.6)
        seen = 0
        sizes = []
        while True:
            f = s.read_frame(timeout=0.5)
            if f is None: break
            sizes.append(len(f))
            seen += 1
        sig = f"V5_USERPROP_FLOOD seen={seen} bytes={sum(sizes)}"
        return BrokerResult(name, True, sig,
                            artifacts={"frames_seen": seen, "total_bytes": sum(sizes)},
                            duration_ms=(time.time()-t0)*1000)
    finally:
        s.close()


def scenario_V5_4_subscription_id_conflict(broker_info) -> BrokerResult:
    """V5-4: Two SUBSCRIBE with the same SubscriptionIdentifier.

    Spec (§3.8.2.1.2) does not forbid duplicates, but broker behavior
    diverges. We test what the broker does with conflict.
    """
    name = broker_info["name"]
    if not broker_info.get("v5"):
        return BrokerResult(name, True, "V5_NOT_SUPPORTED",
                            artifacts={"skipped": True}, duration_ms=0)
    t0 = time.time()
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not s.connect():
            return BrokerResult(name, False, "TCP", error="tcp", duration_ms=0)
        s.send(build_connect(client_id=f"v54_{random.randint(0,9999)}",
                             protocol_level=0x05))
        s.read_frame(timeout=1.5)
        sid = v5_prop_subscription_identifier(7)
        s.send(build_subscribe([("v54/a", 0)], packet_id=10,
                               protocol_level=0x05, properties=sid))
        a1 = s.read_frame(timeout=1.0)
        s.send(build_subscribe([("v54/b", 0)], packet_id=11,
                               protocol_level=0x05, properties=sid))
        a2 = s.read_frame(timeout=1.0)
        sig = f"V5_SUBID_DUP a1={parse_frame(a1).get('reason_codes')} a2={parse_frame(a2).get('reason_codes')}"
        return BrokerResult(name, True, sig,
                            artifacts={"a1": parse_frame(a1) if a1 else None,
                                       "a2": parse_frame(a2) if a2 else None},
                            duration_ms=(time.time()-t0)*1000)
    finally:
        s.close()


# ═════════════════════════════════════════════════════════════
# SECTION 9 — Module: Deep QoS 2 state machine fuzzing (Q-1..Q-6)
# ═════════════════════════════════════════════════════════════
#
# QoS 2 has 6 reachable states per direction. We probe adversarial
# transitions at each.

def scenario_Q1_pubrel_without_publish(broker_info) -> BrokerResult:
    """Q-1: Send PUBREL without prior PUBLISH (orphan)."""
    name = broker_info["name"]
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not s.connect(): return BrokerResult(name, False, "TCP", duration_ms=0)
        if not _do_simple_connect(s, f"q1_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "NO_CK", duration_ms=0)
        s.send(build_pubrel(123))
        time.sleep(0.4)
        responses = []
        while True:
            f = s.read_frame(timeout=0.4)
            if f is None: break
            responses.append(parse_frame(f))
        sig = f"ORPHAN_PUBREL {[r.get('type') for r in responses]}"
        return BrokerResult(name, True, sig,
                            artifacts={"responses": responses}, duration_ms=0)
    finally:
        s.close()


def scenario_Q2_pubcomp_without_pubrel(broker_info) -> BrokerResult:
    """Q-2: Send PUBCOMP without prior PUBREL."""
    name = broker_info["name"]
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not s.connect(): return BrokerResult(name, False, "TCP", duration_ms=0)
        if not _do_simple_connect(s, f"q2_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "NO_CK", duration_ms=0)
        s.send(build_pubcomp(456))
        time.sleep(0.4)
        responses = []
        while True:
            f = s.read_frame(timeout=0.4)
            if f is None: break
            responses.append(parse_frame(f))
        sig = f"ORPHAN_PUBCOMP {[r.get('type') for r in responses]}"
        return BrokerResult(name, True, sig,
                            artifacts={"responses": responses}, duration_ms=0)
    finally:
        s.close()


def scenario_Q3_qos2_inflight_storm(broker_info) -> BrokerResult:
    """Q-3: 50 concurrent QoS 2 PUBLISH without PUBREL.

    Watch broker for crash, slowdown, or rejection.
    """
    name = broker_info["name"]
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=4.0)
    try:
        if not s.connect(): return BrokerResult(name, False, "TCP", duration_ms=0)
        if not _do_simple_connect(s, f"q3_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "NO_CK", duration_ms=0)
        n_pubrec = 0
        t_start = time.time()
        for i in range(50):
            s.send(build_publish(f"q3/t{i}", b"X", qos=2, packet_id=1000+i))
        time.sleep(1.5)
        while True:
            f = s.read_frame(timeout=0.4)
            if f is None: break
            if (f[0] >> 4) == 5:
                n_pubrec += 1
        elapsed = time.time() - t_start
        sig = f"QOS2_INFLIGHT_STORM pubrecs={n_pubrec}/50 in {elapsed:.2f}s"
        return BrokerResult(name, True, sig,
                            artifacts={"pubrecs": n_pubrec, "elapsed": elapsed},
                            duration_ms=elapsed*1000)
    finally:
        s.close()


def scenario_Q4_pubrec_storm_no_pubrel(broker_info) -> BrokerResult:
    """Q-4: Send 30 PUBRECs as if we were the broker."""
    name = broker_info["name"]
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not s.connect(): return BrokerResult(name, False, "TCP", duration_ms=0)
        if not _do_simple_connect(s, f"q4_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "NO_CK", duration_ms=0)
        for i in range(30):
            s.send(build_pubrec(2000 + i))
        time.sleep(0.6)
        responses = []
        while True:
            f = s.read_frame(timeout=0.4)
            if f is None: break
            responses.append(parse_frame(f).get("type"))
        sig = f"PUBREC_STORM responses={responses[:5]}... total={len(responses)}"
        return BrokerResult(name, True, sig, artifacts={"types": responses},
                            duration_ms=0)
    finally:
        s.close()


def scenario_Q5_pid_zero_each_packet_type(broker_info) -> BrokerResult:
    """Q-5: PID=0 on PUBLISH(qos=1), PUBACK, PUBREC, PUBREL, PUBCOMP.

    §2.3.1 forbids PID=0 for any of these — all should be rejected.
    """
    name = broker_info["name"]
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    try:
        if not s.connect(): return BrokerResult(name, False, "TCP", duration_ms=0)
        if not _do_simple_connect(s, f"q5_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "NO_CK", duration_ms=0)
        # 5 frames in one shot
        bundle = (
            build_publish("q5/a", b"x", qos=1, packet_id=0) +
            build_puback(0) +
            build_pubrec(0) +
            build_pubrel(0) +
            build_pubcomp(0)
        )
        s.send(bundle)
        time.sleep(0.6)
        responses = []
        disconnected = False
        while True:
            f = s.read_frame(timeout=0.4)
            if f is None: break
            pf = parse_frame(f)
            responses.append(pf.get("type"))
            if pf.get("type") == "DISCONNECT":
                disconnected = True
        # Probe: still alive?
        s.send(build_pingreq())
        f = s.read_frame(timeout=1.0)
        alive = f is not None and (f[0] >> 4) == 13
        sig = f"PID0_BUNDLE responses={responses} alive={alive}"
        art["responses"] = responses
        art["disconnected"] = disconnected
        art["alive_after"] = alive
        return BrokerResult(name, True, sig, artifacts=art, duration_ms=0)
    finally:
        s.close()


def scenario_Q6_qos2_complete_normal(broker_info) -> BrokerResult:
    """Q-6: Full happy-path QoS 2 — control case (must succeed)."""
    name = broker_info["name"]
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    try:
        if not s.connect(): return BrokerResult(name, False, "TCP", duration_ms=0)
        if not _do_simple_connect(s, f"q6_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "NO_CK", duration_ms=0)
        s.send(build_publish("q6/topic", b"hi", qos=2, packet_id=88))
        f1 = s.read_frame(timeout=1.5)
        art["pubrec"] = (f1[0] >> 4) == 5 if f1 else False
        s.send(build_pubrel(88))
        f2 = s.read_frame(timeout=1.5)
        art["pubcomp"] = (f2[0] >> 4) == 7 if f2 else False
        sig = f"QOS2_HAPPY rec={art['pubrec']} comp={art['pubcomp']}"
        return BrokerResult(name, True, sig, artifacts=art, duration_ms=0)
    finally:
        s.close()


# ═════════════════════════════════════════════════════════════
# SECTION 10 — Module: Protocol-version mixing (X-1..X-2)
# ═════════════════════════════════════════════════════════════

def scenario_X1_v5_pub_v3_sub(broker_info) -> BrokerResult:
    """X-1: v5 publisher (with v5 properties) → v3 subscriber.

    Does the broker strip properties cleanly when delivering to v3?
    """
    name = broker_info["name"]
    if not broker_info.get("v5"):
        return BrokerResult(name, True, "V5_NOT_SUPPORTED",
                            artifacts={"skipped": True}, duration_ms=0)
    t0 = time.time()
    pub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    sub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not sub.connect() or not _do_simple_connect(sub, f"x1s_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "SUB", duration_ms=0)
        sub.send(build_subscribe([("x1/topic", 0)], packet_id=1))
        sub.read_frame(timeout=1.0)

        if not pub.connect():
            return BrokerResult(name, False, "PUB_TCP", duration_ms=0)
        pub.send(build_connect(client_id=f"x1p_{random.randint(0,9999)}",
                               protocol_level=0x05))
        ck = pub.read_frame(timeout=1.5)
        if not ck or (ck[0] >> 4) != 2:
            return BrokerResult(name, False, "PUB_NO_CK", duration_ms=0)
        props = v5_prop_user_property("from_v5", "yes")
        pub.send(build_publish("x1/topic", b"DATA", qos=0,
                               protocol_level=0x05, properties=props))
        time.sleep(0.4)
        delivered = 0
        topic = None
        while True:
            f = sub.read_frame(timeout=0.4)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH":
                delivered += 1
                topic = pf.get("topic")
        sig = f"X1_V5toV3 delivered={delivered} topic={topic}"
        return BrokerResult(name, True, sig,
                            artifacts={"delivered": delivered}, duration_ms=(time.time()-t0)*1000)
    finally:
        pub.close(); sub.close()


def scenario_X2_v3_pub_v5_sub(broker_info) -> BrokerResult:
    """X-2: v3 publisher → v5 subscriber: should still deliver."""
    name = broker_info["name"]
    if not broker_info.get("v5"):
        return BrokerResult(name, True, "V5_NOT_SUPPORTED",
                            artifacts={"skipped": True}, duration_ms=0)
    t0 = time.time()
    pub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    sub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    try:
        if not sub.connect():
            return BrokerResult(name, False, "TCP", duration_ms=0)
        sub.send(build_connect(client_id=f"x2s_{random.randint(0,9999)}",
                               protocol_level=0x05))
        sub.read_frame(timeout=1.5)
        sub.send(build_subscribe([("x2/topic", 0)], packet_id=1, protocol_level=0x05))
        sub.read_frame(timeout=1.0)

        if not pub.connect():
            return BrokerResult(name, False, "PUB_TCP", duration_ms=0)
        _do_simple_connect(pub, f"x2p_{random.randint(0,9999)}")
        pub.send(build_publish("x2/topic", b"DATA", qos=0))
        time.sleep(0.4)
        delivered = 0
        while True:
            f = sub.read_frame(timeout=0.4)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH":
                delivered += 1
        sig = f"X2_V3toV5 delivered={delivered}"
        return BrokerResult(name, True, sig,
                            artifacts={"delivered": delivered}, duration_ms=(time.time()-t0)*1000)
    finally:
        pub.close(); sub.close()


# ═════════════════════════════════════════════════════════════
# SECTION 11 — Module: State-feedback mutation fuzzer (S-FB)
# ═════════════════════════════════════════════════════════════
#
# Track {response_signature → 1} per broker. After each generation
# of mutations, prefer those that produced an as-yet-unseen signature.
# This is a coverage proxy (no real instrumentation), but it's what
# AFLNET-style network fuzzing does in practice.

def scenario_SFB_seed_corpus_mutation(broker_info) -> BrokerResult:
    """S-FB: 80 mutations seeded from a CONNECT, with novelty feedback.

    A small evolutionary loop:
      1. Start with valid CONNECT seed.
      2. Mutate (bit-flip, byte-replace, length-tamper).
      3. Send to broker, read response.
      4. If signature is new for this broker, keep mutation as parent.
      5. Else discard.
    """
    name = broker_info["name"]
    seed = build_connect(client_id="seed", clean_session=True, keepalive=10)
    seen: set = set()
    best = bytearray(seed)
    crashes = 0
    generation = 0
    art: Dict[str, Any] = {"novel_sigs": [], "anomalies": 0}
    t0 = time.time()
    rng = random.Random(0xC0FFEE)

    for i in range(80):
        # produce candidate
        cand = bytearray(best)
        for _ in range(rng.randint(1, 3)):
            op = rng.choice(["flip", "replace", "insert", "delete"])
            if not cand: break
            idx = rng.randint(0, len(cand)-1)
            if op == "flip":
                cand[idx] ^= 1 << rng.randint(0, 7)
            elif op == "replace":
                cand[idx] = rng.randint(0, 255)
            elif op == "insert" and len(cand) < 1024:
                cand.insert(idx, rng.randint(0, 255))
            elif op == "delete" and len(cand) > 6:
                del cand[idx]

        s = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.0)
        if not s.connect():
            crashes += 1
            continue
        try:
            s.send(bytes(cand))
            f = s.read_frame(timeout=1.0)
            if f is not None:
                pf = parse_frame(f)
                sig = pf.get("type", "?")
                if pf.get("type") == "CONNACK":
                    sig += f"({pf.get('return_code')})"
            else:
                sig = "NO_RESPONSE"
            if sig not in seen:
                seen.add(sig)
                art["novel_sigs"].append({"gen": i, "sig": sig, "len": len(cand)})
                # keep candidate as new parent
                best = cand
                generation += 1
        except Exception:
            crashes += 1
        finally:
            s.close()

    art["seen_sigs"] = sorted(seen)
    art["novelty_rate"] = generation / 80.0
    sig = f"SFB novel_sigs={len(seen)} crashes={crashes}"
    return BrokerResult(name, True, sig, artifacts=art,
                        duration_ms=(time.time()-t0)*1000)


# ═════════════════════════════════════════════════════════════
# SECTION 12 — Module: Cross-cutting attack chains (C-1..C-3)
# ═════════════════════════════════════════════════════════════

def scenario_C1_will_retain_hijack_chain(broker_info) -> BrokerResult:
    """C-1: Will + Retain + Hijack composed.

    Step 1: Attacker connects with will_topic=alarms/active,
            will_retain=True, will_payload="CLEAR".
    Step 2: Attacker abruptly disconnects → broker publishes
            retained Will with CLEAR semantics.
    Step 3: A future subscriber sees the poisoned retained payload,
            disabling the alarm.

    This composes V1 (Will) + V2 (Retain) into a one-shot lasting
    attack, even though the attacker is no longer connected.
    """
    name = broker_info["name"]
    t0 = time.time()
    atk = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    sub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    try:
        if not atk.connect():
            return BrokerResult(name, False, "TCP", duration_ms=0)
        atk.send(build_connect(client_id=f"c1a_{random.randint(0,9999)}",
                               will_topic="alarms/active",
                               will_payload=b"CLEAR",
                               will_qos=0,
                               will_retain=True))
        atk.read_frame(timeout=1.0)
        atk.close()  # abrupt
        time.sleep(0.4)

        if not sub.connect() or not _do_simple_connect(sub, f"c1s_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "SUB", duration_ms=0)
        sub.send(build_subscribe([("alarms/active", 0)], packet_id=1))
        sub.read_frame(timeout=1.0)
        time.sleep(0.4)
        poisoned = False
        while True:
            f = sub.read_frame(timeout=0.4)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH" and pf.get("retain"):
                poisoned = True
                art["payload_hex"] = pf.get("payload", b"")[:80].hex()
        art["poisoned"] = poisoned
        sig = "CHAIN_POISONED" if poisoned else "CHAIN_FAILED"
        return BrokerResult(name, True, sig, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        # cleanup
        try:
            cleanup = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.0)
            cleanup.connect()
            _do_simple_connect(cleanup, f"clean_{random.randint(0,9999)}")
            cleanup.send(build_publish("alarms/active", b"", qos=0, retain=True))
            cleanup.close()
        except Exception:
            pass
        atk.close(); sub.close()


def scenario_C2_amplification_chain(broker_info) -> BrokerResult:
    """C-2: Amplification via overlapping subscriptions.

    Single subscriber subscribes to a/b, a/+, +/b, # (4 overlapping
    filters). One PUBLISH should — per spec §3.3.5 — be delivered
    once. Some brokers send N copies (V24 finding).
    """
    name = broker_info["name"]
    t0 = time.time()
    sub = MQTTSession(broker_info["host"], broker_info["port"], timeout=4.0)
    pub = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    art: Dict[str, Any] = {}
    try:
        if not sub.connect() or not _do_simple_connect(sub, f"c2s_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "SUB", duration_ms=0)
        sub.send(build_subscribe([
            ("a/b", 0), ("a/+", 0), ("+/b", 0), ("#", 0)
        ], packet_id=1))
        sub.read_frame(timeout=1.5)

        if not pub.connect() or not _do_simple_connect(pub, f"c2p_{random.randint(0,9999)}"):
            return BrokerResult(name, False, "PUB", duration_ms=0)
        pub.send(build_publish("a/b", b"X", qos=0))
        time.sleep(0.4)
        copies = 0
        while True:
            f = sub.read_frame(timeout=0.4)
            if f is None: break
            pf = parse_frame(f)
            if pf.get("type") == "PUBLISH" and pf.get("topic") == "a/b":
                copies += 1
        art["copies"] = copies
        sig = f"AMP_COPIES={copies}"
        return BrokerResult(name, True, sig, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        sub.close(); pub.close()


def scenario_C3_connection_flood_50(broker_info) -> BrokerResult:
    """C-3: Open 50 concurrent CONNECTs, measure how many succeed."""
    name = broker_info["name"]
    t0 = time.time()
    sessions: List[MQTTSession] = []
    art: Dict[str, Any] = {"accepted": 0, "rejected": 0}
    try:
        for i in range(50):
            s = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.0)
            if not s.connect():
                art["rejected"] += 1
                continue
            s.send(build_connect(client_id=f"flood_{i}_{random.randint(0,99999)}"))
            f = s.read_frame(timeout=1.0)
            if f and (f[0] >> 4) == 2 and len(f) >= 4 and f[3] == 0:
                art["accepted"] += 1
            else:
                art["rejected"] += 1
            sessions.append(s)
        sig = f"FLOOD_50 accepted={art['accepted']}/50"
        return BrokerResult(name, True, sig, artifacts=art,
                            duration_ms=(time.time()-t0)*1000)
    finally:
        for s in sessions:
            try: s.close()
            except Exception: pass


# ═════════════════════════════════════════════════════════════
# SECTION 13 — Master test registry & main runner
# ═════════════════════════════════════════════════════════════

TESTS = [
    # M-series — multi-client scenarios
    ("M1_will_observer", "MULTI_CLIENT", "Cross-client Will message delivery to subscriber",
     "CWE-285", "§3.1.2.5", "high", scenario_M1_will_observer),
    ("M2_session_hijack_with_inflight", "MULTI_CLIENT",
     "ClientID hijack while victim has in-flight QoS1",
     "CWE-287", "§3.1.4", "high", scenario_M2_session_hijack_with_inflight),
    ("M3_retain_poison_chain", "MULTI_CLIENT",
     "Retained-message poison delivered to fresh subscriber",
     "CWE-345", "§3.3.1.3", "high", scenario_M3_retain_poison_chain),
    ("M4_wildcard_eavesdrop", "MULTI_CLIENT",
     "Anonymous '#' wildcard receives all topic traffic",
     "CWE-285", "§4.7.1", "high", scenario_M4_wildcard_eavesdrop),
    ("M5_concurrent_clientid_race", "MULTI_CLIENT",
     "Two clients race to grab same persistent ClientID",
     "CWE-362", "§3.1.4", "medium", scenario_M5_concurrent_clientid_race),

    # R-series — race / timing
    ("R1_qos2_pubrel_dup_race", "RACE_TIMING",
     "PUBREL races duplicate PUBLISH (same PID)",
     "CWE-362", "§4.3.3", "medium", scenario_R1_qos2_pubrel_dup_race),
    ("R2_disconnect_during_pubrec", "RACE_TIMING",
     "Disconnect publisher mid QoS2 handshake",
     "CWE-755", "§4.3.3", "medium", scenario_R2_disconnect_during_pubrec),
    ("R3_keepalive_timing_window", "RACE_TIMING",
     "Keepalive=2s, no traffic for 5s — broker still responds?",
     "CWE-400", "§3.1.2.10", "medium", scenario_R3_keepalive_timing_window),
    ("R4_concurrent_retain_clear", "RACE_TIMING",
     "Concurrent retain set vs retain clear",
     "CWE-362", "§3.3.1.3", "low", scenario_R4_concurrent_retain_clear),

    # V5-series — MQTT v5 abuse
    ("V51_topic_alias_oob", "MQTT5_ABUSE",
     "TopicAlias > broker TopicAliasMaximum",
     "CWE-20", "§3.3.2.3.4", "medium", scenario_V5_1_topic_alias_oob),
    ("V52_session_expiry_overflow", "MQTT5_ABUSE",
     "SessionExpiryInterval = 0xFFFFFFFF",
     "CWE-400", "§3.1.2.11.4", "medium", scenario_V5_2_session_expiry_overflow),
    ("V53_user_property_flood", "MQTT5_ABUSE",
     "PUBLISH with 100 UserProperty entries (~40KB props)",
     "CWE-400", "§2.2.2.2", "medium", scenario_V5_3_user_property_flood),
    ("V54_subscription_id_conflict", "MQTT5_ABUSE",
     "Two SUBSCRIBE with the same SubscriptionIdentifier",
     "CWE-694", "§3.8.2.1.2", "low", scenario_V5_4_subscription_id_conflict),

    # Q-series — QoS 2 state machine
    ("Q1_orphan_pubrel", "QOS2_STATE",
     "Orphan PUBREL (no prior PUBLISH)",
     "CWE-755", "§4.3.3", "low", scenario_Q1_pubrel_without_publish),
    ("Q2_orphan_pubcomp", "QOS2_STATE",
     "Orphan PUBCOMP (no prior PUBREL)",
     "CWE-755", "§4.3.3", "low", scenario_Q2_pubcomp_without_pubrel),
    ("Q3_qos2_inflight_storm", "QOS2_STATE",
     "50 concurrent QoS2 PUBLISH without PUBREL",
     "CWE-400", "§4.4", "medium", scenario_Q3_qos2_inflight_storm),
    ("Q4_pubrec_storm", "QOS2_STATE",
     "30 PUBRECs with no prior PUBLISH",
     "CWE-755", "§4.3.3", "low", scenario_Q4_pubrec_storm_no_pubrel),
    ("Q5_pid_zero_each_packet", "QOS2_STATE",
     "PID=0 in PUBLISH+PUBACK+PUBREC+PUBREL+PUBCOMP",
     "CWE-20", "§2.3.1", "high", scenario_Q5_pid_zero_each_packet_type),
    ("Q6_qos2_happy_control", "QOS2_STATE",
     "Happy-path QoS2 control case",
     "", "§4.3.3", "info", scenario_Q6_qos2_complete_normal),

    # X-series — protocol-version mixing
    ("X1_v5pub_v3sub", "VERSION_MIX",
     "v5 publisher (with props) → v3 subscriber",
     "CWE-694", "§3.3", "low", scenario_X1_v5_pub_v3_sub),
    ("X2_v3pub_v5sub", "VERSION_MIX",
     "v3 publisher → v5 subscriber",
     "CWE-694", "§3.3", "info", scenario_X2_v3_pub_v5_sub),

    # SFB — state-feedback mutation
    ("SFB_seed_corpus_mutation", "STATE_FEEDBACK",
     "80 mutations on CONNECT with novelty feedback",
     "CWE-20", "various", "info", scenario_SFB_seed_corpus_mutation),

    # C-series — chained
    ("C1_will_retain_hijack_chain", "CHAINED",
     "Will + Retain composed for one-shot lasting attack",
     "CWE-285", "§3.1.2.5+§3.3.1.3", "high", scenario_C1_will_retain_hijack_chain),
    ("C2_amplification_chain", "CHAINED",
     "Overlapping subscriptions amplify single PUBLISH",
     "CWE-405", "§3.3.5", "high", scenario_C2_amplification_chain),
    ("C3_connection_flood_50", "CHAINED",
     "50 concurrent CONNECTs — accepted vs rejected",
     "CWE-400", "§3.1", "medium", scenario_C3_connection_flood_50),
]


def run_all(quick: bool = False) -> List[FinalTestResult]:
    results: List[FinalTestResult] = []
    tests = TESTS[:8] if quick else TESTS
    print(f"\n[+] Final Campaign — running {len(tests)} differential test cases")
    print(f"    Brokers: {list(BROKERS.keys())}")
    for tid, cat, desc, cwe, spec, sev, fn in tests:
        print(f"    [{tid:36}] {cat:14} ", end="", flush=True)
        try:
            r = run_differential(fn, tid, cat, desc, cwe=cwe, spec_ref=spec, severity_hint=sev)
            results.append(r)
            mark = "DIVERGENT" if r.is_anomaly else "uniform"
            print(f"{mark:9} sigs:", end=" ")
            for n, br in r.results.items():
                print(f"{n}={br.response_signature[:36]}", end="  ")
            print()
        except Exception as e:
            print(f"ERROR {e}")
    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--quick", action="store_true",
                   help="Run only the first 8 tests for smoke check")
    p.add_argument("--out", default="reports/fuzzing_raw_results_final.json",
                   help="Output JSON path")
    args = p.parse_args()

    print("="*70)
    print(" MQTT Security Agent — FINAL Campaign")
    print(" UCLA ECE 202C — Patrick Argento")
    print("="*70)

    # Pre-flight check brokers
    print("\n[+] Pre-flight broker check:")
    for n, info in BROKERS.items():
        s = MQTTSession(info["host"], info["port"], timeout=2.0)
        ok = s.connect()
        s.close()
        print(f"    {n:10} {info['host']}:{info['port']} {'ONLINE' if ok else 'OFFLINE'}")

    t0 = time.time()
    results = run_all(quick=args.quick)
    elapsed = time.time() - t0

    out = {
        "campaign": "FINAL",
        "started": datetime.utcnow().isoformat(),
        "duration_seconds": elapsed,
        "brokers_tested": list(BROKERS.keys()),
        "test_count": len(results),
        "anomaly_count": sum(1 for r in results if r.is_anomaly),
        "results": [r.to_dict() for r in results],
    }
    out_path = args.out
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print("\n" + "="*70)
    print(f" Done in {elapsed:.1f}s")
    print(f" Tests: {len(results)}  Divergent: {out['anomaly_count']}")
    print(f" Raw output: {out_path}")
    print("="*70)


if __name__ == "__main__":
    main()
