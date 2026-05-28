#!/usr/bin/env python3
"""
demo_public_fuzz.py
===================

Short MQTT fuzzing demo against publicly-accessible test brokers
(broker.hivemq.com, test.mosquitto.org, broker.emqx.io).

These brokers are explicitly provided by their maintainers as public test
endpoints. This harness is intentionally conservative:
  - Each probe sends ONE malformed packet, then closes.
  - No PUBLISH floods, no large reconnect storms, no resource exhaustion.
  - Inter-test delay enforces a per-broker rate limit.
  - A small fixed catalog of well-known protocol-conformance test cases.

The point of the demo is to *observe broker behavior* (accept / reject /
silent-drop / RST / DISCONNECT with reason code), not to find new CVEs.

Author : Patrick Argento (UCLA ECE 202C, IoT Security Final Project)
Date   : 2026-05-17
"""

import socket
import struct
import time
import json
import sys
import os
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any

# ---------------------------------------------------------------------------
# Targets - public MQTT test brokers
# ---------------------------------------------------------------------------
TARGETS = [
    {"name": "HiveMQ Public Broker",     "host": "broker.hivemq.com",   "port": 1883},
    {"name": "Eclipse Mosquitto Test",   "host": "test.mosquitto.org",  "port": 1883},
    {"name": "EMQX Public Broker",       "host": "broker.emqx.io",      "port": 1883},
]

CONNECT_TIMEOUT_S = 5.0
READ_TIMEOUT_S    = 3.0
PER_TEST_DELAY_S  = 0.8      # gentle rate limit
PER_BROKER_DELAY_S = 1.5     # extra gap between target switches


# ---------------------------------------------------------------------------
# MQTT v3.1.1 / v5.0 packet builders (raw bytes, so we can be malformed)
# ---------------------------------------------------------------------------
def encode_remaining_length(n: int) -> bytes:
    """MQTT variable byte integer (1-4 bytes)."""
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            break
    return bytes(out)


def utf8(s: str) -> bytes:
    """MQTT UTF-8 encoded string: 2-byte length prefix + bytes."""
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def build_connect_v311(client_id: str = "demo-fuzz", keepalive: int = 30,
                       protocol_name: bytes = b"MQTT", protocol_level: int = 4,
                       connect_flags: int = 0x02) -> bytes:
    """Standard MQTT 3.1.1 CONNECT with clean-session=1."""
    var_hdr  = utf8(protocol_name.decode())
    var_hdr += bytes([protocol_level])
    var_hdr += bytes([connect_flags])
    var_hdr += struct.pack(">H", keepalive)
    payload  = utf8(client_id)
    remaining = var_hdr + payload
    return bytes([0x10]) + encode_remaining_length(len(remaining)) + remaining


def build_connect_v5(client_id: str = "demo-fuzz-v5", keepalive: int = 30,
                     properties: bytes = b"") -> bytes:
    """MQTT 5.0 CONNECT (protocol level 5) with optional CONNECT properties."""
    var_hdr  = utf8("MQTT")
    var_hdr += bytes([5])         # protocol level 5
    var_hdr += bytes([0x02])      # clean start
    var_hdr += struct.pack(">H", keepalive)
    var_hdr += encode_remaining_length(len(properties)) + properties
    payload  = utf8(client_id)
    payload += encode_remaining_length(0)  # no will properties (no will flag)
    remaining = var_hdr + payload
    return bytes([0x10]) + encode_remaining_length(len(remaining)) + remaining


# ---------------------------------------------------------------------------
# Network harness
# ---------------------------------------------------------------------------
def send_probe(host: str, port: int, packet: bytes,
               read_bytes: int = 256) -> Dict[str, Any]:
    """
    Open TCP socket, send one packet, read response, close. Returns a structured
    observation dict. Never raises; failures are captured in the result.
    """
    obs: Dict[str, Any] = {
        "tcp_connect_ok": False,
        "send_ok": False,
        "response_hex": None,
        "response_len": 0,
        "parsed": None,
        "socket_error": None,
        "rtt_ms": None,
        "behavior": None,
    }
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT_S)
    try:
        s.connect((host, port))
        obs["tcp_connect_ok"] = True
        s.sendall(packet)
        obs["send_ok"] = True
        s.settimeout(READ_TIMEOUT_S)
        try:
            data = s.recv(read_bytes)
            obs["response_len"] = len(data)
            obs["response_hex"] = data.hex()
            obs["parsed"] = parse_response(data)
            if len(data) == 0:
                obs["behavior"] = "server_closed_no_response"
            else:
                obs["behavior"] = "server_responded"
        except socket.timeout:
            obs["behavior"] = "no_response_timeout"
        except ConnectionResetError:
            obs["behavior"] = "tcp_reset"
    except socket.timeout:
        obs["socket_error"] = "connect_timeout"
        obs["behavior"] = "connect_timeout"
    except Exception as e:
        obs["socket_error"] = f"{type(e).__name__}: {e}"
        obs["behavior"] = "socket_error"
    finally:
        try:
            s.close()
        except Exception:
            pass
    obs["rtt_ms"] = round((time.time() - t0) * 1000, 1)
    return obs


def parse_response(data: bytes) -> Optional[Dict[str, Any]]:
    """Best-effort decode of a CONNACK / DISCONNECT response."""
    if not data:
        return None
    pkt_type = (data[0] >> 4) & 0x0F
    names = {
        2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
        6: "PUBREL", 7: "PUBCOMP", 9: "SUBACK", 11: "UNSUBACK",
        13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH",
    }
    info: Dict[str, Any] = {"first_byte": f"0x{data[0]:02x}",
                            "packet_type_id": pkt_type,
                            "packet_type": names.get(pkt_type, "UNKNOWN")}
    if pkt_type == 2 and len(data) >= 4:
        # CONNACK: byte2=remaining_len, byte3=ack_flags, byte4=reason_code
        info["ack_flags"]   = f"0x{data[2]:02x}"
        info["reason_code"] = f"0x{data[3]:02x}"
        info["reason_meaning"] = mqtt_reason_meaning(data[3])
    elif pkt_type == 14 and len(data) >= 3:
        info["reason_code"] = f"0x{data[2]:02x}"
        info["reason_meaning"] = mqtt_reason_meaning(data[2])
    return info


def mqtt_reason_meaning(code: int) -> str:
    """Subset of MQTT v5.0 reason codes most likely to appear in this demo."""
    table = {
        0x00: "Success / Normal disconnection",
        0x80: "Unspecified error",
        0x81: "Malformed Packet",
        0x82: "Protocol Error",
        0x83: "Implementation specific error",
        0x84: "Unsupported Protocol Version",
        0x85: "Client Identifier not valid",
        0x86: "Bad User Name or Password",
        0x87: "Not authorized",
        0x88: "Server unavailable",
        0x8A: "Banned",
        0x90: "Topic Name invalid",
        0x95: "Packet too large",
        0x99: "Payload format invalid",
        0x9C: "Use another server",
        0x9F: "Connection rate exceeded",
    }
    # MQTT 3.1.1 CONNACK return codes 0-5
    v3 = {0: "v3 Accepted", 1: "v3 Unacceptable protocol version",
          2: "v3 Identifier rejected", 3: "v3 Server unavailable",
          4: "v3 Bad user/password", 5: "v3 Not authorized"}
    if code in table:
        return table[code]
    if code in v3:
        return v3[code]
    return f"Unknown/reserved (0x{code:02x})"


# ---------------------------------------------------------------------------
# Test catalog
# ---------------------------------------------------------------------------
def build_test_cases() -> List[Dict[str, Any]]:
    """A small, focused set of protocol-conformance probes."""
    cases: List[Dict[str, Any]] = []

    # T1 baseline: well-formed v3.1.1 CONNECT (should succeed)
    cases.append({
        "id": "T1",
        "category": "Baseline",
        "name": "Valid MQTT 3.1.1 CONNECT (control)",
        "description": "Sanity check: standards-compliant CONNECT, expect CONNACK 0x00.",
        "spec_ref": "MQTT v3.1.1 sec 3.1",
        "expected": "CONNACK reason 0x00",
        "packet": build_connect_v311(client_id="demo-baseline"),
    })

    # T2 baseline: well-formed v5.0 CONNECT (should succeed)
    cases.append({
        "id": "T2",
        "category": "Baseline",
        "name": "Valid MQTT 5.0 CONNECT (control)",
        "description": "Standards-compliant v5 CONNECT, expect CONNACK 0x00.",
        "spec_ref": "MQTT v5.0 sec 3.1",
        "expected": "CONNACK reason 0x00",
        "packet": build_connect_v5(client_id="demo-baseline-v5"),
    })

    # T3: invalid protocol name ("MQQT" instead of "MQTT")
    bad_name = utf8("MQQT") + bytes([4, 0x02]) + struct.pack(">H", 30) + utf8("demo")
    pkt = bytes([0x10]) + encode_remaining_length(len(bad_name)) + bad_name
    cases.append({
        "id": "T3",
        "category": "Malformed CONNECT",
        "name": "Invalid protocol name 'MQQT'",
        "description": "Protocol name field corrupted. Spec requires server to reject with "
                       "CONNACK 0x01 (v3) or 0x84 Unsupported Protocol Version (v5), or to "
                       "close the network connection.",
        "spec_ref": "MQTT v5.0 sec 3.1.2.1 [MQTT-3.1.2-1]",
        "expected": "Reject (CONNACK 0x84) or TCP close",
        "packet": pkt,
    })

    # T4: unsupported protocol level (level=99)
    var = utf8("MQTT") + bytes([99, 0x02]) + struct.pack(">H", 30) + utf8("demo")
    pkt = bytes([0x10]) + encode_remaining_length(len(var)) + var
    cases.append({
        "id": "T4",
        "category": "Malformed CONNECT",
        "name": "Unsupported protocol level 99",
        "description": "Protocol level set to 0x63. Server MUST respond with "
                       "CONNACK reason 0x84 (Unsupported Protocol Version).",
        "spec_ref": "MQTT v5.0 sec 3.1.2.2 [MQTT-3.1.2-2]",
        "expected": "CONNACK reason 0x84 or 0x01",
        "packet": pkt,
    })

    # T5: reserved flag bit 0 set (must be 0 in v3.1.1/v5)
    var = utf8("MQTT") + bytes([4, 0x03]) + struct.pack(">H", 30) + utf8("demo")
    pkt = bytes([0x10]) + encode_remaining_length(len(var)) + var
    cases.append({
        "id": "T5",
        "category": "Malformed CONNECT",
        "name": "Reserved CONNECT flag bit set",
        "description": "Bit 0 of CONNECT flags is reserved and MUST be 0. Server MUST treat "
                       "as malformed packet and close.",
        "spec_ref": "MQTT v5.0 sec 3.1.2.3 [MQTT-3.1.2-3]",
        "expected": "Malformed Packet (0x81) or TCP close",
        "packet": pkt,
    })

    # T6: oversized client ID (4096 bytes)
    big_id = "A" * 4096
    cases.append({
        "id": "T6",
        "category": "Boundary - oversized field",
        "name": "Oversized client ID (4096 bytes)",
        "description": "Spec recommends client IDs up to 23 chars; longer IDs are allowed "
                       "but server may reject. Test memory handling of large UTF-8 payload.",
        "spec_ref": "MQTT v3.1.1 sec 3.1.3.1",
        "expected": "CONNACK 0x00 (accepted) or CONNACK 0x85 (Client ID invalid)",
        "packet": build_connect_v311(client_id=big_id),
    })

    # T7: zero-length client ID, clean_session=0 (illegal in v3.1.1)
    var = utf8("MQTT") + bytes([4, 0x00]) + struct.pack(">H", 30) + utf8("")
    pkt = bytes([0x10]) + encode_remaining_length(len(var)) + var
    cases.append({
        "id": "T7",
        "category": "Malformed CONNECT",
        "name": "Zero-length client ID with clean_session=0",
        "description": "v3.1.1: zero-length client ID requires CleanSession=1. With "
                       "CleanSession=0 server MUST reject with CONNACK 0x02.",
        "spec_ref": "MQTT v3.1.1 sec 3.1.3.1 [MQTT-3.1.3-7]",
        "expected": "CONNACK return code 0x02 (Identifier rejected)",
        "packet": pkt,
    })

    # T8: bogus remaining-length varint (0xFF 0xFF 0xFF 0xFF - invalid)
    pkt = bytes([0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
    cases.append({
        "id": "T8",
        "category": "Malformed CONNECT",
        "name": "Invalid Remaining Length varint (0xFFFFFFFF)",
        "description": "4th byte of variable byte integer must not have continuation bit. "
                       "Server must treat as Malformed Packet.",
        "spec_ref": "MQTT v5.0 sec 1.5.5",
        "expected": "TCP close or DISCONNECT 0x81",
        "packet": pkt,
    })

    # T9: PUBLISH before CONNECT (state machine violation)
    topic = utf8("demo/state-machine")
    pub_remaining = topic + b"hi"
    pkt = bytes([0x30]) + encode_remaining_length(len(pub_remaining)) + pub_remaining
    cases.append({
        "id": "T9",
        "category": "State-machine violation",
        "name": "PUBLISH sent before CONNECT",
        "description": "First packet on a network connection MUST be CONNECT. Any other "
                       "packet MUST cause the server to close the network connection.",
        "spec_ref": "MQTT v5.0 sec 3.1 [MQTT-3.1.0-1]",
        "expected": "TCP close, no response",
        "packet": pkt,
    })

    # T10: QoS = 3 in PUBLISH fixed header (after we'd connect; we pre-send standalone)
    # Wrap it as a single-packet probe: even disconnected, the parser will reject.
    pub = bytes([0x36]) + encode_remaining_length(2 + len(b"x")) + utf8("t") + b"x"
    cases.append({
        "id": "T10",
        "category": "Malformed PUBLISH",
        "name": "PUBLISH with QoS=3 (reserved)",
        "description": "QoS bits 1+2 set simultaneously = QoS 3, which is reserved/invalid. "
                       "Spec: 'A PUBLISH Packet MUST NOT have both QoS bits set to 1.'",
        "spec_ref": "MQTT v5.0 sec 3.3.1.2 [MQTT-3.3.1-4]",
        "expected": "TCP close or Malformed Packet response",
        "packet": pub,
    })

    # T11: v5 CONNECT with Topic Alias Maximum property = 0xFFFF (boundary)
    # Property ID 0x22 = Topic Alias Maximum (2-byte int)
    props = bytes([0x22]) + struct.pack(">H", 0xFFFF)
    cases.append({
        "id": "T11",
        "category": "v5 properties",
        "name": "v5 CONNECT with Topic Alias Maximum = 65535",
        "description": "Tests broker's handling of maximum legal property value.",
        "spec_ref": "MQTT v5.0 sec 3.1.2.11.5",
        "expected": "CONNACK 0x00 with possibly reduced TopicAliasMax in response",
        "packet": build_connect_v5(client_id="demo-prop-max", properties=props),
    })

    # T12: v5 CONNECT with duplicate Session Expiry Interval property (illegal)
    # Property ID 0x11 = Session Expiry Interval (4-byte int)
    props = (bytes([0x11]) + struct.pack(">I", 60) +
             bytes([0x11]) + struct.pack(">I", 120))
    cases.append({
        "id": "T12",
        "category": "v5 properties",
        "name": "v5 CONNECT duplicate Session Expiry Interval",
        "description": "A property MUST NOT appear more than once in a packet. Duplicate "
                       "MUST cause Protocol Error (0x82).",
        "spec_ref": "MQTT v5.0 sec 2.2.2.2",
        "expected": "CONNACK reason 0x82 (Protocol Error) or TCP close",
        "packet": build_connect_v5(client_id="demo-dup-prop", properties=props),
    })

    return cases


# ---------------------------------------------------------------------------
# Campaign runner
# ---------------------------------------------------------------------------
def run_campaign(targets: List[Dict[str, Any]],
                 cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for ti, tgt in enumerate(targets):
        print(f"\n{'=' * 78}")
        print(f"TARGET {ti+1}/{len(targets)}: {tgt['name']} ({tgt['host']}:{tgt['port']})")
        print('=' * 78)

        # Pre-flight TCP check so we don't waste time on dead targets
        try:
            s = socket.socket()
            s.settimeout(CONNECT_TIMEOUT_S)
            s.connect((tgt["host"], tgt["port"]))
            s.close()
            print(f"  TCP reachability: OK")
        except Exception as e:
            print(f"  TCP reachability: FAIL ({e}) - skipping target")
            for c in cases:
                results.append({"target": tgt["name"], "host": tgt["host"],
                                "test_id": c["id"], "name": c["name"],
                                "behavior": "skipped_unreachable"})
            continue

        for ci, case in enumerate(cases):
            print(f"  [{case['id']}] {case['name']}")
            obs = send_probe(tgt["host"], tgt["port"], case["packet"])
            line = f"      -> behavior={obs['behavior']} rtt={obs['rtt_ms']}ms"
            if obs["parsed"]:
                p = obs["parsed"]
                line += f" | resp={p.get('packet_type')}"
                if "reason_code" in p:
                    line += f" reason={p['reason_code']} ({p.get('reason_meaning','')})"
            print(line)
            results.append({
                "target":       tgt["name"],
                "host":         tgt["host"],
                "port":         tgt["port"],
                "test_id":      case["id"],
                "category":     case["category"],
                "name":         case["name"],
                "description":  case["description"],
                "spec_ref":     case["spec_ref"],
                "expected":     case["expected"],
                "packet_hex":   case["packet"].hex(),
                "observation":  obs,
                "timestamp":    datetime.now(timezone.utc).isoformat(),
            })
            time.sleep(PER_TEST_DELAY_S)
        time.sleep(PER_BROKER_DELAY_S)
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a compact summary suitable for the demo presentation."""
    by_target: Dict[str, Dict[str, int]] = {}
    interesting: List[Dict[str, Any]] = []
    behaviors_seen: Dict[str, int] = {}

    for r in results:
        t = r["target"]
        b = r.get("observation", {}).get("behavior", "n/a") if isinstance(r.get("observation"), dict) else r.get("behavior","n/a")
        by_target.setdefault(t, {})
        by_target[t][b] = by_target[t].get(b, 0) + 1
        behaviors_seen[b] = behaviors_seen.get(b, 0) + 1

    # Flag rows where brokers diverged on the same test ID
    by_case: Dict[str, List[Tuple[str, str]]] = {}
    for r in results:
        if not isinstance(r.get("observation"), dict):
            continue
        b = r["observation"]["behavior"]
        parsed = r["observation"].get("parsed") or {}
        sig = b + "|" + (parsed.get("reason_code","") if parsed else "")
        by_case.setdefault(r["test_id"], []).append((r["target"], sig))

    divergences: List[Dict[str, Any]] = []
    for tid, rows in by_case.items():
        sigs = {sig for _, sig in rows}
        if len(sigs) > 1:
            divergences.append({"test_id": tid, "per_target": rows})

    return {
        "totals_by_target_behavior": by_target,
        "behaviors_seen": behaviors_seen,
        "divergences": divergences,
    }


def write_outputs(results: List[Dict[str, Any]], summary: Dict[str, Any],
                  out_dir: str) -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(out_dir, f"demo_public_fuzz_{ts}.json")
    md_path   = os.path.join(out_dir, f"demo_public_fuzz_{ts}.md")

    with open(json_path, "w") as f:
        json.dump({"results": results, "summary": summary}, f, indent=2)

    lines: List[str] = []
    lines.append(f"# MQTT Public-Broker Fuzzing Demo - {ts}\n")
    lines.append("## Summary by target / behavior\n")
    for t, behs in summary["totals_by_target_behavior"].items():
        lines.append(f"- **{t}**")
        for b, c in behs.items():
            lines.append(f"  - {b}: {c}")
    lines.append("\n## Behaviors seen overall\n")
    for b, c in summary["behaviors_seen"].items():
        lines.append(f"- {b}: {c}")
    lines.append("\n## Cross-broker divergences (different responses to same test)\n")
    if not summary["divergences"]:
        lines.append("- None observed.\n")
    else:
        for d in summary["divergences"]:
            lines.append(f"- **{d['test_id']}**")
            for tname, sig in d["per_target"]:
                lines.append(f"  - {tname}: {sig}")
    lines.append("\n## Per-test detail\n")
    for r in results:
        if not isinstance(r.get("observation"), dict):
            continue
        obs = r["observation"]
        parsed = obs.get("parsed") or {}
        lines.append(f"### {r['test_id']} - {r['name']} - {r['target']}")
        lines.append(f"- Category: {r['category']}")
        lines.append(f"- Spec: {r['spec_ref']}")
        lines.append(f"- Expected: {r['expected']}")
        lines.append(f"- Observed behavior: `{obs['behavior']}`  rtt={obs['rtt_ms']}ms")
        if parsed:
            lines.append(f"- Response: {parsed.get('packet_type')} "
                         f"reason={parsed.get('reason_code','-')} "
                         f"({parsed.get('reason_meaning','-')})")
        if obs.get("response_hex"):
            lines.append(f"- Raw response (hex): `{obs['response_hex'][:160]}`")
        lines.append("")
    with open(md_path, "w") as f:
        f.write("\n".join(lines))
    return json_path, md_path


def main() -> int:
    print("MQTT Public-Broker Fuzzing Demo")
    print(f"  Started:  {datetime.now().isoformat()}")
    print(f"  Targets:  {[t['host'] for t in TARGETS]}")

    cases = build_test_cases()
    print(f"  Tests:    {len(cases)} probes per target "
          f"({len(TARGETS) * len(cases)} total)")
    print(f"  Pacing:   {PER_TEST_DELAY_S}s between probes, "
          f"{PER_BROKER_DELAY_S}s between brokers")

    results = run_campaign(TARGETS, cases)
    summary = summarize(results)

    print("\n" + "=" * 78)
    print("CAMPAIGN COMPLETE")
    print("=" * 78)
    print("\nBehavior totals per target:")
    for t, behs in summary["totals_by_target_behavior"].items():
        print(f"  {t}")
        for b, c in behs.items():
            print(f"      {b:30s} {c}")
    print(f"\nDivergences across brokers: {len(summary['divergences'])}")
    for d in summary["divergences"]:
        print(f"  - {d['test_id']}")
        for tname, sig in d["per_target"]:
            print(f"      {tname:32s} -> {sig}")

    out_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    out_dir = os.path.abspath(out_dir)
    jp, mp = write_outputs(results, summary, out_dir)
    print(f"\nArtifacts:\n  {jp}\n  {mp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
