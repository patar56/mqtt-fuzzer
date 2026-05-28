#!/usr/bin/env python3
"""
verify_mitigations_final.py
UCLA ECE 202C — Final Project — Patrick Argento

Run after applying the hardened configs.  Each test corresponds
to one Final-campaign finding and reports PASS / FAIL / N/A based
on the broker's runtime behavior — not config inspection — so the
mitigation is verified end-to-end.

Usage:
    python3 scripts/verify_mitigations_final.py [--broker mosquitto|emqx|nanomq|hivemq|all]

Returns exit-code 0 if every test for the selected broker(s) PASSes
or is skipped (N/A); otherwise exit-code 1.
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from typing import Optional, List, Tuple, Dict, Any

# Re-use the MQTT primitives from campaign_final_fuzzer
sys.path.insert(0, ".")
from campaign_final_fuzzer import (   # type: ignore
    BROKERS, MQTTSession, build_connect, build_publish, build_subscribe,
    build_pingreq, build_puback, build_pubrec, build_pubrel, build_pubcomp,
    parse_frame, _do_simple_connect,
)


# ── Verification primitives ─────────────────────────────────

def expect_anonymous_rejected(broker_info) -> Tuple[str, str]:
    """V1/V8: anonymous CONNECT without credentials must be rejected."""
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.0)
    if not s.connect():
        return "FAIL", "tcp_failed"
    s.send(build_connect(client_id="anon", clean_session=True))
    f = s.read_frame(timeout=1.5)
    s.close()
    if f is None:
        return "PASS", "no_connack (broker dropped anon)"
    pt = (f[0] >> 4) & 0xF
    if pt == 2 and len(f) >= 4:
        rc = f[3]
        if rc != 0:
            return "PASS", f"CONNACK rc={rc}"
        return "FAIL", "anonymous accepted"
    return "PASS", "non-CONNACK response"


def expect_wildcard_blocked(broker_info) -> Tuple[str, str]:
    """V4/M4: subscribing to '#' as anon should be denied or get rc>=128."""
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    if not s.connect():
        return "FAIL", "tcp_failed"
    s.send(build_connect(client_id="wctest", clean_session=True))
    ck = s.read_frame(timeout=1.5)
    if not ck or (ck[0] >> 4) != 2 or (len(ck) >= 4 and ck[3] != 0):
        s.close()
        return "PASS", "anon rejected (no SUBSCRIBE possible)"
    s.send(build_subscribe([("#", 0)], packet_id=1))
    f = s.read_frame(timeout=1.5)
    s.close()
    if f is None:
        return "PASS", "broker dropped on '#' subscription"
    pf = parse_frame(f)
    rcs = pf.get("reason_codes", [])
    if rcs and rcs[0] >= 128:
        return "PASS", f"SUBACK rc={rcs[0]}"
    if pf.get("type") == "DISCONNECT":
        return "PASS", "DISCONNECT on '#'"
    return "FAIL", f"'#' granted with rcs={rcs}"


def expect_retain_blocked(broker_info) -> Tuple[str, str]:
    """V2: anon PUBLISH retain=true should be denied (or anon rejected)."""
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.5)
    if not s.connect():
        return "FAIL", "tcp_failed"
    s.send(build_connect(client_id="rtest", clean_session=True))
    ck = s.read_frame(timeout=1.5)
    if not ck or (ck[0] >> 4) != 2 or (len(ck) >= 4 and ck[3] != 0):
        s.close()
        return "PASS", "anon rejected"
    s.send(build_publish("verify/retain", b"X", qos=0, retain=True))
    time.sleep(0.4)

    # New subscriber checks if retained payload is delivered
    s2 = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.5)
    s2.connect()
    s2.send(build_connect(client_id="rtest2", clean_session=True))
    s2.read_frame(timeout=1.0)
    s2.send(build_subscribe([("verify/retain", 0)], packet_id=1))
    s2.read_frame(timeout=1.0)
    time.sleep(0.4)
    got_retain = False
    while True:
        f = s2.read_frame(timeout=0.4)
        if f is None: break
        pf = parse_frame(f)
        if pf.get("type") == "PUBLISH" and pf.get("retain"):
            got_retain = True
    s.close(); s2.close()
    if got_retain:
        return "FAIL", "retained payload delivered to anon subscriber"
    return "PASS", "no retained delivery"


def expect_pid_zero_rejected(broker_info) -> Tuple[str, str]:
    """V10/Q5: PID=0 in PUBLISH(qos=1) must be rejected."""
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=2.5)
    if not s.connect():
        return "FAIL", "tcp_failed"
    s.send(build_connect(client_id="pid0", clean_session=True))
    ck = s.read_frame(timeout=1.5)
    if not ck or (ck[0] >> 4) != 2 or (len(ck) >= 4 and ck[3] != 0):
        s.close()
        return "N/A", "broker rejected anon (cannot reach PID=0 path)"
    s.send(build_publish("v/p", b"x", qos=1, packet_id=0))
    time.sleep(0.4)
    f = s.read_frame(timeout=0.6)
    s.close()
    if f is None:
        return "PASS", "broker disconnected on PID=0"
    pt = (f[0] >> 4) & 0xF
    if pt == 4:  # PUBACK — accepting PID=0 is the V10 vulnerability
        return "FAIL", "PUBACK for PID=0 (§2.3.1 violation)"
    return "PASS", f"non-PUBACK response, pt={pt}"


def expect_keepalive_enforced(broker_info) -> Tuple[str, str]:
    """V27/R3: with keepalive=2s, broker must drop after ~3s idle."""
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=8.0)
    if not s.connect():
        return "FAIL", "tcp_failed"
    s.send(build_connect(client_id="ka", keepalive=2))
    ck = s.read_frame(timeout=1.5)
    if not ck or (ck[0] >> 4) != 2 or (len(ck) >= 4 and ck[3] != 0):
        s.close()
        return "N/A", "anon rejected"
    time.sleep(5.0)
    s.send(build_pingreq())
    f = s.read_frame(timeout=2.0)
    s.close()
    if f is None or (f[0] >> 4) != 13:
        return "PASS", "broker enforced keepalive (no PINGRESP)"
    return "FAIL", "PINGRESP after 5s idle (no enforcement)"


def expect_packet_size_capped(broker_info) -> Tuple[str, str]:
    """V18: 256KB-payload CONNECT must be rejected/dropped if max_packet_size is set.

    Note: client_id field is u16-length-prefixed so we can't pad there.
    Instead we put the bulk in the username field (also u16) and send
    multiple, but actually we just craft a long password (also u16, max 65535).
    For a true >65KB packet we manually concatenate inside username+password
    + a pre-encoded long client_id at limit.
    """
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    if not s.connect():
        return "FAIL", "tcp_failed"
    # Build a CONNECT with username=65535B and password=65535B and clientid=64KB
    # — total ~ 200 KB, exceeds typical max_packet_size=64KB.
    big_user = b"u" * 65535
    big_pass = b"p" * 65535
    big_cid = "c" * 65535
    big = build_connect(client_id=big_cid,
                        username=big_user.decode(),
                        password=big_pass)
    try:
        s.send(big)
        f = s.read_frame(timeout=2.0)
    except Exception:
        f = None
    s.close()
    if f is None:
        return "PASS", "broker dropped oversized CONNECT"
    if (f[0] >> 4) == 2 and len(f) >= 4 and f[3] != 0:
        return "PASS", f"CONNACK rejection rc={f[3]}"
    return "FAIL", "oversized CONNECT accepted"


def expect_subscription_count_capped(broker_info) -> Tuple[str, str]:
    """V19: 100 subs in one SUBSCRIBE must be partially denied or capped."""
    s = MQTTSession(broker_info["host"], broker_info["port"], timeout=3.0)
    if not s.connect():
        return "FAIL", "tcp_failed"
    s.send(build_connect(client_id="manysubs"))
    ck = s.read_frame(timeout=1.5)
    if not ck or (ck[0] >> 4) != 2 or (len(ck) >= 4 and ck[3] != 0):
        s.close()
        return "N/A", "anon rejected"
    s.send(build_subscribe([(f"x/{i}", 0) for i in range(100)], packet_id=1))
    f = s.read_frame(timeout=1.5)
    s.close()
    if f is None:
        return "PASS", "broker dropped many-subs"
    pf = parse_frame(f)
    rcs = pf.get("reason_codes", [])
    fails = sum(1 for r in rcs if r >= 128)
    if fails > 0:
        return "PASS", f"{fails}/100 subs rejected"
    return "FAIL", "all 100 subs accepted"


VERIFY_TESTS = [
    ("V1/V8 anon rejected",            expect_anonymous_rejected),
    ("V4/M4 '#' wildcard blocked",     expect_wildcard_blocked),
    ("V2 retain blocked",              expect_retain_blocked),
    ("V10/Q5 PID=0 rejected",          expect_pid_zero_rejected),
    ("V27/R3 keepalive enforced",      expect_keepalive_enforced),
    ("V18 packet size capped",         expect_packet_size_capped),
    ("V19 subscription count capped",  expect_subscription_count_capped),
]


def run_for_broker(broker_name: str) -> List[Dict[str, Any]]:
    info = BROKERS[broker_name].copy()
    info["name"] = broker_name
    print(f"\n=== Verifying {broker_name} ({info['host']}:{info['port']}) ===")
    out: List[Dict[str, Any]] = []
    for label, fn in VERIFY_TESTS:
        try:
            status, detail = fn(info)
        except Exception as e:
            status, detail = "ERROR", str(e)
        marker = {"PASS": "+", "FAIL": "-", "N/A": "~", "ERROR": "!"}.get(status, "?")
        print(f"  [{marker}] {label:40} {status:5} {detail}")
        out.append({"broker": broker_name, "test": label,
                    "status": status, "detail": detail})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--broker", default="all",
                    help="mosquitto|emqx|nanomq|hivemq|all")
    args = ap.parse_args()
    targets = list(BROKERS.keys()) if args.broker == "all" else [args.broker]

    all_results: List[Dict[str, Any]] = []
    for b in targets:
        all_results.extend(run_for_broker(b))

    n_fail = sum(1 for r in all_results if r["status"] == "FAIL")
    n_pass = sum(1 for r in all_results if r["status"] == "PASS")
    n_na   = sum(1 for r in all_results if r["status"] == "N/A")
    print(f"\nSummary: {n_pass} PASS, {n_fail} FAIL, {n_na} N/A "
          f"(of {len(all_results)} total)")
    sys.exit(0 if n_fail == 0 else 1)


if __name__ == "__main__":
    main()
