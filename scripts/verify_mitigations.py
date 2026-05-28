#!/usr/bin/env python3
"""
Mitigation Verification Script — Campaign 3
UCLA ECE 202C — IoT Security Final Project
Patrick Argento

Usage:
    python3 scripts/verify_mitigations.py [--host HOST] [--port PORT]
    python3 scripts/verify_mitigations.py --host localhost --port 1883

This script verifies that mitigations for all 10 Campaign 1+2 vulnerabilities
are effective. Run it AFTER applying mosquitto_hardened.conf and acl_hardened.conf.

Exit codes:
    0 — All mitigations passed
    1 — One or more mitigations failed (vulnerabilities still present)
"""

import sys
import socket
import struct
import time
import json
import argparse
from typing import Optional, Tuple, List, Dict
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Packet builders (raw, no library dependency)
# ─────────────────────────────────────────────────────────────

def encode_remaining_length(length: int) -> bytes:
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
    if isinstance(s, str):
        b = s.encode("utf-8", errors="replace")
    else:
        b = bytes(s)
    return struct.pack("!H", len(b)) + b

def encode_u16(v: int) -> bytes:
    return struct.pack("!H", v & 0xFFFF)

def build_connect(
    client_id: str = "mitigation_verify",
    clean_session: bool = True,
    keepalive: int = 60,
    username: Optional[str] = None,
    password: Optional[str] = None,
    will_topic: Optional[str] = None,
    will_message: Optional[bytes] = None,
    will_qos: int = 0,
    will_retain: bool = False,
) -> bytes:
    vh = encode_utf8("MQTT") + bytes([0x04])
    flags = 0
    if clean_session: flags |= 0x02
    if will_topic:
        flags |= 0x04
        flags |= (will_qos & 0x03) << 3
        if will_retain: flags |= 0x20
    if password is not None: flags |= 0x40
    if username is not None: flags |= 0x80
    vh += bytes([flags]) + encode_u16(keepalive)
    payload = encode_utf8(client_id)
    if will_topic:
        payload += encode_utf8(will_topic)
        wm = will_message or b""
        payload += struct.pack("!H", len(wm)) + wm
    if username is not None: payload += encode_utf8(username)
    if password is not None: payload += encode_utf8(password)
    body = vh + payload
    return bytes([0x10]) + encode_remaining_length(len(body)) + body

def build_subscribe(topic: str, packet_id: int = 1, qos: int = 0) -> bytes:
    vh = encode_u16(packet_id)
    payload = encode_utf8(topic) + bytes([qos & 0xFF])
    body = vh + payload
    return bytes([0x82]) + encode_remaining_length(len(body)) + body

def build_unsubscribe(topic: str, packet_id: int = 1) -> bytes:
    vh = encode_u16(packet_id)
    payload = encode_utf8(topic)
    body = vh + payload
    return bytes([0xA2]) + encode_remaining_length(len(body)) + body

def build_publish(topic: str, payload: bytes = b"", qos: int = 0,
                  retain: bool = False, packet_id: int = 1) -> bytes:
    first = 0x30 | ((qos & 0x03) << 1) | (0x01 if retain else 0x00)
    vh = encode_utf8(topic)
    if qos > 0: vh += encode_u16(packet_id)
    body = vh + payload
    return bytes([first]) + encode_remaining_length(len(body)) + body

def build_puback(packet_id: int) -> bytes:
    return bytes([0x40, 0x02]) + encode_u16(packet_id)

# ─────────────────────────────────────────────────────────────
# Connection helper
# ─────────────────────────────────────────────────────────────

class RawConn:
    def __init__(self, host: str, port: int, timeout: float = 4.0):
        self.host = host; self.port = port; self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
            return True
        except Exception:
            self._sock = None; return False

    def send(self, data: bytes) -> bool:
        if not self._sock: return False
        try: self._sock.sendall(data); return True
        except: return False

    def recv(self, timeout: Optional[float] = None) -> Optional[bytes]:
        if not self._sock: return None
        self._sock.settimeout(timeout if timeout is not None else self.timeout)
        try:
            data = self._sock.recv(8192)
            return data if data else None
        except socket.timeout: return None
        except: return None

    def send_recv(self, data: bytes, timeout: float = 3.0) -> Optional[bytes]:
        if not self.send(data): return None
        return self.recv(timeout=timeout)

    def close(self):
        if self._sock:
            try: self._sock.close()
            except: pass
            self._sock = None

    def __enter__(self): self.connect(); return self
    def __exit__(self, *_): self.close()

def parse_connack(data: bytes) -> Tuple[int, int]:
    if data and len(data) >= 4 and (data[0] >> 4) == 2:
        return (data[2] & 0x01), data[3]
    return -1, -1

def parse_suback_codes(data: bytes) -> List[int]:
    if not data or (data[0] >> 4) != 9: return []
    try:
        rem_len_bytes = 1 if data[1] < 0x80 else 2
        start = 1 + rem_len_bytes + 2
        return list(data[start:])
    except: return []

def broker_alive(host: str, port: int) -> bool:
    try:
        with RawConn(host, port, timeout=2.0) as c:
            r = c.send_recv(build_connect("liveness_chk"), timeout=2.0)
            return r is not None and parse_connack(r)[1] == 0
    except: return False


# ─────────────────────────────────────────────────────────────
# Verification Tests
# ─────────────────────────────────────────────────────────────

class MitigationVerifier:

    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"

    def __init__(self, host: str = "localhost", port: int = 1883):
        self.host = host
        self.port = port
        self.results: List[Dict] = []
        self._pass = 0
        self._fail = 0

    def _record(self, vuln_id: str, name: str, status: str, detail: str,
                cvss: str = "", cwe: str = "") -> Dict:
        symbol = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}.get(status, "[????]")
        color  = {"PASS": "\033[92m", "FAIL": "\033[91m", "SKIP": "\033[93m"}.get(status, "")
        reset  = "\033[0m"
        print(f"  {color}{symbol}{reset} {vuln_id}: {name}")
        if detail:
            print(f"         {detail}")
        if status == "PASS": self._pass += 1
        elif status == "FAIL": self._fail += 1
        r = {
            "vuln_id": vuln_id, "test_name": name, "status": status,
            "detail": detail, "cvss": cvss, "cwe": cwe,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.results.append(r)
        return r

    # ── V1: Will Message Exploitation ────────────────────────────
    def verify_v1(self):
        """
        Mitigation: ACL denies PUBLISH (and Will) to admin/# topics.
        Expected behavior: CONNECT with will_topic='admin/control' is rejected
        with CONNACK RC=0x05 (Not Authorized) when allow_anonymous=false.
        """
        try:
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect(
                    "v1_verify", username="sensor_device", password="password",
                    will_topic="admin/control",
                    will_message=b"ATTACKER_WILL",
                ), timeout=3.0)
            if r:
                sp, rc = parse_connack(r)
                if rc != 0:
                    return self._record("V1", "Will message ACL enforcement",
                                        self.PASS,
                                        f"CONNACK RC={rc:#04x} — CONNECT with unauthorized Will topic rejected",
                                        cvss="7.5", cwe="CWE-284")
                else:
                    return self._record("V1", "Will message ACL enforcement",
                                        self.FAIL,
                                        f"CONNACK RC=0x00 — broker accepted CONNECT with Will to admin/control. "
                                        "Ensure ACL denies PUBLISH to admin/# for all non-admin users.",
                                        cvss="7.5", cwe="CWE-284")
            return self._record("V1", "Will message ACL enforcement",
                                self.FAIL, "No CONNACK received", cvss="7.5", cwe="CWE-284")
        except Exception as e:
            return self._record("V1", "Will message ACL enforcement",
                                self.FAIL, f"Exception: {e}", cvss="7.5", cwe="CWE-284")

    # ── V2: Retained Message Poisoning ───────────────────────────
    def verify_v2(self):
        """
        Mitigation: ACL restricts PUBLISH (and therefore retain) to device namespaces.
        An unauthenticated or low-privilege client cannot set retained messages on
        sensitive topics like devices/thermostat/setpoint.
        """
        try:
            # Try to publish retained to a restricted topic (should fail)
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect("v2_verify",
                                              username="sensor_device", password="password"), timeout=3.0)
                if not r or parse_connack(r)[1] != 0:
                    return self._record("V2", "Retained message ACL", self.SKIP,
                                        "Could not connect with sensor_device credentials")
                c.send(build_publish("devices/thermostat/setpoint", b"ATTACKER", retain=True))
                time.sleep(0.3)
            # Check: does a new subscriber get the retained message?
            with RawConn(self.host, self.port) as c2:
                r2 = c2.send_recv(build_connect("v2_check", username="backend_app",
                                                password="password"), timeout=3.0)
                if not r2 or parse_connack(r2)[1] != 0:
                    return self._record("V2", "Retained message ACL", self.SKIP,
                                        "Could not connect with backend_app to verify")
                c2.send(build_subscribe("devices/thermostat/setpoint", packet_id=1, qos=0))
                c2.recv(timeout=1.0)  # SUBACK
                retained = c2.recv(timeout=2.0)
            if retained and (retained[0] >> 4) == 3:
                return self._record("V2", "Retained message ACL", self.FAIL,
                                    "Retained message stored and delivered — ACL did not block unauthorized PUBLISH",
                                    cvss="6.5", cwe="CWE-284")
            return self._record("V2", "Retained message ACL", self.PASS,
                                 "No retained message delivered — ACL blocked unauthorized PUBLISH",
                                 cvss="6.5", cwe="CWE-284")
        except Exception as e:
            return self._record("V2", "Retained message ACL", self.FAIL,
                                f"Exception: {e}", cvss="6.5", cwe="CWE-284")

    # ── V3: ClientID Session Hijacking ───────────────────────────
    def verify_v3(self):
        """
        Mitigation: Authentication (allow_anonymous=false) ensures only the
        authorized owner of a ClientID can connect with it. A session can only
        be taken over by a client that has valid credentials AND uses the same
        ClientID — which in a properly configured system is only the device itself.
        The additional defense is max_connections limiting simultaneous sessions.
        """
        try:
            cid = "v3_sensor_device"
            # Victim: connect with sensor_device credentials
            victim = RawConn(self.host, self.port, timeout=4.0)
            victim.connect()
            r1 = victim.send_recv(build_connect(cid, clean_session=False,
                                                username="sensor_device", password="password"), timeout=3.0)
            if not r1 or parse_connack(r1)[1] != 0:
                victim.close()
                return self._record("V3", "ClientID hijacking prevention", self.SKIP,
                                    "Could not establish victim session with sensor_device credentials")
            # Attacker: attempt hijack WITHOUT valid credentials
            with RawConn(self.host, self.port) as atk:
                r2 = atk.send_recv(build_connect(cid, clean_session=False), timeout=3.0)
                sp2, rc2 = parse_connack(r2) if r2 else (-1, -1)
            victim.close()
            if rc2 != 0:
                return self._record("V3", "ClientID hijacking prevention", self.PASS,
                                    f"Unauthenticated hijack attempt rejected (RC={rc2:#04x}). "
                                    "Authentication required — session takeover blocked.",
                                    cvss="8.1", cwe="CWE-287")
            return self._record("V3", "ClientID hijacking prevention", self.FAIL,
                                f"Hijacker got CONNACK RC=0x00, session_present={sp2}. "
                                "Authentication is not blocking session takeover.",
                                cvss="8.1", cwe="CWE-287")
        except Exception as e:
            return self._record("V3", "ClientID hijacking prevention", self.FAIL,
                                f"Exception: {e}", cvss="8.1", cwe="CWE-287")

    # ── V4: Wildcard Subscription Eavesdrop ──────────────────────
    def verify_v4(self):
        """
        Mitigation: ACL explicitly denies '#' subscription to non-admin users.
        SUBACK should return 0x80 (failure) for the '#' filter.
        """
        try:
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect("v4_verify",
                                              username="sensor_device", password="password"), timeout=3.0)
                if not r or parse_connack(r)[1] != 0:
                    return self._record("V4", "Wildcard subscription ACL", self.SKIP,
                                        "CONNECT failed for sensor_device")
                c.send(build_subscribe("#", packet_id=1, qos=0))
                r2 = c.recv(timeout=2.0)
            codes = parse_suback_codes(r2) if r2 else []
            if codes and all(code == 0x80 for code in codes):
                return self._record("V4", "Wildcard subscription ACL", self.PASS,
                                    f"SUBACK codes={codes} — '#' subscription denied (0x80)",
                                    cvss="7.2", cwe="CWE-285")
            return self._record("V4", "Wildcard subscription ACL", self.FAIL,
                                f"SUBACK codes={codes} — '#' subscription granted. ACL not blocking '#'.",
                                cvss="7.2", cwe="CWE-285")
        except Exception as e:
            return self._record("V4", "Wildcard subscription ACL", self.FAIL,
                                f"Exception: {e}", cvss="7.2", cwe="CWE-285")

    # ── V6: $SYS Topic Information Disclosure ────────────────────
    def verify_v6(self):
        """
        Mitigation: ACL denies $SYS/# to all non-admin users.
        No $SYS data should be received by an authenticated but non-admin client.
        """
        try:
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect("v6_verify",
                                              username="sensor_device", password="password"), timeout=3.0)
                if not r or parse_connack(r)[1] != 0:
                    return self._record("V6", "$SYS topic ACL", self.SKIP, "CONNECT failed")
                c.send(build_subscribe("$SYS/#", packet_id=1, qos=0))
                c.recv(timeout=1.0)  # SUBACK
                sys_data = c.recv(timeout=3.0)
            if sys_data and (sys_data[0] >> 4) == 3:
                return self._record("V6", "$SYS topic ACL", self.FAIL,
                                    "$SYS data delivered to non-admin client — ACL not blocking $SYS/#",
                                    cvss="4.3", cwe="CWE-200")
            return self._record("V6", "$SYS topic ACL", self.PASS,
                                 "No $SYS data delivered to non-admin client",
                                 cvss="4.3", cwe="CWE-200")
        except Exception as e:
            return self._record("V6", "$SYS topic ACL", self.FAIL,
                                f"Exception: {e}", cvss="4.3", cwe="CWE-200")

    # ── V8: Unauthenticated Credential Acceptance ────────────────
    def verify_v8(self):
        """
        Mitigation: allow_anonymous=false forces all clients through authentication.
        Anonymous connects (no username/password) should be rejected with RC=0x05.
        """
        try:
            # Test 1: Anonymous connect (no credentials)
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect("v8_anon"), timeout=3.0)
                sp, rc = parse_connack(r) if r else (-1, -1)
            anon_blocked = (rc != 0)

            # Test 2: SQL injection string
            with RawConn(self.host, self.port) as c:
                r2 = c.send_recv(build_connect("v8_sqli",
                                               username="' OR 1=1--", password="pass"), timeout=3.0)
                _, rc2 = parse_connack(r2) if r2 else (-1, -1)
            sqli_blocked = (rc2 != 0)

            # Test 3: Format string
            with RawConn(self.host, self.port) as c:
                r3 = c.send_recv(build_connect("v8_fmt",
                                               username="%s%s%s%s", password="%n"), timeout=3.0)
                _, rc3 = parse_connack(r3) if r3 else (-1, -1)
            fmt_blocked = (rc3 != 0)

            all_blocked = anon_blocked and sqli_blocked and fmt_blocked
            status = self.PASS if all_blocked else self.FAIL
            detail = (
                f"Anon: {'BLOCKED' if anon_blocked else 'ACCEPTED'} (RC={rc:#04x}), "
                f"SQLi: {'BLOCKED' if sqli_blocked else 'ACCEPTED'} (RC={rc2:#04x}), "
                f"FmtStr: {'BLOCKED' if fmt_blocked else 'ACCEPTED'} (RC={rc3:#04x})"
            )
            return self._record("V8", "Authentication enforcement", status, detail,
                                 cvss="6.5", cwe="CWE-287")
        except Exception as e:
            return self._record("V8", "Authentication enforcement", self.FAIL,
                                f"Exception: {e}", cvss="6.5", cwe="CWE-287")

    # ── V9: Shared Subscription Namespace Abuse ──────────────────
    def verify_v9(self):
        """
        Mitigation: ACL denies $share/# and $SHARE/# patterns.
        Malformed shared subscriptions should get SUBACK 0x80.
        """
        try:
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect("v9_verify",
                                              username="sensor_device", password="password"), timeout=3.0)
                if not r or parse_connack(r)[1] != 0:
                    return self._record("V9", "Shared subscription ACL", self.SKIP, "CONNECT failed")
                c.send(build_subscribe("$share//sensors/temp", packet_id=1, qos=0))
                r2 = c.recv(timeout=2.0)
                codes = parse_suback_codes(r2) if r2 else []
                c.send(build_subscribe("$SHARE/group/sensors/temp", packet_id=2, qos=0))
                r3 = c.recv(timeout=2.0)
                codes2 = parse_suback_codes(r3) if r3 else []

            blocked1 = all(code == 0x80 for code in codes) if codes else False
            blocked2 = all(code == 0x80 for code in codes2) if codes2 else False
            status = self.PASS if (blocked1 and blocked2) else self.FAIL
            return self._record("V9", "Shared subscription ACL", status,
                                f"$share//: codes={codes} {'DENIED' if blocked1 else 'GRANTED'}, "
                                f"$SHARE/group/: codes={codes2} {'DENIED' if blocked2 else 'GRANTED'}",
                                cvss="5.4", cwe="CWE-284")
        except Exception as e:
            return self._record("V9", "Shared subscription ACL", self.FAIL,
                                f"Exception: {e}", cvss="5.4", cwe="CWE-284")

    # ── V10: QoS State Machine Leniency ──────────────────────────
    def verify_v10(self):
        """
        Mitigation: Mosquitto 2.x behavior — invalid PID=0 on QoS 1 should cause
        the broker to DISCONNECT the client (per strict mode). With authentication
        enabled, clients generating malformed QoS state are isolated.
        Verify: broker disconnects client sending QoS 1 with PID=0.
        """
        try:
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect("v10_verify",
                                              username="sensor_device", password="password"), timeout=3.0)
                if not r or parse_connack(r)[1] != 0:
                    return self._record("V10", "QoS PID=0 enforcement", self.SKIP, "CONNECT failed")
                # Send QoS 1 with PID=0 — spec violation §2.3.1
                c.send(build_publish("sensors/v10_verify/temp", b"qos_test", qos=1, packet_id=0))
                r2 = c.recv(timeout=2.0)
                still_alive = broker_alive(self.host, self.port)
            if not still_alive:
                return self._record("V10", "QoS PID=0 enforcement", self.FAIL,
                                    "Broker crashed on QoS 1 PID=0 — critical bug",
                                    cvss="4.3", cwe="CWE-703")
            if r2:
                pkt_type = (r2[0] >> 4) if r2 else 0
                if pkt_type == 14:  # DISCONNECT
                    return self._record("V10", "QoS PID=0 enforcement", self.PASS,
                                        "Broker sent DISCONNECT for QoS1 PID=0 — correct per §2.3.1",
                                        cvss="4.3", cwe="CWE-703")
                elif pkt_type == 4:  # PUBACK
                    return self._record("V10", "QoS PID=0 enforcement", self.FAIL,
                                        "Broker sent PUBACK for PID=0 — still accepting invalid QoS state. "
                                        "Mosquitto does not have a strict PID=0 reject config; "
                                        "mitigation requires network-layer filtering (iptables) or "
                                        "upgrading to a version with §2.3.1 enforcement.",
                                        cvss="4.3", cwe="CWE-703")
            return self._record("V10", "QoS PID=0 enforcement", self.FAIL,
                                "No response to QoS1 PID=0 — broker may have silently accepted",
                                cvss="4.3", cwe="CWE-703")
        except Exception as e:
            return self._record("V10", "QoS PID=0 enforcement", self.FAIL,
                                f"Exception: {e}", cvss="4.3", cwe="CWE-703")

    # ── V11: Session Persistence Resource Accumulation ────────────
    def verify_v11(self):
        """
        Mitigation: max_connections=50, persistent_client_expiration=1h,
        max_queued_messages=20. Connection flood should be rate-limited to < 50.
        """
        try:
            succeeded = 0
            conns = []
            t_start = time.time()
            for i in range(100):
                c = RawConn(self.host, self.port, timeout=1.0)
                if c.connect():
                    r = c.send_recv(build_connect(f"flood_v11_{i}",
                                                   username="sensor_device", password="password",
                                                   clean_session=True), timeout=1.0)
                    if r and parse_connack(r)[1] == 0:
                        succeeded += 1
                    conns.append(c)
            elapsed = time.time() - t_start
            for c in conns: c.close()
            rate = succeeded / max(elapsed, 0.001)
            # Mitigation effective if < 50 connections succeed (max_connections=50)
            if succeeded <= 50:
                return self._record("V11", "Connection limit enforcement", self.PASS,
                                    f"{succeeded}/100 connections succeeded in {elapsed:.2f}s ({rate:.0f}/s). "
                                    f"max_connections=50 is enforcing the limit.",
                                    cvss="5.3", cwe="CWE-400")
            return self._record("V11", "Connection limit enforcement", self.FAIL,
                                f"{succeeded}/100 connections succeeded ({rate:.0f}/s). "
                                "max_connections=50 not limiting effectively.",
                                cvss="5.3", cwe="CWE-400")
        except Exception as e:
            return self._record("V11", "Connection limit enforcement", self.FAIL,
                                f"Exception: {e}", cvss="5.3", cwe="CWE-400")

    # ── V17: Configuration Fingerprinting ────────────────────────
    def verify_v17(self):
        """
        Mitigation: ACL denies $SYS/# access. With authentication, anonymous
        clients cannot subscribe to $SYS/broker/version to extract version info.
        """
        try:
            with RawConn(self.host, self.port) as c:
                r = c.send_recv(build_connect("v17_verify",
                                              username="monitor", password="password"), timeout=3.0)
                if not r or parse_connack(r)[1] != 0:
                    return self._record("V17", "Version fingerprint suppression", self.SKIP,
                                        "Could not connect with monitor credentials")
                c.send(build_subscribe("$SYS/broker/version", packet_id=1, qos=0))
                c.recv(timeout=1.0)  # SUBACK
                version_data = c.recv(timeout=3.0)
            if version_data and (version_data[0] >> 4) == 3:
                return self._record("V17", "Version fingerprint suppression", self.FAIL,
                                    "Version string still delivered to non-admin client. "
                                    "Ensure $SYS/# is denied in ACL for monitor user.",
                                    cvss="3.7", cwe="CWE-200")
            return self._record("V17", "Version fingerprint suppression", self.PASS,
                                 "No version data delivered — $SYS restricted by ACL",
                                 cvss="3.7", cwe="CWE-200")
        except Exception as e:
            return self._record("V17", "Version fingerprint suppression", self.FAIL,
                                f"Exception: {e}", cvss="3.7", cwe="CWE-200")

    def run_all(self) -> Dict:
        print(f"\nMitigation Verification Suite — {self.host}:{self.port}")
        print("=" * 60)
        print(f"Timestamp: {datetime.utcnow().isoformat()}Z")
        print()

        self.verify_v1()
        self.verify_v2()
        self.verify_v3()
        self.verify_v4()
        self.verify_v6()
        self.verify_v8()
        self.verify_v9()
        self.verify_v10()
        self.verify_v11()
        self.verify_v17()

        total = self._pass + self._fail
        print()
        print("=" * 60)
        print(f"Results: {self._pass}/{total} PASS  |  {self._fail}/{total} FAIL")
        if self._fail == 0:
            print("\033[92mAll mitigations verified!\033[0m")
        else:
            print(f"\033[91m{self._fail} mitigation(s) failed — vulnerabilities still present.\033[0m")
            print("Check failed tests above and verify mosquitto_hardened.conf + acl_hardened.conf are applied.")
        print()

        return {
            "host": self.host,
            "port": self.port,
            "timestamp": datetime.utcnow().isoformat(),
            "total": total,
            "passed": self._pass,
            "failed": self._fail,
            "results": self.results,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT Mitigation Verification Script — Campaign 3")
    parser.add_argument("--host", default="localhost", help="Broker host (default: localhost)")
    parser.add_argument("--port", type=int, default=1883, help="Broker port (default: 1883)")
    parser.add_argument("--output", help="Save results to JSON file")
    args = parser.parse_args()

    # Check broker connectivity
    print(f"Checking broker at {args.host}:{args.port}...")
    if not broker_alive(args.host, args.port):
        print(f"ERROR: Broker at {args.host}:{args.port} is not responding.")
        print("Start the broker with mosquitto_hardened.conf and try again.")
        sys.exit(2)
    print("Broker is online.\n")

    verifier = MitigationVerifier(args.host, args.port)
    summary = verifier.run_all()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"Results saved to {args.output}")

    # Exit 0 if all passed, 1 if any failed
    sys.exit(0 if summary["failed"] == 0 else 1)
