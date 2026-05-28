"""
MQTT Security Agent — Campaign 2 Fuzzer
UCLA ECE 202C IoT Security Final Project

Extended fuzzing targeting 10 distinct vulnerability classes beyond Campaign 1.
Covers: auth bypass, topic namespace, QoS attacks, session exhaustion,
payload injection, connection-level, subscription abuse, MQTT v5 specifics,
information leakage, and broker config fingerprinting.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import socket
import struct
import time
import threading
import json
import random
import logging
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime

# ── Reuse existing packet builders ──────────────────────────────────────
from agent.broker.connector import (
    RawMQTTConnection,
    build_connect, build_publish, build_subscribe,
    build_pubrel, build_pubcomp, build_pingreq, build_disconnect,
    build_raw_packet, MQTTResponse, parse_response,
    encode_utf8_string, encode_uint16, encode_remaining_length,
)
from agent.spec.mqtt_spec import PacketType

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("campaign2")

TARGET_HOST = "localhost"
TARGET_PORT = 1883
TIMEOUT = 3.0

# ────────────────────────────────────────────────────────────────────────
# Raw packet helpers — MQTT 5.0 extensions
# ────────────────────────────────────────────────────────────────────────

def build_connect_v5(
    client_id: str = "fuzz_v5",
    clean_start: bool = True,
    keepalive: int = 60,
    session_expiry: int = 0,
    receive_max: int = 65535,
    max_packet_size: Optional[int] = None,
    topic_alias_max: int = 0,
    user_props: Optional[List[Tuple[str, str]]] = None,
    auth_method: Optional[str] = None,
    auth_data: Optional[bytes] = None,
    username: Optional[str] = None,
    password: Optional[bytes] = None,
    will_topic: Optional[str] = None,
    will_payload: Optional[bytes] = None,
    will_qos: int = 0,
    will_retain: bool = False,
) -> bytes:
    """Build an MQTT 5.0 CONNECT packet with properties."""
    # Connect properties
    props = bytearray()

    # Session Expiry Interval (0x11)
    props += bytes([0x11]) + struct.pack("!I", session_expiry)

    # Receive Maximum (0x21)
    props += bytes([0x21]) + struct.pack("!H", receive_max)

    # Maximum Packet Size (0x27)
    if max_packet_size is not None:
        props += bytes([0x27]) + struct.pack("!I", max_packet_size)

    # Topic Alias Maximum (0x22)
    props += bytes([0x22]) + struct.pack("!H", topic_alias_max)

    # User Properties (0x26)
    if user_props:
        for k, v in user_props:
            props += bytes([0x26]) + encode_utf8_string(k) + encode_utf8_string(v)

    # Authentication Method (0x15)
    if auth_method is not None:
        props += bytes([0x15]) + encode_utf8_string(auth_method)

    # Authentication Data (0x16)
    if auth_data is not None:
        props += bytes([0x16]) + struct.pack("!H", len(auth_data)) + auth_data

    props_len = encode_remaining_length(len(props))

    # Connect flags
    connect_flags = 0
    if clean_start:
        connect_flags |= 0x02
    if will_topic is not None:
        connect_flags |= 0x04
        connect_flags |= (will_qos & 0x03) << 3
        if will_retain:
            connect_flags |= 0x20
    if password is not None:
        connect_flags |= 0x40
    if username is not None:
        connect_flags |= 0x80

    variable_header = (
        encode_utf8_string("MQTT")      # Protocol name
        + bytes([0x05])                  # Protocol level = 5
        + bytes([connect_flags])
        + struct.pack("!H", keepalive)
        + props_len + bytes(props)
    )

    # Payload
    payload = encode_utf8_string(client_id)
    if will_topic is not None:
        # Will properties (empty for now)
        payload += bytes([0x00])  # will properties length = 0
        payload += encode_utf8_string(will_topic)
        wp = will_payload or b""
        payload += struct.pack("!H", len(wp)) + wp
    if username is not None:
        payload += encode_utf8_string(username)
    if password is not None:
        payload += struct.pack("!H", len(password)) + password

    remaining = variable_header + payload
    fixed_header = bytes([0x10]) + encode_remaining_length(len(remaining))
    return fixed_header + remaining


def build_publish_v5(
    topic: str,
    payload: bytes = b"",
    qos: int = 0,
    retain: bool = False,
    topic_alias: Optional[int] = None,
    user_props: Optional[List[Tuple[str, str]]] = None,
    payload_format: Optional[int] = None,
    msg_expiry: Optional[int] = None,
    packet_id: int = 1,
) -> bytes:
    """Build an MQTT 5.0 PUBLISH packet with properties."""
    first_byte = (PacketType.PUBLISH << 4) | ((qos & 0x03) << 1)
    if retain:
        first_byte |= 0x01

    variable_header = encode_utf8_string(topic)
    if qos > 0:
        variable_header += encode_uint16(packet_id)

    # Properties
    props = bytearray()
    if payload_format is not None:
        props += bytes([0x01, payload_format])
    if msg_expiry is not None:
        props += bytes([0x02]) + struct.pack("!I", msg_expiry)
    if topic_alias is not None:
        props += bytes([0x23]) + struct.pack("!H", topic_alias)
    if user_props:
        for k, v in user_props:
            props += bytes([0x26]) + encode_utf8_string(k) + encode_utf8_string(v)

    variable_header += encode_remaining_length(len(props)) + bytes(props)
    remaining = variable_header + payload
    return bytes([first_byte]) + encode_remaining_length(len(remaining)) + remaining


def build_subscribe_v5(
    topic_filter: str,
    packet_id: int = 1,
    qos: int = 0,
    sub_id: Optional[int] = None,
    user_props: Optional[List[Tuple[str, str]]] = None,
) -> bytes:
    """Build an MQTT 5.0 SUBSCRIBE packet."""
    # Properties
    props = bytearray()
    if sub_id is not None:
        # Subscription Identifier (0x0B) — variable byte int
        props += bytes([0x0B]) + encode_remaining_length(sub_id)
    if user_props:
        for k, v in user_props:
            props += bytes([0x26]) + encode_utf8_string(k) + encode_utf8_string(v)

    variable_header = encode_uint16(packet_id)
    variable_header += encode_remaining_length(len(props)) + bytes(props)

    # Topic filter + options byte
    options = (qos & 0x03)
    payload = encode_utf8_string(topic_filter) + bytes([options])
    remaining = variable_header + payload
    return bytes([0x82]) + encode_remaining_length(len(remaining)) + remaining


def build_auth_v5(reason_code: int = 0, auth_method: Optional[str] = None, auth_data: Optional[bytes] = None) -> bytes:
    """Build an MQTT 5.0 AUTH packet."""
    props = bytearray()
    if auth_method is not None:
        props += bytes([0x15]) + encode_utf8_string(auth_method)
    if auth_data is not None:
        props += bytes([0x16]) + struct.pack("!H", len(auth_data)) + auth_data
    props_len = encode_remaining_length(len(props))
    remaining = bytes([reason_code]) + props_len + bytes(props)
    return bytes([0xF0]) + encode_remaining_length(len(remaining)) + remaining


# ────────────────────────────────────────────────────────────────────────
# Result dataclass
# ────────────────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    name: str
    category: str
    description: str
    vulnerability_class: str
    packets_sent: int
    responses: List[str]        # string repr of each response
    anomaly: bool
    anomaly_type: str
    anomaly_detail: str
    broker_alive: bool
    raw_send_hex: List[str]
    timing_ms: float = 0.0
    metadata: Dict = field(default_factory=dict)


# ────────────────────────────────────────────────────────────────────────
# Liveness probe
# ────────────────────────────────────────────────────────────────────────

def broker_alive() -> bool:
    try:
        with RawMQTTConnection(TARGET_HOST, TARGET_PORT, timeout=2.0) as conn:
            resp = conn.mqtt_connect(client_id="liveness_c2")
            return resp is not None and resp.connack_return_code == 0
    except Exception:
        return False


# ────────────────────────────────────────────────────────────────────────
# ATTACK MODULES — one function per vulnerability category
# ────────────────────────────────────────────────────────────────────────

results: List[TestResult] = []


def record(name, category, desc, vuln_class, sent, responses, anomaly, atype, adetail, alive, hexes, timing=0.0, meta=None):
    results.append(TestResult(
        name=name, category=category, description=desc, vulnerability_class=vuln_class,
        packets_sent=sent, responses=responses, anomaly=anomaly, anomaly_type=atype,
        anomaly_detail=adetail, broker_alive=alive, raw_send_hex=hexes,
        timing_ms=timing, metadata=meta or {},
    ))


# ────────────────────────────────────────────────────────────────────────
# CATEGORY A: Authentication Bypass Vectors
# ────────────────────────────────────────────────────────────────────────

def test_auth_bypass():
    print("[A] Authentication bypass vectors...")
    tests = [
        # (name, username, password, expected_anomaly_note)
        ("auth_null_username",    "\x00admin",   "password",   "Null byte prefix in username"),
        ("auth_null_password",    "admin",       "\x00secret",  "Null byte in password"),
        ("auth_empty_user_pass",  "",            "",           "Empty username and password"),
        ("auth_very_long_user",   "A" * 65535,   "pass",        "Max-length username (65535 bytes)"),
        ("auth_very_long_pass",   "user",        "P" * 65535,   "Max-length password (65535 bytes)"),
        ("auth_unicode_user",     "用户名",        "密码",         "Unicode credentials"),
        ("auth_sql_inject_user",  "' OR '1'='1", "x",           "SQL injection in username"),
        ("auth_format_string",    "%s%s%s%s%n",  "pass",        "Format string in username"),
        ("auth_newline_user",     "admin\nX-Inject: hdr", "pass", "CRLF injection in username"),
        ("auth_pass_as_no_flag",  None,          "password",    "Password field present but USERNAME flag not set — connector won't add it, test via raw"),
    ]

    for name, user, passwd, note in tests[:9]:
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            pkt = build_connect(
                client_id=f"fuzz_{name[:20]}",
                username=user if user else None,
                password=passwd if passwd else None,
                clean_session=True,
            )
            t0 = time.time()
            conn.send(pkt)
            resp = conn.recv_parsed(timeout=TIMEOUT)
            elapsed = (time.time() - t0) * 1000
            conn.close()

            alive = broker_alive()
            rc = resp.connack_return_code if resp else None
            anomaly = False
            atype = ""
            adetail = ""

            if resp is None:
                anomaly = True; atype = "NO_RESPONSE"; adetail = f"No CONNACK — {note}"
            elif rc == 0:
                # Connected with weird credentials — note as finding
                anomaly = True; atype = "AUTH_ACCEPTED_ANOMALY"
                adetail = f"Broker accepted connection with suspicious credentials: {note}"
            elif rc not in (0, 1, 2, 3, 4, 5):
                anomaly = True; atype = "INVALID_RC"; adetail = f"Unexpected CONNACK RC={rc:#04x}"

            record(name, "AUTH_BYPASS", note, "V8_AUTH_BYPASS",
                   1, [repr(resp)], anomaly, atype, adetail, alive,
                   [pkt.hex()[:80]], elapsed)
        except Exception as e:
            record(name, "AUTH_BYPASS", note, "V8_AUTH_BYPASS",
                   0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # Raw test: password field sent WITHOUT password flag in connect_flags
    # This constructs a CONNECT where password bytes exist in payload but flags say no password
    try:
        client_id_bytes = b"\x00\x09rawtest01"
        proto = b"\x00\x04MQTT\x04"
        # Flags: username=1 (0x80), password=0 => 0x80
        flags = bytes([0x82])  # clean_session + username flag, NO password flag
        keepalive = struct.pack("!H", 60)
        username_field = encode_utf8_string("admin")
        password_bytes_raw = encode_utf8_string("secret")  # Injected without flag

        payload = client_id_bytes + username_field + password_bytes_raw
        variable_header = proto + flags + keepalive
        remaining = variable_header + payload
        raw_pkt = bytes([0x10]) + encode_remaining_length(len(remaining)) + remaining

        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        t0 = time.time()
        conn.send(raw_pkt)
        resp = conn.recv_parsed(timeout=TIMEOUT)
        elapsed = (time.time() - t0) * 1000
        conn.close()

        alive = broker_alive()
        rc = resp.connack_return_code if resp else None
        anomaly = rc == 0  # Should ideally reject or at minimum not parse password as client_id
        record("auth_password_without_flag", "AUTH_BYPASS",
               "Password bytes in payload without password bit in connect_flags",
               "V8_AUTH_BYPASS", 1, [repr(resp)],
               anomaly, "MALFORMED_FLAGS_ACCEPTED" if anomaly else "",
               "Broker accepted CONNECT with mismatched flags/payload structure" if anomaly else "",
               alive, [raw_pkt.hex()[:80]], elapsed)
    except Exception as e:
        record("auth_password_without_flag", "AUTH_BYPASS", "Raw flags mismatch", "V8_AUTH_BYPASS",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY B: Topic Namespace Attacks
# ────────────────────────────────────────────────────────────────────────

def test_topic_namespace():
    print("[B] Topic namespace attacks...")

    # B1: Shared subscription abuse ($share/)
    shared_topics = [
        "$share/group1/#",
        "$share/group1/device/+",
        "$share//test",           # Empty group name
        "$share/g/" + "a" * 100, # Long topic after share
        "$SHARE/group1/#",        # Wrong case — should fail
        "$share",                 # Missing group and topic
        "$share/g",               # Missing topic separator
    ]
    for i, topic in enumerate(shared_topics):
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            conn.send(build_connect(client_id=f"share_sub_{i}"))
            connack = conn.recv_parsed(timeout=TIMEOUT)
            if connack and connack.connack_return_code == 0:
                conn.send(build_subscribe(topic))
                suback = conn.recv_parsed(timeout=TIMEOUT)
                rc_byte = suback.payload[2] if suback and len(suback.payload) >= 3 else None
                anomaly = rc_byte == 0  # Grant on malformed shared sub = anomaly
                atype = "SHARED_SUB_GRANTED" if anomaly else ""
                adetail = f"Shared subscription '{topic}' granted RC={rc_byte}" if anomaly else ""
                record(f"shared_sub_{i}", "TOPIC_NAMESPACE",
                       f"Shared subscription: {topic}", "V9_TOPIC_NAMESPACE",
                       2, [repr(connack), repr(suback)],
                       anomaly, atype, adetail, broker_alive(),
                       [build_subscribe(topic).hex()[:80]])
            conn.close()
        except Exception as e:
            record(f"shared_sub_{i}", "TOPIC_NAMESPACE", topic, "V9_TOPIC_NAMESPACE",
                   0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # B2: Topic alias abuse (MQTT v5)
    alias_tests = [
        (0,     "zero alias — invalid per spec §3.3.2.3.4"),
        (1,     "first valid alias"),
        (65535, "maximum alias value"),
        (65534, "one below max"),
    ]
    for alias_val, note in alias_tests:
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            # Connect with MQTT 5.0 and topic_alias_max=10
            conn.send(build_connect_v5(client_id=f"alias_{alias_val}", topic_alias_max=10))
            connack = conn.recv_parsed(timeout=TIMEOUT)
            if connack and connack.connack_return_code == 0:
                # Publish with topic alias exceeding negotiated maximum
                pkt = build_publish_v5("test/alias", b"alias_payload", topic_alias=alias_val)
                conn.send(pkt)
                resp = conn.recv_parsed(timeout=1.0)  # QoS 0 = no response expected
            conn.close()

            alive = broker_alive()
            anomaly = alias_val == 0 and alive  # Alias=0 is invalid; if broker survives without error, note it
            record(f"topic_alias_{alias_val}", "TOPIC_NAMESPACE",
                   f"Topic alias={alias_val}: {note}", "V9_TOPIC_NAMESPACE",
                   2, [repr(connack)], False, "", "", alive, [])
        except Exception as e:
            record(f"topic_alias_{alias_val}", "TOPIC_NAMESPACE", note, "V9_TOPIC_NAMESPACE",
                   0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # B3: Topic alias beyond declared maximum — spec violation
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        # Declare topic_alias_max=5 in CONNECT
        conn.send(build_connect_v5(client_id="alias_exceed", topic_alias_max=5))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        if connack and connack.connack_return_code == 0:
            # Publish with alias=100 > our declared max of 5
            pkt = build_publish_v5("test/alias_exceed", b"overflow_alias", topic_alias=100)
            conn.send(pkt)
            time.sleep(0.2)
        conn.close()
        alive = broker_alive()
        record("topic_alias_exceed_max", "TOPIC_NAMESPACE",
               "Topic alias 100 exceeds declared maximum of 5 — spec §3.3.2.3.4 violation",
               "V9_TOPIC_NAMESPACE", 2, [repr(connack)],
               not alive, "CRASH" if not alive else "",
               "Broker crashed after topic alias exceeded declared maximum" if not alive else "Broker tolerated alias overflow",
               alive, [])
    except Exception as e:
        record("topic_alias_exceed_max", "TOPIC_NAMESPACE", "Alias exceed max", "V9_TOPIC_NAMESPACE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # B4: $SYS topic variants — probing more system topics
    sys_topics = [
        "$SYS/broker/version",
        "$SYS/broker/uptime",
        "$SYS/broker/clients/total",
        "$SYS/broker/clients/connected",
        "$SYS/broker/clients/disconnected",
        "$SYS/broker/messages/sent",
        "$SYS/broker/messages/received",
        "$SYS/broker/bytes/sent",
        "$SYS/broker/bytes/received",
        "$SYS/broker/publish/messages/sent",
        "$SYS/broker/retained messages/count",
        "$SYS/broker/subscriptions/count",
        "$SYS/broker/heap/current",
        "$SYS/broker/heap/maximum",
        "$SYS/broker/load/connections/1min",
    ]
    sys_received = []
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="sys_probe"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        if connack and connack.connack_return_code == 0:
            conn.send(build_subscribe("$SYS/#", packet_id=99))
            suback = conn.recv_parsed(timeout=TIMEOUT)
            # Drain messages for 2 seconds
            deadline = time.time() + 2.0
            while time.time() < deadline:
                msg = conn.recv_parsed(timeout=0.3)
                if msg and msg.packet_type == PacketType.PUBLISH:
                    # Parse topic from payload
                    if len(msg.payload) >= 2:
                        tlen = struct.unpack("!H", msg.payload[:2])[0]
                        topic_bytes = msg.payload[2:2+tlen]
                        sys_received.append(topic_bytes.decode("utf-8", errors="replace"))
        conn.close()

        anomaly = len(sys_received) > 0
        record("sys_topic_enumeration", "TOPIC_NAMESPACE",
               f"$SYS/# subscription exposed {len(sys_received)} system topics",
               "V6_SYS_TOPIC_EXPOSURE", 2,
               [f"Received {len(sys_received)} $SYS messages"],
               anomaly, "INFO_DISCLOSURE" if anomaly else "",
               f"Topics exposed: {sys_received[:8]}", broker_alive(), [],
               meta={"sys_topics_found": sys_received})
    except Exception as e:
        record("sys_topic_enumeration", "TOPIC_NAMESPACE", "$SYS enumeration", "V6_SYS_TOPIC_EXPOSURE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY C: QoS Flow Attacks
# ────────────────────────────────────────────────────────────────────────

def test_qos_attacks():
    print("[C] QoS flow attacks...")

    # C1: PUBREL storm — send PUBREL for non-existent packet IDs
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="pubrel_storm"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        orphan_ids = [0x0001, 0x7FFF, 0xFFFF, 0x0100, 0x1234]
        responses = []
        if connack and connack.connack_return_code == 0:
            for pid in orphan_ids:
                conn.send(build_pubrel(pid))
                resp = conn.recv_parsed(timeout=1.0)
                responses.append(repr(resp))
        conn.close()
        alive = broker_alive()
        record("pubrel_storm_orphan_ids", "QOS_ATTACK",
               f"PUBREL for non-existent packet IDs: {orphan_ids}",
               "V10_QOS_ATTACK", len(orphan_ids)+1, responses,
               not alive, "CRASH" if not alive else "PUBREL_ORPHAN",
               "Broker crashed under PUBREL storm" if not alive else
               f"Broker processed {len(orphan_ids)} orphan PUBRELs without error",
               alive, [])
    except Exception as e:
        record("pubrel_storm_orphan_ids", "QOS_ATTACK", "PUBREL storm", "V10_QOS_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # C2: Packet ID = 0 for QoS 1 (invalid, spec §2.3.1)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="pid_zero"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        if connack and connack.connack_return_code == 0:
            pkt = build_publish("test/qos1", b"pid_zero_test", qos=1, packet_id=0)
            conn.send(pkt)
            resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        record("publish_qos1_pid_zero", "QOS_ATTACK",
               "QoS 1 PUBLISH with packet_id=0 (invalid per spec §2.3.1)",
               "V10_QOS_ATTACK", 2, [repr(resp if 'resp' in dir() else None)],
               not alive, "CRASH" if not alive else "",
               "Broker crashed on PID=0" if not alive else "Broker tolerated PID=0 PUBLISH",
               alive, [build_publish("test/qos1", b"x", qos=1, packet_id=0).hex()[:80]])
    except Exception as e:
        record("publish_qos1_pid_zero", "QOS_ATTACK", "PID=0 QoS1", "V10_QOS_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # C3: QoS 2 duplicate publish (V5 retry) — same PID before PUBCOMP
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="qos2_dup"))
        connack = conn.recv_parsed(timeout=TIMEOUT)

        observer_msgs = []
        obs = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        obs.connect_tcp()
        obs.send(build_connect(client_id="qos2_obs"))
        obs.recv_parsed(timeout=TIMEOUT)
        obs.send(build_subscribe("test/qos2_dup", packet_id=2))
        obs.recv_parsed(timeout=TIMEOUT)

        if connack and connack.connack_return_code == 0:
            # First QoS 2 publish
            pid = 42
            pkt1 = build_publish("test/qos2_dup", b"original_msg", qos=2, packet_id=pid)
            conn.send(pkt1)
            pubrec = conn.recv_parsed(timeout=TIMEOUT)  # Expect PUBREC

            # Before sending PUBREL, send duplicate PUBLISH with same PID
            pkt_dup = build_publish("test/qos2_dup", b"duplicate_msg", qos=2, packet_id=pid, dup=True)
            conn.send(pkt_dup)
            resp2 = conn.recv_parsed(timeout=1.0)

            # Now complete the original handshake
            conn.send(build_pubrel(pid))
            pubcomp = conn.recv_parsed(timeout=TIMEOUT)

        # Drain observer
        deadline = time.time() + 1.5
        while time.time() < deadline:
            m = obs.recv_parsed(timeout=0.3)
            if m and m.packet_type == PacketType.PUBLISH:
                observer_msgs.append(repr(m))

        conn.close()
        obs.close()
        alive = broker_alive()

        # If observer received 2 messages, the duplicate was delivered = spec violation
        anomaly = len(observer_msgs) > 1
        record("qos2_duplicate_inject", "QOS_ATTACK",
               "QoS 2 duplicate PUBLISH injection before PUBCOMP",
               "V5_QOS2_TIMING", 3, observer_msgs,
               anomaly, "DUPLICATE_DELIVERY" if anomaly else "QOS2_HANDLED_CORRECTLY",
               f"Observer received {len(observer_msgs)} messages (expected 1)" if anomaly else
               f"Observer received exactly {len(observer_msgs)} message",
               alive, [], meta={"observer_message_count": len(observer_msgs)})
    except Exception as e:
        record("qos2_duplicate_inject", "QOS_ATTACK", "QoS 2 dup inject", "V5_QOS2_TIMING",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # C4: In-flight QoS 1 flood — many pending messages without PUBACK
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="inflight_flood", clean_session=True))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        sent_count = 0
        if connack and connack.connack_return_code == 0:
            # Send 200 QoS 1 messages without reading PUBACKs
            for pid in range(1, 201):
                pkt = build_publish("test/inflight", f"msg_{pid}".encode(), qos=1, packet_id=pid)
                if not conn.send(pkt):
                    break
                sent_count += 1
            # Drain responses briefly
            time.sleep(0.5)
        conn.close()
        alive = broker_alive()
        record("qos1_inflight_flood", "QOS_ATTACK",
               f"QoS 1 in-flight flood: {sent_count} messages without PUBACK",
               "V10_QOS_ATTACK", sent_count, [],
               not alive, "CRASH" if not alive else "INFLIGHT_FLOOD",
               f"Sent {sent_count} QoS 1 msgs without PUBACK — broker {'crashed' if not alive else 'survived'}",
               alive, [], meta={"msgs_sent": sent_count})
    except Exception as e:
        record("qos1_inflight_flood", "QOS_ATTACK", "In-flight flood", "V10_QOS_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # C5: PUBACK flooding — send PUBACKs for non-existent QoS 1 packets
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="puback_flood"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        if connack and connack.connack_return_code == 0:
            for pid in range(1, 51):
                # PUBACK = 0x40, remaining=2, then packet_id
                puback = bytes([0x40, 0x02]) + struct.pack("!H", pid)
                conn.send(puback)
        time.sleep(0.2)
        conn.close()
        alive = broker_alive()
        record("puback_flood_phantom", "QOS_ATTACK",
               "PUBACK flood for 50 non-existent QoS 1 packets",
               "V10_QOS_ATTACK", 51, [],
               not alive, "CRASH" if not alive else "PUBACK_ORPHAN",
               "Broker crashed under phantom PUBACK flood" if not alive else "Broker tolerated phantom PUBACKs",
               alive, [])
    except Exception as e:
        record("puback_flood_phantom", "QOS_ATTACK", "PUBACK flood", "V10_QOS_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # C6: QoS downgrade — publisher sends QoS 2, subscriber at QoS 0
    # Check if broker correctly downgrades and doesn't break QoS state machine
    try:
        obs = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        obs.connect_tcp()
        obs.send(build_connect(client_id="qos_downgrade_obs"))
        obs.recv_parsed(timeout=TIMEOUT)
        obs.send(build_subscribe("test/qos_downgrade", packet_id=1, requested_qos=0))
        obs.recv_parsed(timeout=TIMEOUT)

        pub = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        pub.connect_tcp()
        pub.send(build_connect(client_id="qos_downgrade_pub"))
        pub.recv_parsed(timeout=TIMEOUT)
        pub.send(build_publish("test/qos_downgrade", b"qos2_msg", qos=2, packet_id=1))
        pubrec = pub.recv_parsed(timeout=TIMEOUT)
        if pubrec:
            pub.send(build_pubrel(1))
            pubcomp = pub.recv_parsed(timeout=TIMEOUT)

        delivered = obs.recv_parsed(timeout=1.5)
        obs.close(); pub.close()
        alive = broker_alive()

        record("qos_downgrade_delivery", "QOS_ATTACK",
               "QoS 2 publish → QoS 0 subscriber (downgrade path)",
               "V10_QOS_ATTACK", 3,
               [repr(pubrec if 'pubrec' in dir() else None), repr(delivered)],
               False, "", "Downgrade path tested",
               alive, [])
    except Exception as e:
        record("qos_downgrade_delivery", "QOS_ATTACK", "QoS downgrade", "V10_QOS_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY D: Session State Attacks
# ────────────────────────────────────────────────────────────────────────

def test_session_attacks():
    print("[D] Session state attacks...")

    # D1: Rapid connect/disconnect cycle (resource exhaustion)
    try:
        CYCLE_COUNT = 100
        successful = 0
        t0 = time.time()
        for i in range(CYCLE_COUNT):
            try:
                conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, 1.0)
                conn.connect_tcp()
                conn.send(build_connect(client_id=f"rapid_cd_{i % 10}", clean_session=True))
                resp = conn.recv_parsed(timeout=1.0)
                if resp and resp.connack_return_code == 0:
                    successful += 1
                conn.close()
            except Exception:
                pass
        elapsed = time.time() - t0
        alive = broker_alive()
        rate = successful / elapsed
        anomaly = not alive or successful < CYCLE_COUNT * 0.5
        record("rapid_connect_disconnect", "SESSION_ATTACK",
               f"Rapid connect/disconnect: {CYCLE_COUNT} cycles in {elapsed:.1f}s ({rate:.0f}/s), {successful} successful",
               "V11_SESSION_EXHAUSTION", CYCLE_COUNT,
               [f"{successful}/{CYCLE_COUNT} successful, {rate:.0f} ops/s"],
               anomaly, "CRASH" if not alive else ("DEGRADED" if anomaly else ""),
               f"Broker {'crashed' if not alive else f'survived {CYCLE_COUNT} rapid cycles ({rate:.0f}/s)'}",
               alive, [], timing=elapsed*1000,
               meta={"cycles": CYCLE_COUNT, "successful": successful, "rate_per_sec": rate})
    except Exception as e:
        record("rapid_connect_disconnect", "SESSION_ATTACK", "Rapid cycle", "V11_SESSION_EXHAUSTION",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # D2: Persistent session memory exhaustion
    # Connect with clean_session=False, subscribe to many topics, disconnect repeatedly
    try:
        PERSIST_CLIENTS = 50
        for i in range(PERSIST_CLIENTS):
            try:
                conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, 1.5)
                conn.connect_tcp()
                conn.send(build_connect(client_id=f"persist_exhaust_{i:04d}", clean_session=False))
                resp = conn.recv_parsed(timeout=1.5)
                if resp and resp.connack_return_code == 0:
                    # Subscribe to 10 topics per client
                    for j in range(10):
                        conn.send(build_subscribe(f"persist/{i}/topic/{j}", packet_id=j+1, requested_qos=1))
                        conn.recv_parsed(timeout=0.5)
                conn.close()  # Disconnect without DISCONNECT packet — session persists
            except Exception:
                pass
        alive = broker_alive()
        record("persistent_session_exhaust", "SESSION_ATTACK",
               f"Persistent session exhaustion: {PERSIST_CLIENTS} clients × 10 topics each",
               "V11_SESSION_EXHAUSTION", PERSIST_CLIENTS,
               [f"Created {PERSIST_CLIENTS} persistent sessions"],
               not alive, "CRASH" if not alive else "SESSION_ACCUMULATION",
               f"Broker {'crashed' if not alive else f'accepted {PERSIST_CLIENTS} persistent sessions with subscriptions'}",
               alive, [], meta={"persist_clients": PERSIST_CLIENTS, "topics_per_client": 10})
    except Exception as e:
        record("persistent_session_exhaust", "SESSION_ATTACK", "Persist exhaust", "V11_SESSION_EXHAUSTION",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # D3: Overlapping ClientID reconnect (session hijacking extension of V3)
    try:
        SHARED_ID = "overlap_victim_c2"
        # Victim: persistent session with subscription
        victim = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        victim.connect_tcp()
        victim.send(build_connect(client_id=SHARED_ID, clean_session=False))
        v_connack = victim.recv_parsed(timeout=TIMEOUT)
        if v_connack and v_connack.connack_return_code == 0:
            victim.send(build_subscribe("device/secret/commands", packet_id=1, requested_qos=1))
            victim.recv_parsed(timeout=TIMEOUT)

        # Publisher queues a QoS 1 message
        pub = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        pub.connect_tcp()
        pub.send(build_connect(client_id="overlap_publisher"))
        pub.recv_parsed(timeout=TIMEOUT)
        pub.send(build_publish("device/secret/commands", b"SECRET_COMMAND_FOR_VICTIM", qos=1, packet_id=10))
        pub.recv_parsed(timeout=TIMEOUT)  # PUBACK
        pub.close()

        # Attacker hijacks session
        attacker = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        attacker.connect_tcp()
        attacker.send(build_connect(client_id=SHARED_ID, clean_session=False))
        a_connack = attacker.recv_parsed(timeout=TIMEOUT)

        session_hijacked = (a_connack and a_connack.connack_session_present == True)

        # Check if attacker receives queued messages
        time.sleep(0.5)
        queued_msg = attacker.recv_parsed(timeout=1.5)

        victim.close()
        attacker.close()
        alive = broker_alive()

        anomaly = session_hijacked or (queued_msg is not None)
        record("session_overlap_hijack", "SESSION_ATTACK",
               "ClientID overlap: attacker reconnects with victim's persistent session ClientID",
               "V3_CLIENTID_HIJACKING", 3,
               [repr(a_connack), repr(queued_msg)],
               anomaly, "SESSION_HIJACK" if anomaly else "",
               f"session_present={session_hijacked}, queued_msg={'YES' if queued_msg else 'NO'}",
               alive, [], meta={"session_present": session_hijacked,
                                "received_queued_msg": queued_msg is not None})
    except Exception as e:
        record("session_overlap_hijack", "SESSION_ATTACK", "Session overlap", "V3_CLIENTID_HIJACKING",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # D4: Zero-length ClientID with clean_session=False (V7 — spec §3.1.3.1)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="", clean_session=False))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        rc = resp.connack_return_code if resp else None
        # Spec says MUST reject with 0x02 if CleanSession=0 and ClientID=""
        anomaly = rc == 0  # Accepted = spec violation
        record("zero_clientid_persistent", "SESSION_ATTACK",
               "Zero-length ClientID with clean_session=False — spec §3.1.3.1 MUST reject with RC=0x02",
               "V7_ZERO_LENGTH_CLIENTID", 1, [repr(resp)],
               anomaly, "SPEC_VIOLATION_V7" if anomaly else "CORRECTLY_REJECTED",
               f"CONNACK RC={rc:#04x} — {'ACCEPTED (spec violation)' if rc == 0 else 'correctly rejected'}" if rc is not None else "No response",
               alive, [build_connect(client_id="", clean_session=False).hex()[:80]])
    except Exception as e:
        record("zero_clientid_persistent", "SESSION_ATTACK", "Zero ClientID", "V7_ZERO_LENGTH_CLIENTID",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # D5: Zero-length ClientID with clean_session=True (allowed per spec)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="", clean_session=True))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        rc = resp.connack_return_code if resp else None
        # Should be ACCEPTED (RC=0) per MQTT 3.1.1 §3.1.3.1 when CleanSession=1
        record("zero_clientid_clean", "SESSION_ATTACK",
               "Zero-length ClientID with clean_session=True — spec §3.1.3.1 SHOULD accept",
               "V7_ZERO_LENGTH_CLIENTID", 1, [repr(resp)],
               rc != 0 if rc is not None else True,
               "UNEXPECTED_REJECTION" if (rc is not None and rc != 0) else "",
               f"CONNACK RC={rc:#04x} — {'correctly accepted' if rc == 0 else 'rejected (implementation choice)'}",
               alive, [])
    except Exception as e:
        record("zero_clientid_clean", "SESSION_ATTACK", "Zero ClientID clean", "V7_ZERO_LENGTH_CLIENTID",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY E: Payload-Level Attacks
# ────────────────────────────────────────────────────────────────────────

def test_payload_attacks():
    print("[E] Payload-level attacks...")

    # E1: Large payload — probe message_size_limit
    sizes = [
        (1024,        "1KB"),
        (65535,       "64KB"),
        (131072,      "128KB"),
        (1048576,     "1MB"),
        (10485760,    "10MB"),
    ]
    for size, label in sizes:
        try:
            payload = b"A" * size
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            conn.send(build_connect(client_id=f"payload_{label.replace('KB','k').replace('MB','m')}"))
            connack = conn.recv_parsed(timeout=TIMEOUT)
            sent_ok = False
            resp = None
            if connack and connack.connack_return_code == 0:
                pkt = build_publish("fuzz/payload", payload, qos=0)
                t0 = time.time()
                sent_ok = conn.send(pkt)
                time.sleep(0.3)
                elapsed = (time.time() - t0) * 1000
            conn.close()
            alive = broker_alive()
            anomaly = not alive
            record(f"payload_size_{label}", "PAYLOAD_ATTACK",
                   f"Large payload: {label} ({size} bytes)",
                   "V12_PAYLOAD_ATTACK", 2, [repr(connack), f"send_ok={sent_ok}"],
                   anomaly, "CRASH" if anomaly else "",
                   f"Broker {'crashed' if not alive else 'survived'} {label} payload",
                   alive, [], timing=elapsed if sent_ok else 0,
                   meta={"payload_size": size, "send_success": sent_ok})
        except Exception as e:
            record(f"payload_size_{label}", "PAYLOAD_ATTACK", f"{label} payload", "V12_PAYLOAD_ATTACK",
                   0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # E2: Payload containing MQTT control bytes (protocol injection)
    control_payloads = [
        (b"\x10\x13\x00\x04MQTT\x04\x02\x00\x3c\x00\x07inject1",  "CONNECT packet embedded in payload"),
        (b"\xe0\x00",                                               "DISCONNECT packet embedded in payload"),
        (b"\xc0\x00",                                               "PINGREQ embedded in payload"),
        (b"\x82\x08\x00\x01\x00\x03\x23\x2f\x23\x00",             "SUBSCRIBE embedded in payload"),
        (b"\x00" * 10 + b"\x10\x02\x00\x04" + b"\x00" * 10,       "CONNECT header bytes mid-payload"),
    ]
    for i, (payload, note) in enumerate(control_payloads):
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            conn.send(build_connect(client_id=f"ctrl_byte_{i}"))
            connack = conn.recv_parsed(timeout=TIMEOUT)
            if connack and connack.connack_return_code == 0:
                pkt = build_publish("fuzz/ctrl_bytes", payload)
                conn.send(pkt)
                time.sleep(0.2)
            conn.close()
            alive = broker_alive()
            record(f"payload_ctrl_bytes_{i}", "PAYLOAD_ATTACK",
                   note, "V12_PAYLOAD_ATTACK", 2,
                   [repr(connack)], not alive,
                   "CRASH" if not alive else "",
                   f"Broker {'crashed' if not alive else 'survived'} control-byte payload injection",
                   alive, [payload.hex()[:80]])
        except Exception as e:
            record(f"payload_ctrl_bytes_{i}", "PAYLOAD_ATTACK", note, "V12_PAYLOAD_ATTACK",
                   0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # E3: Binary payload with all 256 byte values
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="all_bytes"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        if connack and connack.connack_return_code == 0:
            payload = bytes(range(256)) * 4  # 1024 bytes with all values
            conn.send(build_publish("fuzz/all_bytes", payload))
            time.sleep(0.2)
        conn.close()
        alive = broker_alive()
        record("payload_all_bytes", "PAYLOAD_ATTACK",
               "Payload with all 256 byte values repeated",
               "V12_PAYLOAD_ATTACK", 2, [repr(connack)],
               not alive, "CRASH" if not alive else "",
               "Broker survived all-byte payload" if alive else "Broker crashed",
               alive, [])
    except Exception as e:
        record("payload_all_bytes", "PAYLOAD_ATTACK", "All bytes payload", "V12_PAYLOAD_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # E4: Retain flag with very large payload — retained message storage abuse
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="retain_large"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        if connack and connack.connack_return_code == 0:
            # 1MB retained message
            large_retain = b"R" * 1048576
            pkt = build_publish("fuzz/large_retain", large_retain, retain=True)
            conn.send(pkt)
            time.sleep(0.5)
        conn.close()
        alive = broker_alive()
        record("retain_large_payload", "PAYLOAD_ATTACK",
               "Retained message with 1MB payload — storage abuse",
               "V2_UNAUTHORIZED_RETAIN", 2, [repr(connack)],
               not alive, "CRASH" if not alive else "LARGE_RETAIN",
               f"Broker {'crashed' if not alive else 'accepted 1MB retained message'}",
               alive, [], meta={"retain_size_bytes": 1048576})
    except Exception as e:
        record("retain_large_payload", "PAYLOAD_ATTACK", "Large retain", "V2_UNAUTHORIZED_RETAIN",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY F: Connection-Level Attacks
# ────────────────────────────────────────────────────────────────────────

def test_connection_attacks():
    print("[F] Connection-level attacks...")

    # F1: Keepalive=0 — disable broker timeout
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="keepalive_zero", keepalive=0))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        time.sleep(2)  # Wait — broker should not disconnect since keepalive=0 disables it
        # Try to publish — still connected?
        still_alive = False
        if resp and resp.connack_return_code == 0:
            conn.send(build_publish("fuzz/keepalive_zero", b"test"))
            time.sleep(0.2)
            # Send PINGREQ to check connection
            conn.send(build_pingreq())
            pingresp = conn.recv_parsed(timeout=1.0)
            still_alive = pingresp is not None
        conn.close()
        alive = broker_alive()
        record("keepalive_zero", "CONNECTION_ATTACK",
               "keepalive=0 disables server-side timeout — connection should persist indefinitely",
               "V13_CONNECTION_ATTACK", 2, [repr(resp)],
               False, "", f"keepalive=0 connection {'still active after 2s' if still_alive else 'dropped'}",
               alive, [], meta={"still_active_after_2s": still_alive})
    except Exception as e:
        record("keepalive_zero", "CONNECTION_ATTACK", "Keepalive=0", "V13_CONNECTION_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # F2: Very short keepalive=1 (force rapid pings)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="keepalive_one", keepalive=1))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        ping_count = 0
        if resp and resp.connack_return_code == 0:
            for _ in range(5):
                conn.send(build_pingreq())
                pr = conn.recv_parsed(timeout=1.5)
                if pr and pr.packet_type == 0xD:  # PINGRESP
                    ping_count += 1
                time.sleep(0.8)
        conn.close()
        alive = broker_alive()
        record("keepalive_one_rapid_ping", "CONNECTION_ATTACK",
               f"keepalive=1s rapid ping: {ping_count}/5 pings acknowledged",
               "V13_CONNECTION_ATTACK", 6, [repr(resp)],
               not alive, "CRASH" if not alive else "",
               f"Rapid ping test: {ping_count}/5 PINGRESPs received",
               alive, [], meta={"ping_responses": ping_count})
    except Exception as e:
        record("keepalive_one_rapid_ping", "CONNECTION_ATTACK", "Rapid ping", "V13_CONNECTION_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # F3: Half-open connections — connect TCP but never send CONNECT
    try:
        half_open_socks = []
        for i in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((TARGET_HOST, TARGET_PORT))
                half_open_socks.append(s)
            except Exception:
                break
        time.sleep(1.0)  # Hold connections open
        opened = len(half_open_socks)
        for s in half_open_socks:
            try: s.close()
            except: pass
        alive = broker_alive()
        record("half_open_connections", "CONNECTION_ATTACK",
               f"Half-open TCP connections (no MQTT CONNECT): opened {opened}/20",
               "V13_CONNECTION_ATTACK", opened, [],
               not alive, "CRASH" if not alive else "HALF_OPEN",
               f"Broker {'crashed' if not alive else f'tolerated {opened} half-open connections'}",
               alive, [], meta={"half_open_count": opened})
    except Exception as e:
        record("half_open_connections", "CONNECTION_ATTACK", "Half-open", "V13_CONNECTION_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # F4: CONNECT flood — rapid new connections
    try:
        FLOOD_COUNT = 50
        successful = 0
        t0 = time.time()
        for i in range(FLOOD_COUNT):
            try:
                conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, 1.0)
                conn.connect_tcp()
                conn.send(build_connect(client_id=f"flood_{i:05d}"))
                resp = conn.recv_parsed(timeout=0.5)
                if resp and resp.connack_return_code == 0:
                    successful += 1
                conn.close()
            except Exception:
                pass
        elapsed = time.time() - t0
        alive = broker_alive()
        record("connect_flood", "CONNECTION_ATTACK",
               f"CONNECT flood: {FLOOD_COUNT} unique clients in {elapsed:.1f}s, {successful} accepted",
               "V13_CONNECTION_ATTACK", FLOOD_COUNT, [f"{successful}/{FLOOD_COUNT} accepted"],
               not alive, "CRASH" if not alive else "",
               f"Flood rate: {FLOOD_COUNT/elapsed:.1f}/s, {successful} accepted",
               alive, [], meta={"flood_count": FLOOD_COUNT, "successful": successful,
                                 "rate_per_sec": FLOOD_COUNT/elapsed})
    except Exception as e:
        record("connect_flood", "CONNECTION_ATTACK", "CONNECT flood", "V13_CONNECTION_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # F5: Double CONNECT on same TCP connection
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="double_connect_1"))
        resp1 = conn.recv_parsed(timeout=TIMEOUT)
        if resp1 and resp1.connack_return_code == 0:
            # Send second CONNECT without disconnecting
            conn.send(build_connect(client_id="double_connect_2"))
            resp2 = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        # Per spec, second CONNECT must cause disconnect
        got_second_connack = resp2 is not None if 'resp2' in dir() else False
        record("double_connect_same_tcp", "CONNECTION_ATTACK",
               "Send CONNECT twice on same TCP connection without disconnect",
               "V13_CONNECTION_ATTACK", 2,
               [repr(resp1), repr(resp2 if 'resp2' in dir() else None)],
               got_second_connack, "DOUBLE_CONNECT_ACCEPTED" if got_second_connack else "",
               f"Second CONNECT {'accepted (protocol violation)' if got_second_connack else 'correctly rejected/ignored'}",
               alive, [])
    except Exception as e:
        record("double_connect_same_tcp", "CONNECTION_ATTACK", "Double CONNECT", "V13_CONNECTION_ATTACK",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY G: Subscription Abuse
# ────────────────────────────────────────────────────────────────────────

def test_subscription_abuse():
    print("[G] Subscription abuse...")

    # G1: Subscribe to many topics in a single client
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="sub_many"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        sub_count = 0
        if connack and connack.connack_return_code == 0:
            for i in range(200):
                pkt = build_subscribe(f"test/topic/{i:04d}", packet_id=(i % 65535) + 1)
                conn.send(pkt)
                resp = conn.recv_parsed(timeout=0.5)
                if resp: sub_count += 1
        conn.close()
        alive = broker_alive()
        record("subscribe_many_topics", "SUBSCRIPTION_ABUSE",
               f"Subscribe to 200 distinct topics: {sub_count} accepted",
               "V14_SUB_ABUSE", sub_count + 1,
               [f"{sub_count}/200 subscriptions accepted"],
               not alive, "CRASH" if not alive else "MASS_SUBSCRIPTION",
               f"Broker {'crashed' if not alive else f'accepted {sub_count}/200 subscriptions'}",
               alive, [], meta={"subs_attempted": 200, "subs_accepted": sub_count})
    except Exception as e:
        record("subscribe_many_topics", "SUBSCRIPTION_ABUSE", "Mass subscribe", "V14_SUB_ABUSE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # G2: Duplicate subscriptions — subscribe to same topic many times
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="sub_dup"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        dup_count = 0
        if connack and connack.connack_return_code == 0:
            for i in range(50):
                conn.send(build_subscribe("test/dup_topic", packet_id=i+1))
                resp = conn.recv_parsed(timeout=0.5)
                if resp: dup_count += 1
        # Now publish and check if observer gets multiple copies
        pub = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        pub.connect_tcp()
        pub.send(build_connect(client_id="dup_pub"))
        pub.recv_parsed(timeout=TIMEOUT)
        pub.send(build_publish("test/dup_topic", b"dup_test_payload"))
        pub.close()

        copies = 0
        deadline = time.time() + 1.5
        while time.time() < deadline:
            m = conn.recv_parsed(timeout=0.3)
            if m and m.packet_type == PacketType.PUBLISH:
                copies += 1
        conn.close()
        alive = broker_alive()
        anomaly = copies > 1
        record("subscribe_duplicate", "SUBSCRIPTION_ABUSE",
               f"Duplicate subscription to same topic 50 times — received {copies} copies of 1 publish",
               "V14_SUB_ABUSE", 51, [f"{copies} message copies received"],
               anomaly, "DUPLICATE_DELIVERY" if anomaly else "",
               f"{'ANOMALY: ' if anomaly else ''}Received {copies} copies for 1 publish on {dup_count} duplicate subs",
               alive, [], meta={"duplicate_subs": dup_count, "copies_received": copies})
    except Exception as e:
        record("subscribe_duplicate", "SUBSCRIPTION_ABUSE", "Dup subscribe", "V14_SUB_ABUSE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # G3: Wildcard subscription eavesdrop — confirm V4
    try:
        # Set up publishers on distinct topics
        pub_topics = ["home/sensor/temp", "office/data/secret", "factory/control/cmd"]
        for t in pub_topics:
            p = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            p.connect_tcp()
            p.send(build_connect(client_id=f"pub_{''.join(c for c in t if c.isalnum())[:10]}"))
            p.recv_parsed(timeout=TIMEOUT)
            p.send(build_publish(t, b"SENSITIVE_PAYLOAD", retain=True))
            p.close()

        # Wildcard subscriber
        wc = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        wc.connect_tcp()
        wc.send(build_connect(client_id="wildcard_eaves"))
        wc.recv_parsed(timeout=TIMEOUT)
        wc.send(build_subscribe("#", packet_id=1))
        suback = wc.recv_parsed(timeout=TIMEOUT)

        collected = []
        deadline = time.time() + 2.0
        while time.time() < deadline:
            m = wc.recv_parsed(timeout=0.3)
            if m and m.packet_type == PacketType.PUBLISH:
                if len(m.payload) >= 2:
                    tlen = struct.unpack("!H", m.payload[:2])[0]
                    topic = m.payload[2:2+tlen].decode("utf-8", errors="replace")
                    collected.append(topic)
        wc.close()
        alive = broker_alive()

        intercepted = [t for t in collected if t in pub_topics]
        anomaly = len(intercepted) > 0
        record("wildcard_eavesdrop_confirm", "SUBSCRIPTION_ABUSE",
               f"Wildcard '#' eavesdrop on {len(intercepted)}/{len(pub_topics)} target topics",
               "V4_TOPIC_AUTH_BYPASS", 4, [f"Collected: {collected[:10]}"],
               anomaly, "EAVESDROP" if anomaly else "",
               f"Wildcard subscriber intercepted: {intercepted}",
               alive, [], meta={"topics_intercepted": intercepted,
                                 "total_collected": len(collected)})
    except Exception as e:
        record("wildcard_eavesdrop_confirm", "SUBSCRIPTION_ABUSE", "Wildcard eavesdrop", "V4_TOPIC_AUTH_BYPASS",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # G4: Subscribe to $SYS/# and count metrics exposed
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="sys_metrics"))
        conn.recv_parsed(timeout=TIMEOUT)
        conn.send(build_subscribe("$SYS/#", packet_id=1))
        conn.recv_parsed(timeout=TIMEOUT)

        sys_data = {}
        deadline = time.time() + 3.0
        while time.time() < deadline:
            m = conn.recv_parsed(timeout=0.5)
            if m and m.packet_type == PacketType.PUBLISH:
                if len(m.payload) >= 2:
                    tlen = struct.unpack("!H", m.payload[:2])[0]
                    topic = m.payload[2:2+tlen].decode("utf-8", errors="replace")
                    val_start = 2 + tlen
                    val = m.payload[val_start:].decode("utf-8", errors="replace")
                    sys_data[topic] = val
        conn.close()
        alive = broker_alive()

        anomaly = len(sys_data) > 0
        record("sys_metrics_exposure", "SUBSCRIPTION_ABUSE",
               f"$SYS/# subscription: {len(sys_data)} broker metrics exposed to unauthenticated client",
               "V6_SYS_TOPIC_EXPOSURE", 2,
               [f"Exposed: {list(sys_data.keys())[:8]}"],
               anomaly, "INFO_DISCLOSURE" if anomaly else "",
               f"Metrics exposed: {len(sys_data)} topics. Version: {sys_data.get('$SYS/broker/version', 'N/A')}",
               alive, [], meta={"sys_metrics": sys_data})
    except Exception as e:
        record("sys_metrics_exposure", "SUBSCRIPTION_ABUSE", "$SYS metrics", "V6_SYS_TOPIC_EXPOSURE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY H: MQTT v5 Specific
# ────────────────────────────────────────────────────────────────────────

def test_mqtt_v5():
    print("[H] MQTT v5 specific tests...")

    # H1: User properties injection — oversized key-value pairs
    try:
        huge_props = [("K" * 1000, "V" * 1000)] * 50  # 50 × 2KB = 100KB of user props
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        pkt = build_connect_v5(client_id="user_prop_bomb", user_props=huge_props)
        conn.send(pkt)
        resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        record("mqtt5_user_props_bomb", "MQTT5_SPECIFIC",
               f"MQTT 5.0 User Properties bomb: 50 × 2KB key-value pairs in CONNECT",
               "V15_MQTT5", 1, [repr(resp)],
               not alive, "CRASH" if not alive else "",
               f"Broker {'crashed' if not alive else 'survived'} user properties bomb",
               alive, [], meta={"prop_count": 50, "prop_size_bytes": 100000})
    except Exception as e:
        record("mqtt5_user_props_bomb", "MQTT5_SPECIFIC", "User props bomb", "V15_MQTT5",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # H2: Subscription Identifier abuse
    sub_ids = [0, 1, 268435455, 268435456, 0x0FFFFFFF]  # 0 and >268435455 are invalid
    for sid in sub_ids:
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            conn.send(build_connect_v5(client_id=f"subid_{sid}"))
            connack = conn.recv_parsed(timeout=TIMEOUT)
            if connack and connack.connack_return_code == 0:
                conn.send(build_subscribe_v5("test/subid", packet_id=1, sub_id=sid if sid < 268435456 else None))
                suback = conn.recv_parsed(timeout=TIMEOUT)
            conn.close()
            alive = broker_alive()
            record(f"mqtt5_sub_id_{sid}", "MQTT5_SPECIFIC",
                   f"Subscription Identifier={sid} (0 and >268435455 invalid per spec §3.8.2.1.2)",
                   "V15_MQTT5", 2, [repr(connack), repr(suback if 'suback' in dir() else None)],
                   not alive, "CRASH" if not alive else "",
                   f"Broker {'crashed' if not alive else 'handled'} sub ID={sid}",
                   alive, [])
        except Exception as e:
            record(f"mqtt5_sub_id_{sid}", "MQTT5_SPECIFIC", f"Sub ID={sid}", "V15_MQTT5",
                   0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # H3: AUTH packet sent without prior CONNECT (out-of-order)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        pkt = build_auth_v5(reason_code=0x18, auth_method="SCRAM-SHA-256", auth_data=b"challenge")
        conn.send(pkt)
        resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        record("mqtt5_auth_no_connect", "MQTT5_SPECIFIC",
               "AUTH packet sent before CONNECT (protocol violation)",
               "V15_MQTT5", 1, [repr(resp)],
               not alive, "CRASH" if not alive else "",
               f"Broker {'crashed' if not alive else 'handled'} premature AUTH packet",
               alive, [pkt.hex()[:80]])
    except Exception as e:
        record("mqtt5_auth_no_connect", "MQTT5_SPECIFIC", "Premature AUTH", "V15_MQTT5",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # H4: Max Packet Size property — publish exceeding declared limit
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        # Declare max_packet_size=128 bytes in CONNECT
        conn.send(build_connect_v5(client_id="max_pkt_size", max_packet_size=128))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        if connack and connack.connack_return_code == 0:
            # Publish 1000-byte payload — exceeds our declared maximum
            conn.send(build_publish("test/big", b"X" * 1000))
            resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        record("mqtt5_max_packet_exceed", "MQTT5_SPECIFIC",
               "PUBLISH 1000B when client declared MaxPacketSize=128 in CONNECT",
               "V15_MQTT5", 2, [repr(connack)],
               not alive, "CRASH" if not alive else "",
               f"Broker {'crashed' if not alive else 'handled'} max packet size violation",
               alive, [])
    except Exception as e:
        record("mqtt5_max_packet_exceed", "MQTT5_SPECIFIC", "Max pkt exceed", "V15_MQTT5",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # H5: Session Expiry Interval = 0xFFFFFFFF (maximum — never expire)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect_v5(client_id="sess_expiry_max",
                                    clean_start=False, session_expiry=0xFFFFFFFF))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        record("mqtt5_session_expiry_max", "MQTT5_SPECIFIC",
               "Session Expiry Interval=0xFFFFFFFF (4294967295s ≈ 136 years) — memory leak risk",
               "V15_MQTT5", 1, [repr(resp)],
               False, "", f"CONNACK RC={resp.connack_return_code if resp else 'N/A'}",
               alive, [])
    except Exception as e:
        record("mqtt5_session_expiry_max", "MQTT5_SPECIFIC", "Session expiry max", "V15_MQTT5",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # H6: Receive Maximum = 0 (invalid per spec §3.2.2.3.3)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        # Build v5 CONNECT with receive_max=0 (forbidden)
        conn.send(build_connect_v5(client_id="rcv_max_zero", receive_max=0))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        record("mqtt5_receive_max_zero", "MQTT5_SPECIFIC",
               "Receive Maximum=0 in CONNECT (invalid per MQTT 5.0 §3.1.2.11.4)",
               "V15_MQTT5", 1, [repr(resp)],
               not alive, "CRASH" if not alive else "",
               f"Broker {'crashed' if not alive else 'handled'} Receive Maximum=0",
               alive, [])
    except Exception as e:
        record("mqtt5_receive_max_zero", "MQTT5_SPECIFIC", "Receive max=0", "V15_MQTT5",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY I: Information Leakage
# ────────────────────────────────────────────────────────────────────────

def test_info_leakage():
    print("[I] Information leakage tests...")

    # I1: Timing side-channel on authentication
    # Compare response time for valid vs. invalid credentials
    ITERATIONS = 20
    times_valid = []
    times_invalid = []

    for _ in range(ITERATIONS):
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            pkt = build_connect(client_id="timing_valid", username="admin", password="admin")
            t0 = time.perf_counter()
            conn.send(pkt)
            resp = conn.recv_parsed(timeout=TIMEOUT)
            t1 = time.perf_counter()
            if resp: times_valid.append((t1 - t0) * 1000)
            conn.close()
        except: pass

    for _ in range(ITERATIONS):
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            conn.connect_tcp()
            pkt = build_connect(client_id="timing_invalid", username="xXinvalidXx", password="wrongpass")
            t0 = time.perf_counter()
            conn.send(pkt)
            resp = conn.recv_parsed(timeout=TIMEOUT)
            t1 = time.perf_counter()
            if resp: times_invalid.append((t1 - t0) * 1000)
            conn.close()
        except: pass

    alive = broker_alive()
    avg_valid = sum(times_valid) / len(times_valid) if times_valid else 0
    avg_invalid = sum(times_invalid) / len(times_invalid) if times_invalid else 0
    diff_ms = abs(avg_valid - avg_invalid)
    anomaly = diff_ms > 5  # >5ms timing difference = potential side channel

    record("auth_timing_sidechannel", "INFO_LEAKAGE",
           f"Authentication timing: valid avg={avg_valid:.2f}ms, invalid avg={avg_invalid:.2f}ms, diff={diff_ms:.2f}ms",
           "V16_INFO_LEAKAGE", ITERATIONS * 2,
           [f"valid_times={times_valid[:5]}", f"invalid_times={times_invalid[:5]}"],
           anomaly, "TIMING_SIDECHANNEL" if anomaly else "",
           f"Timing difference of {diff_ms:.2f}ms {'exceeds' if anomaly else 'within'} 5ms threshold",
           alive, [], meta={"avg_valid_ms": avg_valid, "avg_invalid_ms": avg_invalid,
                             "diff_ms": diff_ms, "iterations": ITERATIONS})

    # I2: CONNACK session_present reveals existing sessions (info leakage)
    try:
        target_id = "info_leak_victim"
        # Create a persistent session
        conn1 = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn1.connect_tcp()
        conn1.send(build_connect(client_id=target_id, clean_session=False))
        conn1.recv_parsed(timeout=TIMEOUT)
        conn1.close()

        # Attacker probes with same ClientID
        conn2 = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn2.connect_tcp()
        conn2.send(build_connect(client_id=target_id, clean_session=False))
        resp2 = conn2.recv_parsed(timeout=TIMEOUT)
        conn2.close()

        # Probe with non-existent ID
        conn3 = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn3.connect_tcp()
        conn3.send(build_connect(client_id="nonexistent_zzzzzz", clean_session=False))
        resp3 = conn3.recv_parsed(timeout=TIMEOUT)
        conn3.close()

        alive = broker_alive()
        sp_existing = resp2.connack_session_present if resp2 else None
        sp_nonexist = resp3.connack_session_present if resp3 else None

        # If session_present differs between existing/nonexistent IDs, it's an oracle
        anomaly = sp_existing != sp_nonexist
        record("connack_session_present_oracle", "INFO_LEAKAGE",
               "CONNACK session_present bit reveals whether a ClientID has an existing session",
               "V16_INFO_LEAKAGE", 3,
               [repr(resp2), repr(resp3)],
               anomaly, "SESSION_ORACLE" if anomaly else "",
               f"Existing ID session_present={sp_existing}, Non-existent ID session_present={sp_nonexist}. "
               f"{'ORACLE: can enumerate client IDs' if anomaly else 'No difference'}",
               alive, [], meta={"existing_sp": sp_existing, "nonexist_sp": sp_nonexist})
    except Exception as e:
        record("connack_session_present_oracle", "INFO_LEAKAGE", "Session oracle", "V16_INFO_LEAKAGE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # I3: $SYS topic reveals client count (active session enumeration)
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="sys_count"))
        conn.recv_parsed(timeout=TIMEOUT)
        conn.send(build_subscribe("$SYS/broker/clients/+", packet_id=1))
        conn.recv_parsed(timeout=TIMEOUT)

        client_metrics = {}
        deadline = time.time() + 2.0
        while time.time() < deadline:
            m = conn.recv_parsed(timeout=0.4)
            if m and m.packet_type == PacketType.PUBLISH:
                if len(m.payload) >= 2:
                    tlen = struct.unpack("!H", m.payload[:2])[0]
                    topic = m.payload[2:2+tlen].decode("utf-8", errors="replace")
                    val = m.payload[2+tlen:].decode("utf-8", errors="replace")
                    client_metrics[topic] = val
        conn.close()
        alive = broker_alive()

        anomaly = len(client_metrics) > 0
        record("sys_client_count_exposure", "INFO_LEAKAGE",
               f"$SYS/broker/clients/+ exposes {len(client_metrics)} client count metrics",
               "V6_SYS_TOPIC_EXPOSURE", 2,
               [f"Metrics: {client_metrics}"],
               anomaly, "INFO_DISCLOSURE" if anomaly else "",
               f"Client metrics exposed: {client_metrics}",
               alive, [], meta={"client_metrics": client_metrics})
    except Exception as e:
        record("sys_client_count_exposure", "INFO_LEAKAGE", "Client count", "V6_SYS_TOPIC_EXPOSURE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # I4: Error message content analysis — do error responses leak implementation details?
    try:
        error_resps = {}
        # Invalid protocol version
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(protocol_level=0xFF))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        if resp: error_resps["invalid_proto"] = resp.raw.hex()
        conn.close()

        # Invalid topic
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect())
        conn.recv_parsed(timeout=TIMEOUT)
        conn.send(build_publish("", b"empty_topic"))  # Empty topic invalid
        resp2 = conn.recv_parsed(timeout=TIMEOUT)
        if resp2: error_resps["empty_topic"] = resp2.raw.hex()
        conn.close()

        alive = broker_alive()
        record("error_message_analysis", "INFO_LEAKAGE",
               f"Error response analysis: {len(error_resps)} error responses captured",
               "V16_INFO_LEAKAGE", 3,
               [f"Error responses: {error_resps}"],
               False, "",
               f"Error responses: {error_resps}",
               alive, [], meta={"error_responses": error_resps})
    except Exception as e:
        record("error_message_analysis", "INFO_LEAKAGE", "Error analysis", "V16_INFO_LEAKAGE",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY J: Broker Config Fingerprinting
# ────────────────────────────────────────────────────────────────────────

def test_config_fingerprinting():
    print("[J] Broker configuration fingerprinting...")

    # J1: Probe max_inflight_messages limit
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="inflight_probe"))
        connack = conn.recv_parsed(timeout=TIMEOUT)

        # Subscribe first so we can be the recipient of queued messages
        conn.send(build_subscribe("test/inflight_probe", packet_id=1, requested_qos=1))
        conn.recv_parsed(timeout=TIMEOUT)

        # Publish many QoS 1 messages without reading PUBACKs
        pub = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        pub.connect_tcp()
        pub.send(build_connect(client_id="inflight_pub"))
        pub.recv_parsed(timeout=TIMEOUT)

        acked = 0
        refused_at = None
        for i in range(30):
            pub.send(build_publish("test/inflight_probe", f"msg_{i}".encode(), qos=1, packet_id=i+1))
            puback = pub.recv_parsed(timeout=0.5)
            if puback:
                acked += 1

        pub.close()
        conn.close()
        alive = broker_alive()

        record("inflight_limit_probe", "CONFIG_FINGERPRINT",
               f"In-flight message limit probe: {acked}/30 QoS 1 messages acknowledged",
               "V17_CONFIG_FINGERPRINT", 31,
               [f"{acked}/30 ACKed"],
               False, "",
               f"Observed in-flight limit: at least {acked} messages processed",
               alive, [], meta={"acked": acked, "attempted": 30})
    except Exception as e:
        record("inflight_limit_probe", "CONFIG_FINGERPRINT", "In-flight probe", "V17_CONFIG_FINGERPRINT",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # J2: Max queued messages probe
    try:
        # Create a persistent offline client (subscribed to QoS 1)
        offline_id = "queued_offline_c2"
        setup = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        setup.connect_tcp()
        setup.send(build_connect(client_id=offline_id, clean_session=False))
        setup.recv_parsed(timeout=TIMEOUT)
        setup.send(build_subscribe("test/queue_probe", packet_id=1, requested_qos=1))
        setup.recv_parsed(timeout=TIMEOUT)
        setup.close()  # Go offline WITHOUT disconnect — session persists

        # Now flood with QoS 1 messages to the topic (will queue for offline client)
        pub = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        pub.connect_tcp()
        pub.send(build_connect(client_id="queue_pub"))
        pub.recv_parsed(timeout=TIMEOUT)

        queued = 0
        for i in range(200):
            pub.send(build_publish("test/queue_probe", f"q_{i}".encode(), qos=1, packet_id=i+1))
            pr = pub.recv_parsed(timeout=0.3)
            if pr: queued += 1
        pub.close()

        # Reconnect offline client — see how many messages are waiting
        recv = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        recv.connect_tcp()
        recv.send(build_connect(client_id=offline_id, clean_session=False))
        connack = recv.recv_parsed(timeout=TIMEOUT)

        msgs_received = 0
        deadline = time.time() + 3.0
        while time.time() < deadline:
            m = recv.recv_parsed(timeout=0.4)
            if m and m.packet_type == PacketType.PUBLISH:
                msgs_received += 1
                # Send PUBACK
                if len(m.payload) >= 4:
                    pid = struct.unpack("!H", m.payload[2:4])[0]
                    recv.send(bytes([0x40, 0x02]) + struct.pack("!H", pid))
        recv.close()

        alive = broker_alive()
        record("max_queued_messages_probe", "CONFIG_FINGERPRINT",
               f"Max queued messages: sent {queued} QoS 1, offline client received {msgs_received} on reconnect",
               "V17_CONFIG_FINGERPRINT", queued + 2,
               [f"{msgs_received}/{queued} delivered on reconnect"],
               False, "",
               f"Queue limit appears to be ~{msgs_received} messages (sent {queued})",
               alive, [], meta={"sent": queued, "received_on_reconnect": msgs_received,
                                 "implied_queue_limit": msgs_received})
    except Exception as e:
        record("max_queued_messages_probe", "CONFIG_FINGERPRINT", "Queue probe", "V17_CONFIG_FINGERPRINT",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # J3: Message size limit probe — find broker's max_packet_size
    limits_found = {}
    for size in [1024, 4096, 65535, 262144, 1048576, 10485760]:
        try:
            conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, 5.0)
            conn.connect_tcp()
            conn.send(build_connect(client_id=f"sizelimit_{size//1024}k"))
            connack = conn.recv_parsed(timeout=TIMEOUT)
            accepted = False
            if connack and connack.connack_return_code == 0:
                pkt = build_publish("test/size_probe", b"X" * size)
                if conn.send(pkt):
                    time.sleep(0.3)
                    accepted = broker_alive()
                    limits_found[size] = accepted
            conn.close()
        except Exception:
            limits_found[size] = False

    max_accepted = max((s for s, ok in limits_found.items() if ok), default=0)
    alive = broker_alive()
    record("message_size_limit_probe", "CONFIG_FINGERPRINT",
           f"Message size limit: max accepted payload = {max_accepted:,} bytes",
           "V17_CONFIG_FINGERPRINT", len(limits_found),
           [str(limits_found)],
           False, "",
           f"Broker accepts payloads up to {max_accepted:,} bytes",
           alive, [], meta={"size_tests": limits_found, "max_accepted": max_accepted})

    # J4: Simultaneous connection limit probe
    try:
        active = []
        max_conn = 0
        for i in range(50):
            try:
                conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, 1.0)
                conn.connect_tcp()
                conn.send(build_connect(client_id=f"connlimit_{i:04d}"))
                resp = conn.recv_parsed(timeout=1.0)
                if resp and resp.connack_return_code == 0:
                    active.append(conn)
                    max_conn = len(active)
                else:
                    conn.close()
            except Exception:
                break
        for c in active:
            try: c.close()
            except: pass
        alive = broker_alive()
        record("connection_limit_probe", "CONFIG_FINGERPRINT",
               f"Simultaneous connection limit: held {max_conn} concurrent connections",
               "V17_CONFIG_FINGERPRINT", max_conn,
               [f"max_concurrent={max_conn}"],
               False, "",
               f"Broker accepted at least {max_conn} simultaneous connections",
               alive, [], meta={"max_concurrent": max_conn})
    except Exception as e:
        record("connection_limit_probe", "CONFIG_FINGERPRINT", "Conn limit", "V17_CONFIG_FINGERPRINT",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # J5: Topic length limit probe
    try:
        max_topic_accepted = 0
        for tlen in [100, 1000, 10000, 32767, 65535]:
            try:
                conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
                conn.connect_tcp()
                conn.send(build_connect(client_id=f"topiclen_{tlen}"))
                connack = conn.recv_parsed(timeout=TIMEOUT)
                if connack and connack.connack_return_code == 0:
                    topic = "a" * tlen
                    conn.send(build_publish(topic, b"len_test"))
                    time.sleep(0.2)
                    if broker_alive():
                        max_topic_accepted = tlen
                conn.close()
            except Exception:
                break
        alive = broker_alive()
        record("topic_length_limit_probe", "CONFIG_FINGERPRINT",
               f"Topic length limit: max accepted = {max_topic_accepted} chars",
               "V17_CONFIG_FINGERPRINT", 5,
               [f"max_topic_len={max_topic_accepted}"],
               False, "",
               f"Max topic length accepted: {max_topic_accepted} characters",
               alive, [], meta={"max_topic_len": max_topic_accepted})
    except Exception as e:
        record("topic_length_limit_probe", "CONFIG_FINGERPRINT", "Topic length", "V17_CONFIG_FINGERPRINT",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY K: Will Message Extended Tests
# ────────────────────────────────────────────────────────────────────────

def test_will_extended():
    print("[K] Extended Will message tests...")

    # K1: Will to multiple sensitive topic namespaces
    will_targets = [
        ("restricted/admin", b"ATTACKER_WILL_ADMIN"),
        ("commands/all",     b"ATTACKER_WILL_COMMANDS"),
        ("alerts/critical",  b"ATTACKER_WILL_ALERT"),
        ("internal/control", b"ATTACKER_WILL_INTERNAL"),
        ("$SYS/test",        b"ATTACKER_WILL_SYS"),     # Should be silently ignored
        ("user/1/commands",  b"ATTACKER_WILL_USER"),
    ]
    delivered = []
    for will_topic, will_msg in will_targets:
        try:
            # Observer
            obs = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            obs.connect_tcp()
            obs.send(build_connect(client_id=f"will_obs_{will_topic[:10].replace('/', '_')}"))
            obs.recv_parsed(timeout=TIMEOUT)
            obs.send(build_subscribe(will_topic if "$SYS" not in will_topic else "test/placeholder",
                                     packet_id=1))
            obs.recv_parsed(timeout=TIMEOUT)

            # Attacker with will
            atk = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
            atk.connect_tcp()
            atk.send(build_connect(client_id="will_attacker_c2", will_topic=will_topic,
                                    will_message=will_msg))
            connack = atk.recv_parsed(timeout=TIMEOUT)
            # Abruptly close TCP — triggers will delivery
            atk.close()

            time.sleep(0.5)
            msg = obs.recv_parsed(timeout=1.0)
            if msg and msg.packet_type == PacketType.PUBLISH:
                delivered.append(will_topic)
            obs.close()
        except Exception:
            pass

    alive = broker_alive()
    anomaly = len(delivered) > 0
    record("will_topic_namespace_attack", "WILL_ATTACK",
           f"Will message delivery to {len(delivered)}/{len(will_targets)} targeted topics",
           "V1_UNAUTHORIZED_WILL", len(will_targets) * 2,
           [f"Delivered: {delivered}"],
           anomaly, "UNAUTHORIZED_WILL" if anomaly else "",
           f"Will messages delivered to: {delivered} without authorization",
           alive, [], meta={"targets": [t for t, _ in will_targets], "delivered": delivered})

    # K2: Will with QoS 2 — retained will message
    try:
        obs = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        obs.connect_tcp()
        obs.send(build_connect(client_id="will_qos2_obs"))
        obs.recv_parsed(timeout=TIMEOUT)
        obs.send(build_subscribe("fuzz/will_qos2", packet_id=1))
        obs.recv_parsed(timeout=TIMEOUT)

        atk = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        atk.connect_tcp()
        atk.send(build_connect(client_id="will_qos2_atk", will_topic="fuzz/will_qos2",
                                will_message=b"WILL_QOS2_RETAINED", will_qos=2, will_retain=True))
        connack = atk.recv_parsed(timeout=TIMEOUT)
        atk.close()

        time.sleep(0.5)
        msg = obs.recv_parsed(timeout=1.5)
        obs.close()

        alive = broker_alive()
        delivered_flag = msg is not None and msg.packet_type == PacketType.PUBLISH
        record("will_qos2_retained", "WILL_ATTACK",
               "Will message with QoS=2 and retain=True",
               "V1_UNAUTHORIZED_WILL", 2, [repr(msg)],
               delivered_flag, "WILL_DELIVERED" if delivered_flag else "",
               f"Will with QoS2+retain {'delivered' if delivered_flag else 'not delivered'}",
               alive, [])
    except Exception as e:
        record("will_qos2_retained", "WILL_ATTACK", "Will QoS2 retain", "V1_UNAUTHORIZED_WILL",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # K3: Oversized will message — memory pressure
    try:
        large_will = b"W" * 65535
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="will_large", will_topic="fuzz/large_will",
                                 will_message=large_will))
        resp = conn.recv_parsed(timeout=TIMEOUT)
        conn.close()
        alive = broker_alive()
        record("will_large_payload", "WILL_ATTACK",
               "Will message with 64KB payload",
               "V1_UNAUTHORIZED_WILL", 1, [repr(resp)],
               not alive, "CRASH" if not alive else "",
               f"Broker {'crashed' if not alive else 'accepted'} 64KB will message",
               alive, [], meta={"will_size": len(large_will)})
    except Exception as e:
        record("will_large_payload", "WILL_ATTACK", "Large will", "V1_UNAUTHORIZED_WILL",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# CATEGORY L: Retained Message Attacks
# ────────────────────────────────────────────────────────────────────────

def test_retained_attacks():
    print("[L] Retained message attacks...")

    # L1: Retained message bomb — fill broker with retained messages
    try:
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="retain_bomb"))
        connack = conn.recv_parsed(timeout=TIMEOUT)
        retained_sent = 0
        if connack and connack.connack_return_code == 0:
            for i in range(500):
                pkt = build_publish(f"fuzz/retain/bomb/{i}", b"RETAINED_BOMB", retain=True)
                if not conn.send(pkt):
                    break
                retained_sent += 1
            time.sleep(0.5)
        conn.close()
        alive = broker_alive()
        record("retained_message_bomb", "RETAINED_ATTACK",
               f"Retained message bomb: {retained_sent} retained messages published",
               "V2_UNAUTHORIZED_RETAIN", retained_sent,
               [f"{retained_sent} retained messages created"],
               not alive, "CRASH" if not alive else "RETAIN_ACCUMULATION",
               f"Broker {'crashed' if not alive else f'stored {retained_sent} retained messages'}",
               alive, [], meta={"retained_count": retained_sent})
    except Exception as e:
        record("retained_message_bomb", "RETAINED_ATTACK", "Retain bomb", "V2_UNAUTHORIZED_RETAIN",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])

    # L2: Delete retained message via empty retained publish
    try:
        # Set then clear a retained message
        conn = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        conn.connect_tcp()
        conn.send(build_connect(client_id="retain_del"))
        conn.recv_parsed(timeout=TIMEOUT)
        conn.send(build_publish("fuzz/retain/delete", b"INITIAL_RETAINED", retain=True))
        time.sleep(0.2)
        # Delete by publishing empty payload with retain=True
        conn.send(build_publish("fuzz/retain/delete", b"", retain=True))
        time.sleep(0.2)
        conn.close()

        # Verify: new subscriber should NOT get retained message
        obs = RawMQTTConnection(TARGET_HOST, TARGET_PORT, TIMEOUT)
        obs.connect_tcp()
        obs.send(build_connect(client_id="retain_del_obs"))
        obs.recv_parsed(timeout=TIMEOUT)
        obs.send(build_subscribe("fuzz/retain/delete", packet_id=1))
        obs.recv_parsed(timeout=TIMEOUT)
        msg = obs.recv_parsed(timeout=1.5)
        obs.close()
        alive = broker_alive()

        anomaly = msg is not None  # Should not receive anything if delete worked
        record("retained_delete_test", "RETAINED_ATTACK",
               "Retained message deletion via empty payload",
               "V2_UNAUTHORIZED_RETAIN", 3, [repr(msg)],
               anomaly, "RETAIN_DELETE_FAILED" if anomaly else "",
               f"Retained message deletion {'failed (still received)' if anomaly else 'succeeded'}",
               alive, [])
    except Exception as e:
        record("retained_delete_test", "RETAINED_ATTACK", "Retain delete", "V2_UNAUTHORIZED_RETAIN",
               0, [], True, "EXCEPTION", str(e), broker_alive(), [])


# ────────────────────────────────────────────────────────────────────────
# Main execution
# ────────────────────────────────────────────────────────────────────────

def run_all():
    print("=" * 60)
    print("MQTT Campaign 2 Fuzzer — Starting...")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
    print("=" * 60)

    if not broker_alive():
        print("ERROR: Broker not alive at start. Aborting.")
        sys.exit(1)

    test_auth_bypass()
    test_topic_namespace()
    test_qos_attacks()
    test_session_attacks()
    test_payload_attacks()
    test_connection_attacks()
    test_subscription_abuse()
    test_mqtt_v5()
    test_info_leakage()
    test_config_fingerprinting()
    test_will_extended()
    test_retained_attacks()

    print("=" * 60)
    print(f"Campaign 2 complete. Total test cases: {len(results)}")
    anomalies = [r for r in results if r.anomaly]
    print(f"Anomalies: {len(anomalies)}")
    alive = broker_alive()
    print(f"Broker alive at end: {alive}")

    return results


if __name__ == "__main__":
    run_all()
    # Print summary
    cats = {}
    for r in results:
        cats[r.category] = cats.get(r.category, 0) + 1
    print("\nTest counts by category:")
    for cat, n in sorted(cats.items()):
        print(f"  {cat}: {n}")
