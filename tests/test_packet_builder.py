"""
Unit tests for the MQTT packet builder.
Run: python -m pytest tests/ -v
"""

import pytest
import struct
from agent.broker.connector import (
    encode_remaining_length, decode_remaining_length,
    encode_utf8_string, build_connect, build_publish,
    build_subscribe, build_disconnect, build_pingreq,
    parse_response, MQTTResponse,
)
from agent.spec.mqtt_spec import PacketType


# ─────────────────────────────────────────────────────────────
# Remaining Length Encoding (MQTT §2.2.3)
# ─────────────────────────────────────────────────────────────

class TestRemainingLength:
    def test_single_byte_values(self):
        assert encode_remaining_length(0)   == b'\x00'
        assert encode_remaining_length(1)   == b'\x01'
        assert encode_remaining_length(127) == b'\x7F'

    def test_two_byte_values(self):
        assert encode_remaining_length(128) == b'\x80\x01'
        assert encode_remaining_length(16383) == b'\xFF\x7F'

    def test_three_byte_values(self):
        assert encode_remaining_length(16384) == b'\x80\x80\x01'

    def test_four_byte_max(self):
        result = encode_remaining_length(268435455)
        assert result == b'\xFF\xFF\xFF\x7F'

    def test_roundtrip(self):
        for n in [0, 1, 127, 128, 1000, 16383, 16384, 100000, 268435455]:
            encoded = encode_remaining_length(n)
            decoded, _ = decode_remaining_length(b'\x10' + encoded)
            assert decoded == n, f"Roundtrip failed for {n}"


# ─────────────────────────────────────────────────────────────
# UTF-8 String Encoding
# ─────────────────────────────────────────────────────────────

class TestStringEncoding:
    def test_basic_string(self):
        result = encode_utf8_string("MQTT")
        assert result == b'\x00\x04MQTT'

    def test_empty_string(self):
        result = encode_utf8_string("")
        assert result == b'\x00\x00'

    def test_length_prefix(self):
        s = "hello"
        result = encode_utf8_string(s)
        length = struct.unpack("!H", result[:2])[0]
        assert length == len(s)

    def test_unicode(self):
        # UTF-8 encoded length may differ from string length
        result = encode_utf8_string("café")
        # "café" in UTF-8 is 5 bytes (é = 2 bytes)
        length = struct.unpack("!H", result[:2])[0]
        assert length == len("café".encode("utf-8"))


# ─────────────────────────────────────────────────────────────
# CONNECT Packet
# ─────────────────────────────────────────────────────────────

class TestConnectPacket:
    def test_fixed_header(self):
        pkt = build_connect("test_client")
        assert pkt[0] == 0x10, "CONNECT first byte should be 0x10"

    def test_protocol_name(self):
        pkt = build_connect("test_client")
        # After fixed header + remaining length (at least 2 bytes):
        # Variable header starts with "MQTT" length-prefixed
        # Find "MQTT" bytes
        assert b'MQTT' in pkt

    def test_protocol_level_311(self):
        pkt = build_connect("test_client", protocol_level=0x04)
        # Protocol level 0x04 should be present
        assert 0x04 in pkt

    def test_protocol_level_50(self):
        pkt = build_connect("test_client", protocol_level=0x05)
        assert 0x05 in pkt

    def test_clean_session_flag(self):
        clean = build_connect("c", clean_session=True)
        persistent = build_connect("c", clean_session=False)
        # The connect flags byte differs
        assert clean != persistent

    def test_clientid_in_payload(self):
        cid = "my_test_client"
        pkt = build_connect(cid)
        assert cid.encode() in pkt

    def test_will_message(self):
        pkt = build_connect(
            "c", will_topic="will/test", will_message=b"goodbye", will_qos=1
        )
        assert b"will/test" in pkt
        assert b"goodbye" in pkt

    def test_empty_clientid(self):
        pkt = build_connect("", clean_session=True)
        # Should be buildable without error
        assert pkt[0] == 0x10

    def test_min_packet_size(self):
        pkt = build_connect("c")
        assert len(pkt) >= 14  # Minimum valid CONNECT packet

    def test_custom_protocol_name(self):
        pkt = build_connect("c", protocol_name=b"mqtt")
        assert b"mqtt" in pkt


# ─────────────────────────────────────────────────────────────
# PUBLISH Packet
# ─────────────────────────────────────────────────────────────

class TestPublishPacket:
    def test_fixed_header_qos0(self):
        pkt = build_publish("test/topic", b"payload")
        assert (pkt[0] >> 4) == PacketType.PUBLISH

    def test_retain_flag(self):
        retained = build_publish("t", retain=True)
        not_retained = build_publish("t", retain=False)
        assert retained[0] & 0x01 == 1
        assert not_retained[0] & 0x01 == 0

    def test_dup_flag(self):
        dup = build_publish("t", dup=True, qos=1, packet_id=1)
        assert dup[0] & 0x08 == 0x08

    def test_qos_flags(self):
        for qos in [0, 1, 2]:
            pkt = build_publish("t", qos=qos, packet_id=1)
            extracted_qos = (pkt[0] >> 1) & 0x03
            assert extracted_qos == qos

    def test_packet_id_qos1(self):
        pkt = build_publish("t", b"", qos=1, packet_id=42)
        assert b'\x00\x2a' in pkt  # packet_id=42 = 0x002A

    def test_topic_in_packet(self):
        pkt = build_publish("home/temp", b"25.0")
        assert b"home/temp" in pkt

    def test_empty_payload(self):
        pkt = build_publish("t", b"")
        assert len(pkt) >= 4


# ─────────────────────────────────────────────────────────────
# SUBSCRIBE Packet
# ─────────────────────────────────────────────────────────────

class TestSubscribePacket:
    def test_fixed_header(self):
        pkt = build_subscribe("test/#")
        assert pkt[0] == 0x82  # SUBSCRIBE with required flags

    def test_topic_in_packet(self):
        pkt = build_subscribe("home/devices/+")
        assert b"home/devices/+" in pkt

    def test_packet_id(self):
        pkt = build_subscribe("t", packet_id=99)
        assert b'\x00\x63' in pkt  # 99 = 0x0063


# ─────────────────────────────────────────────────────────────
# Control Packets
# ─────────────────────────────────────────────────────────────

class TestControlPackets:
    def test_pingreq(self):
        pkt = build_pingreq()
        assert pkt == b'\xC0\x00'

    def test_disconnect(self):
        pkt = build_disconnect()
        assert pkt == b'\xE0\x00'


# ─────────────────────────────────────────────────────────────
# Response Parser
# ─────────────────────────────────────────────────────────────

class TestResponseParser:
    def test_parse_connack_accepted(self):
        # CONNACK: 0x20 0x02 0x00 0x00
        raw = bytes([0x20, 0x02, 0x00, 0x00])
        resp = parse_response(raw)
        assert resp is not None
        assert resp.packet_type == PacketType.CONNACK
        assert resp.connack_return_code == 0
        assert resp.connack_session_present == False

    def test_parse_connack_session_present(self):
        raw = bytes([0x20, 0x02, 0x01, 0x00])
        resp = parse_response(raw)
        assert resp.connack_session_present == True

    def test_parse_connack_refused(self):
        raw = bytes([0x20, 0x02, 0x00, 0x05])  # Not authorized
        resp = parse_response(raw)
        assert resp.connack_return_code == 5

    def test_parse_pingresp(self):
        raw = bytes([0xD0, 0x00])
        resp = parse_response(raw)
        assert resp.packet_type == PacketType.PINGRESP

    def test_parse_too_short(self):
        resp = parse_response(b'\x20')  # Only 1 byte
        assert resp is None

    def test_type_name(self):
        raw = bytes([0x20, 0x02, 0x00, 0x00])
        resp = parse_response(raw)
        assert resp.type_name == "CONNACK"
