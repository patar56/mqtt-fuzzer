"""
Raw MQTT Packet Builder and TCP Connector

Implements MQTT 3.1.1 packet encoding from scratch (without a client library)
so we can craft malformed, boundary-case, and out-of-sequence packets that
a compliant client library would refuse to send.

This gives us the same capability as FUME's custom fuzzing transport layer:
full control over every byte on the wire.
"""

import socket
import struct
import time
import logging
from typing import Optional, Tuple
from dataclasses import dataclass, field

from agent.spec.mqtt_spec import PacketType, QoSLevel

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Encoding Helpers
# ─────────────────────────────────────────────────────────────

def encode_remaining_length(length: int) -> bytes:
    """Encode variable-length integer (MQTT §2.2.3)."""
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


def encode_utf8_string(s: str) -> bytes:
    """Encode UTF-8 string with 2-byte length prefix (MQTT §1.5.3)."""
    if isinstance(s, str):
        encoded = s.encode("utf-8")
    else:
        encoded = s  # Already bytes
    return struct.pack("!H", len(encoded)) + encoded


def encode_uint16(value: int) -> bytes:
    return struct.pack("!H", value & 0xFFFF)


def decode_remaining_length(data: bytes, offset: int = 1) -> Tuple[int, int]:
    """Decode variable-length integer, return (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    consumed = 0
    while True:
        byte = data[offset + consumed]
        value += (byte & 0x7F) * multiplier
        consumed += 1
        multiplier *= 128
        if not (byte & 0x80):
            break
        if multiplier > 128 * 128 * 128:
            raise ValueError("Remaining Length decode error")
    return value, consumed


# ─────────────────────────────────────────────────────────────
# Packet Builders
# ─────────────────────────────────────────────────────────────

def build_connect(
    client_id: str = "mqtt_agent_fuzz",
    clean_session: bool = True,
    keepalive: int = 60,
    username: Optional[str] = None,
    password: Optional[str] = None,
    will_topic: Optional[str] = None,
    will_message: Optional[bytes] = None,
    will_qos: int = 0,
    will_retain: bool = False,
    protocol_level: int = 0x04,       # 0x04 = MQTT 3.1.1, 0x05 = MQTT 5.0
    protocol_name: bytes = b"MQTT",   # Fuzzable
) -> bytes:
    """Build a CONNECT packet with full control over all fields."""
    # Variable header
    variable_header = encode_utf8_string(protocol_name.decode("latin-1"))
    variable_header += bytes([protocol_level])

    # Connect flags byte
    connect_flags = 0
    if clean_session:
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

    variable_header += bytes([connect_flags])
    variable_header += encode_uint16(keepalive)

    # Payload
    payload = encode_utf8_string(client_id)
    if will_topic is not None:
        payload += encode_utf8_string(will_topic)
        payload += struct.pack("!H", len(will_message or b""))
        payload += (will_message or b"")
    if username is not None:
        payload += encode_utf8_string(username)
    if password is not None:
        payload += encode_utf8_string(password)

    remaining = variable_header + payload
    fixed_header = bytes([0x10]) + encode_remaining_length(len(remaining))
    return fixed_header + remaining


def build_publish(
    topic: str,
    payload: bytes = b"",
    qos: int = 0,
    retain: bool = False,
    dup: bool = False,
    packet_id: int = 1,
) -> bytes:
    """Build a PUBLISH packet."""
    # Fixed header first byte
    first_byte = PacketType.PUBLISH << 4
    if dup:
        first_byte |= 0x08
    first_byte |= (qos & 0x03) << 1
    if retain:
        first_byte |= 0x01

    variable_header = encode_utf8_string(topic)
    if qos > 0:
        variable_header += encode_uint16(packet_id)

    remaining = variable_header + payload
    return bytes([first_byte]) + encode_remaining_length(len(remaining)) + remaining


def build_subscribe(
    topic_filter: str,
    packet_id: int = 1,
    requested_qos: int = 0,
) -> bytes:
    """Build a SUBSCRIBE packet."""
    variable_header = encode_uint16(packet_id)
    payload = encode_utf8_string(topic_filter) + bytes([requested_qos & 0x03])
    remaining = variable_header + payload
    fixed_header = bytes([0x82]) + encode_remaining_length(len(remaining))
    return fixed_header + remaining


def build_unsubscribe(topic_filter: str, packet_id: int = 1) -> bytes:
    """Build an UNSUBSCRIBE packet."""
    variable_header = encode_uint16(packet_id)
    payload = encode_utf8_string(topic_filter)
    remaining = variable_header + payload
    fixed_header = bytes([0xA2]) + encode_remaining_length(len(remaining))
    return fixed_header + remaining


def build_pubrel(packet_id: int) -> bytes:
    """Build a PUBREL packet (QoS 2 step 2)."""
    return bytes([0x62, 0x02]) + encode_uint16(packet_id)


def build_pubrec(packet_id: int) -> bytes:
    """Build a PUBREC packet."""
    return bytes([0x50, 0x02]) + encode_uint16(packet_id)


def build_pubcomp(packet_id: int) -> bytes:
    """Build a PUBCOMP packet."""
    return bytes([0x70, 0x02]) + encode_uint16(packet_id)


def build_pingreq() -> bytes:
    """Build a PINGREQ packet."""
    return bytes([0xC0, 0x00])


def build_disconnect() -> bytes:
    """Build a DISCONNECT packet."""
    return bytes([0xE0, 0x00])


def build_raw_packet(packet_type: int, flags: int, payload: bytes) -> bytes:
    """Build an arbitrary raw packet — for malformed packet testing."""
    first_byte = ((packet_type & 0x0F) << 4) | (flags & 0x0F)
    return bytes([first_byte]) + encode_remaining_length(len(payload)) + payload


# ─────────────────────────────────────────────────────────────
# Response Parser
# ─────────────────────────────────────────────────────────────

@dataclass
class MQTTResponse:
    packet_type: int
    flags: int
    payload: bytes
    raw: bytes

    @property
    def type_name(self) -> str:
        try:
            return PacketType(self.packet_type).name
        except ValueError:
            return f"UNKNOWN(0x{self.packet_type:02X})"

    @property
    def connack_return_code(self) -> Optional[int]:
        if self.packet_type == PacketType.CONNACK and len(self.payload) >= 2:
            return self.payload[1]
        return None

    @property
    def connack_session_present(self) -> Optional[bool]:
        if self.packet_type == PacketType.CONNACK and len(self.payload) >= 1:
            return bool(self.payload[0] & 0x01)
        return None

    def __repr__(self) -> str:
        return (
            f"MQTTResponse({self.type_name}, flags=0x{self.flags:02X}, "
            f"payload_len={len(self.payload)}, raw={self.raw.hex()})"
        )


def parse_response(data: bytes) -> Optional[MQTTResponse]:
    """Parse a raw MQTT response from the broker."""
    if len(data) < 2:
        return None
    first_byte = data[0]
    packet_type = (first_byte >> 4) & 0x0F
    flags = first_byte & 0x0F
    try:
        remaining_len, consumed = decode_remaining_length(data)
    except (ValueError, IndexError):
        logger.warning(f"Failed to decode remaining length from: {data.hex()}")
        return None
    payload_start = 1 + consumed
    payload = data[payload_start : payload_start + remaining_len]
    return MQTTResponse(
        packet_type=packet_type,
        flags=flags,
        payload=payload,
        raw=data,
    )


# ─────────────────────────────────────────────────────────────
# Raw TCP Connector
# ─────────────────────────────────────────────────────────────

class RawMQTTConnection:
    """
    Raw TCP connection to an MQTT broker.
    Sends and receives bytes directly — no MQTT client library.
    This gives the fuzzer full control over the wire protocol.
    """

    def __init__(self, host: str = "localhost", port: int = 1883, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self.connected = False

    def connect_tcp(self) -> bool:
        """Establish raw TCP connection."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
            self.connected = True
            logger.debug(f"TCP connected to {self.host}:{self.port}")
            return True
        except (ConnectionRefusedError, OSError) as e:
            logger.error(f"TCP connection failed: {e}")
            self.connected = False
            return False

    def send(self, data: bytes) -> bool:
        """Send raw bytes to broker."""
        if not self._sock:
            return False
        try:
            self._sock.sendall(data)
            logger.debug(f"SENT {len(data)} bytes: {data.hex()}")
            return True
        except OSError as e:
            logger.warning(f"Send failed: {e}")
            self.connected = False
            return False

    def recv(self, bufsize: int = 4096, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive raw bytes from broker."""
        if not self._sock:
            return None
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(bufsize)
            if data:
                logger.debug(f"RECV {len(data)} bytes: {data.hex()}")
                return data
            else:
                # Connection closed by broker
                logger.info("Broker closed connection")
                self.connected = False
                return None
        except socket.timeout:
            logger.debug("Receive timeout — broker did not respond")
            return None
        except OSError as e:
            logger.warning(f"Recv failed: {e}")
            self.connected = False
            return None

    def recv_parsed(self, timeout: Optional[float] = None) -> Optional[MQTTResponse]:
        """Receive and parse a single MQTT response packet."""
        raw = self.recv(timeout=timeout)
        if raw is None:
            return None
        return parse_response(raw)

    def close(self):
        """Close TCP connection (without sending DISCONNECT — simulates crash)."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self.connected = False

    def graceful_disconnect(self):
        """Send DISCONNECT then close."""
        if self.connected:
            self.send(build_disconnect())
        self.close()

    def mqtt_connect(
        self,
        client_id: str = "fuzz_agent",
        clean_session: bool = True,
        keepalive: int = 60,
        **kwargs,
    ) -> Optional[MQTTResponse]:
        """Perform full MQTT CONNECT and return CONNACK."""
        if not self.connected:
            if not self.connect_tcp():
                return None
        pkt = build_connect(
            client_id=client_id,
            clean_session=clean_session,
            keepalive=keepalive,
            **kwargs,
        )
        self.send(pkt)
        return self.recv_parsed(timeout=self.timeout)

    def __enter__(self):
        self.connect_tcp()
        return self

    def __exit__(self, *_):
        self.close()
