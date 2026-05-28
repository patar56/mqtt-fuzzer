"""
MQTT Protocol Specification Knowledge Base
Encodes MQTT 3.1.1 (RFC) and MQTT 5.0 protocol structure.

This module provides the structured protocol knowledge that the LLM agent
will use to reason about valid/invalid packet sequences. Inspired by
MGPTFuzz's approach of extracting FSMs from protocol specs.

Sources:
  - OASIS MQTT 3.1.1 Specification
  - OASIS MQTT 5.0 Specification
  - FUME paper: packet type taxonomy
"""

from enum import IntEnum, auto
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────
# MQTT Control Packet Types (MQTT 3.1.1 §2.1.1)
# ─────────────────────────────────────────────────────────────
class PacketType(IntEnum):
    CONNECT     = 1
    CONNACK     = 2
    PUBLISH     = 3
    PUBACK      = 4   # QoS 1 ACK
    PUBREC      = 5   # QoS 2 received
    PUBREL      = 6   # QoS 2 release
    PUBCOMP     = 7   # QoS 2 complete
    SUBSCRIBE   = 8
    SUBACK      = 9
    UNSUBSCRIBE = 10
    UNSUBACK    = 11
    PINGREQ     = 12
    PINGRESP    = 13
    DISCONNECT  = 14
    AUTH        = 15  # MQTT 5.0 only


# ─────────────────────────────────────────────────────────────
# QoS Levels
# ─────────────────────────────────────────────────────────────
class QoSLevel(IntEnum):
    AT_MOST_ONCE  = 0
    AT_LEAST_ONCE = 1
    EXACTLY_ONCE  = 2


# ─────────────────────────────────────────────────────────────
# CONNACK Return Codes (MQTT 3.1.1 §3.2.2.3)
# ─────────────────────────────────────────────────────────────
class ConnackReturnCode(IntEnum):
    ACCEPTED                     = 0x00
    REFUSED_PROTOCOL_VERSION     = 0x01
    REFUSED_IDENTIFIER_REJECTED  = 0x02
    REFUSED_SERVER_UNAVAILABLE   = 0x03
    REFUSED_BAD_USERNAME         = 0x04
    REFUSED_NOT_AUTHORIZED       = 0x05


# ─────────────────────────────────────────────────────────────
# MQTT 5.0 Reason Codes (§2.4)
# ─────────────────────────────────────────────────────────────
class ReasonCode(IntEnum):
    SUCCESS                      = 0x00
    NORMAL_DISCONNECTION         = 0x00
    QOS_0                        = 0x00
    QOS_1                        = 0x01
    QOS_2                        = 0x02
    DISCONNECT_WITH_WILL         = 0x04
    NO_MATCHING_SUBSCRIBERS      = 0x10
    NO_SUBSCRIPTION_FOUND        = 0x11
    UNSPECIFIED_ERROR            = 0x80
    MALFORMED_PACKET             = 0x81
    PROTOCOL_ERROR               = 0x82
    IMPLEMENTATION_SPECIFIC      = 0x83
    UNSUPPORTED_PROTOCOL_VERSION = 0x84
    CLIENT_ID_NOT_VALID          = 0x85
    BAD_USERNAME_OR_PASSWORD     = 0x86
    NOT_AUTHORIZED               = 0x87
    SERVER_UNAVAILABLE           = 0x88
    SERVER_BUSY                  = 0x89
    BANNED                       = 0x8A
    SERVER_SHUTTING_DOWN         = 0x8B
    BAD_AUTHENTICATION_METHOD    = 0x8C
    KEEP_ALIVE_TIMEOUT           = 0x8D
    SESSION_TAKEN_OVER           = 0x8E
    TOPIC_FILTER_INVALID         = 0x8F
    TOPIC_NAME_INVALID           = 0x90
    PACKET_IDENTIFIER_IN_USE     = 0x91
    PACKET_IDENTIFIER_NOT_FOUND  = 0x92
    RECEIVE_MAXIMUM_EXCEEDED     = 0x93
    TOPIC_ALIAS_INVALID          = 0x94
    PACKET_TOO_LARGE             = 0x95
    MESSAGE_RATE_TOO_HIGH        = 0x96
    QUOTA_EXCEEDED               = 0x97
    PAYLOAD_FORMAT_INVALID       = 0x99
    RETAIN_NOT_SUPPORTED         = 0x9A
    QOS_NOT_SUPPORTED            = 0x9B
    USE_ANOTHER_SERVER           = 0x9C
    SERVER_MOVED                 = 0x9D
    SHARED_SUBSCRIPTIONS_NOT_SUPPORTED = 0x9E
    CONNECTION_RATE_EXCEEDED     = 0x9F
    SUBSCRIPTION_IDS_NOT_SUPPORTED = 0xA1
    WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED = 0xA2


# ─────────────────────────────────────────────────────────────
# Protocol States (FSM nodes - inspired by MGPTFuzz FSM extraction)
# ─────────────────────────────────────────────────────────────
class BrokerState(IntEnum):
    """States a client session can be in from the broker's perspective."""
    DISCONNECTED    = 0
    CONNECTING      = 1
    CONNECTED       = 2
    SUBSCRIBING     = 3
    SUBSCRIBED      = 4
    PUBLISHING      = 5
    QOS2_PUBREC     = 6  # Waiting for PUBREC in QoS 2 flow
    QOS2_PUBREL     = 7  # Waiting for PUBREL in QoS 2 flow
    QOS2_PUBCOMP    = 8  # Waiting for PUBCOMP in QoS 2 flow
    DISCONNECTING   = 9


# ─────────────────────────────────────────────────────────────
# Field Specifications (for generation-based fuzzing)
# ─────────────────────────────────────────────────────────────
@dataclass
class FieldSpec:
    """Describes a packet field for test-case generation."""
    name: str
    min_len: int = 0
    max_len: int = 65535
    required: bool = True
    valid_values: list = field(default_factory=list)
    boundary_values: list = field(default_factory=list)
    description: str = ""


# ─────────────────────────────────────────────────────────────
# MQTT Packet Specifications
# ─────────────────────────────────────────────────────────────
MQTT_PACKET_SPECS = {
    PacketType.CONNECT: {
        "description": "Client requests connection to broker",
        "fields": {
            "protocol_name": FieldSpec(
                name="protocol_name",
                valid_values=[b"MQTT"],
                boundary_values=[b"mqtt", b"MQTT5", b"", b"M" * 256],
                description="Must be 'MQTT' for MQTT 3.1.1+"
            ),
            "protocol_level": FieldSpec(
                name="protocol_level",
                valid_values=[0x04, 0x05],  # 3.1.1=0x04, 5.0=0x05
                boundary_values=[0x00, 0x03, 0x06, 0xFF],
                description="Protocol version byte"
            ),
            "client_id": FieldSpec(
                name="client_id",
                min_len=0,
                max_len=23,  # Recommended max per spec
                boundary_values=["", "A" * 23, "A" * 24, "A" * 256, "A" * 65535],
                description="Client identifier (0 bytes allowed with clean_session=1)"
            ),
            "clean_session": FieldSpec(
                name="clean_session",
                valid_values=[0, 1],
                description="Discard/preserve session state"
            ),
            "will_flag": FieldSpec(
                name="will_flag",
                valid_values=[0, 1],
                description="Whether Will message is set"
            ),
            "will_qos": FieldSpec(
                name="will_qos",
                valid_values=[0, 1, 2],
                boundary_values=[3],  # Invalid - must cause error
                description="QoS of Will message"
            ),
            "will_retain": FieldSpec(
                name="will_retain",
                valid_values=[0, 1],
                description="Whether Will message is retained"
            ),
            "keepalive": FieldSpec(
                name="keepalive",
                min_len=0,
                max_len=65535,
                boundary_values=[0, 1, 60, 65535],
                description="Keep-alive interval in seconds"
            ),
        },
        "transitions": {
            BrokerState.DISCONNECTED: BrokerState.CONNECTING
        }
    },
    PacketType.PUBLISH: {
        "description": "Client publishes message to broker",
        "fields": {
            "topic_name": FieldSpec(
                name="topic_name",
                min_len=1,
                max_len=65535,
                boundary_values=[
                    "",           # Invalid: empty topic
                    "#",          # Wildcard - invalid in PUBLISH
                    "+",          # Wildcard - invalid in PUBLISH
                    "a" * 65535,  # Maximum length
                    "$SYS/test",  # System topic
                    "$SYS/broker/clients/connected",  # Live system topic
                ],
                description="Topic name (no wildcards allowed)"
            ),
            "packet_id": FieldSpec(
                name="packet_id",
                valid_values=list(range(1, 0xFFFF)),
                boundary_values=[0, 0xFFFF],
                description="Packet identifier (QoS 1 and 2 only)"
            ),
            "payload": FieldSpec(
                name="payload",
                min_len=0,
                max_len=268435455,  # 256MB max packet
                boundary_values=[b"", b"\x00", b"\xFF" * 1000],
                description="Application message payload"
            ),
            "qos": FieldSpec(
                name="qos",
                valid_values=[0, 1, 2],
                boundary_values=[3],
                description="QoS level"
            ),
            "retain": FieldSpec(
                name="retain",
                valid_values=[0, 1],
                description="Retain message flag"
            ),
            "dup": FieldSpec(
                name="dup",
                valid_values=[0, 1],
                description="Duplicate delivery flag"
            ),
        }
    },
    PacketType.SUBSCRIBE: {
        "description": "Client subscribes to topics",
        "fields": {
            "topic_filter": FieldSpec(
                name="topic_filter",
                boundary_values=[
                    "#",           # Global wildcard
                    "+",           # Single-level wildcard
                    "$SYS/#",      # Subscribe to all system topics
                    "a/b/c",       # Normal
                    "a/#/b",       # Invalid: # must be last
                    "+/+/+",       # Multiple single wildcards
                    "",            # Empty - invalid
                    "a" * 65535,   # Maximum length
                ],
                description="Topic filter (wildcards allowed unlike PUBLISH)"
            ),
            "qos": FieldSpec(
                name="qos",
                valid_values=[0, 1, 2],
                boundary_values=[3, 128, 255],
                description="Requested QoS"
            ),
        }
    }
}


# ─────────────────────────────────────────────────────────────
# FSM: Valid Packet Sequences (from MQTT spec state machine)
# Inspired by MGPTFuzz's LLM-extracted FSM representation
# ─────────────────────────────────────────────────────────────
VALID_SEQUENCES = {
    "basic_connect": [
        PacketType.CONNECT,
        # Broker responds: CONNACK
    ],
    "connect_subscribe_publish": [
        PacketType.CONNECT,
        PacketType.SUBSCRIBE,
        PacketType.PUBLISH,
        PacketType.DISCONNECT,
    ],
    "qos2_publish_flow": [
        PacketType.CONNECT,
        PacketType.PUBLISH,   # QoS=2
        # Broker: PUBREC
        PacketType.PUBREL,
        # Broker: PUBCOMP
        PacketType.DISCONNECT,
    ],
    "keepalive_flow": [
        PacketType.CONNECT,
        PacketType.PINGREQ,
        # Broker: PINGRESP
        PacketType.DISCONNECT,
    ],
}

# Invalid sequences that SHOULD be rejected by a correct broker
INVALID_SEQUENCES = {
    "publish_before_connect": [
        PacketType.PUBLISH,   # Must be rejected - no session
    ],
    "subscribe_before_connect": [
        PacketType.SUBSCRIBE,
    ],
    "double_connect": [
        PacketType.CONNECT,
        PacketType.CONNECT,   # Second CONNECT should disconnect client (§3.1.0)
    ],
    "pubrel_without_pubrec": [
        PacketType.CONNECT,
        PacketType.PUBREL,    # No preceding QoS 2 PUBLISH
    ],
}


# ─────────────────────────────────────────────────────────────
# Vulnerability Classes (from Burglars' IoT Paradise + MQTTactic)
# ─────────────────────────────────────────────────────────────
VULNERABILITY_CLASSES = {
    "V1_UNAUTHORIZED_WILL": {
        "name": "Unauthorized Will Message Exploitation",
        "source": "Burglars' IoT Paradise §V.A",
        "description": (
            "An attacker sets a Will message on connect, then disconnects "
            "ungracefully. The broker publishes the Will to a topic the attacker "
            "could not normally publish to. This bypasses topic authorization."
        ),
        "cvss_estimate": 7.5,
        "attack_sequence": [
            "CONNECT with will_flag=1, will_topic=<restricted_topic>",
            "Establish connection (CONNACK received)",
            "Abruptly close TCP connection (no DISCONNECT packet)",
            "Observe: broker publishes Will to restricted topic",
        ],
        "detection": "Subscriber on restricted topic receives unexpected message after disconnect",
    },
    "V2_UNAUTHORIZED_RETAIN": {
        "name": "Unauthorized Retained Message Exploitation",
        "source": "Burglars' IoT Paradise §V.B",
        "description": (
            "Retained messages persist on the broker indefinitely. An attacker "
            "who can publish a retained message to a topic 'poisons' all future "
            "subscribers to that topic, even after the attacker disconnects."
        ),
        "cvss_estimate": 6.5,
        "attack_sequence": [
            "CONNECT with clean_session=0",
            "PUBLISH to target/topic with retain=1",
            "DISCONNECT",
            "New client subscribes to target/topic",
            "Observe: new client receives attacker's retained message",
        ],
        "detection": "New subscriber receives retained message from unexpected source",
    },
    "V3_CLIENTID_HIJACKING": {
        "name": "ClientID-Based Session Hijacking",
        "source": "Burglars' IoT Paradise §V.C",
        "description": (
            "If a broker does not enforce unique ClientIDs or authentication, "
            "an attacker can connect with a victim's ClientID. The broker "
            "disconnects the legitimate client and gives the attacker its session, "
            "including any queued QoS 1/2 messages and subscriptions."
        ),
        "cvss_estimate": 8.1,
        "attack_sequence": [
            "Victim CONNECTs with ClientID='victim_device_001', clean_session=0",
            "Victim subscribes to 'commands/#' and goes idle",
            "Attacker CONNECTs with same ClientID='victim_device_001'",
            "Broker disconnects victim",
            "Observe: attacker receives victim's queued messages and subscriptions",
        ],
        "detection": "Legitimate client gets disconnected; attacker receives its session data",
    },
    "V4_TOPIC_AUTH_BYPASS": {
        "name": "Topic Authorization Bypass via Wildcards",
        "source": "MQTTactic §4.2 + Burglars §V.D",
        "description": (
            "Brokers that implement ACLs may fail to properly validate wildcard "
            "topic filters. An attacker subscribes with '#' or '+' wildcards to "
            "receive messages from topics they should not have access to."
        ),
        "cvss_estimate": 7.2,
        "attack_sequence": [
            "CONNECT as unauthorized client",
            "SUBSCRIBE to '#' (global wildcard)",
            "Observe SUBACK - check granted QoS",
            "Monitor: if messages arrive from restricted topics, bypass confirmed",
        ],
        "detection": "Messages from restricted topics arrive on wildcard subscription",
    },
    "V5_QOS2_TIMING": {
        "name": "QoS 2 Duplicate Message Injection",
        "source": "FUME §3.3 + MQTTactic §4.3",
        "description": (
            "QoS 2 uses a 4-step handshake: PUBLISH→PUBREC→PUBREL→PUBCOMP. "
            "If a broker incorrectly handles duplicate PUBLISH packets with the "
            "same packet ID before the handshake completes, an attacker can "
            "inject duplicate messages or exhaust broker state."
        ),
        "cvss_estimate": 5.3,
        "attack_sequence": [
            "CONNECT",
            "PUBLISH (QoS=2, packet_id=1)",
            "Receive PUBREC",
            "Send PUBLISH again (QoS=2, packet_id=1, dup=1) before PUBREL",
            "Observe: broker behavior - duplicate storage, error, or crash",
        ],
        "detection": "Duplicate message stored, state machine violation, or crash",
    },
    "V6_SYS_TOPIC_EXPOSURE": {
        "name": "$SYS Topic Information Disclosure",
        "source": "Burglars' IoT Paradise §V.E",
        "description": (
            "The $SYS topic hierarchy exposes broker internals (client count, "
            "version, uptime, connected clients). If accessible without auth, "
            "attackers can enumerate the broker's state for reconnaissance."
        ),
        "cvss_estimate": 4.3,
        "attack_sequence": [
            "CONNECT without credentials",
            "SUBSCRIBE to '$SYS/#'",
            "Observe: broker publishes system statistics",
        ],
        "detection": "Broker publishes $SYS data to unauthenticated subscriber",
    },
    "V7_ZERO_LENGTH_CLIENTID": {
        "name": "Zero-Length ClientID Clean Session Bypass",
        "source": "MQTT 3.1.1 §3.1.3.1",
        "description": (
            "The spec mandates that a zero-length ClientID is only valid with "
            "clean_session=1. Brokers that accept zero-length ClientID with "
            "clean_session=0 violate the spec and may share sessions across clients."
        ),
        "cvss_estimate": 6.0,
        "attack_sequence": [
            "CONNECT with client_id='', clean_session=0",
            "Observe: CONNACK response (should be REFUSED_IDENTIFIER_REJECTED)",
            "If ACCEPTED: broker violation confirmed",
        ],
        "detection": "CONNACK returns 0x00 (accepted) for empty ClientID + persistent session",
    },
    "V8_WILL_DELAY_EXPLOIT": {
        "name": "Will Delay Interval Message Timing Attack (MQTT 5.0)",
        "source": "MQTT 5.0 §3.1.3.2.2",
        "description": (
            "MQTT 5.0 introduces Will Delay Interval. If a client reconnects "
            "before the delay expires, the Will is suppressed. Attackers can "
            "exploit this to send delayed messages or suppress Will messages "
            "from legitimate disconnects."
        ),
        "cvss_estimate": 5.0,
        "attack_sequence": [
            "CONNECT (MQTT 5.0) with will_delay_interval=30",
            "Force disconnect before delay expires",
            "Reconnect with same ClientID before 30s",
            "Observe: Will message suppressed",
        ],
        "detection": "Expected Will message never published due to reconnect race",
    },
}


# ─────────────────────────────────────────────────────────────
# Broker Response Anomaly Signatures (from FUME feedback model)
# ─────────────────────────────────────────────────────────────
ANOMALY_SIGNATURES = {
    "crash": {
        "pattern": "connection_refused|connection_reset|EOF",
        "severity": "CRITICAL",
        "description": "Broker process crashed or became unavailable",
    },
    "unexpected_disconnect": {
        "pattern": "DISCONNECT received unexpectedly",
        "severity": "HIGH",
        "description": "Broker disconnected without error code",
    },
    "malformed_connack": {
        "pattern": "return_code > 5",
        "severity": "HIGH",
        "description": "CONNACK return code outside valid range",
    },
    "wrong_state_transition": {
        "pattern": "PUBLISH received before CONNACK",
        "severity": "MEDIUM",
        "description": "Broker accepted packet in wrong state",
    },
    "spec_violation_empty_clientid": {
        "pattern": "CONNACK=0x00 with empty clientID and clean_session=0",
        "severity": "HIGH",
        "description": "Spec violation: broker accepted invalid connection",
    },
    "timeout": {
        "pattern": "no_response_within_timeout",
        "severity": "MEDIUM",
        "description": "Broker did not respond within expected window",
    },
}
