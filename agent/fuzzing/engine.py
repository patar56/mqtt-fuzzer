"""
MQTT Fuzzing Engine
Inspired by FUME (Fuzzing Message Queuing Telemetry Transport Brokers)

Combines:
  1. Generation-based fuzzing: create packets from scratch using FSM knowledge
  2. Mutation-based fuzzing: mutate valid packets (boundary values, bit flips, etc.)
  3. Markov chain state tracking: track broker state transitions for stateful fuzzing
  4. Response feedback: use broker responses to guide next test case selection

FUME (2022) found 6 zero-day vulnerabilities with this approach.
"""

import random
import struct
import logging
import itertools
from enum import Enum, auto
from typing import List, Optional, Dict, Tuple, Iterator
from dataclasses import dataclass, field

from agent.broker.connector import (
    RawMQTTConnection,
    build_connect, build_publish, build_subscribe,
    build_pubrel, build_pubcomp, build_pingreq, build_disconnect,
    build_raw_packet, MQTTResponse, parse_response,
)
from agent.spec.mqtt_spec import PacketType, QoSLevel, BrokerState, MQTT_PACKET_SPECS

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Markov Chain State Tracker (FUME §4.1)
# ─────────────────────────────────────────────────────────────

class StateTracker:
    """
    Tracks MQTT session state transitions using a Markov-inspired model.
    New states discovered by unexpected responses get higher exploration weight.
    """

    def __init__(self):
        self.current_state = BrokerState.DISCONNECTED
        self.transition_counts: Dict[Tuple[BrokerState, int], int] = {}
        self.new_state_bonus: Dict[BrokerState, float] = {}
        self._history: List[Tuple[BrokerState, int, BrokerState]] = []

    def transition(self, sent_packet_type: int, response: Optional[MQTTResponse]) -> BrokerState:
        """Update state based on what we sent and what broker responded."""
        old_state = self.current_state
        new_state = self._infer_state(sent_packet_type, response)

        key = (old_state, sent_packet_type)
        self.transition_counts[key] = self.transition_counts.get(key, 0) + 1

        # If this is a new state, give it a bonus weight (encourages exploration)
        if new_state not in [t[2] for t in self._history]:
            self.new_state_bonus[new_state] = 2.0

        self._history.append((old_state, sent_packet_type, new_state))
        self.current_state = new_state
        logger.debug(f"State: {old_state.name} --[{PacketType(sent_packet_type).name if sent_packet_type in [p.value for p in PacketType] else sent_packet_type}]--> {new_state.name}")
        return new_state

    def _infer_state(self, sent_type: int, response: Optional[MQTTResponse]) -> BrokerState:
        """Infer the new broker state from the response."""
        if response is None:
            return BrokerState.DISCONNECTED

        resp_type = response.packet_type

        if sent_type == PacketType.CONNECT:
            if resp_type == PacketType.CONNACK:
                if response.connack_return_code == 0:
                    return BrokerState.CONNECTED
                else:
                    return BrokerState.DISCONNECTED
        elif sent_type == PacketType.SUBSCRIBE:
            if resp_type == PacketType.SUBACK:
                return BrokerState.SUBSCRIBED
        elif sent_type == PacketType.PUBLISH:
            qos = (response.flags >> 1) & 0x03 if response else 0
            if qos == 2 and resp_type == PacketType.PUBREC:
                return BrokerState.QOS2_PUBREC
            return BrokerState.CONNECTED
        elif sent_type == PacketType.PUBREL:
            if resp_type == PacketType.PUBCOMP:
                return BrokerState.CONNECTED
        elif sent_type == PacketType.DISCONNECT:
            return BrokerState.DISCONNECTED
        elif sent_type == PacketType.PINGREQ:
            if resp_type == PacketType.PINGRESP:
                return self.current_state

        return self.current_state

    def reset(self):
        self.current_state = BrokerState.DISCONNECTED


# ─────────────────────────────────────────────────────────────
# Test Case
# ─────────────────────────────────────────────────────────────

@dataclass
class TestCase:
    """A single fuzzing test case — one or more packets to send."""
    name: str
    packets: List[bytes]
    description: str = ""
    vulnerability_class: Optional[str] = None
    expected_anomaly: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class FuzzResult:
    """Result of executing a test case."""
    test_case: TestCase
    responses: List[Optional[MQTTResponse]]
    anomaly_detected: bool = False
    anomaly_type: Optional[str] = None
    anomaly_description: str = ""
    broker_alive: bool = True
    raw_log: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"Test: {self.test_case.name}"]
        lines.append(f"  Anomaly: {'YES - ' + self.anomaly_type if self.anomaly_detected else 'None'}")
        lines.append(f"  Broker alive: {self.broker_alive}")
        for i, (pkt, resp) in enumerate(zip(self.test_case.packets, self.responses)):
            resp_str = repr(resp) if resp else "NO RESPONSE"
            lines.append(f"  [{i}] sent {len(pkt)}B -> {resp_str}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Generation-Based Fuzzer (creates packets from FSM knowledge)
# ─────────────────────────────────────────────────────────────

class GenerationFuzzer:
    """
    Generate test cases from scratch using protocol knowledge.
    Targets boundary values, invalid states, and known vulnerability patterns.
    """

    # Boundary values for various fields
    CLIENT_IDS = [
        "",                   # Empty (spec violation with clean_session=0)
        "a",                  # Minimum length
        "A" * 23,             # Recommended max
        "A" * 24,             # Over recommended max
        "A" * 65535,          # Absolute max (2-byte length field)
        "client id spaces",   # Spaces in ClientID
        "client\x00null",     # Null byte injection
        "client\nline",       # Newline injection
        "../../../etc/passwd",# Path traversal attempt
        "❤️🔥💀",            # Unicode/emoji
        "a" * 1024,           # Large ClientID
    ]

    TOPICS = [
        "test/fuzz",
        "#",                  # Global wildcard (invalid in PUBLISH)
        "+",                  # Single wildcard (invalid in PUBLISH)
        "$SYS/test",          # System topic namespace
        "$SYS/broker/clients/connected",
        "",                   # Empty topic (invalid)
        "a" * 65535,          # Maximum topic length
        "a/b/c/d/e/f/g/h",   # Deep nesting
        "topic\x00null",      # Null injection
        "/leading/slash",     # Leading slash
        "trailing/slash/",    # Trailing slash
        "a" * 32767 + "/" + "b" * 32767,  # Very deep topic
    ]

    PAYLOADS = [
        b"",                  # Empty payload
        b"\x00",              # Null byte
        b"\xFF" * 256,        # All 0xFF
        b"A" * 1024,          # 1KB
        b"A" * 65535,         # 64KB
        b"\x00\x01\x02\x03", # Binary
        b"SELECT * FROM users",  # SQL injection
        b"<script>alert(1)</script>",  # XSS
        b"\xef\xbf\xbd",      # UTF-8 replacement char
        bytes(range(256)),    # All byte values
    ]

    def generate_connect_variants(self) -> Iterator[TestCase]:
        """Generate CONNECT packet variants targeting known vulnerabilities."""

        # 1. Zero-length ClientID with persistent session (spec violation test V7)
        yield TestCase(
            name="connect_empty_clientid_persistent",
            packets=[build_connect(client_id="", clean_session=False)],
            description="Zero-length ClientID with clean_session=0 — should be REFUSED (spec §3.1.3.1)",
            vulnerability_class="V7_ZERO_LENGTH_CLIENTID",
            expected_anomaly="CONNACK return code should be 0x02 (Identifier Rejected)",
        )

        # 2. Duplicate ClientID session hijacking (V3)
        yield TestCase(
            name="connect_duplicate_clientid",
            packets=[
                build_connect(client_id="victim_device_001", clean_session=False),
                # Second connect with same ID happens in a separate connection (see vuln module)
            ],
            description="First connection with persistent session — used as baseline for hijacking test",
            vulnerability_class="V3_CLIENTID_HIJACKING",
        )

        # 3. Invalid protocol version
        for version in [0x00, 0x03, 0x06, 0x7F, 0xFF]:
            yield TestCase(
                name=f"connect_invalid_protocol_version_{version:#04x}",
                packets=[build_connect(protocol_level=version)],
                description=f"Invalid protocol version byte 0x{version:02X} — should be REFUSED (0x01)",
                expected_anomaly="CONNACK return code 0x01 (Unacceptable Protocol Version)",
            )

        # 4. Invalid protocol name
        for proto_name in [b"mqtt", b"MQTT5", b"MQIsdp", b"", b"\x00" * 4, b"MQTT\x00"]:
            safe_name = proto_name.hex() if not proto_name.isascii() else proto_name.decode()
            yield TestCase(
                name=f"connect_invalid_protocol_name_{safe_name[:20]}",
                packets=[build_connect(protocol_name=proto_name)],
                description=f"Invalid protocol name {proto_name!r}",
            )

        # 5. Malformed ClientID variants
        for cid in self.CLIENT_IDS[:6]:
            yield TestCase(
                name=f"connect_clientid_{repr(cid)[:30]}",
                packets=[build_connect(client_id=cid)],
                description=f"ClientID boundary test: {repr(cid)[:50]}",
            )

        # 6. Will message targeting system topics (V1)
        for sys_topic in ["$SYS/broker/clients/connected", "$SYS/#", "$SYS/test"]:
            yield TestCase(
                name=f"connect_will_sys_topic_{sys_topic.replace('/', '_')}",
                packets=[build_connect(
                    will_topic=sys_topic,
                    will_message=b"attacker_will",
                    will_qos=0,
                    will_retain=False,
                )],
                description=f"Will message targeting system topic {sys_topic}",
                vulnerability_class="V1_UNAUTHORIZED_WILL",
                expected_anomaly="Broker should reject or silently ignore Will to $SYS topics",
            )

    def generate_publish_variants(self) -> Iterator[TestCase]:
        """Generate PUBLISH packet variants."""

        # 1. Publish without connecting first (protocol violation)
        yield TestCase(
            name="publish_before_connect",
            packets=[build_publish("test/topic", b"unauthorized")],
            description="PUBLISH without prior CONNECT — broker should drop/disconnect",
            expected_anomaly="Broker should close connection without sending response",
        )

        # 2. Wildcard topics in PUBLISH (invalid per spec)
        for topic in ["#", "+", "a/+/b", "a/#"]:
            yield TestCase(
                name=f"publish_wildcard_topic_{topic.replace('/', '_').replace('#', 'hash').replace('+', 'plus')}",
                packets=[
                    build_connect(),
                    build_publish(topic, b"wildcard_payload"),
                ],
                description=f"PUBLISH to wildcard topic '{topic}' — invalid, should be rejected",
                expected_anomaly="Broker should disconnect client for invalid topic",
            )

        # 3. QoS 2 duplicate injection (V5)
        yield TestCase(
            name="qos2_duplicate_publish",
            packets=[
                build_connect(),
                build_publish("test/qos2", b"first", qos=2, packet_id=1),
                # Wait for PUBREC — handled in engine
                build_publish("test/qos2", b"duplicate", qos=2, packet_id=1, dup=True),
            ],
            description="QoS 2 duplicate PUBLISH with same packet_id before handshake completes",
            vulnerability_class="V5_QOS2_TIMING",
            expected_anomaly="Broker may store duplicate, ignore, or crash",
        )

        # 4. Retained message poisoning (V2)
        for topic in ["home/devices/thermostat", "alerts/all", "commands/all"]:
            yield TestCase(
                name=f"retain_poison_{topic.replace('/', '_')}",
                packets=[
                    build_connect(),
                    build_publish(topic, b"ATTACKER_RETAINED", retain=True),
                ],
                description=f"Retained message poisoning on topic {topic}",
                vulnerability_class="V2_UNAUTHORIZED_RETAIN",
            )

        # 5. $SYS topic PUBLISH (should be read-only)
        for sys_topic in ["$SYS/test", "$SYS/broker/version", "$SYS/broker/clients/connected"]:
            yield TestCase(
                name=f"publish_sys_topic_{sys_topic.replace('/', '_').replace('$', 'dollar')}",
                packets=[
                    build_connect(),
                    build_publish(sys_topic, b"sys_injection"),
                ],
                description=f"Attempt to PUBLISH to read-only $SYS topic: {sys_topic}",
                expected_anomaly="Broker should silently ignore or disconnect",
            )

        # 6. Payload boundary tests
        for i, payload in enumerate(self.PAYLOADS):
            if len(payload) < 1000:  # Skip enormous ones for now
                yield TestCase(
                    name=f"publish_payload_boundary_{i}",
                    packets=[
                        build_connect(),
                        build_publish("fuzz/payload", payload),
                    ],
                    description=f"Payload boundary test: {repr(payload[:30])}",
                )

    def generate_subscribe_variants(self) -> Iterator[TestCase]:
        """Generate SUBSCRIBE packet variants."""

        # 1. Global wildcard subscription (V4 — topic auth bypass)
        yield TestCase(
            name="subscribe_global_wildcard",
            packets=[
                build_connect(),
                build_subscribe("#"),
            ],
            description="Subscribe to '#' — global wildcard, may expose all messages",
            vulnerability_class="V4_TOPIC_AUTH_BYPASS",
            expected_anomaly="Should be rejected or return QoS 0x80 (failure) without ACL",
        )

        # 2. $SYS topic subscription (V6 — info disclosure)
        yield TestCase(
            name="subscribe_sys_wildcard",
            packets=[
                build_connect(),
                build_subscribe("$SYS/#"),
            ],
            description="Subscribe to $SYS/# — exposes broker internals to unauthenticated client",
            vulnerability_class="V6_SYS_TOPIC_EXPOSURE",
            expected_anomaly="Unauthenticated client should not receive $SYS data",
        )

        # 3. Invalid topic filters
        for tf in ["a/#/b", "#a", "a#", "+"]:
            yield TestCase(
                name=f"subscribe_invalid_filter_{tf.replace('/', '_').replace('#', 'hash').replace('+', 'plus')}",
                packets=[
                    build_connect(),
                    build_subscribe(tf),
                ],
                description=f"Invalid topic filter '{tf}' — broker should reject",
            )

        # 4. QoS boundary in SUBSCRIBE
        for qos in [0, 1, 2, 3, 127, 128, 255]:
            yield TestCase(
                name=f"subscribe_qos_{qos}",
                packets=[
                    build_connect(),
                    build_subscribe("test/topic", requested_qos=qos),
                ],
                description=f"SUBSCRIBE with QoS={qos} (values >2 are invalid)",
            )

    def generate_malformed_packets(self) -> Iterator[TestCase]:
        """Generate intentionally malformed raw packets."""

        # Zero-length remaining length with each packet type
        for ptype in range(1, 16):
            yield TestCase(
                name=f"malformed_zero_remaining_{ptype}",
                packets=[
                    build_connect(),
                    bytes([ptype << 4, 0x00]),  # Packet type with 0 remaining length
                ],
                description=f"Packet type {ptype} with 0 remaining length",
            )

        # Invalid fixed header flags
        for flags in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]:
            yield TestCase(
                name=f"malformed_publish_flags_{flags:#04x}",
                packets=[
                    build_connect(),
                    build_raw_packet(PacketType.PUBLISH, flags, b"test"),
                ],
                description=f"PUBLISH with invalid fixed header flags={flags:#04x}",
            )

        # Truncated packets
        for pkt_builder, name in [
            (build_connect(), "connect"),
            (build_subscribe("test"), "subscribe"),
        ]:
            for trunc in [1, 2, 4, len(pkt_builder) // 2]:
                if trunc < len(pkt_builder):
                    yield TestCase(
                        name=f"truncated_{name}_{trunc}bytes",
                        packets=[pkt_builder[:trunc]],
                        description=f"Truncated {name} packet at {trunc} bytes",
                    )

    def all_test_cases(self) -> Iterator[TestCase]:
        """Yield all generation-based test cases."""
        yield from self.generate_connect_variants()
        yield from self.generate_publish_variants()
        yield from self.generate_subscribe_variants()
        yield from self.generate_malformed_packets()


# ─────────────────────────────────────────────────────────────
# Mutation-Based Fuzzer (mutates valid packets)
# ─────────────────────────────────────────────────────────────

class MutationFuzzer:
    """Mutate valid MQTT packets to find parsing bugs."""

    SEEDS = {
        "valid_connect": build_connect("seed_client"),
        "valid_subscribe": build_connect("seed_client") + build_subscribe("test/topic"),
        "valid_publish_qos0": build_connect("seed_client") + build_publish("test/topic", b"hello"),
        "valid_publish_qos1": build_connect("seed_client") + build_publish("test/topic", b"hello", qos=1, packet_id=1),
    }

    def __init__(self, seed_extra: Optional[List[bytes]] = None):
        if seed_extra:
            for i, s in enumerate(seed_extra):
                self.SEEDS[f"extra_{i}"] = s
        self._rng = random.Random(42)

    def _bit_flip(self, data: bytes, n_flips: int = 1) -> bytes:
        arr = bytearray(data)
        for _ in range(n_flips):
            if arr:
                idx = self._rng.randint(0, len(arr) - 1)
                arr[idx] ^= (1 << self._rng.randint(0, 7))
        return bytes(arr)

    def _byte_replace(self, data: bytes) -> bytes:
        arr = bytearray(data)
        if arr:
            idx = self._rng.randint(0, len(arr) - 1)
            arr[idx] = self._rng.randint(0, 255)
        return bytes(arr)

    def _boundary_byte(self, data: bytes) -> bytes:
        """Replace a random byte with a boundary value."""
        arr = bytearray(data)
        boundary = self._rng.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
        if arr:
            idx = self._rng.randint(0, len(arr) - 1)
            arr[idx] = boundary
        return bytes(arr)

    def _insert_bytes(self, data: bytes, n: int = 1) -> bytes:
        arr = bytearray(data)
        idx = self._rng.randint(0, len(arr))
        arr[idx:idx] = [self._rng.randint(0, 255) for _ in range(n)]
        return bytes(arr)

    def _delete_bytes(self, data: bytes, n: int = 1) -> bytes:
        arr = bytearray(data)
        if len(arr) > n:
            idx = self._rng.randint(0, len(arr) - n)
            del arr[idx:idx + n]
        return bytes(arr)

    def generate(self, n_per_seed: int = 50) -> Iterator[TestCase]:
        """Generate n_per_seed mutations per seed packet."""
        mutators = [
            ("bit_flip_1", lambda d: self._bit_flip(d, 1)),
            ("bit_flip_4", lambda d: self._bit_flip(d, 4)),
            ("byte_replace", self._byte_replace),
            ("boundary_byte", self._boundary_byte),
            ("insert_1", lambda d: self._insert_bytes(d, 1)),
            ("insert_4", lambda d: self._insert_bytes(d, 4)),
            ("delete_1", lambda d: self._delete_bytes(d, 1)),
            ("delete_4", lambda d: self._delete_bytes(d, 4)),
        ]

        for seed_name, seed_bytes in self.SEEDS.items():
            for i in range(n_per_seed):
                mutator_name, mutator_fn = self._rng.choice(mutators)
                mutated = mutator_fn(seed_bytes)
                yield TestCase(
                    name=f"mutation_{seed_name}_{mutator_name}_{i}",
                    packets=[mutated],
                    description=f"Mutation of '{seed_name}' using {mutator_name}",
                )


# ─────────────────────────────────────────────────────────────
# Main Fuzzing Engine
# ─────────────────────────────────────────────────────────────

class FuzzingEngine:
    """
    Orchestrates generation and mutation fuzzing against a target broker.
    Uses response feedback to detect anomalies (FUME §4.2 approach).
    """

    def __init__(self, host: str = "localhost", port: int = 1883, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.state_tracker = StateTracker()
        self.gen_fuzzer = GenerationFuzzer()
        self.mut_fuzzer = MutationFuzzer()
        self.results: List[FuzzResult] = []

    def _is_broker_alive(self) -> bool:
        """Check if broker is responsive via a clean ping."""
        try:
            with RawMQTTConnection(self.host, self.port, timeout=2.0) as conn:
                resp = conn.mqtt_connect(client_id="liveness_check")
                return resp is not None and resp.connack_return_code == 0
        except Exception:
            return False

    def _detect_anomaly(
        self,
        test_case: TestCase,
        responses: List[Optional[MQTTResponse]],
        broker_alive: bool,
    ) -> Tuple[bool, Optional[str], str]:
        """
        Analyze responses for anomalies.
        Returns: (anomaly_detected, anomaly_type, description)
        """
        if not broker_alive:
            return True, "CRASH", "Broker stopped responding after test case"

        for i, resp in enumerate(responses):
            if resp is None:
                # No response when one was expected
                pkt = test_case.packets[i] if i < len(test_case.packets) else b""
                pkt_type = (pkt[0] >> 4) if pkt else 0
                # CONNECT always expects CONNACK; SUBSCRIBE expects SUBACK
                if pkt_type in (PacketType.CONNECT, PacketType.SUBSCRIBE):
                    return True, "NO_RESPONSE", f"No response to packet type {pkt_type} (index {i})"
                continue

            # Check for invalid CONNACK return codes
            if resp.packet_type == PacketType.CONNACK:
                rc = resp.connack_return_code
                if rc is not None and rc > 5:
                    return True, "INVALID_CONNACK_RC", f"CONNACK return code {rc:#04x} is outside valid range 0x00-0x05"

            # Spec violation: CONNACK 0x00 with empty ClientID and persistent session
            if (
                resp.packet_type == PacketType.CONNACK
                and resp.connack_return_code == 0
                and test_case.vulnerability_class == "V7_ZERO_LENGTH_CLIENTID"
            ):
                return True, "SPEC_VIOLATION_V7", "Broker accepted empty ClientID with clean_session=0 (violates §3.1.3.1)"

            # Unexpected DISCONNECT from broker (when we didn't send one)
            if resp.packet_type == PacketType.DISCONNECT:
                return True, "UNEXPECTED_DISCONNECT", "Broker sent DISCONNECT unexpectedly"

        return False, None, ""

    def run_test_case(self, test_case: TestCase) -> FuzzResult:
        """Execute a single test case and collect results."""
        responses: List[Optional[MQTTResponse]] = []
        raw_log: List[str] = []

        conn = RawMQTTConnection(self.host, self.port, self.timeout)
        try:
            if not conn.connect_tcp():
                return FuzzResult(
                    test_case=test_case,
                    responses=[],
                    anomaly_detected=True,
                    anomaly_type="CONNECTION_FAILED",
                    anomaly_description="Could not establish TCP connection to broker",
                    broker_alive=False,
                )

            for i, pkt in enumerate(test_case.packets):
                raw_log.append(f"SEND[{i}]: {pkt.hex()[:80]}")
                sent = conn.send(pkt)
                if not sent:
                    responses.append(None)
                    raw_log.append(f"RECV[{i}]: SEND_FAILED")
                    break

                pkt_type = (pkt[0] >> 4) & 0x0F if pkt else 0

                # Only wait for response if the packet type warrants one
                expects_response = pkt_type in {
                    PacketType.CONNECT,
                    PacketType.SUBSCRIBE,
                    PacketType.UNSUBSCRIBE,
                    PacketType.PINGREQ,
                }
                qos = (pkt[0] >> 1) & 0x03 if pkt_type == PacketType.PUBLISH else 0
                if qos > 0:
                    expects_response = True

                resp = conn.recv_parsed(timeout=self.timeout) if expects_response else None
                responses.append(resp)
                raw_log.append(f"RECV[{i}]: {repr(resp)}")

                self.state_tracker.transition(pkt_type, resp)

        finally:
            conn.close()

        # Check broker liveness after test
        broker_alive = self._is_broker_alive()

        anomaly, anomaly_type, anomaly_desc = self._detect_anomaly(test_case, responses, broker_alive)

        result = FuzzResult(
            test_case=test_case,
            responses=responses,
            anomaly_detected=anomaly,
            anomaly_type=anomaly_type,
            anomaly_description=anomaly_desc,
            broker_alive=broker_alive,
            raw_log=raw_log,
        )

        if anomaly:
            logger.warning(f"ANOMALY [{anomaly_type}]: {test_case.name}")
            logger.warning(f"  {anomaly_desc}")

        self.results.append(result)
        return result

    def run_generation_campaign(self, max_cases: Optional[int] = None) -> List[FuzzResult]:
        """Run all generation-based test cases."""
        logger.info("Starting generation-based fuzzing campaign...")
        results = []
        for i, tc in enumerate(self.gen_fuzzer.all_test_cases()):
            if max_cases and i >= max_cases:
                break
            result = self.run_test_case(tc)
            results.append(result)
            if not result.broker_alive:
                logger.critical("BROKER CRASHED! Stopping campaign.")
                break
        return results

    def run_mutation_campaign(self, n_per_seed: int = 50) -> List[FuzzResult]:
        """Run mutation-based fuzzing campaign."""
        logger.info("Starting mutation-based fuzzing campaign...")
        results = []
        for tc in self.mut_fuzzer.generate(n_per_seed):
            result = self.run_test_case(tc)
            results.append(result)
            if not result.broker_alive:
                logger.critical("BROKER CRASHED! Stopping mutation campaign.")
                break
        return results

    def get_anomalies(self) -> List[FuzzResult]:
        """Return only results with detected anomalies."""
        return [r for r in self.results if r.anomaly_detected]

    def summary_stats(self) -> Dict:
        """Return summary statistics for the campaign."""
        total = len(self.results)
        anomalies = len(self.get_anomalies())
        crashes = sum(1 for r in self.results if not r.broker_alive)
        by_type: Dict[str, int] = {}
        for r in self.get_anomalies():
            by_type[r.anomaly_type or "UNKNOWN"] = by_type.get(r.anomaly_type or "UNKNOWN", 0) + 1
        return {
            "total_tests": total,
            "anomalies": anomalies,
            "anomaly_rate": f"{anomalies/max(total,1)*100:.1f}%",
            "crashes": crashes,
            "anomaly_types": by_type,
        }
