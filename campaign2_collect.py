"""
Campaign 2 — Data collection script.
Runs the fuzzer, collects detailed results, and writes JSON.
"""
import sys, os, json, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from campaign2_fuzzer import run_all, broker_alive, results
from agent.broker.connector import (
    RawMQTTConnection, build_connect, build_publish, build_subscribe,
    build_pingreq, MQTTResponse,
)
from agent.spec.mqtt_spec import PacketType

def serialize_result(r):
    return {
        "name": r.name,
        "category": r.category,
        "description": r.description,
        "vulnerability_class": r.vulnerability_class,
        "packets_sent": r.packets_sent,
        "responses": r.responses,
        "anomaly": r.anomaly,
        "anomaly_type": r.anomaly_type,
        "anomaly_detail": r.anomaly_detail,
        "broker_alive": r.broker_alive,
        "timing_ms": r.timing_ms,
        "metadata": r.metadata,
    }


def run_additional_targeted():
    """Run a few extra targeted tests not in the main fuzzer to fill detail."""
    extras = []

    # Extra: Confirm retained message poisoning explicitly
    try:
        poison_topic = "fuzz/poison_c2"
        poison_payload = b"CAMPAIGN2_ATTACKER_RETAINED_" + b"A" * 50

        pub = RawMQTTConnection("localhost", 1883, 3.0)
        pub.connect_tcp()
        pub.send(build_connect(client_id="c2_poison_pub", clean_session=True))
        pub.recv_parsed(timeout=3.0)
        pub.send(build_publish(poison_topic, poison_payload, retain=True))
        time.sleep(0.2)
        pub.close()

        # New subscriber gets poisoned message
        sub = RawMQTTConnection("localhost", 1883, 3.0)
        sub.connect_tcp()
        sub.send(build_connect(client_id="c2_poison_sub", clean_session=True))
        sub.recv_parsed(timeout=3.0)
        sub.send(build_subscribe(poison_topic, packet_id=1))
        sub.recv_parsed(timeout=3.0)
        msg = sub.recv_parsed(timeout=2.0)
        sub.close()

        delivered = msg is not None and msg.packet_type == PacketType.PUBLISH
        extras.append({
            "name": "targeted_retain_poison_confirm",
            "category": "TARGETED",
            "description": "Explicit retained message poisoning: attacker publishes, later subscriber receives",
            "vulnerability_class": "V2_UNAUTHORIZED_RETAIN",
            "packets_sent": 3,
            "responses": [repr(msg)],
            "anomaly": delivered,
            "anomaly_type": "RETAIN_POISON_DELIVERED" if delivered else "",
            "anomaly_detail": f"Poisoned payload delivered to new subscriber: {poison_payload[:40]}" if delivered else "",
            "broker_alive": broker_alive(),
            "timing_ms": 0,
            "metadata": {"poison_topic": poison_topic, "payload_size": len(poison_payload)},
        })
    except Exception as e:
        extras.append({"name": "targeted_retain_poison_confirm", "anomaly": True,
                        "anomaly_type": "EXCEPTION", "anomaly_detail": str(e), "broker_alive": broker_alive()})

    # Extra: Confirm V3 session hijacking explicitly
    try:
        victim_id = "c2_victim_789"
        secret_topic = "device/c2/secrets"

        # Step 1: victim connects with persistent session
        victim = RawMQTTConnection("localhost", 1883, 3.0)
        victim.connect_tcp()
        victim.send(build_connect(client_id=victim_id, clean_session=False))
        v_connack = victim.recv_parsed(timeout=3.0)
        victim.send(build_subscribe(secret_topic, packet_id=1, requested_qos=1))
        victim.recv_parsed(timeout=3.0)

        # Step 2: publisher sends queued message
        pub = RawMQTTConnection("localhost", 1883, 3.0)
        pub.connect_tcp()
        pub.send(build_connect(client_id="c2_publisher"))
        pub.recv_parsed(timeout=3.0)
        pub.send(build_publish(secret_topic, b"SECRET_MSG_FOR_VICTIM_C2", qos=1, packet_id=5))
        pub.recv_parsed(timeout=3.0)
        pub.close()

        # Victim goes offline (abrupt TCP close — session persists)
        victim.close()
        time.sleep(0.2)

        # Step 3: attacker reconnects with victim's ClientID
        atk = RawMQTTConnection("localhost", 1883, 3.0)
        atk.connect_tcp()
        atk.send(build_connect(client_id=victim_id, clean_session=False))
        a_connack = atk.recv_parsed(timeout=3.0)
        session_present = a_connack.connack_session_present if a_connack else None

        # Wait for queued message to arrive
        time.sleep(0.3)
        queued = atk.recv_parsed(timeout=2.0)
        atk.close()

        hijacked = session_present == True
        got_msg = queued is not None and queued.packet_type == PacketType.PUBLISH
        extras.append({
            "name": "targeted_session_hijack_confirm",
            "category": "TARGETED",
            "description": "Explicit ClientID session hijacking: attacker steals persistent session and queued messages",
            "vulnerability_class": "V3_CLIENTID_HIJACKING",
            "packets_sent": 4,
            "responses": [repr(a_connack), repr(queued)],
            "anomaly": hijacked or got_msg,
            "anomaly_type": "SESSION_HIJACK" if hijacked else ("QUEUED_MSG_STOLEN" if got_msg else ""),
            "anomaly_detail": f"session_present={session_present}, queued_msg_received={got_msg}",
            "broker_alive": broker_alive(),
            "timing_ms": 0,
            "metadata": {"victim_id": victim_id, "session_hijacked": hijacked, "queued_msg_received": got_msg},
        })
    except Exception as e:
        extras.append({"name": "targeted_session_hijack_confirm", "anomaly": True,
                        "anomaly_type": "EXCEPTION", "anomaly_detail": str(e), "broker_alive": broker_alive()})

    # Extra: Confirm V7 zero-length ClientID
    try:
        conn = RawMQTTConnection("localhost", 1883, 3.0)
        conn.connect_tcp()
        conn.send(build_connect(client_id="", clean_session=False))
        resp = conn.recv_parsed(timeout=3.0)
        conn.close()
        rc = resp.connack_return_code if resp else None
        accepted = rc == 0
        extras.append({
            "name": "targeted_zero_clientid_persistent",
            "category": "TARGETED",
            "description": "Zero-length ClientID with persistent session — MQTT 3.1.1 §3.1.3.1 MUST reject",
            "vulnerability_class": "V7_ZERO_LENGTH_CLIENTID",
            "packets_sent": 1,
            "responses": [repr(resp)],
            "anomaly": accepted,
            "anomaly_type": "SPEC_VIOLATION" if accepted else "CORRECTLY_REJECTED",
            "anomaly_detail": f"CONNACK RC={rc:#04x} — {'ACCEPTED (spec violation)' if accepted else 'correctly rejected'}",
            "broker_alive": broker_alive(),
            "timing_ms": 0,
            "metadata": {"connack_rc": rc, "spec_says": "MUST reject with 0x02"},
        })
    except Exception as e:
        extras.append({"name": "targeted_zero_clientid_persistent", "anomaly": True,
                        "anomaly_type": "EXCEPTION", "anomaly_detail": str(e), "broker_alive": broker_alive()})

    # Extra: Confirm V7 zero-length ClientID with clean session (should accept)
    try:
        conn = RawMQTTConnection("localhost", 1883, 3.0)
        conn.connect_tcp()
        conn.send(build_connect(client_id="", clean_session=True))
        resp = conn.recv_parsed(timeout=3.0)
        conn.close()
        rc = resp.connack_return_code if resp else None
        extras.append({
            "name": "targeted_zero_clientid_clean",
            "category": "TARGETED",
            "description": "Zero-length ClientID with clean session — should be accepted per spec",
            "vulnerability_class": "V7_ZERO_LENGTH_CLIENTID",
            "packets_sent": 1,
            "responses": [repr(resp)],
            "anomaly": False,
            "anomaly_type": "",
            "anomaly_detail": f"CONNACK RC={rc} — {'accepted as expected' if rc == 0 else 'rejected'}",
            "broker_alive": broker_alive(),
            "timing_ms": 0,
            "metadata": {"connack_rc": rc},
        })
    except Exception as e:
        extras.append({"name": "targeted_zero_clientid_clean", "anomaly": False,
                        "anomaly_type": "", "anomaly_detail": str(e), "broker_alive": broker_alive()})

    # Extra: $SYS topic version disclosure
    try:
        import struct
        conn = RawMQTTConnection("localhost", 1883, 3.0)
        conn.connect_tcp()
        conn.send(build_connect(client_id="c2_sys_ver"))
        conn.recv_parsed(timeout=3.0)
        conn.send(build_subscribe("$SYS/broker/version", packet_id=1))
        conn.recv_parsed(timeout=3.0)
        msg = conn.recv_parsed(timeout=3.0)
        version = ""
        if msg and msg.packet_type == PacketType.PUBLISH:
            tlen = struct.unpack("!H", msg.payload[:2])[0]
            version = msg.payload[2+tlen:].decode("utf-8", errors="replace")
        conn.close()
        extras.append({
            "name": "targeted_sys_version_disclosure",
            "category": "TARGETED",
            "description": "$SYS/broker/version exposes exact broker version string to unauthenticated client",
            "vulnerability_class": "V6_SYS_TOPIC_EXPOSURE",
            "packets_sent": 2,
            "responses": [repr(msg)],
            "anomaly": bool(version),
            "anomaly_type": "VERSION_DISCLOSURE" if version else "",
            "anomaly_detail": f"Version disclosed: '{version}'" if version else "No version received",
            "broker_alive": broker_alive(),
            "timing_ms": 0,
            "metadata": {"broker_version": version},
        })
    except Exception as e:
        extras.append({"name": "targeted_sys_version_disclosure", "anomaly": True,
                        "anomaly_type": "EXCEPTION", "anomaly_detail": str(e), "broker_alive": broker_alive()})

    return extras


if __name__ == "__main__":
    # Run main campaign
    run_all()

    # Run targeted extras
    print("\nRunning targeted confirmation tests...")
    extras = run_additional_targeted()
    print(f"Extras: {len(extras)} tests")

    # Combine all results
    all_results = [serialize_result(r) for r in results] + extras

    # Compute statistics
    total = len(all_results)
    anomalies = sum(1 for r in all_results if r.get("anomaly"))
    categories = {}
    for r in all_results:
        cat = r.get("category", "UNKNOWN")
        categories[cat] = categories.get(cat, 0) + 1

    anomaly_types = {}
    for r in all_results:
        at = r.get("anomaly_type", "")
        if at:
            anomaly_types[at] = anomaly_types.get(at, 0) + 1

    output = {
        "campaign_metadata": {
            "campaign": "Campaign 2",
            "date": "2026-05-05",
            "broker": "Eclipse Mosquitto 2.0.18",
            "broker_container": "mqtt_target_broker",
            "broker_port": 1883,
            "broker_config": "permissive (allow_anonymous=true, no ACL, retained_persistence=true)",
            "protocol_scope": "MQTT 3.1.1 + MQTT 5.0",
            "tool": "MQTT Security Agent Campaign 2 (extended Python fuzzer)",
            "categories_tested": list(categories.keys()),
        },
        "statistics": {
            "total_tests": total,
            "anomalies_detected": anomalies,
            "anomaly_rate": f"{anomalies/max(total,1)*100:.1f}%",
            "broker_alive_at_end": broker_alive(),
            "tests_by_category": categories,
            "anomaly_types": anomaly_types,
        },
        "test_results": all_results,
    }

    out_path = "/Users/patrickargento/Documents/Masters/IOT Security/Final Project/mqtt-security-agent/reports/fuzzing_raw_results_campaign2.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults written to: {out_path}")
    print(f"Total: {total} tests, {anomalies} anomalies ({anomalies/max(total,1)*100:.1f}%)")
    print(f"Anomaly types: {anomaly_types}")
