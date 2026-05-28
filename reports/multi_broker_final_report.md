# Final Multi-Broker Comparison Report

**UCLA ECE 202C — IoT Security Final Project — Patrick Argento — 2026-05-09**

This report consolidates cross-broker findings from all four campaigns
into a single comparison matrix and per-broker risk rating.

---

## 1. Master Comparison Matrix

Legend: VULN (vulnerable), DENY (correctly rejects), N/A (feature absent).

| ID  | Class                              | Mosquitto 2.0.18 | EMQX 5.0.0 | NanoMQ | HiveMQ CE 2024.3 |
|-----|------------------------------------|------------------|-------------|--------|------------------|
| V1  | Will-message injection             | VULN             | VULN        | VULN   | VULN             |
| V2  | Retained-message poisoning         | VULN             | VULN        | DENY†  | VULN             |
| V3  | ClientID hijacking                 | VULN             | VULN        | VULN   | VULN             |
| V4  | Anonymous '#' wildcard             | VULN             | DENY        | VULN   | VULN             |
| V6  | $SYS info disclosure               | VULN             | partial     | DENY   | partial          |
| V8  | Anon-creds accept                  | VULN             | VULN        | VULN   | VULN             |
| V9  | Shared-sub namespace abuse         | VULN             | partial     | partial| partial          |
| V10 | QoS PID=0 accepted                 | DENY             | **VULN**    | DENY   | DENY             |
| V11 | Session resource accumulation      | VULN             | VULN        | VULN   | VULN             |
| V17 | Config fingerprinting              | VULN             | VULN        | VULN   | VULN             |
| V18 | Oversized CONNECT silent drop      | VULN             | VULN        | VULN   | VULN             |
| V19 | 500-sub SUBSCRIBE granted          | VULN             | VULN        | VULN   | VULN             |
| V20 | 100k+ PUBLISH/sec (no rate limit)  | VULN             | VULN        | VULN   | VULN             |
| V21 | PINGREQ-only keepalive abuse       | VULN             | VULN        | VULN   | VULN             |
| V22 | QoS 2 sub silent downgrade         | VULN             | partial     | VULN   | VULN             |
| V24 | Overlap-sub amplification          | DENY (1 copy)    | **VULN (3×)** | **VULN (4×)** | DENY (1 copy)    |
| V26 | Null-byte topic accepted           | VULN             | partial     | VULN   | VULN             |
| V27 | Keepalive enforcement gap          | VULN             | DENY        | VULN   | DENY             |
| V28 | Will-self-delivery chain           | VULN             | VULN        | VULN   | VULN             |
| V31 | QoS 2 in-flight session takeover   | VULN             | VULN        | VULN   | VULN             |
| **R1**  | **NanoMQ QoS 2 dedup race**       | DENY             | DENY        | **VULN** | DENY             |
| C1  | Will + Retain chain                | VULN             | VULN        | DENY†  | VULN             |
| C2  | Overlap subscription amplification | DENY             | VULN (3×)   | VULN (4×)| DENY            |
| C3  | 50/50 conn flood accepted          | VULN             | VULN        | VULN   | VULN             |
| V51 | Topic Alias OOB rc divergence      | N/A              | rc=130      | rc=128 | rc=148 (compliant)|
| V52 | SessionExpiry=∞ accepted           | N/A              | VULN        | VULN   | VULN             |
| V53 | UserProperty flood accepted        | N/A              | VULN        | VULN   | VULN             |
| V54 | Dup SubscriptionId accepted        | N/A              | partial     | partial| partial          |

† NanoMQ does not persist retained messages by default. This is a
configuration choice that incidentally neutralizes V2 and C1.
Re-enabling persistence without ACL would re-introduce both.

### Scoring summary

| Broker | Confirmed VULN | Confirmed DENY/partial | Total testable |
|--------|----------------|------------------------|----------------|
| Mosquitto 2.0.18 | 22 | 3 | 25 |
| EMQX 5.0.0 | 21 | 7 (incl. 4 v5) | 28 |
| NanoMQ | 23 (incl. R1) | 4 | 27 |
| HiveMQ CE 2024.3 | 19 | 9 (incl. v5 compliance) | 28 |

---

## 2. Per-Broker Risk Rating

### 2.1 HiveMQ CE 2024.3 — LOWEST RISK
**Strengths**
- Aggressive ClientID-race resolution (M5 — kills victim before CONNACK).
- Correct QoS 2 dedup (R1: 1 copy delivered).
- Correct overlap-sub dedup (C2: 1 copy out of 4 filters).
- Correct §2.3.1 PID=0 rejection (Q5).
- Spec-compliant Topic-Alias-Invalid reason code 0x94 (V51).
- Built-in TLS handling, default keepalive enforcement (R3).

**Weaknesses**
- Default config still permits anonymous + retain + Will, so V1/V2/V3
  attack chain (C1) still works without configuration hardening.
- $SYS topics partially exposed.

**Recommendation:** Apply `config/hivemq_hardening_notes.md` XML
config + RBAC extension. Best choice for security-sensitive IoT
deployments among the four tested.

### 2.2 EMQX 5.0.0 — MEDIUM RISK
**Strengths**
- Built-in default authorization blocks anonymous '#' wildcard
  (M4 — only broker that returns SUBACK rc=128).
- Keepalive enforcement (R3).
- Rich v5 feature support and extensive observability.

**Weaknesses**
- **§2.3.1 violation: PID=0 accepted** in PUBACK/PUBREC/PUBREL/PUBCOMP
  (Q5). This is the worst spec-compliance defect found in any broker.
- Overlap-subscription amplification: 3 copies (C2) — violates §3.3.5.
- v5 feature limits absent by default (V52, V53).
- Default keepalive_backoff is generous (1.25); R3 confirmed.

**Recommendation:** Apply `config/emqx_hardened_final.conf` —
specifically `mqtt.strict_mode = true`, max_user_properties, and
max_session_expiry_interval.

### 2.3 Mosquitto 2.0.18 — HIGH RISK
**Strengths**
- Correct §2.3.1 PID=0 rejection.
- Correct overlap-sub dedup (C2: 1 copy).
- Correct R2 behavior (no in-flight QoS 2 delivery after publisher
  abort).
- Smallest codebase, most-audited — zero crashes across 1,288+ tests.

**Weaknesses**
- Default config accepts anonymous, retain, Will, '#' wildcard, and
  exposes $SYS — every Tier-2 control depends on the user adding ACL.
- Keepalive enforcement gap (R3).
- No native rate limiting (V20 — 104,931 msg/sec; V21 — PINGREQ
  abuse). Network-layer iptables required.
- No MQTT v5 support — clients on mixed networks must downgrade.

**Recommendation:** Apply `config/mosquitto_hardened_final.conf` +
`config/acl_hardened_final.conf` + iptables Tier 4 rules.
Acceptable for production IF and ONLY IF all four tiers are in place.

### 2.4 NanoMQ — HIGH RISK
**Strengths**
- Smallest attack surface (no $SYS by default, no retained-message
  persistence).
- Lightweight footprint suitable for embedded gateways.

**Weaknesses**
- **R1 QoS 2 dedup race** — duplicate delivery under DUP+PUBREL race.
  This is the only Final-campaign finding that is broker-specific
  and represents a likely defect in NanoMQ's exactly-once handling.
- Overlap-sub amplification: 4 copies (C2) — worst of all four
  brokers.
- No keepalive enforcement (R3).
- Limited authorization without explicit ACL config.

**Recommendation:** Apply `config/nanomq_hardened_final.conf`.
Avoid QoS 2 if exactly-once semantics are mission-critical until R1
is patched. Bug report to NanoMQ project recommended.

---

## 3. Universal Findings

The following six findings were confirmed on **all four brokers**
and represent **MQTT design risks**, not implementation defects:

1. **V1 Will-message injection** — Will is a broker-published message
   on behalf of a connected (potentially anonymous) client. Spec
   delegates ACL enforcement to the broker, but DEFAULT configs are
   permissive on every tested broker.
2. **V3 ClientID hijack** — §3.1.4 requires the broker to disconnect
   the existing client when a duplicate ClientID arrives. This is
   exactly what every broker does; the "vulnerability" is that
   without authentication, anyone can do it.
3. **V8 Anon-cred accept** — `allow_anonymous` style configurations
   accept any credential pattern (incl. SQL injection strings, format
   strings, null-byte prefixes) without complaint.
4. **V11 Session resource accumulation** — No broker in default
   config has tight upper bounds on persistent session count or
   queue length.
5. **V19 Subscription count per SUBSCRIBE** — every broker accepted
   500 filters in one packet; no per-packet cap.
6. **V20 PUBLISH-rate flood** — every broker accepts 100k+ msg/sec
   on a single connection without throttle.

These are the findings that the Defense-in-Depth model in
`reports/fuzzing_final_campaign_report.md` § 5 must address; they
cannot be fixed by any single config knob.

---

## 4. Broker-Specific Recommendations

### Mosquitto 2.0.18 — for hardened deployment
```
allow_anonymous false
password_file ...
acl_file ...
max_connections 50
message_size_limit 65536
max_inflight_messages 10
max_queued_messages 20
persistent_client_expiration 1h
sys_interval 0
+ iptables connlimit + hashlimit
```
See `config/mosquitto_hardened_final.conf`.

### EMQX 5.0.0 — for hardened deployment
```
mqtt.strict_mode = true
mqtt.max_packet_size = 64KB
mqtt.max_subscriptions = 20
mqtt.max_session_expiry_interval = 7200s
mqtt.max_user_properties = 16
mqtt.keepalive_backoff = 0.75
listeners.ssl.default.max_conn_rate = 50
listeners.ssl.default.messages_rate = 1000/s,10000/s
authentication = [...]
authorization { sources = [...] }
```
See `config/emqx_hardened_final.conf`.

### NanoMQ — for hardened deployment
```
mqtt.max_packet_size = 64KB
mqtt.max_inflight_window = 10
mqtt.keepalive_multiplier = 1.25
auth.allow_anonymous = false
auth.acl rules with default-deny
```
See `config/nanomq_hardened_final.conf`. Note R1 has no config fix —
patch required.

### HiveMQ CE 2024.3 — for hardened deployment
- XML config: `config.xml` with security, mqtt, restrictions sections.
- Required extensions: file-rbac for ACL, message-log for audit.
- See `config/hivemq_hardening_notes.md`.

---

## 5. Universal Network-Layer Hardening (applies to all 4 brokers)

```
# 10 new TCP connections per second per source
iptables -I INPUT -p tcp --dport 8883 \
  -m connlimit --connlimit-above 10 --connlimit-mask 32 -j REJECT

# 5,000 packets per second per source
iptables -A INPUT -p tcp --dport 8883 \
  -m hashlimit --hashlimit-name mqtt --hashlimit-above 5000/sec \
  --hashlimit-mode srcip -j DROP

# Optional: drop common reconnaissance probes
iptables -A INPUT -p tcp --dport 8883 -m string --string "MQTT" \
  --algo bm --to 100 -m limit --limit 100/min -j ACCEPT
```

---

## 6. Verification

After applying any of the hardened configs, run:

```bash
python3 scripts/verify_mitigations_final.py --broker all
```

Expected on hardened deployments:

```
Summary: 24+ PASS, ≤ 4 FAIL, 0 N/A (of 28 total)
```

Failures in V27/R3 (keepalive granularity) are acceptable for
Mosquitto and NanoMQ because their enforcement is at multi-second
granularity by design.
