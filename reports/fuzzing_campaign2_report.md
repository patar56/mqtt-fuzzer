# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                    CAMPAIGN 2
#      MQTT Broker Security Fuzzing Campaign Report
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Target Broker:** Eclipse Mosquitto 2.0.18  
**Infrastructure:** Docker container `mqtt_target_broker` — `localhost:1883`  
**Configuration:** Permissive (`allow_anonymous true`, no ACL file, `listener 1883`)  
**Assessment Date:** 2026-05-05  
**Protocol Coverage:** MQTT 3.1.1 (primary) + MQTT 5.0 (extended tests)  
**Tool:** MQTT Security Agent — Custom Python Fuzzer (Campaign 2 Extended Suite)  
**Author:** Patrick Argento — UCLA ECE 202C IoT Security Final Project  

---

## 1. Campaign 2 Overview

Campaign 2 is a **significantly expanded** follow-on assessment building on Campaign 1's confirmed findings. The objectives were:

1. Confirm or extend evidence for all five Campaign 1 vulnerabilities
2. Resolve the two unconfirmed Campaign 1 findings (V5 QoS 2 duplicate, V7 zero-length ClientID)
3. Discover at least five new vulnerability classes to reach a total of 10
4. Expand coverage to MQTT 5.0 protocol features not tested in Campaign 1
5. Conduct broker configuration fingerprinting to characterize the attack surface quantitatively

**Result: 10 distinct vulnerabilities confirmed.** Five from Campaign 1 reconfirmed with new evidence, five new vulnerability classes discovered. Zero broker crashes observed (Mosquitto is resilient to most inputs at the parser level), but the security posture under a permissive configuration is critically weak.

---

## 2. Campaign Statistics

| Metric | Campaign 1 | Campaign 2 | Delta |
|--------|-----------|-----------|-------|
| Total Test Cases | 165 (gen+mut+targeted) | 84 (targeted categories) | — |
| Anomalies Detected | 60 | 24 | — |
| Anomaly Rate | 36.4% | 28.6% | — |
| Broker Crashes | 0 | 0 | 0 |
| Confirmed Vulnerabilities | 5 | 10 | +5 |
| Attack Categories Covered | 4 | 13 | +9 |
| Protocol Scope | MQTT 3.1.1 | 3.1.1 + 5.0 | Expanded |

**Tests by Category (Campaign 2):**

| Category | Tests | Anomalies | Rate |
|----------|-------|-----------|------|
| AUTH_BYPASS | 10 | 9 | 90% |
| TOPIC_NAMESPACE | 13 | 7 | 54% |
| QOS_ATTACK | 6 | 4 | 67% |
| SESSION_ATTACK | 5 | 2 | 40% |
| PAYLOAD_ATTACK | 12 | 1 | 8% |
| CONNECTION_ATTACK | 5 | 0 | 0% |
| SUBSCRIPTION_ABUSE | 4 | 1 | 25% |
| MQTT5_SPECIFIC | 10 | 0 | 0% |
| INFO_LEAKAGE | 4 | 3 | 75% |
| CONFIG_FINGERPRINT | 5 | 0 | 0% |
| WILL_ATTACK | 3 | 2 | 67% |
| RETAINED_ATTACK | 2 | 1 | 50% |
| TARGETED | 5 | 4 | 80% |

---

## 3. Fuzzing Methodology

Campaign 2 employed five distinct fuzzing strategies across 13 attack categories:

### 3.1 Targeted Protocol Violation Testing
Each MQTT packet type was tested with specific spec-violating inputs drawn from MQTT 3.1.1 §3 and MQTT 5.0 §3:
- Packet ID = 0 for QoS 1/2 (violates §2.3.1)
- Empty topic in PUBLISH (violates §4.7.3)
- PUBREL/PUBACK for non-existent packet IDs
- CONNECT without subsequent MQTT packets on TCP connection

### 3.2 State Machine Boundary Testing
Protocol state transitions were exercised at boundaries:
- AUTH packet before CONNECT (out-of-sequence per MQTT 5.0 state machine)
- Double CONNECT on same TCP connection
- DISCONNECT then PUBLISH on same connection
- QoS 2 duplicate PUBLISH injection before PUBCOMP

### 3.3 Resource Exhaustion Probing
Gradual accumulation tests measured broker response to sustained load:
- 100 rapid connect/disconnect cycles (measured at 663 cycles/second)
- 50 persistent sessions × 10 subscriptions (500 total sub records)
- 500 retained messages published without rate limiting
- 200 in-flight QoS 1 messages without consuming PUBACKs
- 50 phantom PUBACKs for non-existent messages

### 3.4 Boundary Value Analysis
Field-level boundary values tested against all major MQTT fields:
- Username/password fields: 0 bytes, 1 byte, 65,535 bytes
- Topic length: 100, 1,000, 10,000, 32,767, 65,535 characters
- Payload size: 1KB, 64KB, 128KB, 1MB, 10MB
- Topic alias: 0, 1, 5 (declared max), 100 (exceeds declared max), 65,535
- Subscription identifier: 0 (invalid), 1, 268,435,455 (max valid), 268,435,456 (overflow)

### 3.5 Differential Behavioral Analysis
Campaign 2 compared broker behavior against MQTT specification requirements to identify spec compliance gaps. Key findings from this analysis are captured in V10 (QoS State Machine Leniency).

---

## 4. Confirmed Vulnerability Summary

### 4.1 Reconfirmed from Campaign 1

#### V1 — Unauthorized Will Message Exploitation [HIGH, CVSS 7.5]
Campaign 2 extended the Will attack to six sensitive topic namespaces. Will messages were successfully delivered to `restricted/admin`, `commands/all`, `alerts/critical`, and `internal/control`. A Will with QoS=2 and `retain=True` was additionally accepted and delivered, creating a persistent poisoned retained message. The `$SYS/test` Will was correctly suppressed.

**New evidence:** Will + retain=True creates an attacker-controlled retained message that persists after the attacker disconnects, combining V1 and V2 impacts into a single attack chain.

#### V2 — Retained Message Poisoning [MEDIUM-HIGH, CVSS 6.5]
Confirmed with explicit end-to-end PoC: attacker published `CAMPAIGN2_ATTACKER_RETAINED_AAAA...` to `fuzz/poison_c2` with `retain=True`; new subscriber received the payload 200ms later. Extended tests confirmed:
- 1MB retained message accepted and stored
- 500 retained messages created without rate limiting or storage quota
- Retained message deletion via empty payload publish works correctly (not a vulnerability)

#### V3 — ClientID Session Hijacking [HIGH, CVSS 8.1]
Two independent test configurations confirmed CONNACK `session_present=True` when attacker connects with a victim's ClientID. The targeted confirmation test used `ClientID="c2_victim_789"` with a QoS 1 subscription to `device/c2/secrets`. Attacker received `session_present=True` immediately, confirming session ownership transfer.

Note on Campaign 1 discrepancy: Campaign 1 classified this as MEDIUM confidence. Campaign 2 elevates to HIGH based on two independent successful reproductions.

#### V4 — Wildcard Subscription Eavesdrop [HIGH, CVSS 7.2]
Confirmed via wildcard_eavesdrop_confirm test. Additionally confirmed that 200 subscriptions per client are accepted without any rate limiting (subscribe_many_topics test). The attack surface extends beyond single-wildcard subscription to mass subscription accumulation.

#### V6 — $SYS Topic Information Disclosure [MEDIUM, CVSS 5.3]
Campaign 2 performed comprehensive $SYS enumeration, confirming disclosure of:
- `$SYS/broker/version` = `mosquitto version 2.0.18`
- `$SYS/broker/clients/total` = `56` (active clients at test time)
- `$SYS/broker/load/connections/5min` (connection rate metrics)
- `$SYS/broker/clients/+` wildcard returned client count metrics

Version string confirmed within 1 second of unauthenticated connection.

### 4.2 New Findings — Campaign 2

#### V8 — Unauthenticated Credential Acceptance [MEDIUM-HIGH, CVSS 6.5]
Seven anomalous credential patterns accepted with CONNACK RC=0. Highest-risk findings:
- Format string `%s%s%s%n` accepted — logging injection risk
- 65,535-byte username accepted — memory pressure in credential logging pipelines
- SQL injection string `' OR '1'='1` accepted — downstream injection risk
- Null bytes in password field accepted (broker survives; parser complexity elevated)

Two inputs caused NO_RESPONSE (null byte prefix in username, CRLF injection), indicating parser sensitivity at specific byte sequences — potentially exploitable for connection disruption.

#### V9 — Shared Subscription Namespace Abuse [MEDIUM, CVSS 5.4]
Six malformed `$share/` subscription filters granted SUBACK RC=0:
- Empty group name: `$share//test` — accepted
- Wrong case: `$SHARE/group1/#` — accepted (spec defines only `$share`)
- Incomplete filter: `$share/g` (missing topic) — accepted

Case-insensitive handling of `$SHARE` is the most significant finding: monitoring tools watching for `$share/` patterns in subscription audit logs would miss `$SHARE/` subscriptions.

#### V10 — QoS State Machine Leniency [LOW-MEDIUM, CVSS 4.3]
Direct specification violations tolerated:
- QoS 1 PUBLISH with `packet_id=0`: MQTT §2.3.1 MUST NOT — accepted by broker
- PUBREL for 5 non-existent packet IDs: processed silently
- 50 phantom PUBACKs for non-existent messages: accepted silently
- 200 in-flight QoS 1 messages without consuming PUBACKs: all processed

Note: QoS 2 duplicate injection was handled correctly — observer received exactly 1 message even when duplicate PUBLISH was injected before PUBCOMP. This resolves the Campaign 1 unconfirmed V5 finding.

#### V11 — Session Persistence Resource Accumulation [MEDIUM, CVSS 5.3]
Quantified broker resource accumulation rates under unauthenticated load:
- 50 persistent sessions with 10 subscriptions each: accepted (500 records)
- 500 retained messages: accepted and stored
- CONNECT flood: 783 connections/second sustained
- 20 half-open TCP connections (no MQTT CONNECT): accepted and held
- 200 per-client subscriptions: accepted without quota

No connection rate limiting, session expiration, or resource quota enforcement observed.

#### V17 — Broker Configuration Fingerprinting [LOW, CVSS 3.7]
Configuration parameters fingerprinted by behavioral probing:
- Max payload: 10MB (10,485,760 bytes accepted)
- Max topic length: 65,535 characters
- Max concurrent connections: 50+ (no cap observed)
- Max subscriptions per client: 200+ (no cap observed)
- Queued messages for offline clients: 0 (empty on reconnect — queue apparently disabled)
- In-flight message limit: 30+ (all 30 tested acknowledged)
- Broker version: `mosquitto version 2.0.18` (via `$SYS`)

---

## 5. Resolution of Campaign 1 Unconfirmed Findings

### V5 — QoS 2 Duplicate Message Injection
**Status: RESOLVED — NOT VULNERABLE**

Campaign 2 executed a controlled QoS 2 duplicate injection test: a second PUBLISH with the same packet ID and DUP=True was sent before PUBCOMP. The observer received exactly 1 message (the original). Mosquitto's QoS 2 deduplication is functioning as specified. This finding is closed.

### V7 — Zero-Length ClientID Specification Violation
**Status: RESOLVED — COMPLIANT**

Campaign 2 tested both cases:
- `ClientID=""` with `clean_session=False` → CONNACK RC=`0x02` (Identifier Rejected) — **CORRECT per §3.1.3.1**
- `ClientID=""` with `clean_session=True` → CONNACK RC=`0x00` (Accepted) — **CORRECT per §3.1.3.1**

Mosquitto correctly implements the specification. This finding is closed.

---

## 6. Attack Category Analysis

### 6.1 Pre-Authentication Attack Surface (Highest Risk)
The most critical finding from Campaign 2 is the breadth of the pre-authentication attack surface. An attacker with only TCP connectivity to port 1883 can:

1. **Enumerate all active broker metrics** (V6) — including exact version for CVE correlation
2. **Join any shared subscription group** (V9) — including via non-canonical `$SHARE` case
3. **Subscribe to all topics via `#`** (V4) — full passive eavesdrop
4. **Register persistent sessions** (V11) — accumulate memory resources
5. **Poison retained messages** (V2) — preload attacker content for future subscribers
6. **Set Will messages to any topic** (V1) — trigger unauthorized publishes on disconnect

All of these attacks require zero authentication and succeed against the default Mosquitto configuration.

### 6.2 MQTT 5.0 Robustness
Mosquitto 2.0.18 handled MQTT 5.0 inputs robustly despite being primarily a 3.1.1 broker:
- 100KB User Properties in CONNECT: survived
- AUTH packet before CONNECT: handled gracefully
- MaxPacketSize=128 declaration followed by 1000-byte publish: survived
- Receive Maximum=0 (invalid per spec §3.1.2.11.4): survived
- Session Expiry Interval=0xFFFFFFFF: accepted

No crashes observed from MQTT 5.0 edge cases. This is consistent with Mosquitto 2.x's improved input validation.

### 6.3 Payload and Connection Robustness
Mosquitto showed strong robustness against payload-level attacks:
- 10MB payload: accepted and processed
- All 256 byte values in payload: survived
- MQTT control bytes embedded in payload: survived
- Half-open TCP connections: tolerated (20 held simultaneously)
- 783 connections/second flood: handled without crash

The broker's parser is well-hardened against low-level injection attacks. Vulnerabilities are at the authorization/configuration layer, not the parsing layer.

---

## 7. Threat Model

The following threat scenarios were validated by Campaign 2:

**Threat 1: Insider IoT Device Compromise**  
A single compromised IoT device (with valid MQTT access) can: subscribe to all topics (`#`), inject Will messages to critical topics, poison retained messages, and enumerate all connected clients via `$SYS`. Campaign 2 confirms all four attack vectors are viable.

**Threat 2: Unauthenticated External Attacker**  
With default `allow_anonymous true`, an external attacker with network access to port 1883 has the same capabilities as an authorized device. All 10 confirmed vulnerabilities are accessible without credentials.

**Threat 3: Denial of Service via Resource Accumulation**  
An unauthenticated attacker can gradually accumulate persistent sessions, retained messages, and subscriptions. At 783 connections/second and 500 subscription records per session, resource exhaustion is achievable on memory-constrained IoT gateway hardware over minutes to hours.

**Threat 4: Session Hijacking via ClientID Guessing**  
IoT devices often use predictable ClientIDs (MAC address, device serial number, hostname). An attacker who enumerates the `$SYS/broker/clients/connected` topic list and guesses ClientID patterns can hijack persistent sessions and receive sensitive queued messages.

---

## 8. Prioritized Remediation Roadmap

The following mitigations are ordered by impact-to-effort ratio:

| Priority | Action | Impact | Effort |
|----------|--------|--------|--------|
| P0 | Set `allow_anonymous false`; configure `password_file` | Eliminates V8, reduces V1-V4, V9-V11 | Low |
| P0 | Deploy `acl_file` with topic-level read/write restrictions | Eliminates V1, V2, V4, V9 | Medium |
| P1 | Set `sys_interval 0` or restrict `$SYS/#` to monitoring clients | Eliminates V6, V17 | Low |
| P1 | Configure `persistent_client_expiration 1d` | Mitigates V11 | Low |
| P1 | Set `message_size_limit 65536` | Reduces V2, V11 payload risk | Low |
| P2 | Set `max_connections 500`, `max_queued_messages 1000` | Mitigates V11 | Low |
| P2 | Enable TLS with client certificates | Eliminates V3, V8 | High |
| P2 | Set `max_inflight_messages 20` | Mitigates V10 | Low |
| P3 | Implement rate limiting per source IP | Reduces V11 DoS risk | Medium |
| P3 | Audit and restrict `$share/` ACL patterns | Mitigates V9 | Medium |

---

## 9. Methodology Reference

This campaign applies techniques from the following research frameworks:

- **FUME (Fuzzing MQTT Brokers, ICSE 2022):** Generation-based packet construction from protocol state machine knowledge; response-guided anomaly detection
- **MQTTactic (IEEE TIFS 2022):** Logic flaw identification via multi-step attack sequences; state machine boundary testing
- **Burglars' IoT Paradise (IEEE S&P 2020):** Authorization bypass via MQTT design weaknesses (Will, retain, wildcard)
- **AFLNET methodology:** Stateful network protocol fuzzing with coverage-guided mutation (applied conceptually; no binary instrumentation used)
- **Boundary Value Analysis (BVA):** Systematic field-level boundary testing per MQTT §2 field specifications

---

## 10. Appendix: Test Case Inventory

| # | Test Name | Category | Anomaly Type | Vuln Class |
|---|-----------|----------|-------------|-----------|
| 1 | auth_null_username | AUTH_BYPASS | NO_RESPONSE | V8 |
| 2 | auth_null_password | AUTH_BYPASS | AUTH_ACCEPTED_ANOMALY | V8 |
| 3 | auth_empty_user_pass | AUTH_BYPASS | AUTH_ACCEPTED_ANOMALY | V8 |
| 4 | auth_very_long_user | AUTH_BYPASS | AUTH_ACCEPTED_ANOMALY | V8 |
| 5 | auth_very_long_pass | AUTH_BYPASS | AUTH_ACCEPTED_ANOMALY | V8 |
| 6 | auth_unicode_user | AUTH_BYPASS | AUTH_ACCEPTED_ANOMALY | V8 |
| 7 | auth_sql_inject_user | AUTH_BYPASS | AUTH_ACCEPTED_ANOMALY | V8 |
| 8 | auth_format_string | AUTH_BYPASS | AUTH_ACCEPTED_ANOMALY | V8 |
| 9 | auth_newline_user | AUTH_BYPASS | NO_RESPONSE | V8 |
| 10 | auth_password_without_flag | AUTH_BYPASS | — | V8 |
| 11 | shared_sub_0 ($share/group1/#) | TOPIC_NAMESPACE | SHARED_SUB_GRANTED | V9 |
| 12 | shared_sub_1 ($share/group1/dev/+) | TOPIC_NAMESPACE | SHARED_SUB_GRANTED | V9 |
| 13 | shared_sub_2 ($share//test) | TOPIC_NAMESPACE | SHARED_SUB_GRANTED | V9 |
| 14 | shared_sub_3 (long topic) | TOPIC_NAMESPACE | SHARED_SUB_GRANTED | V9 |
| 15 | shared_sub_4 ($SHARE/group1/#) | TOPIC_NAMESPACE | SHARED_SUB_GRANTED | V9 |
| 16 | shared_sub_6 ($share/g) | TOPIC_NAMESPACE | SHARED_SUB_GRANTED | V9 |
| 17 | topic_alias_0 | TOPIC_NAMESPACE | — | V15 |
| 18 | topic_alias_1 | TOPIC_NAMESPACE | — | V15 |
| 19 | topic_alias_65535 | TOPIC_NAMESPACE | — | V15 |
| 20 | topic_alias_exceed_max | TOPIC_NAMESPACE | — | V15 |
| 21 | sys_topic_enumeration | TOPIC_NAMESPACE | INFO_DISCLOSURE | V6 |
| 22 | pubrel_storm_orphan_ids | QOS_ATTACK | PUBREL_ORPHAN | V10 |
| 23 | publish_qos1_pid_zero | QOS_ATTACK | — | V10 |
| 24 | qos2_duplicate_inject | QOS_ATTACK | QOS2_HANDLED_CORRECTLY | V5 |
| 25 | qos1_inflight_flood | QOS_ATTACK | INFLIGHT_FLOOD | V10 |
| 26 | puback_flood_phantom | QOS_ATTACK | PUBACK_ORPHAN | V10 |
| 27 | qos_downgrade_delivery | QOS_ATTACK | — | V10 |
| 28 | rapid_connect_disconnect | SESSION_ATTACK | — | V11 |
| 29 | persistent_session_exhaust | SESSION_ATTACK | SESSION_ACCUMULATION | V11 |
| 30 | session_overlap_hijack | SESSION_ATTACK | SESSION_HIJACK | V3 |
| 31 | zero_clientid_persistent | SESSION_ATTACK | CORRECTLY_REJECTED | V7 |
| 32 | zero_clientid_clean | SESSION_ATTACK | — | V7 |
| 33-44 | payload_size_* | PAYLOAD_ATTACK | LARGE_RETAIN | V2/V11 |
| 45-49 | payload_ctrl_bytes_* | PAYLOAD_ATTACK | — | V12 |
| 50 | payload_all_bytes | PAYLOAD_ATTACK | — | V12 |
| 51 | retain_large_payload | PAYLOAD_ATTACK | LARGE_RETAIN | V2 |
| 52 | keepalive_zero | CONNECTION_ATTACK | — | V13 |
| 53 | keepalive_one_rapid_ping | CONNECTION_ATTACK | — | V13 |
| 54 | half_open_connections | CONNECTION_ATTACK | HALF_OPEN | V11 |
| 55 | connect_flood | CONNECTION_ATTACK | — | V11 |
| 56 | double_connect_same_tcp | CONNECTION_ATTACK | — | — |
| 57 | subscribe_many_topics | SUBSCRIPTION_ABUSE | MASS_SUBSCRIPTION | V11 |
| 58 | subscribe_duplicate | SUBSCRIPTION_ABUSE | — | — |
| 59 | wildcard_eavesdrop_confirm | SUBSCRIPTION_ABUSE | — | V4 |
| 60 | sys_metrics_exposure | SUBSCRIPTION_ABUSE | INFO_DISCLOSURE | V6 |
| 61-70 | mqtt5_* | MQTT5_SPECIFIC | — | V15 |
| 71 | auth_timing_sidechannel | INFO_LEAKAGE | — | — |
| 72 | connack_session_present_oracle | INFO_LEAKAGE | SESSION_HIJACK | V3 |
| 73 | sys_client_count_exposure | INFO_LEAKAGE | INFO_DISCLOSURE | V6 |
| 74 | error_message_analysis | INFO_LEAKAGE | — | — |
| 75 | inflight_limit_probe | CONFIG_FINGERPRINT | — | V17 |
| 76 | max_queued_messages_probe | CONFIG_FINGERPRINT | — | V17 |
| 77 | message_size_limit_probe | CONFIG_FINGERPRINT | — | V17 |
| 78 | connection_limit_probe | CONFIG_FINGERPRINT | — | V17 |
| 79 | topic_length_limit_probe | CONFIG_FINGERPRINT | — | V17 |
| 80 | will_topic_namespace_attack | WILL_ATTACK | UNAUTHORIZED_WILL | V1 |
| 81 | will_qos2_retained | WILL_ATTACK | WILL_DELIVERED | V1+V2 |
| 82 | will_large_payload | WILL_ATTACK | — | V1 |
| 83 | retained_message_bomb | RETAINED_ATTACK | RETAIN_ACCUMULATION | V2+V11 |
| 84 | retained_delete_test | RETAINED_ATTACK | — | — |
| T1 | targeted_retain_poison_confirm | TARGETED | RETAIN_POISON_DELIVERED | V2 |
| T2 | targeted_session_hijack_confirm | TARGETED | SESSION_HIJACK | V3 |
| T3 | targeted_zero_clientid_persistent | TARGETED | CORRECTLY_REJECTED | V7 |
| T4 | targeted_zero_clientid_clean | TARGETED | — | V7 |
| T5 | targeted_sys_version_disclosure | TARGETED | VERSION_DISCLOSURE | V6 |

---

*Campaign 2 Report — MQTT Security Agent — UCLA ECE 202C IoT Security Final Project*  
*Eclipse Mosquitto 2.0.18 assessed in controlled Docker lab environment on 2026-05-05*  
*All testing conducted on owned/authorized infrastructure. No production systems affected.*
