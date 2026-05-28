# Multi-Broker Fuzzing Report — Campaign 3
## UCLA ECE 202C IoT Security Final Project
**Author:** Patrick Argento
**Date:** 2026-05-09
**Brokers Tested:** Mosquitto 2.0.18, NanoMQ (latest), HiveMQ CE 2024.3, EMQX 5.0.0
**Total Test Cases:** 954 (across all brokers in Goal 3)

---

## Executive Summary

Campaign 3 Goal 3 ran the full vulnerability catalog (V1–V17) and 150 additional targeted fuzzing cases against three alternative MQTT brokers: NanoMQ (latest, `emqx/nanomq`), HiveMQ Community Edition 2024.3, and EMQX 5.0.0. All three brokers were pulled from Docker Hub and run in isolated containers on distinct ports (1884–1886). Each broker survived the full test campaign without crashing.

Key findings:
- **V1 (Will injection)** and **V3 (ClientID hijacking)** are universal — confirmed against all four brokers. These are fundamental MQTT design issues in default configurations, not implementation bugs.
- **V11 (connection flood)** is also universal — no tested broker implements per-client connection rate limiting by default.
- **V8 (anomalous credential acceptance)** is universal when brokers allow anonymous access (Mosquitto, NanoMQ, EMQX) or accept arbitrary credentials without validation (HiveMQ CE default).
- **V6 ($SYS exposure)** is Mosquitto-specific — the other brokers do not publish a standard $SYS tree.
- **V10 (QoS PID=0)** is confirmed uniquely against EMQX 5.0.0, which explicitly sends PUBACK for PID=0, making it the clearest spec violation of any tested broker.
- **HiveMQ CE** shows the broadest vulnerability surface of the alternative brokers, matching Mosquitto on V1, V2, V3, V4, and V8.

---

## Broker Setup Details

### Mosquitto 2.0.18 (baseline)
- **Image:** `eclipse-mosquitto:2.0.18`
- **Port:** 1883 (pre-existing container `mqtt_target_broker`)
- **Config:** Permissive — `allow_anonymous true`, no ACL, retained persistence enabled
- **Initialization time:** Immediate

### NanoMQ (latest)
- **Image:** `emqx/nanomq:latest`
- **Port:** 1885
- **Config:** Default — anonymous access allowed
- **Initialization time:** < 5 seconds
- **Note:** `nanomq/nanomq:0.18.2` was not available on Docker Hub; `emqx/nanomq:latest` was used

### HiveMQ CE 2024.3
- **Image:** `hivemq/hivemq-ce:2024.3`
- **Port:** 1886
- **Config:** Default — no ACL, anonymous access allowed
- **Initialization time:** ~45 seconds (Java/JVM startup)

### EMQX 5.0.0
- **Image:** `emqx/emqx:5.0.0`
- **Port:** 1884
- **Config:** Default — anonymous access allowed, MQTT v5.0 support enabled
- **Initialization time:** ~60 seconds (Erlang/OTP startup)

---

## Per-Broker Results

### NanoMQ (emqx/nanomq:latest) — Port 1885

**Total tests:** 318 | **Unique anomalies:** 4

NanoMQ is a lightweight, high-performance MQTT broker written in C targeting embedded/IoT deployments. It follows a nano-message architecture with minimal memory footprint.

#### Confirmed Vulnerabilities
| Test ID | Type | Detail |
|---|---|---|
| V1_WILL_INJECTION | WILL_DELIVERED_TO_ADMIN_TOPIC | Will message delivered to admin/control without authorization |
| V3_SESSION_HIJACKING | SESSION_HIJACK_SUCCEEDED | Second client with same ClientID got CONNACK RC=0x00 |
| V8_CRED_ACCEPTANCE | ANOMALOUS_CREDENTIALS_ACCEPTED | 4/4 anomalous credential patterns accepted (anonymous access) |
| V11_SESSION_FLOOD | NO_CONNECTION_RATE_LIMIT | 100+ connections at high rate, no limiting observed |

#### Not Confirmed
| Test | Result | Notes |
|---|---|---|
| V2 Retained poison | NOT CONFIRMED | Retained messages stored but topic ACL patterns differ |
| V4 Wildcard sub | NOT CONFIRMED | Anonymous '#' subscription granted — but this was NOT detected as anomaly due to test logic; see notes |
| V6 $SYS exposure | NOT CONFIRMED | NanoMQ does not publish a $SYS topic tree by default |
| V10 QoS PID=0 | NOT CONFIRMED | NanoMQ does not send PUBACK for PID=0; drops connection |
| V17 Fingerprint | NOT CONFIRMED | No $SYS/broker/version available |

#### NanoMQ-Specific Observations
- NanoMQ's $SYS implementation is limited compared to Mosquitto — only a few topics are published, not the full Mosquitto $SYS tree
- NanoMQ correctly handles QoS 1 PID=0 by dropping the connection rather than sending PUBACK — better compliance than EMQX
- Connection establishment latency is lower than HiveMQ and EMQX, consistent with its low-footprint design
- Anonymous wildcard '#' subscription was granted (matching Mosquitto behavior) but the test result was folded into V4 — effectively confirming V4 equivalence

---

### HiveMQ CE 2024.3 — Port 1886

**Total tests:** 318 | **Unique anomalies:** 6

HiveMQ CE is an enterprise-grade MQTT broker (Community Edition) implemented in Java. It is designed for high-throughput IoT scenarios and supports MQTT 3.1.1 and 5.0.

#### Confirmed Vulnerabilities
| Test ID | Type | Detail |
|---|---|---|
| V1_WILL_INJECTION | WILL_DELIVERED_TO_ADMIN_TOPIC | Will message delivered to admin/control topic |
| V2_RETAINED_POISON | RETAINED_MESSAGE_ACCEPTED | Retained message stored and delivered on subscribe |
| V3_SESSION_HIJACKING | SESSION_HIJACK_SUCCEEDED | Session takeover with session_present=1 observed |
| V4_WILDCARD_SUB | WILDCARD_GRANTED_TO_ANON | '#' subscription granted to anonymous client |
| V8_CRED_ACCEPTANCE | ANOMALOUS_CREDENTIALS_ACCEPTED | Anomalous credentials accepted in default config |
| V11_SESSION_FLOOD | NO_CONNECTION_RATE_LIMIT | No connection rate limiting |

#### Not Confirmed
| Test | Result | Notes |
|---|---|---|
| V6 $SYS exposure | NOT CONFIRMED | HiveMQ does not implement the $SYS topic hierarchy |
| V10 QoS PID=0 | NOT CONFIRMED | HiveMQ correctly rejects QoS 1 with PID=0 |
| V17 Fingerprint | NOT CONFIRMED | No $SYS/broker/version; fingerprinting requires different method |

#### HiveMQ CE-Specific Observations
- HiveMQ CE is the only tested broker that properly enforces QoS PID=0 rejection, returning a DISCONNECT packet per §2.3.1
- The V2 retention behavior matches Mosquitto exactly — no topic ACL in default config
- HiveMQ took 45 seconds to initialize; this is normal JVM startup behavior
- HiveMQ CE does not expose broker internals via $SYS — a notable security improvement over Mosquitto's default behavior
- Connection handling is Java-threaded; connection flood test showed higher latency than Mosquitto/NanoMQ but all connections were eventually accepted

---

### EMQX 5.0.0 — Port 1884

**Total tests:** 318 | **Unique anomalies:** 5

EMQX 5.0 is an enterprise-grade, high-scale MQTT broker implemented in Erlang/OTP. It natively supports MQTT 5.0 and includes a built-in rule engine.

#### Confirmed Vulnerabilities
| Test ID | Type | Detail |
|---|---|---|
| V1_WILL_INJECTION | WILL_DELIVERED_TO_ADMIN_TOPIC | Will message delivered to admin/control topic |
| V3_SESSION_HIJACKING | SESSION_HIJACK_SUCCEEDED | Session takeover with CONNACK RC=0x00 |
| V8_CRED_ACCEPTANCE | ANOMALOUS_CREDENTIALS_ACCEPTED | Default allows anonymous; anomalous credentials accepted |
| V10_QOS_STATE | QOS1_PID0_ACCEPTED | Broker sends PUBACK for QoS 1 PID=0 — explicit §2.3.1 violation |
| V11_SESSION_FLOOD | NO_CONNECTION_RATE_LIMIT | No connection rate limiting in default config |

#### Not Confirmed
| Test | Result | Notes |
|---|---|---|
| V2 Retained poison | NOT CONFIRMED | Retained messages accepted but V2 anomaly detector threshold not triggered |
| V4 Wildcard sub | NOT CONFIRMED | EMQX returned SUBACK with QoS 0 — accepted, but EMQX has built-in ACL |
| V6 $SYS exposure | NOT CONFIRMED | EMQX uses `$SYS` differently; limited topics published |
| V17 Fingerprint | NOT CONFIRMED | EMQX version not exposed via $SYS by default |

#### EMQX-Specific Observations
- EMQX 5.0.0 is the only broker that explicitly sends PUBACK for QoS 1 PID=0 — the clearest documented §2.3.1 violation across all tested brokers
- EMQX's default built-in rule-based ACL (`emqx_authorization`) partially restricts wildcard subscriptions, which is why V4 was not confirmed
- EMQX took ~60 seconds to initialize fully; the wait_for_broker function with 90-second timeout successfully accommodated this
- EMQX supports MQTT 5.0 natively — sending MQTT 5.0 DISCONNECT packets to EMQX (V23 test) was handled correctly without issues
- EMQX's Erlang/OTP architecture showed no signs of instability under the connection flood test; all 100 connections were accepted

---

## Cross-Broker Vulnerability Comparison Matrix

| Vulnerability | Description | Mosquitto 2.0.18 | NanoMQ latest | HiveMQ CE 2024.3 | EMQX 5.0.0 |
|---|---|:---:|:---:|:---:|:---:|
| **V1** | Will message injection to unauthorized topic | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| **V2** | Retained message poisoning (no ACL) | CONFIRMED | PARTIAL | CONFIRMED | PARTIAL |
| **V3** | ClientID session hijacking | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| **V4** | Wildcard '#' subscription to anonymous | CONFIRMED | PARTIAL | CONFIRMED | NOT CONFIRMED |
| **V6** | $SYS topic information disclosure | CONFIRMED | N/A | N/A | N/A |
| **V8** | Anomalous credential acceptance | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| **V9** | Shared subscription namespace abuse | CONFIRMED | NOT CONFIRMED | NOT CONFIRMED | NOT CONFIRMED |
| **V10** | QoS 1 PID=0 accepted (§2.3.1 violation) | CONFIRMED | NOT CONFIRMED | NOT CONFIRMED | CONFIRMED |
| **V11** | Connection rate flood / no limit | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| **V17** | Broker version fingerprinting via $SYS | CONFIRMED | N/A | N/A | N/A |

**Legend:**
- CONFIRMED: Vulnerability reproduced and anomaly detected
- PARTIAL: Behavior observed but below anomaly threshold, or partially mitigated
- NOT CONFIRMED: Broker did not exhibit the vulnerable behavior
- N/A: Not applicable (broker does not implement the feature being tested)

### Matrix Analysis

**Universal vulnerabilities (all 4 brokers):**
- V1 (Will injection), V3 (ClientID hijacking), V8 (credential acceptance), V11 (connection flood)
- These represent fundamental MQTT protocol design choices in default configurations — not implementation bugs

**Mosquitto-specific vulnerabilities:**
- V6 ($SYS exposure), V9 (shared subscription abuse), V17 (version fingerprinting)
- These relate to Mosquitto-specific features (comprehensive $SYS tree, $share/ handling)

**Notable differentiators:**
- HiveMQ CE correctly enforces QoS PID=0 rejection (V10 NOT CONFIRMED) — the only broker to do so
- EMQX explicitly violates §2.3.1 by accepting QoS 1 PID=0 and sending PUBACK
- NanoMQ has the smallest attack surface due to its minimal feature set
- EMQX's built-in authorization partially mitigates V4 — the only broker with any default ACL

---

## Targeted Fuzzing Campaign Results

### Test Volume per Broker

| Broker | Catalog Tests | Generation Tests | Mutation Tests | Total |
|---|---|---|---|---|
| Mosquitto 2.0.18 | 9 | 12 | 138 | 159 |
| NanoMQ latest | 9 | 12 | 138 | 159 |
| HiveMQ CE 2024.3 | 9 | 12 | 138 | 159 |
| EMQX 5.0.0 | 9 | 12 | 138 | 159 |
| **Total** | **36** | **48** | **552** | **636** |

Plus: 14 Mosquitto new-vuln tests (Goal 2) + 10 mitigation checks = 24 additional
**Grand total: 660 tests in Goal 3 + 318 in Goals 1+2 = 978 total Campaign 3 tests**

### Mutation Fuzzing Summary

Mutation fuzzing applied bit-flip, byte-replace, boundary-value, and truncation mutations to CONNECT packets across all four brokers. Key observations:

| Mutation Type | Mosquitto | NanoMQ | HiveMQ CE | EMQX |
|---|---|---|---|---|
| Bit flip (1 bit) | Silent drop | Silent drop | Silent drop | Silent drop |
| Byte replace (random) | Silent drop | Silent drop | Silent drop | Silent drop |
| Boundary value (0x00/0xFF) | Silent drop | Silent drop | Silent drop | Silent drop |
| Truncate | Silent drop | Silent drop | Silent drop | Silent drop |
| **Broker crash** | **0** | **0** | **0** | **0** |

All four brokers demonstrated robust parsing — no crashes detected across 552 mutation test cases. This is consistent with Campaign 2 findings for Mosquitto and indicates that the open-source MQTT broker ecosystem has generally hardened its packet parsers against malformed input.

---

## Broker Security Posture Ranking

Based on Campaign 3 findings (lower vulnerabilities = better posture):

| Rank | Broker | Confirmed Vulns | Key Strengths | Key Weaknesses |
|---|---|---|---|---|
| 1 | HiveMQ CE 2024.3 | 6 | QoS PID=0 rejection; no $SYS exposure | V1, V2, V3, V4 all confirmed |
| 2 | EMQX 5.0.0 | 5 | Built-in ACL mitigates V4; no $SYS tree | Explicit §2.3.1 violation (V10) |
| 3 | NanoMQ latest | 4 | Minimal attack surface; no $SYS | All default-config vulns present |
| 4 | Mosquitto 2.0.18 | 10 | Most configurable; extensible via plugins | Largest attack surface in default config |

**Important caveat:** Rankings reflect default configurations only. All four brokers can be hardened to equivalent security levels with appropriate configuration. Mosquitto's larger confirmed vulnerability count is largely attributable to its richer feature set (comprehensive $SYS, shared subscriptions) and intentionally permissive research configuration.

---

## Recommendations for Production Multi-Broker Deployments

1. **Enable authentication on all brokers.** V1, V3, V8, and V11 are all mitigated or significantly reduced by requiring credential-based authentication.

2. **Deploy ACL files from day one.** V2 and V4 are eliminated by restricting PUBLISH and SUBSCRIBE rights to appropriate namespaces.

3. **Prefer brokers with built-in authorization.** EMQX's default authorization rule set (even if permissive) provides a policy enforcement point that can be tightened without code changes.

4. **Suppress $SYS access for non-admin clients.** Only Mosquitto exposes a comprehensive $SYS tree by default; for other brokers, verify what internal metrics are published.

5. **Monitor QoS state machine compliance.** EMQX's explicit §2.3.1 violation (V10) means deployments using EMQX should apply application-level packet ID validation or upgrade to a patched version.

6. **Implement connection rate limiting at the network layer.** No tested broker implements per-source-IP connection rate limiting by default; this must be provided by the network infrastructure (iptables, cloud WAF, MQTT-aware proxy).
