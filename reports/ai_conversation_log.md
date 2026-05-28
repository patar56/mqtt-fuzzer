# AI Conversation Log — MQTT Security Agent Project
**Course:** UCLA ECE 202C — IoT Security  
**Student:** Patrick Argento  
**AI System:** Claude (Anthropic) — claude-sonnet-4-6 / claude-opus-4-7 (Final Campaign)  
**Project:** MQTT Protocol Fuzzing & Security Assessment  
**Conversation Date:** 2026-05-05 through 2026-05-09  

---

## Overview

This document logs the full AI-assisted conversation used to design, execute, and report on a multi-campaign MQTT broker security fuzzing project. The AI agent (Claude) acted as a security research collaborator, designing fuzzing strategies, writing fuzzing tools, executing live attacks against Docker-hosted MQTT brokers, analyzing results, and producing academic-quality reports.

---

## Conversation Thread

---

### Turn 1 — Campaign 1: Initial Fuzzing Setup

**User prompt:**
> Spin up a docker container with an MQTT broker and launch some fuzzing against it to find vulnerabilities. Remember this is for my final project so do good!

**AI actions:**
- Spun up Eclipse Mosquitto 2.0.18 in a Docker container (`mqtt_target_broker`) with permissive config (anonymous access, no ACL)
- Implemented a multi-phase fuzzing engine (`agent/fuzzing/engine.py`) combining:
  - **Phase 1:** Grammar-based generation fuzzing (boundary values, invalid fields, protocol violations)
  - **Phase 2:** Mutation-based fuzzing (bit flips, byte replacement, truncation, insertion) with Markov chain state tracking
  - **Phase 3:** Targeted vulnerability attacks from academic literature (Burglars' IoT Paradise, MQTTactic)
- Executed 285 total test cases against the live broker
- Produced `reports/fuzzing_campaign_report.md` and `reports/vulnerability_report.md`

**Key findings (Campaign 1):**

| ID | Vulnerability | Severity | CVSS |
|----|--------------|----------|------|
| V1 | Unauthorized Will Message Exploitation | HIGH | 7.5 |
| V2 | Retained Message Poisoning | MEDIUM-HIGH | 6.5 |
| V3 | ClientID Session Hijacking | HIGH | 8.1 |
| V4 | Wildcard Subscription Eavesdrop (`#`) | HIGH | 7.2 |
| V6 | $SYS Topic Information Disclosure | MEDIUM | 4.3 |

**Not confirmed:** V5 (QoS 2 duplicate injection — Mosquitto is spec-compliant), V7 (Zero-length ClientID — spec-compliant)

**Broker stability:** 0 crashes across all 285 test cases. Anomaly rate: 41.4% (118/285).

---

### Turn 2 — User Views the Report

**User prompt:**
> show me the fuzzing report

**AI actions:**
- Read and displayed `reports/fuzzing_campaign_report.md` and `reports/vulnerability_report.md` in full
- Summarized all 5 confirmed vulnerabilities with CVSS scores, root causes, and mitigations
- Noted that all 5 vulnerabilities trace to a single root cause: `allow_anonymous true` with no ACL file

---

### Turn 3 — Campaign 2: Expanded Fuzzing (10 Vulnerabilities Goal)

**User prompt:**
> Launch another fuzzing campaign with the goal of finding 10 vulnerabilities. Also make sure the reports show clear results and make sure you name it so I know it's another campaign

**AI actions:**
- Designed Campaign 2 targeting vulnerability classes not covered in Campaign 1:
  - Authentication bypass vectors (credential field manipulation)
  - Topic namespace attacks (shared subscriptions, `$share/` variants)
  - QoS flow attacks (PID=0, orphan PUBREL/PUBACK)
  - Session state attacks (persistent session exhaustion, connection flooding)
  - Payload-level attacks (oversized payloads, binary injection)
  - Broker configuration fingerprinting
- Executed 84 test cases against Mosquitto 2.0.18
- Named all output files with `_campaign2` suffix

**New findings (Campaign 2):**

| ID | Vulnerability | CVSS |
|----|--------------|------|
| V8 | Unauthenticated Credential Acceptance | 6.5 |
| V9 | Shared Subscription Namespace Abuse | 5.4 |
| V10 | QoS State Machine Leniency (PID=0 accepted) | 4.3 |
| V11 | Session Persistence Resource Accumulation | 5.3 |
| V17 | Broker Configuration Fingerprinting | 3.7 |

**Cumulative confirmed vulnerabilities: 10**

**Evidence highlight — V11:** Sustained 783 connections/second with zero rate limiting observed. 50 persistent sessions stored with no expiry enforcement.

---

### Turn 4 — Campaign 3: Mitigations + 10 More Vulns + Multi-Broker

**User prompt:**
> Let's run another campaign but with a few more tasks. With the vulnerabilities that we've found can you find solutions to mitigate and patch the vulnerabilities? Find 10 more vulnerabilities. Also perform attacks on other popular MQTT brokers in docker

**AI actions:**
- **Goal 1 — Mitigations:** Produced concrete, deployable fixes for all 10 prior vulnerabilities:
  - `config/mosquitto_hardened.conf` (7 directives including `allow_anonymous false`, `max_connections 50`, `message_size_limit 65536`)
  - `config/acl_hardened.conf` (explicit deny rules for `$SYS/#`, `$share/#`, wildcards, per-client namespace isolation)
  - `scripts/verify_mitigations.py` (automated PASS/FAIL verifier for all 10 vulns)
  - `reports/mitigations_campaign3.md` (before/after evidence for each mitigation)

- **Goal 2 — 10 New Vulnerabilities:** Expanded attack surface with 978 total test cases:

| ID | Vulnerability | CVSS |
|----|--------------|------|
| V18 | Oversized CONNECT silent drop (no CONNACK) | 6.5 |
| V19 | 500 subscriptions granted in one SUBSCRIBE packet | 5.3 |
| V20 | 104,931 PUBLISH/sec with zero rate limiting | 7.5 |
| V21 | PINGREQ keepalive abuse (200 pings, no data) | 5.3 |
| V22 | QoS 2 subscriber silently downgraded to QoS 0 | 5.4 |
| V24 | 1 PUBLISH → 263 delivered copies via overlapping subs | 7.5 |
| V26 | Null bytes / invalid UTF-8 accepted in topic names | 6.5 |
| V27 | keepalive=2s not enforced until 5.5s (§3.1.2.10 violation) | 5.3 |
| V28 | Will self-delivery enables cross-client injection chain | 6.8 |
| V31 | QoS 2 in-flight session hijacking (inherits PUBREL state) | 8.1 |

**Cumulative confirmed vulnerabilities: 20**

- **Goal 3 — Multi-Broker Testing:** Pulled and tested 3 additional brokers:
  - **NanoMQ 0.18.2** — Docker container on port 1885
  - **HiveMQ CE 2024.3** — Docker container on port 1886
  - **EMQX 5.0.0** — Docker container on port 1884

**Cross-broker findings (Campaign 3):**

| Vulnerability | Mosquitto | NanoMQ | HiveMQ CE | EMQX |
|---|:---:|:---:|:---:|:---:|
| V1 Will injection | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| V2 Retained poison | CONFIRMED | PARTIAL | CONFIRMED | PARTIAL |
| V3 Session hijacking | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| V4 Wildcard `#` | CONFIRMED | PARTIAL | CONFIRMED | NOT CONFIRMED |
| V6 $SYS disclosure | CONFIRMED | N/A | N/A | N/A |
| V8 Cred acceptance | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| V10 QoS PID=0 | CONFIRMED | NOT CONFIRMED | NOT CONFIRMED | CONFIRMED |
| V11 Connection flood | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |

**Key insight:** V1, V3, V8, V11 are universal across all four brokers — they are MQTT protocol design defaults, not implementation-specific bugs. HiveMQ CE is the only broker that correctly rejects PID=0.

---

### Turn 5 — Final Campaign: Rethink Fuzzing + All Brokers + Comprehensive Solutions

**User prompt:**
> Now that you're going to use your Opus model. Let's plan a final fuzzing campaign across all MQTT brokers we've tested. See if we can find solutions to the vulnerabilities that we've found so far. Rethink also how you are going about performing these fuzzing attacks to see if you can do better. I'm not going to give you a goal number this time. Find vulnerabilities!

**AI model:** claude-opus-4-7 (upgraded for deeper reasoning)

**AI strategy critique of prior campaigns:**
Prior campaigns were limited by:
1. Single-client packet fuzzing — most interesting MQTT bugs require 2+ simultaneous clients
2. Dumb random mutation with no feedback loop
3. Sequential (not parallel) test execution
4. No timing/race condition coverage
5. No differential testing across brokers

**New approach implemented in `campaign_final_fuzzer.py` (1,849 lines, raw-socket, no paho dependency):**
- **Stateful multi-client coordination** — Publisher/Subscriber/Attacker/Observer roles via `threading.Barrier`
- **Differential testing** — every test fanned out in parallel across all 4 brokers; response signatures auto-compared
- **7 fuzzing modules:** Multi-client (M), Race/timing (R), MQTT v5 abuse (V5), QoS 2 deep state (Q), Version-mixing (X), State-feedback mutation (SFB), Cross-cutting chains (C)

**Final Campaign results (25 differential tests × 4 brokers = 100 broker-runs):**

| Finding | Detail | Brokers Affected |
|---------|--------|-----------------|
| R1 NEW | NanoMQ delivers 2 copies of QoS 2 PUBLISH when DUP races PUBREL | NanoMQ only |
| C2 Quantified | Message amplification: EMQX 3×, NanoMQ 4×, Mosquitto/HiveMQ 1× (4 overlapping filters) | All |
| Q5 Reproduced | EMQX 5.0.0 accepts PID=0 in PUBACK/PUBREC/PUBREL/PUBCOMP | EMQX, Mosquitto |
| V51 NEW | Unbounded SessionExpiry (MQTT v5) | EMQX |
| V52 NEW | UserProperty flood accepted | EMQX, HiveMQ |
| V53 NEW | Divergent reason codes for Topic Alias out-of-bounds | EMQX vs HiveMQ differ |
| V54 NEW | Version-mixing: v5 CONNECT features on v3.1.1 broker | Mosquitto, NanoMQ |

**Anomaly rate:** 16 anomalies / 25 tests = **64% divergence rate**

**Broker risk ranking (Final):** HiveMQ CE 2024.3 (lowest risk) < EMQX 5.0.0 < Mosquitto 2.0.18 ≈ NanoMQ

**Defense-in-depth model (4 tiers):**
- **Tier 1 — Authentication:** `allow_anonymous false`, password file, TLS client certificates
- **Tier 2 — Authorization:** ACL file with per-client topic permissions, deny wildcards, deny `$SYS/#`
- **Tier 3 — Resource controls:** `max_connections`, `max_inflight_messages`, `max_queued_messages`, `message_size_limit`, `persistent_client_expiration`
- **Tier 4 — Network controls:** mTLS required, VPN/private network, firewall rules restricting port 1883

**Hardened configs produced for all brokers:**
- `config/mosquitto_hardened_final.conf`
- `config/nanomq_hardened_final.conf`
- `config/emqx_hardened_final.conf` (HOCON format)
- `config/hivemq_hardening_notes.md` (XML-based config)
- `scripts/verify_mitigations_final.py` (28 checks across 4 brokers)

**Verifier baseline (permissive configs):** 8 PASS / 20 FAIL — correctly fingerprints unhardened state.

---

## Total Project Statistics

| Metric | Value |
|--------|-------|
| Campaigns run | 4 (C1, C2, C3, Final) |
| Total test cases executed | 285 + 84 + 978 + 100 = **1,447** |
| Distinct vulnerabilities confirmed | **20+** (V1–V31 range) |
| MQTT brokers tested | **4** (Mosquitto, NanoMQ, HiveMQ CE, EMQX) |
| Broker crashes | **0** |
| Overall anomaly rate | ~45% across all campaigns |
| Hardened config files produced | **5** |
| Fuzzing scripts written | **4** |
| Report documents produced | **11** |

---

## Files Produced

### Fuzzing Engines
| File | Campaign | Description |
|------|----------|-------------|
| `agent/fuzzing/engine.py` | C1 | Grammar-based + mutation fuzzer |
| `campaign2_fuzzer.py` | C2 | Extended fuzzer (V8–V17 coverage) |
| `campaign3_fuzzer.py` | C3 | Multi-broker fuzzer |
| `campaign_final_fuzzer.py` | Final | Multi-client differential fuzzer (1,849 lines) |

### Reports
| File | Campaign | Description |
|------|----------|-------------|
| `reports/fuzzing_campaign_report.md` | C1 | Campaign 1 narrative |
| `reports/vulnerability_report.md` | C1 | V1–V6 deep dives |
| `reports/fuzzing_campaign2_report.md` | C2 | Campaign 2 narrative |
| `reports/vulnerability_report_campaign2.md` | C2 | V8–V17 deep dives |
| `reports/fuzzing_campaign3_report.md` | C3 | Campaign 3 narrative |
| `reports/vulnerability_report_campaign3.md` | C3 | V18–V31 deep dives |
| `reports/mitigations_campaign3.md` | C3 | Mitigation guide V1–V17 |
| `reports/multi_broker_report_campaign3.md` | C3 | Cross-broker matrix |
| `reports/fuzzing_final_campaign_report.md` | Final | Master narrative (all campaigns) |
| `reports/vulnerability_report_final.md` | Final | Definitive vulnerability catalog |
| `reports/multi_broker_final_report.md` | Final | Final cross-broker analysis |

### Configs & Scripts
| File | Description |
|------|-------------|
| `config/mosquitto_hardened.conf` | C3 hardened Mosquitto config |
| `config/acl_hardened.conf` | C3 hardened ACL |
| `config/mosquitto_hardened_final.conf` | Final hardened Mosquitto config |
| `config/nanomq_hardened_final.conf` | Final hardened NanoMQ config |
| `config/emqx_hardened_final.conf` | Final hardened EMQX config (HOCON) |
| `config/hivemq_hardening_notes.md` | HiveMQ hardening guidance |
| `scripts/verify_mitigations.py` | C3 verifier (10 vulns) |
| `scripts/verify_mitigations_final.py` | Final verifier (28 checks, 4 brokers) |

---

## References

1. Choi et al., *Burglars' IoT Paradise: Understanding and Mitigating Security Risks of General Messaging Protocols on Cloud Platforms*, IEEE S&P 2020
2. Chen et al., *MQTTactic: Security Analysis and Implementation for Logic Flaws in MQTT Brokers*, 2022
3. Situ et al., *FUME: Fuzzing Message Queuing Telemetry Transport Brokers*, IEEE INFOCOM 2022
4. Deng et al., *Large Language Model guided Protocol Fuzzing*, NDSS 2024
5. OASIS, *MQTT Version 3.1.1*, OASIS Standard, 2014
6. OASIS, *MQTT Version 5.0*, OASIS Standard, 2019

---

*Log generated for UCLA ECE 202C IoT Security Final Project submission*  
*AI assistant: Claude (Anthropic) | Project: MQTT Security Agent*
