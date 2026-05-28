# MQTT Security Agent

**UCLA ECE 202C — IoT Security Final Project**

An AI-powered MQTT broker security assessment tool built on top of **Claude Code** (Anthropic's CLI). The agent autonomously designs fuzzing campaigns, constructs raw MQTT packets, executes stateful multi-client attacks against live Docker-hosted brokers, and produces structured vulnerability reports — all driven by natural-language prompts in the Claude Code terminal.

---

## How It Works

This project uses a **custom Claude Code subagent** (`mqtt-protocol-fuzzer`) defined in `.claude/agents/mqtt-protocol-fuzzer.md`. Rather than running a traditional Python CLI, you interact with the agent directly through the Claude Code terminal using `@agent-mqtt-protocol-fuzzer` prompts. The agent reasons about the MQTT protocol, writes and executes fuzzing scripts, spins up Docker containers, and produces reports — autonomously, in a single conversation turn.

```
You (Claude Code terminal)
  │
  └─ @agent-mqtt-protocol-fuzzer <natural language prompt>
        │
        ├─ Reasons about MQTT protocol state machines
        ├─ Writes fuzzing scripts (raw TCP, no paho dependency)
        ├─ Spins up / verifies Docker broker containers
        ├─ Executes multi-client coordinated attack scenarios
        ├─ Analyzes broker responses and classifies vulnerabilities
        └─ Writes campaign reports to reports/
```

---

## Research Basis

This project synthesizes findings and techniques from five papers:

| Paper | Contribution |
|---|---|
| [Burglars' IoT Paradise](https://ieeexplore.ieee.org/document/9152645) (IEEE S&P 2020) | MQTT vulnerability taxonomy (V1–V6) |
| [MQTTactic](https://www.usenix.org/conference/usenixsecurity22/presentation/chen-bin-mqtt) (USENIX Sec 2022) | Authorization logic flaw categories |
| [FUME](https://dl.acm.org/doi/10.1145/3548606.3560570) (CCS 2022) | Stateful fuzzing engine with response feedback |
| [MGPTFuzz / LLM Protocol Fuzzing](https://www.ndss-symposium.org/ndss-paper/large-language-model-guided-protocol-fuzzing/) (NDSS 2024) | LLM-guided protocol spec parsing → FSM extraction |
| FirmAgent (2026) | Hybrid fuzzing + LLM agent reasoning loop |

---

## Repository Structure

```
mqtt-security-agent/
├── .claude/
│   └── agents/
│       └── mqtt-protocol-fuzzer.md   # Subagent definition (tools, system prompt)
├── agent/
│   ├── spec/mqtt_spec.py             # Protocol FSM, vulnerability taxonomy
│   ├── fuzzing/engine.py             # Campaign 1 fuzzing engine
│   ├── vulnerabilities/attacks.py    # 7 targeted attack classes (V1–V7)
│   └── broker/
│       ├── connector.py              # Raw TCP MQTT packet builder
│       └── docker_mgr.py            # Docker broker lifecycle management
├── campaign2_fuzzer.py               # Campaign 2 fuzzing engine
├── campaign3_fuzzer.py               # Campaign 3 multi-broker fuzzer
├── campaign_final_fuzzer.py          # Final campaign: multi-client differential fuzzer
├── config/
│   ├── mosquitto_hardened_final.conf # Hardened Mosquitto configuration
│   ├── acl_hardened_final.conf       # Hardened ACL file
│   ├── emqx_hardened_final.conf      # Hardened EMQX configuration (HOCON)
│   ├── nanomq_hardened_final.conf    # Hardened NanoMQ configuration
│   └── hivemq_hardening_notes.md    # HiveMQ hardening guidance (XML-based)
├── scripts/
│   ├── verify_mitigations.py         # Campaign 3 PASS/FAIL verifier
│   └── verify_mitigations_final.py   # Final campaign verifier (28 checks, 4 brokers)
├── reports/                          # All campaign outputs (see below)
├── docker/
│   ├── docker-compose.yml
│   └── mosquitto/mosquitto.conf      # Intentionally permissive config for research
└── tests/
    └── test_packet_builder.py        # 37 unit tests (protocol encoding)
```

---

## Prerequisites

- [Claude Code CLI](https://claude.ai/code) installed and authenticated
- Docker Desktop running
- Python 3.10+ (for fuzzing scripts executed by the agent)
- Python packages: `paho-mqtt` (Campaign 1 analysis only — later campaigns use raw sockets)

```bash
git clone https://github.com/patar56/mqtt-security-agent.git
cd mqtt-security-agent
pip install -r requirements.txt
```

---

## Usage

All interaction happens through the **Claude Code terminal**. Open Claude Code in this project directory and use `@agent-mqtt-protocol-fuzzer` to invoke the fuzzing agent.

### Start a fuzzing campaign

```
@agent-mqtt-protocol-fuzzer Spin up a Docker container with an MQTT broker
and launch a fuzzing campaign to find vulnerabilities.
```

The agent will:
1. Pull and start `eclipse-mosquitto:2.0.18` in Docker with a permissive config
2. Run generation-based and mutation-based fuzzing
3. Execute targeted vulnerability attacks from the academic literature
4. Write results to `reports/`

### Target a specific broker or vulnerability class

```
@agent-mqtt-protocol-fuzzer Run the session hijacking attack (V3) against
the broker on localhost:1884.
```

### Multi-broker campaign

```
@agent-mqtt-protocol-fuzzer Run a fuzzing campaign against Mosquitto,
EMQX, HiveMQ CE, and NanoMQ. Produce a cross-broker comparison matrix.
```

### Request mitigations

```
@agent-mqtt-protocol-fuzzer Produce hardened configs and a mitigation guide
for all confirmed vulnerabilities.
```

### Continue a prior campaign

The agent maintains memory between sessions. Use `@agent-mqtt-protocol-fuzzer` with any follow-up prompt and it will pick up from prior findings.

---

## Campaign History & Results

Four campaigns were run over the course of this project, each building on the prior methodology.

### Campaign 1 — Mosquitto 2.0.18 (285 test cases)
Grammar-based generation fuzzing + mutation fuzzing + academic vulnerability reproduction.

| Vuln | Name | CVSS | Result |
|------|------|------|--------|
| V1 | Unauthorized Will Message Exploitation | 7.5 | CONFIRMED |
| V2 | Retained Message Poisoning | 6.5 | CONFIRMED |
| V3 | ClientID Session Hijacking | 8.1 | CONFIRMED |
| V4 | Wildcard Subscription Eavesdrop (`#`) | 7.2 | CONFIRMED |
| V5 | QoS 2 Duplicate Message Injection | 5.3 | NOT CONFIRMED (spec-compliant) |
| V6 | $SYS Topic Information Disclosure | 4.3 | CONFIRMED |
| V7 | Zero-Length ClientID Spec Violation | 6.0 | NOT CONFIRMED (spec-compliant) |

**Anomaly rate:** 41.4% (118/285) | **Broker crashes:** 0

### Campaign 2 — Mosquitto 2.0.18 (84 test cases)
Expanded attack surface: credential fields, shared subscriptions, QoS state machine, connection flooding, fingerprinting.

| Vuln | Name | CVSS | Result |
|------|------|------|--------|
| V8 | Unauthenticated Credential Acceptance | 6.5 | CONFIRMED |
| V9 | Shared Subscription Namespace Abuse | 5.4 | CONFIRMED |
| V10 | QoS State Machine Leniency (PID=0) | 4.3 | CONFIRMED |
| V11 | Session Persistence Resource Accumulation | 5.3 | CONFIRMED |
| V17 | Broker Configuration Fingerprinting | 3.7 | CONFIRMED |

**Cumulative confirmed vulnerabilities: 10**

### Campaign 3 — 4 Brokers, 978 test cases
Multi-broker testing: Mosquitto, NanoMQ, HiveMQ CE 2024.3, EMQX 5.0.0. Plus 10 new vulnerability classes and concrete mitigations for all prior findings.

| Vuln | Name | CVSS |
|------|------|------|
| V18 | Oversized CONNECT silent drop | 6.5 |
| V19 | 500 subscriptions per packet granted | 5.3 |
| V20 | 104,931 PUBLISH/sec — no rate limiting | 7.5 |
| V21 | PINGREQ keepalive abuse | 5.3 |
| V22 | QoS 2 silently downgraded to QoS 0 | 5.4 |
| V24 | 1 PUBLISH → 263 copies (overlapping subs) | 7.5 |
| V26 | Null bytes / invalid UTF-8 in topic names | 6.5 |
| V27 | keepalive timeout enforcement gap | 5.3 |
| V28 | Will self-delivery cross-client injection | 6.8 |
| V31 | QoS 2 in-flight session hijacking | 8.1 |

**Cumulative confirmed vulnerabilities: 20**

**Cross-broker highlights:**
- V1, V3, V8, V11 confirmed on **all four brokers** — MQTT protocol design defaults, not implementation bugs
- EMQX 5.0.0: worst §2.3.1 offender (accepts PID=0 in PUBACK/PUBREC/PUBREL/PUBCOMP)
- HiveMQ CE: only broker that correctly rejects PID=0
- EMQX: correctly blocks `#` wildcard subscriptions (V4 not confirmed)

### Final Campaign — All 4 Brokers, Differential Fuzzing (100 broker-runs)
Fundamentally redesigned fuzzer (`campaign_final_fuzzer.py`, 1,849 lines, raw sockets, no paho dependency). Key improvements over prior campaigns:
- **Stateful multi-client coordination** — Publisher / Subscriber / Attacker / Observer roles via `threading.Barrier`
- **Differential testing** — identical inputs fanned out to all 4 brokers in parallel; response signatures compared automatically
- **7 fuzzing modules:** Multi-client (M), Race/timing (R), MQTT v5 abuse (V5), QoS 2 deep state (Q), Version-mixing (X), State-feedback mutation (SFB), Chained attacks (C)

**New final campaign findings:**

| Finding | Detail | Broker(s) |
|---------|--------|-----------|
| R1 | NanoMQ delivers 2 copies of QoS 2 PUBLISH when DUP races PUBREL | NanoMQ |
| C2 | Message amplification: EMQX 3×, NanoMQ 4× with 4 overlapping filters | EMQX, NanoMQ |
| V51 | Unbounded `SessionExpiry` accepted (MQTT v5) | EMQX |
| V52 | `UserProperty` flood accepted without limit | EMQX, HiveMQ |
| V53 | Divergent reason codes for Topic Alias out-of-bounds | EMQX vs HiveMQ |
| V54 | v5 CONNECT fields accepted silently on v3.1.1 brokers | Mosquitto, NanoMQ |

**Divergence rate:** 64% (16/25 differential tests showed broker disagreement)

**Final broker risk ranking:** HiveMQ CE 2024.3 (lowest) < EMQX 5.0.0 < Mosquitto 2.0.18 ≈ NanoMQ

---

## Project Totals

| Metric | Value |
|--------|-------|
| Campaigns | 4 |
| Total test cases | 1,447 |
| MQTT brokers tested | 4 (Mosquitto, NanoMQ, HiveMQ CE, EMQX) |
| Confirmed vulnerabilities | 20+ |
| Broker crashes | 0 |
| Hardened configs produced | 4 (one per broker) |

---

## Reports & Outputs

All reports are in `reports/`. Raw JSON results are included for reproducibility.

| File | Description |
|------|-------------|
| `fuzzing_campaign_report.md` | Campaign 1 narrative |
| `vulnerability_report.md` | Campaign 1 vulnerability deep-dives |
| `fuzzing_campaign2_report.md` | Campaign 2 narrative |
| `vulnerability_report_campaign2.md` | V8–V17 deep-dives |
| `fuzzing_campaign3_report.md` | Campaign 3 narrative |
| `vulnerability_report_campaign3.md` | V18–V31 deep-dives |
| `mitigations_campaign3.md` | Mitigation guide for V1–V17 |
| `multi_broker_report_campaign3.md` | Cross-broker comparison matrix (C3) |
| `fuzzing_final_campaign_report.md` | **Master narrative — all 4 campaigns** |
| `vulnerability_report_final.md` | **Definitive vulnerability catalog** |
| `multi_broker_final_report.md` | **Final cross-broker analysis** |
| `ai_conversation_log.md` | Full AI interaction log for submission |
| `figures/*.png` | 6 visualizations (scorecard, timelines, matrices) |
| `fuzzing_raw_results*.json` | Raw test data per campaign |

---

## Defense-in-Depth Model

Mitigations are layered across 4 tiers, with hardened configs in `config/`:

| Tier | Control | Implementation |
|------|---------|----------------|
| 1 — Authentication | Who can connect | `allow_anonymous false`, password file, TLS client certs |
| 2 — Authorization | Who can publish/subscribe to what | ACL file, deny wildcards, deny `$SYS/#`, per-client namespaces |
| 3 — Resource controls | DoS prevention | `max_connections`, `max_inflight_messages`, `message_size_limit`, `persistent_client_expiration` |
| 4 — Network | Perimeter defense | mTLS required, broker on private network, firewall blocks port 1883 externally |

Run the automated verifier to check mitigation status:

```bash
python scripts/verify_mitigations_final.py
# Runs 28 checks across all 4 brokers, outputs PASS/FAIL + JSON
```

---

## Running Unit Tests

```bash
python -m pytest tests/ -v
# 37 passed (protocol packet encoding)
```

---

## Course Deliverables

| Deliverable | Location |
|---|---|
| Code repository | This repo |
| Agent design document | `AGENT_DESIGN.md` |
| AI interaction log | `reports/ai_conversation_log.md` |
| Final campaign report | `reports/fuzzing_final_campaign_report.md` |
| Definitive vulnerability catalog | `reports/vulnerability_report_final.md` |
| Cross-broker analysis | `reports/multi_broker_final_report.md` |
| Mitigation guide | `reports/mitigations_campaign3.md` |
| All campaign reports | `reports/fuzzing_campaign*.md` |
| Hardened configs | `config/*_hardened_final.conf` |
| Figures | `reports/figures/*.png` |

---

*UCLA ECE 202C IoT Security — Prof. Nader Sehatbakhsh*
