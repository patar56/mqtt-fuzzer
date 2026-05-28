# MQTT Security Agent — Design Document

**UCLA ECE 202C — IoT Security Final Project**
**Author:** Patrick Argento

---

## Overview

The MQTT Security Agent is an AI-driven security research system built on **Claude Code** (Anthropic's CLI). A custom subagent — `mqtt-protocol-fuzzer` — is invoked through the Claude Code terminal via natural-language prompts. The agent reasons about the MQTT protocol, writes and executes fuzzing code, manages Docker broker containers, and produces structured vulnerability reports autonomously.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Developer (Claude Code terminal)                   │
│  > @agent-mqtt-protocol-fuzzer <prompt>             │
└────────────────────┬────────────────────────────────┘
                     │ spawns
┌────────────────────▼────────────────────────────────┐
│  mqtt-protocol-fuzzer Subagent                      │
│  Model: Claude Opus 4                               │
│  Defined in: .claude/agents/mqtt-protocol-fuzzer.md │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Protocol    │  │  Fuzzing     │  │  Report   │  │
│  │ Knowledge   │  │  Execution   │  │  Writing  │  │
│  │ (MQTT spec) │  │  (Python)    │  │  (MD/JSON)│  │
│  └─────────────┘  └──────────────┘  └───────────┘  │
└────────────────────┬────────────────────────────────┘
                     │ targets
┌────────────────────▼────────────────────────────────┐
│  MQTT Brokers (Docker containers, local network)    │
│  - Mosquitto 2.0.18  :1883                          │
│  - EMQX 5.0.0        :1884                          │
│  - NanoMQ 0.18.2     :1885                          │
│  - HiveMQ CE 2024.3  :1886                          │
└─────────────────────────────────────────────────────┘
```

---

## Tools Available to the Agent

The subagent has access to the following Claude Code tools:

| Tool | Purpose |
|------|---------|
| `Bash` | Execute Python fuzzing scripts, manage Docker containers, run `git` commands |
| `Read` | Read protocol specs, existing fuzzing engines, and prior campaign reports |
| `Write` | Write new fuzzing scripts, configs, and report files |
| `Edit` | Modify existing files (e.g., update `.gitignore`, patch fuzzer logic) |
| `WebSearch` / `WebFetch` | Look up MQTT spec sections, CVEs, broker documentation |
| `TaskCreate` / `TaskUpdate` | Track multi-step campaign progress |

---

## Fuzzing Engine Evolution

Each campaign produced a progressively more capable fuzzer:

| Campaign | File | Technique |
|----------|------|-----------|
| 1 | `agent/fuzzing/engine.py` | Grammar-based generation + dumb mutation, single client |
| 2 | `campaign2_fuzzer.py` | Targeted attack matrix, expanded vulnerability classes |
| 3 | `campaign3_fuzzer.py` | Multi-broker parallel single-client testing |
| Final | `campaign_final_fuzzer.py` | Stateful multi-client, differential, race-aware (1,849 lines, raw sockets) |

The Final fuzzer is built with **raw TCP sockets and hand-crafted MQTT byte frames** — no `paho-mqtt` dependency — so it can emit malformed packets that no conforming client library would produce.

---

## Key Design Decisions

**Raw socket implementation:** Fuzzing libraries like `paho-mqtt` enforce protocol correctness. All later campaigns bypass this by building MQTT frames from scratch using Python's `struct` and `socket` modules, enabling PID=0 injection, invalid QoS values, malformed UTF-8 topics, and other spec violations.

**Multi-client coordination:** Most MQTT vulnerabilities require 2–3 simultaneous clients (e.g., Will delivery requires an observer subscriber; session hijacking requires a victim and an attacker). The Final fuzzer uses `threading.Barrier` to synchronize roles.

**Differential testing:** The same test is run against all four brokers in a `ThreadPoolExecutor`. Responses are hashed into signatures; any divergence is flagged as an anomaly. This is how the NanoMQ QoS 2 deduplication defect (R1) was discovered.

**Persistent agent memory:** The subagent maintains a file-based memory at `.claude/agent-memory/mqtt-protocol-fuzzer/` to carry broker-specific findings and campaign context across separate conversation sessions.

---

## External Dependencies

| Dependency | Version | Use |
|------------|---------|-----|
| Docker Desktop | any | Broker container lifecycle |
| Python | 3.10+ | Fuzzing engine runtime |
| paho-mqtt | 1.6.x | Campaign 1 analysis only |
| matplotlib | 3.x | Report figures |
| Claude Code CLI | latest | Agent orchestration |

No API key configuration is required beyond Claude Code authentication — the subagent is invoked directly through the CLI.

---

## Running the Agent

```bash
# In the Claude Code terminal, from the project root:
@agent-mqtt-protocol-fuzzer <your prompt>

# Examples:
@agent-mqtt-protocol-fuzzer Run a fuzzing campaign against Mosquitto on localhost:1883
@agent-mqtt-protocol-fuzzer Find vulnerabilities in EMQX and produce a report
@agent-mqtt-protocol-fuzzer Apply mitigations for all confirmed vulnerabilities
```

See `README.md` for the full usage guide and campaign results.
