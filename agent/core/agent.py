"""
MQTT Security Agent — Core LLM Agent Loop

This is the brain of the system. It uses the Anthropic Claude API with
tool use to orchestrate multi-step security testing of MQTT brokers.

Architecture pattern inspired by FirmAgent (2026):
  - Agent receives high-level goal: "find vulnerabilities in target broker"
  - Agent uses tools to: read MQTT spec, run fuzzing campaigns, execute
    targeted attacks, analyze results, generate PoC, write reports
  - Agent reasons about findings and decides next steps autonomously
  - Multi-turn conversation maintains context across the entire session

The agent has access to the following tools:
  1. read_mqtt_spec_section(topic) — retrieve protocol knowledge
  2. run_fuzz_campaign(mode, max_cases) — execute fuzzing engine
  3. run_vulnerability_attack(vuln_id) — run a specific targeted attack
  4. run_all_vulnerability_attacks() — run full attack suite
  5. check_broker_health() — liveness check
  6. get_fuzz_results() — retrieve current fuzzing results
  7. generate_report() — create final vulnerability report
  8. start_broker(image) — start Docker broker
  9. stop_broker() — stop Docker broker
"""

import json
import time
import logging
import os
from typing import Any, Dict, List, Optional
from datetime import datetime

import anthropic

from agent.spec.mqtt_spec import VULNERABILITY_CLASSES, MQTT_PACKET_SPECS, VALID_SEQUENCES, INVALID_SEQUENCES
from agent.fuzzing.engine import FuzzingEngine
from agent.vulnerabilities.attacks import AttackRunner, AttackResult
from agent.broker.docker_mgr import DockerBrokerManager
from agent.analysis.analyzer import ResultAnalyzer
from agent.analysis.reporter import ReportGenerator

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Tool Definitions (passed to Claude API)
# ─────────────────────────────────────────────────────────────

AGENT_TOOLS = [
    {
        "name": "read_mqtt_spec_section",
        "description": (
            "Retrieve a section of the MQTT protocol specification or vulnerability "
            "knowledge base. Use this to understand protocol rules before crafting "
            "test cases, or to reason about whether a broker behavior is spec-compliant."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "topic": {
                    "type": "string",
                    "description": (
                        "The topic to look up. Valid values: "
                        "'packet_types', 'vulnerability_classes', "
                        "'valid_sequences', 'invalid_sequences', "
                        "'connect_fields', 'publish_fields', 'subscribe_fields', "
                        "'anomaly_signatures', 'all'"
                    ),
                }
            },
            "required": ["topic"],
        },
    },
    {
        "name": "run_fuzz_campaign",
        "description": (
            "Execute a fuzzing campaign against the target MQTT broker. "
            "Returns a summary of anomalies detected. "
            "Use 'generation' mode to test known vulnerability patterns, "
            "'mutation' mode to find unexpected parsing bugs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["generation", "mutation", "both"],
                    "description": "Fuzzing mode to run",
                },
                "max_cases": {
                    "type": "integer",
                    "description": "Maximum number of test cases (default: 50). Reduce for quick runs.",
                },
                "focus_vulnerability": {
                    "type": "string",
                    "description": "Optional: focus generation fuzzing on a specific vulnerability ID (e.g., 'V1_UNAUTHORIZED_WILL')",
                },
            },
            "required": ["mode"],
        },
    },
    {
        "name": "run_vulnerability_attack",
        "description": (
            "Execute a specific targeted vulnerability attack against the broker. "
            "These are precise, multi-step exploit attempts — not random fuzzing. "
            "Use after fuzzing identifies a potential vulnerability, or to directly "
            "test a known attack class."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability_id": {
                    "type": "string",
                    "description": (
                        "The vulnerability ID to test. Valid values: "
                        "V1_UNAUTHORIZED_WILL, V2_UNAUTHORIZED_RETAIN, "
                        "V3_CLIENTID_HIJACKING, V4_TOPIC_AUTH_BYPASS, "
                        "V5_QOS2_TIMING, V6_SYS_TOPIC_EXPOSURE, V7_ZERO_LENGTH_CLIENTID"
                    ),
                }
            },
            "required": ["vulnerability_id"],
        },
    },
    {
        "name": "run_all_vulnerability_attacks",
        "description": (
            "Run the complete suite of targeted vulnerability attacks against the broker. "
            "Tests all 7 known MQTT vulnerability classes from the research literature. "
            "Provides a comprehensive assessment. Use when you want a full picture."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "check_broker_health",
        "description": (
            "Check if the target MQTT broker is alive and accepting connections. "
            "Returns connection status, CONNACK return code, and basic broker info. "
            "Use before starting a campaign or after a potential crash."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_results_summary",
        "description": (
            "Retrieve a summary of all fuzzing and attack results collected so far. "
            "Includes anomaly counts, vulnerability confirmations, and broker stability."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "generate_poc",
        "description": (
            "Generate a Proof of Concept (PoC) script for a confirmed vulnerability. "
            "Creates a standalone Python script that reproduces the vulnerability. "
            "Use after a vulnerability attack returns success=True."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability_id": {
                    "type": "string",
                    "description": "The vulnerability ID to generate PoC for",
                }
            },
            "required": ["vulnerability_id"],
        },
    },
    {
        "name": "generate_report",
        "description": (
            "Generate a final structured vulnerability report covering all findings. "
            "Includes confirmed vulnerabilities, fuzzing statistics, PoC summaries, "
            "and remediation recommendations. Call this at the end of the session."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["markdown", "json"],
                    "description": "Report output format",
                }
            },
            "required": [],
        },
    },
    {
        "name": "restart_broker",
        "description": (
            "Restart the Docker MQTT broker container. Use after a crash or when "
            "the broker becomes unresponsive during fuzzing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]


# ─────────────────────────────────────────────────────────────
# Tool Handler (executes tool calls from Claude)
# ─────────────────────────────────────────────────────────────

class ToolHandler:
    """Handles all tool calls from the LLM agent."""

    def __init__(
        self,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        report_dir: str = "reports",
        log_dir: str = "logs",
    ):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.report_dir = report_dir
        self.log_dir = log_dir

        self.fuzzing_engine = FuzzingEngine(broker_host, broker_port)
        self.attack_runner = AttackRunner(broker_host, broker_port)
        self.docker_mgr = DockerBrokerManager()
        self.analyzer = ResultAnalyzer()
        self.reporter = ReportGenerator(report_dir)

        # Session state
        self.session_start = datetime.now()
        self.tool_calls_log: List[Dict] = []

    def handle(self, tool_name: str, tool_input: Dict) -> str:
        """Dispatch a tool call and return JSON-serializable result string."""
        logger.info(f"Tool call: {tool_name}({tool_input})")

        # Log every tool call for the course deliverable (AI interaction logs)
        self.tool_calls_log.append({
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "input": tool_input,
        })

        try:
            if tool_name == "read_mqtt_spec_section":
                return self._read_spec(tool_input["topic"])
            elif tool_name == "run_fuzz_campaign":
                return self._run_fuzz(tool_input)
            elif tool_name == "run_vulnerability_attack":
                return self._run_attack(tool_input["vulnerability_id"])
            elif tool_name == "run_all_vulnerability_attacks":
                return self._run_all_attacks()
            elif tool_name == "check_broker_health":
                return self._check_health()
            elif tool_name == "get_results_summary":
                return self._get_summary()
            elif tool_name == "generate_poc":
                return self._generate_poc(tool_input["vulnerability_id"])
            elif tool_name == "generate_report":
                return self._generate_report(tool_input.get("format", "markdown"))
            elif tool_name == "restart_broker":
                return self._restart_broker()
            else:
                return json.dumps({"error": f"Unknown tool: {tool_name}"})
        except Exception as e:
            logger.exception(f"Tool {tool_name} raised exception")
            return json.dumps({"error": str(e), "tool": tool_name})

    def _read_spec(self, topic: str) -> str:
        """Return MQTT spec knowledge in structured JSON."""
        data: Dict[str, Any] = {}

        if topic in ("all", "vulnerability_classes"):
            data["vulnerability_classes"] = {
                k: {
                    "name": v["name"],
                    "description": v["description"],
                    "attack_sequence": v["attack_sequence"],
                    "cvss_estimate": v.get("cvss_estimate"),
                }
                for k, v in VULNERABILITY_CLASSES.items()
            }

        if topic in ("all", "packet_types"):
            data["packet_types"] = {
                "CONNECT": {"value": 1, "direction": "client->broker", "description": "Initiate connection"},
                "CONNACK": {"value": 2, "direction": "broker->client", "description": "Connection acknowledgment"},
                "PUBLISH": {"value": 3, "direction": "bidirectional", "description": "Publish message"},
                "SUBSCRIBE": {"value": 8, "direction": "client->broker", "description": "Subscribe to topics"},
                "SUBACK": {"value": 9, "direction": "broker->client", "description": "Subscribe acknowledgment"},
                "PINGREQ": {"value": 12, "direction": "client->broker", "description": "Ping request"},
                "PINGRESP": {"value": 13, "direction": "broker->client", "description": "Ping response"},
                "DISCONNECT": {"value": 14, "direction": "client->broker", "description": "Disconnect"},
            }

        if topic in ("all", "valid_sequences"):
            data["valid_sequences"] = {
                k: [p.name for p in v]
                for k, v in VALID_SEQUENCES.items()
            }

        if topic in ("all", "invalid_sequences"):
            data["invalid_sequences"] = {
                k: [p.name for p in v]
                for k, v in INVALID_SEQUENCES.items()
            }

        if topic in ("all", "connect_fields"):
            spec = MQTT_PACKET_SPECS.get(1, {})  # PacketType.CONNECT = 1
            data["connect_fields"] = {
                name: {
                    "description": f.description,
                    "boundary_values": [str(b)[:50] for b in f.boundary_values[:5]],
                    "required": f.required,
                }
                for name, f in spec.get("fields", {}).items()
            }

        if topic in ("all", "publish_fields"):
            spec = MQTT_PACKET_SPECS.get(3, {})  # PacketType.PUBLISH = 3
            data["publish_fields"] = {
                name: {
                    "description": f.description,
                    "boundary_values": [str(b)[:50] for b in f.boundary_values[:5]],
                }
                for name, f in spec.get("fields", {}).items()
            }

        if not data:
            data["error"] = f"Unknown topic: {topic}. Valid: packet_types, vulnerability_classes, valid_sequences, invalid_sequences, connect_fields, publish_fields, subscribe_fields, anomaly_signatures, all"

        return json.dumps(data, indent=2, default=str)

    def _run_fuzz(self, params: Dict) -> str:
        """Execute fuzzing campaign."""
        mode = params.get("mode", "generation")
        max_cases = params.get("max_cases", 50)
        focus = params.get("focus_vulnerability")

        results = []
        if mode in ("generation", "both"):
            gen_results = self.fuzzing_engine.run_generation_campaign(max_cases)
            results.extend(gen_results)
        if mode in ("mutation", "both"):
            mut_results = self.fuzzing_engine.run_mutation_campaign(n_per_seed=max(10, max_cases // 4))
            results.extend(mut_results)

        stats = self.fuzzing_engine.summary_stats()
        anomalies = self.fuzzing_engine.get_anomalies()

        summary = {
            "mode": mode,
            "statistics": stats,
            "anomalies_found": [
                {
                    "test_name": r.test_case.name,
                    "anomaly_type": r.anomaly_type,
                    "description": r.anomaly_description,
                    "vulnerability_class": r.test_case.vulnerability_class,
                    "broker_alive": r.broker_alive,
                }
                for r in anomalies[:20]  # Top 20
            ],
            "recommendation": self._fuzz_recommendation(stats, anomalies),
        }

        # Feed anomalies to analyzer
        self.analyzer.ingest_fuzz_results(anomalies)

        return json.dumps(summary, indent=2)

    def _fuzz_recommendation(self, stats: Dict, anomalies: List) -> str:
        if stats["crashes"] > 0:
            return "CRITICAL: Broker crashed during fuzzing. Run run_vulnerability_attack for crash-inducing test cases."
        if stats["anomalies"] > 10:
            return f"HIGH: {stats['anomalies']} anomalies detected. Run targeted vulnerability attacks to confirm exploitability."
        if stats["anomalies"] > 0:
            top_vuln = list(set(a.test_case.vulnerability_class for a in anomalies if a.test_case.vulnerability_class))
            if top_vuln:
                return f"MEDIUM: Anomalies suggest testing {top_vuln[0]} specifically."
        return "LOW: No major anomalies. Consider expanding mutation campaign or testing MQTT 5.0 features."

    def _run_attack(self, vuln_id: str) -> str:
        """Run a specific targeted attack."""
        result = self.attack_runner.run_by_id(vuln_id)
        if result is None:
            return json.dumps({"error": f"Unknown vulnerability ID: {vuln_id}"})

        self.analyzer.ingest_attack_result(result)

        return json.dumps({
            "vulnerability_id": result.vulnerability_id,
            "vulnerability_name": result.vulnerability_name,
            "success": result.success,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "reproduction_steps": result.reproduction_steps,
            "error": result.error,
        }, indent=2)

    def _run_all_attacks(self) -> str:
        """Run full attack suite."""
        results = self.attack_runner.run_all()
        self.analyzer.ingest_all_attack_results(results)

        return json.dumps({
            "summary": self.attack_runner.summary(),
            "results": [
                {
                    "id": r.vulnerability_id,
                    "name": r.vulnerability_name,
                    "vulnerable": r.success,
                    "confidence": r.confidence,
                    "evidence_count": len(r.evidence),
                    "top_evidence": r.evidence[:3] if r.evidence else [],
                }
                for r in results
            ],
            "vulnerable_count": self.attack_runner.vulnerable_count(),
            "total_tested": len(results),
        }, indent=2)

    def _check_health(self) -> str:
        """Check broker liveness."""
        from agent.broker.connector import RawMQTTConnection
        conn = RawMQTTConnection(self.broker_host, self.broker_port, timeout=3.0)
        try:
            conn.connect_tcp()
            resp = conn.mqtt_connect("health_check_agent")
            if resp:
                return json.dumps({
                    "alive": True,
                    "connack_return_code": resp.connack_return_code,
                    "connack_rc_meaning": {
                        0: "Connection Accepted",
                        1: "Refused: Unacceptable Protocol Version",
                        2: "Refused: Identifier Rejected",
                        3: "Refused: Server Unavailable",
                        4: "Refused: Bad Username/Password",
                        5: "Refused: Not Authorized",
                    }.get(resp.connack_return_code, f"Unknown (0x{resp.connack_return_code:02X})"),
                    "session_present": resp.connack_session_present,
                    "host": self.broker_host,
                    "port": self.broker_port,
                })
            else:
                return json.dumps({"alive": False, "reason": "No CONNACK received"})
        except Exception as e:
            return json.dumps({"alive": False, "reason": str(e)})
        finally:
            conn.close()

    def _get_summary(self) -> str:
        """Get comprehensive results summary."""
        fuzz_stats = self.fuzzing_engine.summary_stats()
        attack_results = self.attack_runner.results

        confirmed_vulns = [r for r in attack_results if r.success]
        possible_vulns = self.fuzzing_engine.get_anomalies()

        return json.dumps({
            "session_duration": str(datetime.now() - self.session_start),
            "fuzzing": fuzz_stats,
            "targeted_attacks": {
                "total_run": len(attack_results),
                "confirmed_vulnerable": len(confirmed_vulns),
                "confirmed_ids": [r.vulnerability_id for r in confirmed_vulns],
            },
            "fuzz_anomalies": [
                {
                    "name": r.test_case.name,
                    "type": r.anomaly_type,
                    "vuln_class": r.test_case.vulnerability_class,
                }
                for r in possible_vulns[:10]
            ],
            "overall_risk": self._assess_overall_risk(confirmed_vulns, possible_vulns),
        }, indent=2)

    def _assess_overall_risk(self, confirmed: List, anomalies: List) -> str:
        if any(not r.broker_alive for r in self.fuzzing_engine.results):
            return "CRITICAL — broker crashed during testing"
        if len(confirmed) >= 3:
            return "HIGH — multiple confirmed vulnerabilities"
        if len(confirmed) >= 1:
            return "MEDIUM — at least one confirmed vulnerability"
        if len(anomalies) >= 5:
            return "LOW-MEDIUM — multiple anomalies need investigation"
        return "LOW — no confirmed vulnerabilities detected"

    def _generate_poc(self, vuln_id: str) -> str:
        """Generate a PoC Python script for a confirmed vulnerability."""
        result = next((r for r in self.attack_runner.results if r.vulnerability_id == vuln_id), None)

        if result is None:
            return json.dumps({"error": f"No attack result for {vuln_id}. Run the attack first."})
        if not result.success:
            return json.dumps({"warning": f"{vuln_id} was not confirmed vulnerable. PoC may not reproduce."})

        poc = self.reporter.generate_poc_script(result, self.broker_host, self.broker_port)
        poc_path = os.path.join(self.report_dir, f"poc_{vuln_id.lower()}.py")
        os.makedirs(self.report_dir, exist_ok=True)
        with open(poc_path, "w") as f:
            f.write(poc)

        return json.dumps({
            "poc_path": poc_path,
            "vulnerability_id": vuln_id,
            "preview": poc[:500] + "...",
        })

    def _generate_report(self, fmt: str = "markdown") -> str:
        """Generate final report."""
        report = self.reporter.generate(
            fuzz_results=self.fuzzing_engine.get_anomalies(),
            attack_results=self.attack_runner.results,
            fuzz_stats=self.fuzzing_engine.summary_stats(),
            format=fmt,
            session_start=self.session_start,
        )
        ext = "md" if fmt == "markdown" else "json"
        report_path = os.path.join(self.report_dir, f"vulnerability_report.{ext}")
        os.makedirs(self.report_dir, exist_ok=True)
        with open(report_path, "w") as f:
            f.write(report if isinstance(report, str) else json.dumps(report, indent=2))

        # Also save AI interaction logs
        log_path = os.path.join(self.log_dir, "agent_tool_calls.json")
        os.makedirs(self.log_dir, exist_ok=True)
        with open(log_path, "w") as f:
            json.dump(self.tool_calls_log, f, indent=2)

        return json.dumps({
            "report_path": report_path,
            "log_path": log_path,
            "summary": f"Report saved ({len(report) if isinstance(report, str) else 'JSON'} chars). Tool call log saved ({len(self.tool_calls_log)} calls).",
        })

    def _restart_broker(self) -> str:
        """Restart the Docker broker."""
        try:
            success = self.docker_mgr.restart_broker()
            if success:
                time.sleep(2)  # Wait for broker to be ready
                return json.dumps({"success": True, "message": "Broker restarted successfully"})
            return json.dumps({"success": False, "message": "Failed to restart broker"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})


# ─────────────────────────────────────────────────────────────
# Main Agent Class
# ─────────────────────────────────────────────────────────────

class MQTTSecurityAgent:
    """
    The main LLM-powered agent. Uses Claude claude-opus-4-5 via the Anthropic API
    with tool use to autonomously discover vulnerabilities in MQTT brokers.

    Reasoning loop (inspired by FirmAgent):
    1. Agent receives goal: "perform security assessment of broker at host:port"
    2. Agent reads MQTT spec sections to build understanding
    3. Agent runs fuzzing campaign and analyzes results
    4. Agent selects targeted attacks based on findings
    5. Agent confirms vulnerabilities and generates PoCs
    6. Agent generates final report

    The loop continues until the agent decides it has sufficient findings
    or the max_turns limit is reached.
    """

    SYSTEM_PROMPT = """You are an expert IoT security researcher specializing in the MQTT protocol.
Your task is to perform a comprehensive security assessment of an MQTT broker.

You have access to tools that allow you to:
1. Read the MQTT protocol specification and vulnerability database
2. Run automated fuzzing campaigns against the broker
3. Execute targeted vulnerability attacks
4. Generate proof-of-concept scripts
5. Generate vulnerability reports

## Your methodology (follow this order):
1. First, check broker health to confirm connectivity
2. Read the MQTT vulnerability classes to understand what you're testing
3. Run a generation-based fuzzing campaign to identify anomalies
4. Based on fuzzing results, run targeted vulnerability attacks on the most promising classes
5. For any confirmed vulnerabilities, note the evidence and reproduction steps
6. Run all remaining vulnerability attacks to ensure complete coverage
7. Generate a final report

## Important guidelines:
- Be systematic: don't skip steps or rush to conclusions
- Always check broker liveness after fuzzing campaigns (crashes are findings!)
- Cross-reference fuzzing anomalies with known vulnerability classes
- When an attack succeeds, note the exact evidence — it will be included in the report
- If the broker crashes, that is itself a critical finding
- You are testing a LOCAL broker in a controlled research environment — this is authorized

Think step by step, use your tools, and be thorough. You are producing a real security report.
"""

    def __init__(
        self,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        api_key: Optional[str] = None,
        model: str = "claude-opus-4-5",
        max_turns: int = 25,
        report_dir: str = "reports",
        log_dir: str = "logs",
    ):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.model = model
        self.max_turns = max_turns

        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.tool_handler = ToolHandler(broker_host, broker_port, report_dir, log_dir)

        self.conversation: List[Dict] = []
        self.turn_count = 0

        # Full conversation log for course deliverable
        self.full_log: List[Dict] = []
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    def _log(self, role: str, content: Any):
        """Log message to conversation history."""
        self.full_log.append({
            "turn": self.turn_count,
            "timestamp": datetime.now().isoformat(),
            "role": role,
            "content": content if isinstance(content, str) else str(content)[:500],
        })

    def run(self, goal: Optional[str] = None) -> str:
        """
        Run the agent until it completes the assessment or hits max_turns.
        Returns the agent's final message.
        """
        if goal is None:
            goal = (
                f"Perform a comprehensive security assessment of the MQTT broker "
                f"running at {self.broker_host}:{self.broker_port}. "
                f"Find all vulnerabilities you can, generate PoCs for confirmed ones, "
                f"and produce a final report."
            )

        logger.info(f"Starting MQTT Security Agent")
        logger.info(f"Target: {self.broker_host}:{self.broker_port}")
        logger.info(f"Model: {self.model}")
        logger.info(f"Goal: {goal}")

        self.conversation = [{"role": "user", "content": goal}]
        self._log("user", goal)

        final_message = ""

        while self.turn_count < self.max_turns:
            self.turn_count += 1
            logger.info(f"\n{'='*50}\nAgent turn {self.turn_count}/{self.max_turns}\n{'='*50}")

            # Call Claude
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.SYSTEM_PROMPT,
                tools=AGENT_TOOLS,
                messages=self.conversation,
            )

            logger.info(f"Stop reason: {response.stop_reason}")

            # Process response content blocks
            assistant_content = []
            tool_results = []
            has_tool_calls = False

            for block in response.content:
                if block.type == "text":
                    logger.info(f"Agent: {block.text[:200]}{'...' if len(block.text) > 200 else ''}")
                    self._log("assistant_text", block.text)
                    final_message = block.text
                    assistant_content.append({"type": "text", "text": block.text})

                elif block.type == "tool_use":
                    has_tool_calls = True
                    logger.info(f"Tool call: {block.name}({json.dumps(block.input)[:100]})")
                    self._log("tool_call", {"tool": block.name, "input": block.input})

                    assistant_content.append({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

                    # Execute tool
                    tool_result = self.tool_handler.handle(block.name, block.input)
                    logger.info(f"Tool result: {tool_result[:200]}{'...' if len(tool_result) > 200 else ''}")
                    self._log("tool_result", {"tool": block.name, "result": tool_result[:200]})

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": tool_result,
                    })

            # Add assistant turn to conversation
            self.conversation.append({"role": "assistant", "content": assistant_content})

            # If there were tool calls, add results and continue
            if has_tool_calls and tool_results:
                self.conversation.append({"role": "user", "content": tool_results})
            elif response.stop_reason == "end_turn":
                # Agent finished naturally
                logger.info("Agent completed assessment.")
                break

        # Save full conversation log
        self._save_logs()

        return final_message

    def _save_logs(self):
        """Save all logs for course deliverables."""
        # Full conversation log
        conv_path = os.path.join(self.log_dir, "full_conversation_log.json")
        with open(conv_path, "w") as f:
            json.dump(self.full_log, f, indent=2)

        # Tool calls log
        tool_path = os.path.join(self.log_dir, "tool_calls.json")
        with open(tool_path, "w") as f:
            json.dump(self.tool_handler.tool_calls_log, f, indent=2)

        logger.info(f"Logs saved: {conv_path}, {tool_path}")
        logger.info(f"Agent turns: {self.turn_count}")
        logger.info(f"Tool calls: {len(self.tool_handler.tool_calls_log)}")
