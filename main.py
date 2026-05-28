#!/usr/bin/env python3
"""
MQTT Security Agent — Entry Point
UCLA ECE 202C IoT Security Final Project

Usage:
  python main.py                          # Full autonomous agent run
  python main.py --fuzz-only              # Fuzzing only, no LLM agent
  python main.py --attack-only            # Targeted attacks only
  python main.py --setup                  # Start Docker broker and exit
  python main.py --host 192.168.1.10      # Target a remote broker
  python main.py --vuln V3_CLIENTID_HIJACKING  # Test one vulnerability
"""

import os
import sys
import logging
import argparse
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ─────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────

def setup_logging(log_dir: str = "logs", verbose: bool = False):
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file),
        ]
    )
    return log_file


# ─────────────────────────────────────────────────────────────
# Rich console output
# ─────────────────────────────────────────────────────────────

def print_banner():
    try:
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel.fit(
            "[bold red]MQTT Security Agent[/bold red]\n"
            "[dim]UCLA ECE 202C — IoT Security Final Project[/dim]\n"
            "[dim]Inspired by: FUME · MGPTFuzz · MQTTactic · Burglars' IoT Paradise · FirmAgent[/dim]",
            border_style="red",
        ))
    except ImportError:
        print("=" * 60)
        print("MQTT Security Agent")
        print("UCLA ECE 202C — IoT Security Final Project")
        print("=" * 60)


# ─────────────────────────────────────────────────────────────
# Modes
# ─────────────────────────────────────────────────────────────

def run_full_agent(args):
    """Run the full LLM-powered agent."""
    from agent.core.agent import MQTTSecurityAgent
    from agent.analysis.visualizer import (
        generate_all_figures,
        print_vulnerability_table,
        print_fuzzing_stats,
        print_final_summary,
    )
    import json

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set in environment or .env file")
        sys.exit(1)

    agent = MQTTSecurityAgent(
        broker_host=args.host,
        broker_port=args.port,
        api_key=api_key,
        model=args.model,
        max_turns=args.max_turns,
        report_dir=args.report_dir,
        log_dir=args.log_dir,
    )

    print(f"\nStarting autonomous agent against {args.host}:{args.port}")
    print(f"Model: {args.model} | Max turns: {args.max_turns}\n")

    final_msg = agent.run()

    # ── Post-run: statistics + figures ──
    handler = agent.tool_handler
    fuzz_stats   = handler.fuzzing_engine.summary_stats()
    fuzz_results = handler.fuzzing_engine.get_anomalies()
    attack_results = handler.attack_runner.results

    print_fuzzing_stats(fuzz_stats, fuzz_results)
    print_vulnerability_table(attack_results)

    figures = generate_all_figures(
        fuzz_results=fuzz_results,
        attack_results=attack_results,
        fuzz_stats=fuzz_stats,
        tool_calls_log=handler.tool_calls_log,
        figures_dir=os.path.join(args.report_dir, "figures"),
    )

    print_final_summary(fuzz_stats, attack_results, figures, args.log_dir, args.report_dir)

    print("\nAgent final message:")
    print("─" * 60)
    print(final_msg)
    print("─" * 60)


def run_fuzz_only(args):
    """Run fuzzing campaign without the LLM agent."""
    from agent.fuzzing.engine import FuzzingEngine
    from agent.analysis.visualizer import (
        generate_all_figures, print_fuzzing_stats, print_final_summary
    )

    print(f"\nRunning fuzzing campaign against {args.host}:{args.port}")
    engine = FuzzingEngine(args.host, args.port)

    if args.mode in ("generation", "both"):
        print("\n[Phase 1] Generation-based fuzzing...")
        engine.run_generation_campaign(max_cases=args.max_cases)

    if args.mode in ("mutation", "both"):
        print("\n[Phase 2] Mutation-based fuzzing...")
        engine.run_mutation_campaign()

    stats = engine.summary_stats()
    anomalies = engine.get_anomalies()

    print_fuzzing_stats(stats, anomalies)

    if anomalies:
        print("\nTop anomalies:")
        for a in anomalies[:20]:
            print(f"  [{a.anomaly_type}] {a.test_case.name}")
            if a.anomaly_description:
                print(f"    → {a.anomaly_description}")

    figures = generate_all_figures(
        fuzz_results=anomalies,
        attack_results=[],
        fuzz_stats=stats,
        tool_calls_log=[],
        figures_dir=os.path.join(args.report_dir, "figures"),
    )
    print_final_summary(stats, [], figures, args.log_dir, args.report_dir)


def run_attacks_only(args):
    """Run targeted vulnerability attacks without fuzzing."""
    from agent.vulnerabilities.attacks import AttackRunner
    from agent.analysis.visualizer import (
        generate_all_figures, print_vulnerability_table, print_final_summary
    )

    runner = AttackRunner(args.host, args.port)

    if args.vuln:
        print(f"\nRunning targeted attack: {args.vuln}")
        result = runner.run_by_id(args.vuln)
        if result:
            print(result)
        else:
            print(f"Unknown vulnerability ID: {args.vuln}")
            print("Valid IDs:", ", ".join([
                "V1_UNAUTHORIZED_WILL", "V2_UNAUTHORIZED_RETAIN",
                "V3_CLIENTID_HIJACKING", "V4_TOPIC_AUTH_BYPASS",
                "V5_QOS2_TIMING", "V6_SYS_TOPIC_EXPOSURE",
                "V7_ZERO_LENGTH_CLIENTID",
            ]))
    else:
        print(f"\nRunning all vulnerability attacks against {args.host}:{args.port}")
        runner.run_all()
        print_vulnerability_table(runner.results)

        figures = generate_all_figures(
            fuzz_results=[],
            attack_results=runner.results,
            fuzz_stats={"total_tests": 0, "anomalies": 0, "crashes": 0, "anomaly_rate": "0%"},
            tool_calls_log=[],
            figures_dir=os.path.join(args.report_dir, "figures"),
        )
        print_final_summary(
            {"total_tests": 0, "anomalies": 0, "crashes": 0, "anomaly_rate": "0%"},
            runner.results, figures, args.log_dir, args.report_dir
        )


def run_setup(args):
    """Start Docker broker and verify connectivity."""
    from agent.broker.docker_mgr import DockerBrokerManager
    from agent.broker.connector import RawMQTTConnection

    print("Setting up broker environment...")
    mgr = DockerBrokerManager()

    if mgr.is_container_running():
        print("✅ Broker container already running")
    else:
        print("Starting broker container...")
        success = mgr.start_broker(wait_seconds=3.0)
        if success:
            print("✅ Broker container started")
        else:
            print("❌ Failed to start broker. Is Docker running?")
            print("   Try: cd docker && docker compose up -d")
            sys.exit(1)

    # Verify MQTT connectivity
    print(f"Testing MQTT connectivity to {args.host}:{args.port}...")
    conn = RawMQTTConnection(args.host, args.port, timeout=5.0)
    conn.connect_tcp()
    resp = conn.mqtt_connect("setup_test_client")
    conn.close()

    if resp and resp.connack_return_code == 0:
        print(f"✅ MQTT broker responding (CONNACK 0x00)")
        print(f"\nBroker is ready. Run: python main.py")
    else:
        rc = resp.connack_return_code if resp else "NO RESPONSE"
        print(f"❌ MQTT connection issue (CONNACK: {rc})")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="MQTT Security Agent — UCLA ECE 202C IoT Security Final Project"
    )
    parser.add_argument("--host", default="localhost", help="Broker host (default: localhost)")
    parser.add_argument("--port", type=int, default=1883, help="Broker port (default: 1883)")
    parser.add_argument("--model", default="claude-opus-4-5", help="Claude model to use")
    parser.add_argument("--max-turns", type=int, default=25, help="Max agent turns")
    parser.add_argument("--max-cases", type=int, default=50, help="Max fuzzing test cases")
    parser.add_argument("--mode", choices=["generation", "mutation", "both"], default="both")
    parser.add_argument("--report-dir", default="reports", help="Report output directory")
    parser.add_argument("--log-dir", default="logs", help="Log output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    # Modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--fuzz-only", action="store_true", help="Run fuzzing only")
    mode_group.add_argument("--attack-only", action="store_true", help="Run attacks only")
    mode_group.add_argument("--setup", action="store_true", help="Setup broker environment")
    parser.add_argument("--vuln", help="Specific vulnerability ID to test (with --attack-only)")

    return parser.parse_args()


def main():
    args = parse_args()
    log_file = setup_logging(args.log_dir, args.verbose)
    print_banner()
    print(f"Log file: {log_file}")

    if args.setup:
        run_setup(args)
    elif args.fuzz_only:
        run_fuzz_only(args)
    elif args.attack_only:
        run_attacks_only(args)
    else:
        run_full_agent(args)


if __name__ == "__main__":
    main()
