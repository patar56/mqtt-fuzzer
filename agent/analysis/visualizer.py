"""
Visualization Module

Generates matplotlib figures and rich terminal tables summarizing
the security assessment results.

Figures produced (saved to reports/figures/):
  fig1_vulnerability_scorecard.png  — CVSS + confirmed/not per vulnerability class
  fig2_fuzzing_statistics.png       — anomaly type breakdown from fuzzing campaign
  fig3_packet_coverage.png          — which MQTT packet types were exercised
  fig4_agent_timeline.png           — agent tool call timeline (Gantt-style)
  fig5_attack_summary.png           — attack outcomes (confirmed / safe / error)
  fig6_risk_matrix.png              — likelihood vs impact 2×2 grid

Rich terminal figures:
  - Live vulnerability table
  - Fuzzing stats panel
  - Final findings panel
"""

import os
import json
from typing import List, Dict, Optional, Any
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Matplotlib (safe import — falls back gracefully if headless)
# ─────────────────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend — saves to file, no display needed
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import matplotlib.gridspec as gridspec
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

# ─────────────────────────────────────────────────────────────
# Rich (terminal output)
# ─────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich.bar import Bar
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ─────────────────────────────────────────────────────────────
# Security color theme
# ─────────────────────────────────────────────────────────────
COLORS = {
    "critical": "#FF2D55",
    "high":     "#FF6B35",
    "medium":   "#FFB400",
    "low":      "#34C759",
    "info":     "#5AC8FA",
    "neutral":  "#8E8E93",
    "bg":       "#1C1C1E",
    "grid":     "#2C2C2E",
    "text":     "#F2F2F7",
}

VULN_SEVERITY = {
    "V1_UNAUTHORIZED_WILL":    ("HIGH",     7.5),
    "V2_UNAUTHORIZED_RETAIN":  ("MEDIUM",   6.5),
    "V3_CLIENTID_HIJACKING":   ("HIGH",     8.1),
    "V4_TOPIC_AUTH_BYPASS":    ("HIGH",     7.2),
    "V5_QOS2_TIMING":          ("MEDIUM",   5.3),
    "V6_SYS_TOPIC_EXPOSURE":   ("LOW",      4.3),
    "V7_ZERO_LENGTH_CLIENTID": ("MEDIUM",   6.0),
    "V8_WILL_DELAY_EXPLOIT":   ("LOW",      5.0),
}

SEVERITY_COLOR = {
    "CRITICAL": COLORS["critical"],
    "HIGH":     COLORS["high"],
    "MEDIUM":   COLORS["medium"],
    "LOW":      COLORS["low"],
    "INFO":     COLORS["info"],
}


def _setup_dark_style():
    """Apply dark security-themed matplotlib style."""
    plt.rcParams.update({
        "figure.facecolor":  COLORS["bg"],
        "axes.facecolor":    COLORS["bg"],
        "axes.edgecolor":    COLORS["grid"],
        "axes.labelcolor":   COLORS["text"],
        "axes.titlecolor":   COLORS["text"],
        "text.color":        COLORS["text"],
        "xtick.color":       COLORS["text"],
        "ytick.color":       COLORS["text"],
        "grid.color":        COLORS["grid"],
        "grid.alpha":        0.5,
        "font.family":       "monospace",
        "axes.spines.top":   False,
        "axes.spines.right": False,
    })


def _save(fig, path: str):
    fig.savefig(path, bbox_inches="tight", dpi=150, facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  Saved: {path}")


# ═══════════════════════════════════════════════════════════════
# Figure 1: Vulnerability Scorecard
# ═══════════════════════════════════════════════════════════════

def fig1_vulnerability_scorecard(attack_results: List, out_path: str):
    """
    Horizontal bar chart: each vulnerability class with its CVSS score,
    colored by severity, with CONFIRMED / SAFE / NOT-RUN overlay.
    """
    if not HAS_MPL:
        return
    _setup_dark_style()

    vulns = list(VULN_SEVERITY.keys())
    labels = [v.replace("_", " ") for v in vulns]
    cvss_scores = [VULN_SEVERITY[v][1] for v in vulns]
    severities = [VULN_SEVERITY[v][0] for v in vulns]
    bar_colors = [SEVERITY_COLOR.get(s, COLORS["neutral"]) for s in severities]

    # Map attack results
    result_map = {r.vulnerability_id: r for r in attack_results}

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.suptitle("MQTT Vulnerability Scorecard — CVSS Base Scores",
                 fontsize=14, fontweight="bold", color=COLORS["text"], y=1.02)

    y_pos = list(range(len(vulns)))
    bars = ax.barh(y_pos, cvss_scores, color=bar_colors, alpha=0.85, height=0.6, zorder=3)

    # Overlay status badges
    for i, vid in enumerate(vulns):
        result = result_map.get(vid)
        if result is None:
            badge, badge_color = "NOT RUN", COLORS["neutral"]
        elif result.success:
            badge, badge_color = "VULNERABLE ⚠", COLORS["critical"]
        else:
            badge, badge_color = "SAFE ✓", COLORS["low"]

        ax.text(cvss_scores[i] + 0.1, i, f" {badge}", va="center",
                fontsize=9, color=badge_color, fontweight="bold")
        ax.text(-0.1, i, f"{cvss_scores[i]:.1f}", va="center", ha="right",
                fontsize=10, color=COLORS["text"], fontweight="bold")

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("CVSS v3.1 Base Score", fontsize=10)
    ax.set_xlim(0, 11)
    ax.axvline(x=7.0, color=COLORS["high"], linestyle="--", alpha=0.5, linewidth=1, label="High threshold (7.0)")
    ax.axvline(x=4.0, color=COLORS["medium"], linestyle="--", alpha=0.5, linewidth=1, label="Medium threshold (4.0)")
    ax.grid(axis="x", zorder=0)
    ax.legend(loc="lower right", fontsize=8)

    # Legend for severity
    patches = [
        mpatches.Patch(color=COLORS["high"], label="HIGH"),
        mpatches.Patch(color=COLORS["medium"], label="MEDIUM"),
        mpatches.Patch(color=COLORS["low"], label="LOW"),
    ]
    ax.legend(handles=patches, loc="lower right", fontsize=8)

    plt.tight_layout()
    _save(fig, out_path)


# ═══════════════════════════════════════════════════════════════
# Figure 2: Fuzzing Statistics
# ═══════════════════════════════════════════════════════════════

def fig2_fuzzing_statistics(fuzz_results: List, fuzz_stats: Dict, out_path: str):
    """
    Left: stacked bar of anomaly types.
    Right: pie chart of test outcomes (normal / anomaly / crash).
    """
    if not HAS_MPL:
        return
    _setup_dark_style()

    fig, (ax_bar, ax_pie) = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Fuzzing Campaign Statistics", fontsize=14,
                 fontweight="bold", color=COLORS["text"])

    # — Left: anomaly type breakdown —
    type_counts: Dict[str, int] = {}
    vuln_class_counts: Dict[str, int] = {}

    for r in fuzz_results:
        atype = r.anomaly_type or "UNKNOWN"
        type_counts[atype] = type_counts.get(atype, 0) + 1
        vc = r.test_case.vulnerability_class or "General"
        vuln_class_counts[vc] = vuln_class_counts.get(vc, 0) + 1

    if type_counts:
        anomaly_colors = [
            COLORS["critical"] if "CRASH" in k else
            COLORS["high"] if "SPEC" in k else
            COLORS["medium"] if "NO_RESPONSE" in k else
            COLORS["info"]
            for k in type_counts
        ]
        ax_bar.barh(list(type_counts.keys()), list(type_counts.values()),
                    color=anomaly_colors, alpha=0.85, height=0.5, zorder=3)
        ax_bar.set_xlabel("Count", fontsize=10)
        ax_bar.set_title("Anomaly Types Detected", fontsize=11, pad=10)
        ax_bar.grid(axis="x", zorder=0)
        for i, (k, v) in enumerate(type_counts.items()):
            ax_bar.text(v + 0.1, i, str(v), va="center", fontsize=9, color=COLORS["text"])
    else:
        ax_bar.text(0.5, 0.5, "No anomalies detected", ha="center", va="center",
                    transform=ax_bar.transAxes, fontsize=12, color=COLORS["neutral"])
        ax_bar.set_title("Anomaly Types Detected", fontsize=11)

    # — Right: outcome pie chart —
    total = fuzz_stats.get("total_tests", 1)
    anomalies = fuzz_stats.get("anomalies", 0)
    crashes = fuzz_stats.get("crashes", 0)
    normal = max(0, total - anomalies)

    sizes = [normal, max(0, anomalies - crashes), crashes]
    labels = [f"Normal\n({normal})", f"Anomaly\n({max(0, anomalies-crashes)})", f"Crash\n({crashes})"]
    pie_colors = [COLORS["low"], COLORS["medium"], COLORS["critical"]]
    explode = [0, 0.05, 0.1]

    non_zero = [(s, l, c, e) for s, l, c, e in zip(sizes, labels, pie_colors, explode) if s > 0]
    if non_zero:
        s_, l_, c_, e_ = zip(*non_zero)
        wedges, texts, autotexts = ax_pie.pie(
            s_, labels=l_, colors=c_, explode=e_,
            autopct="%1.1f%%", startangle=90,
            textprops={"color": COLORS["text"], "fontsize": 9},
            pctdistance=0.75,
        )
        for at in autotexts:
            at.set_color(COLORS["bg"])
            at.set_fontweight("bold")

    ax_pie.set_title(f"Test Outcome Distribution\n(n={total} tests)", fontsize=11, pad=10)

    plt.tight_layout()
    _save(fig, out_path)


# ═══════════════════════════════════════════════════════════════
# Figure 3: MQTT Packet Type Coverage
# ═══════════════════════════════════════════════════════════════

def fig3_packet_coverage(fuzz_results: List, out_path: str):
    """
    Donut chart showing which MQTT packet types were exercised in fuzzing.
    """
    if not HAS_MPL:
        return
    _setup_dark_style()

    # Count how many test cases included each packet type
    from agent.spec.mqtt_spec import PacketType
    from agent.broker.connector import build_connect, build_publish, build_subscribe

    type_counts: Dict[str, int] = {
        "CONNECT": 0, "PUBLISH": 0, "SUBSCRIBE": 0,
        "PINGREQ": 0, "DISCONNECT": 0, "PUBREL": 0, "Malformed": 0,
    }

    for r in fuzz_results:
        name = r.test_case.name.lower()
        if "connect" in name:
            type_counts["CONNECT"] += 1
        if "publish" in name or "retain" in name or "qos" in name:
            type_counts["PUBLISH"] += 1
        if "subscribe" in name or "wildcard" in name:
            type_counts["SUBSCRIBE"] += 1
        if "pubrel" in name:
            type_counts["PUBREL"] += 1
        if "malformed" in name or "truncat" in name:
            type_counts["Malformed"] += 1

    # Remove zeros
    type_counts = {k: v for k, v in type_counts.items() if v > 0}

    fig, (ax_donut, ax_bar) = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("MQTT Protocol Coverage — Packet Types Tested",
                 fontsize=14, fontweight="bold", color=COLORS["text"])

    colors_cycle = [
        COLORS["critical"], COLORS["high"], COLORS["medium"],
        COLORS["low"], COLORS["info"], "#AF52DE", "#FF9F0A"
    ]

    if type_counts:
        wedges, texts, autos = ax_donut.pie(
            list(type_counts.values()),
            labels=list(type_counts.keys()),
            colors=colors_cycle[:len(type_counts)],
            autopct="%1.0f%%",
            startangle=140,
            pctdistance=0.75,
            wedgeprops=dict(width=0.55),
            textprops={"color": COLORS["text"], "fontsize": 9},
        )
        for at in autos:
            at.set_color(COLORS["bg"])
            at.set_fontweight("bold")
        ax_donut.set_title("By Test Case Count", fontsize=11, pad=10)

    # Right: all MQTT packet types with coverage indicator
    all_types = [
        ("CONNECT", True), ("CONNACK", False), ("PUBLISH", True),
        ("PUBACK", False), ("PUBREC", False), ("PUBREL", True),
        ("PUBCOMP", False), ("SUBSCRIBE", True), ("SUBACK", False),
        ("UNSUBSCRIBE", False), ("UNSUBACK", False),
        ("PINGREQ", True), ("PINGRESP", False), ("DISCONNECT", True), ("AUTH", False),
    ]
    names = [t[0] for t in all_types]
    tested = [type_counts.get(t[0], 0) for t in all_types]
    bar_c = [COLORS["low"] if t[1] else COLORS["grid"] for t in all_types]

    ax_bar.barh(names, [1 if c > 0 else 0.1 for c in tested],
                color=bar_c, alpha=0.85, height=0.6)
    ax_bar.set_xlim(0, 1.4)
    ax_bar.set_xlabel("Tested (green) / Not tested (gray)", fontsize=9)
    ax_bar.set_title("All MQTT Packet Types", fontsize=11, pad=10)
    ax_bar.set_xticks([])
    ax_bar.grid(axis="x", zorder=0, alpha=0.2)

    plt.tight_layout()
    _save(fig, out_path)


# ═══════════════════════════════════════════════════════════════
# Figure 4: Agent Tool Call Timeline
# ═══════════════════════════════════════════════════════════════

def fig4_agent_timeline(tool_calls_log: List[Dict], out_path: str):
    """
    Horizontal Gantt-style chart of the agent's tool calls over time.
    Shows the agent's reasoning sequence visually.
    """
    if not HAS_MPL or not tool_calls_log:
        return
    _setup_dark_style()

    # Parse timestamps
    events = []
    t0 = None
    for call in tool_calls_log:
        try:
            t = datetime.fromisoformat(call["timestamp"])
            if t0 is None:
                t0 = t
            elapsed = (t - t0).total_seconds()
            events.append({
                "tool": call["tool"],
                "elapsed": elapsed,
                "turn": call.get("turn", 0),
            })
        except Exception:
            continue

    if not events:
        return

    TOOL_COLORS = {
        "check_broker_health":         COLORS["info"],
        "read_mqtt_spec_section":      "#AF52DE",
        "run_fuzz_campaign":           COLORS["medium"],
        "run_vulnerability_attack":    COLORS["high"],
        "run_all_vulnerability_attacks": COLORS["critical"],
        "get_results_summary":         COLORS["low"],
        "generate_poc":                COLORS["high"],
        "generate_report":             COLORS["low"],
        "restart_broker":              COLORS["critical"],
    }

    fig, ax = plt.subplots(figsize=(14, max(4, len(events) * 0.45 + 1)))
    fig.suptitle("Agent Tool Call Timeline — Reasoning Sequence",
                 fontsize=14, fontweight="bold", color=COLORS["text"])

    tool_names = []
    for i, ev in enumerate(events):
        tool = ev["tool"]
        t = ev["elapsed"]
        color = TOOL_COLORS.get(tool, COLORS["neutral"])
        ax.broken_barh([(t, 0.8)], (i - 0.3, 0.6), facecolors=color, alpha=0.85, zorder=3)
        ax.text(t + 0.5, i, f"Turn {ev['turn']+1}: {tool}", va="center",
                fontsize=8, color=COLORS["text"])
        tool_names.append(f"{i+1}. {tool}")

    ax.set_yticks(range(len(events)))
    ax.set_yticklabels([f"Call {i+1}" for i in range(len(events))], fontsize=8)
    ax.set_xlabel("Time elapsed (seconds)", fontsize=10)
    ax.set_title(f"Total tool calls: {len(events)}", fontsize=10, pad=8)
    ax.grid(axis="x", zorder=0)

    # Legend
    seen_tools = list(dict.fromkeys(ev["tool"] for ev in events))
    patches = [mpatches.Patch(color=TOOL_COLORS.get(t, COLORS["neutral"]), label=t)
               for t in seen_tools]
    ax.legend(handles=patches, loc="lower right", fontsize=7, ncol=2)

    plt.tight_layout()
    _save(fig, out_path)


# ═══════════════════════════════════════════════════════════════
# Figure 5: Attack Results Summary
# ═══════════════════════════════════════════════════════════════

def fig5_attack_summary(attack_results: List, out_path: str):
    """
    Grouped horizontal bar showing VULNERABLE / SAFE for each attack,
    with confidence badges.
    """
    if not HAS_MPL:
        return
    _setup_dark_style()

    fig, ax = plt.subplots(figsize=(11, 5))
    fig.suptitle("Targeted Vulnerability Attack Results",
                 fontsize=14, fontweight="bold", color=COLORS["text"])

    y_pos = list(range(len(attack_results)))
    for i, r in enumerate(attack_results):
        color = COLORS["critical"] if r.success else COLORS["low"]
        score = VULN_SEVERITY.get(r.vulnerability_id, ("MEDIUM", 5.0))[1]
        ax.barh(i, score, color=color, alpha=0.8, height=0.55, zorder=3)

        # Status label
        status = f"VULNERABLE [{r.confidence}]" if r.success else f"SAFE [{r.confidence}]"
        ax.text(score + 0.1, i, status, va="center", fontsize=9,
                color=color, fontweight="bold")

    labels = [r.vulnerability_id.replace("_", " ") for r in attack_results]
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("CVSS Score", fontsize=10)
    ax.set_xlim(0, 12)
    ax.axvline(x=7.0, color=COLORS["high"], linestyle="--", alpha=0.5, linewidth=1)
    ax.grid(axis="x", zorder=0)

    legend = [
        mpatches.Patch(color=COLORS["critical"], label="VULNERABLE"),
        mpatches.Patch(color=COLORS["low"], label="SAFE"),
    ]
    ax.legend(handles=legend, loc="lower right", fontsize=9)

    plt.tight_layout()
    _save(fig, out_path)


# ═══════════════════════════════════════════════════════════════
# Figure 6: Risk Matrix
# ═══════════════════════════════════════════════════════════════

def fig6_risk_matrix(attack_results: List, out_path: str):
    """
    2D risk matrix: Likelihood (x) vs Impact (y) with each vulnerability
    plotted as a labeled dot.
    """
    if not HAS_MPL:
        return
    _setup_dark_style()

    # Likelihood = 1 (not confirmed) / 3 (confirmed) + noise for readability
    # Impact = CVSS base score / 2 (normalized to 5)
    import random
    rng = random.Random(42)

    fig, ax = plt.subplots(figsize=(10, 8))
    fig.suptitle("Risk Matrix — MQTT Vulnerability Landscape",
                 fontsize=14, fontweight="bold", color=COLORS["text"])

    # Background quadrants
    ax.fill_between([0, 2.5], [0, 0], [2.5, 2.5], alpha=0.08, color=COLORS["low"])
    ax.fill_between([0, 2.5], [2.5, 2.5], [5, 5], alpha=0.08, color=COLORS["medium"])
    ax.fill_between([2.5, 5], [0, 0], [2.5, 2.5], alpha=0.08, color=COLORS["medium"])
    ax.fill_between([2.5, 5], [2.5, 2.5], [5, 5], alpha=0.08, color=COLORS["critical"])

    result_map = {r.vulnerability_id: r for r in attack_results}

    for vid, (severity, cvss) in VULN_SEVERITY.items():
        impact = cvss / 2.0  # normalize to 0-5
        result = result_map.get(vid)
        likelihood = rng.uniform(2.5, 4.5) if (result and result.success) else rng.uniform(0.5, 2.4)

        color = SEVERITY_COLOR.get(severity, COLORS["neutral"])
        marker = "D" if (result and result.success) else "o"
        size = 180 if (result and result.success) else 120

        ax.scatter(likelihood, impact, c=color, s=size, marker=marker,
                   zorder=5, edgecolors="white", linewidth=0.5, alpha=0.9)
        short = vid.replace("V", "").split("_")[0] + "_" + "_".join(vid.split("_")[1:3])[:8]
        ax.annotate(vid.replace("_UNAUTHORIZED", "").replace("_", " ")[:18],
                    (likelihood, impact),
                    xytext=(6, 4), textcoords="offset points",
                    fontsize=7, color=COLORS["text"], alpha=0.9)

    ax.set_xlim(0, 5)
    ax.set_ylim(0, 5)
    ax.set_xlabel("Likelihood (confirmed = right, unconfirmed = left)", fontsize=10)
    ax.set_ylabel("Impact (CVSS / 2)", fontsize=10)
    ax.axhline(y=2.5, color=COLORS["grid"], linestyle="--", alpha=0.4)
    ax.axvline(x=2.5, color=COLORS["grid"], linestyle="--", alpha=0.4)
    ax.text(0.5, 4.7, "MEDIUM RISK", fontsize=8, color=COLORS["medium"], alpha=0.6)
    ax.text(3.0, 4.7, "HIGH RISK", fontsize=8, color=COLORS["critical"], alpha=0.6)
    ax.text(0.5, 0.2, "LOW RISK", fontsize=8, color=COLORS["low"], alpha=0.6)
    ax.text(3.0, 0.2, "MEDIUM RISK", fontsize=8, color=COLORS["medium"], alpha=0.6)
    ax.grid(zorder=0, alpha=0.2)

    legend = [
        mpatches.Patch(color=COLORS["critical"], label="VULNERABLE (diamond)"),
        mpatches.Patch(color=COLORS["neutral"], label="SAFE / Not Run (circle)"),
    ]
    ax.legend(handles=legend, loc="upper left", fontsize=8)

    plt.tight_layout()
    _save(fig, out_path)


# ═══════════════════════════════════════════════════════════════
# Master: generate all figures
# ═══════════════════════════════════════════════════════════════

def generate_all_figures(
    fuzz_results: List,
    attack_results: List,
    fuzz_stats: Dict,
    tool_calls_log: List[Dict],
    figures_dir: str = "reports/figures",
) -> List[str]:
    """
    Generate all 6 figures. Returns list of saved file paths.
    """
    os.makedirs(figures_dir, exist_ok=True)

    if not HAS_MPL:
        print("  [figures] matplotlib not available — skipping figure generation")
        return []

    print("\nGenerating figures...")
    saved = []

    paths = {
        "fig1": os.path.join(figures_dir, "fig1_vulnerability_scorecard.png"),
        "fig2": os.path.join(figures_dir, "fig2_fuzzing_statistics.png"),
        "fig3": os.path.join(figures_dir, "fig3_packet_coverage.png"),
        "fig4": os.path.join(figures_dir, "fig4_agent_timeline.png"),
        "fig5": os.path.join(figures_dir, "fig5_attack_summary.png"),
        "fig6": os.path.join(figures_dir, "fig6_risk_matrix.png"),
    }

    fig1_vulnerability_scorecard(attack_results, paths["fig1"])
    saved.append(paths["fig1"])

    fig2_fuzzing_statistics(fuzz_results, fuzz_stats, paths["fig2"])
    saved.append(paths["fig2"])

    fig3_packet_coverage(fuzz_results, paths["fig3"])
    saved.append(paths["fig3"])

    if tool_calls_log:
        fig4_agent_timeline(tool_calls_log, paths["fig4"])
        saved.append(paths["fig4"])

    if attack_results:
        fig5_attack_summary(attack_results, paths["fig5"])
        saved.append(paths["fig5"])

        fig6_risk_matrix(attack_results, paths["fig6"])
        saved.append(paths["fig6"])

    print(f"  {len(saved)} figures saved to {figures_dir}/")
    return saved


# ═══════════════════════════════════════════════════════════════
# Rich Terminal Output
# ═══════════════════════════════════════════════════════════════

def print_vulnerability_table(attack_results: List):
    """Print a color-coded vulnerability table to the terminal."""
    if not HAS_RICH:
        _plain_vuln_table(attack_results)
        return

    console = Console()
    table = Table(
        title="[bold red]Vulnerability Assessment Results[/bold red]",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=True,
    )
    table.add_column("ID", style="dim", width=28)
    table.add_column("Vulnerability", width=32)
    table.add_column("Status", justify="center", width=16)
    table.add_column("Confidence", justify="center", width=12)
    table.add_column("CVSS", justify="right", width=6)

    severity_style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green"}

    for r in attack_results:
        sev, cvss = VULN_SEVERITY.get(r.vulnerability_id, ("MEDIUM", 5.0))
        style = severity_style.get(sev, "white")

        if r.success:
            status = "[bold red]VULNERABLE ⚠[/bold red]"
        else:
            status = "[bold green]  SAFE ✓  [/bold green]"

        conf_style = "green" if r.confidence == "HIGH" else "yellow" if r.confidence == "MEDIUM" else "dim"
        table.add_row(
            f"[{style}]{r.vulnerability_id}[/{style}]",
            r.vulnerability_name[:32],
            status,
            f"[{conf_style}]{r.confidence}[/{conf_style}]",
            f"[{style}]{cvss}[/{style}]",
        )

    console.print()
    console.print(table)


def print_fuzzing_stats(fuzz_stats: Dict, fuzz_results: List):
    """Print fuzzing statistics panel to terminal."""
    if not HAS_RICH:
        _plain_fuzz_stats(fuzz_stats)
        return

    console = Console()

    total = fuzz_stats.get("total_tests", 0)
    anomalies = fuzz_stats.get("anomalies", 0)
    crashes = fuzz_stats.get("crashes", 0)
    rate = fuzz_stats.get("anomaly_rate", "0%")

    # Stats table
    stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats_table.add_column("Metric", style="dim")
    stats_table.add_column("Value", justify="right")
    stats_table.add_row("Total Tests", f"[bold]{total}[/bold]")
    stats_table.add_row("Anomalies", f"[bold yellow]{anomalies}[/bold yellow]")
    stats_table.add_row("Crashes", f"[bold red]{crashes}[/bold red]" if crashes else f"[bold green]{crashes}[/bold green]")
    stats_table.add_row("Anomaly Rate", f"[bold]{rate}[/bold]")

    # Anomaly type breakdown
    by_type = fuzz_stats.get("anomaly_types", {})
    type_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    type_table.add_column("Anomaly Type", style="dim")
    type_table.add_column("Count", justify="right")
    for atype, count in sorted(by_type.items(), key=lambda x: -x[1]):
        color = "red" if "CRASH" in atype else "yellow" if "SPEC" in atype else "cyan"
        type_table.add_row(f"[{color}]{atype}[/{color}]", str(count))

    console.print()
    console.print(Panel(
        Columns([stats_table, type_table]),
        title="[bold cyan]Fuzzing Campaign Statistics[/bold cyan]",
        border_style="cyan",
    ))


def print_final_summary(fuzz_stats: Dict, attack_results: List, figures: List[str], log_dir: str, report_dir: str):
    """Print the final summary panel after the full run."""
    if not HAS_RICH:
        _plain_final_summary(fuzz_stats, attack_results, figures)
        return

    console = Console()
    confirmed = [r for r in attack_results if r.success]

    # Top section: overall verdict
    verdict_color = "red" if confirmed else "green"
    verdict_text = (
        f"[bold red]{len(confirmed)} VULNERABILITIES CONFIRMED[/bold red]"
        if confirmed
        else "[bold green]NO VULNERABILITIES CONFIRMED[/bold green]"
    )

    # Deliverables table
    deliverables = Table(box=box.ROUNDED, title="[bold]Course Deliverables Generated[/bold]", border_style="green")
    deliverables.add_column("File", style="dim green")
    deliverables.add_column("Contents", style="dim")
    deliverables.add_column("Submit?", justify="center")

    deliverables.add_row(
        f"{report_dir}/vulnerability_report.md",
        "Full vulnerability report (5-8 pages equivalent)",
        "[bold green]YES[/bold green]"
    )
    deliverables.add_row(
        f"{log_dir}/full_conversation_log.json",
        "Every agent message + reasoning turn",
        "[bold green]YES[/bold green]"
    )
    deliverables.add_row(
        f"{log_dir}/tool_calls.json",
        "All tool calls with inputs/outputs (AI interaction log)",
        "[bold green]YES[/bold green]"
    )
    deliverables.add_row(
        f"{log_dir}/session_*.log",
        "Timestamped session log with all debug output",
        "[bold green]YES[/bold green]"
    )
    for r in attack_results:
        if r.success:
            deliverables.add_row(
                f"{report_dir}/poc_{r.vulnerability_id.lower()}.py",
                f"Standalone PoC for {r.vulnerability_id}",
                "[bold green]YES[/bold green]"
            )
    if figures:
        deliverables.add_row(
            f"{report_dir}/figures/ ({len(figures)} files)",
            "Vulnerability scorecard, fuzzing stats, risk matrix, etc.",
            "[bold green]YES[/bold green]"
        )
    deliverables.add_row(
        "mqtt-security-agent/ (this repo)",
        "Full source code",
        "[bold green]YES[/bold green]"
    )

    console.print()
    console.print(Panel(
        f"{verdict_text}\n\n"
        f"  Tests run:   [bold]{fuzz_stats.get('total_tests', 0)}[/bold] fuzzing cases\n"
        f"  Attacks run: [bold]{len(attack_results)}[/bold] targeted attacks\n"
        f"  Confirmed:   [bold {'red' if confirmed else 'green'}]{len(confirmed)}[/bold {'red' if confirmed else 'green'}] vulnerabilities\n",
        title="[bold red]MQTT Security Assessment Complete[/bold red]",
        border_style=verdict_color,
        expand=False,
    ))
    console.print()
    console.print(deliverables)
    console.print()


def _plain_vuln_table(attack_results):
    print("\n=== VULNERABILITY ASSESSMENT ===")
    for r in attack_results:
        sev, cvss = VULN_SEVERITY.get(r.vulnerability_id, ("?", 0))
        status = "VULNERABLE" if r.success else "SAFE"
        print(f"  [{status:10s}] [{r.confidence:6s}] CVSS={cvss} — {r.vulnerability_id}")

def _plain_fuzz_stats(fuzz_stats):
    print("\n=== FUZZING STATS ===")
    for k, v in fuzz_stats.items():
        print(f"  {k}: {v}")

def _plain_final_summary(fuzz_stats, attack_results, figures):
    confirmed = [r for r in attack_results if r.success]
    print(f"\n=== FINAL SUMMARY ===")
    print(f"Tests: {fuzz_stats.get('total_tests', 0)}")
    print(f"Confirmed vulnerabilities: {len(confirmed)}")
    print(f"Figures saved: {len(figures)}")
