"""
Result Analyzer

Ingests fuzzing results and attack results, correlates them,
and produces risk assessments aligned with the MQTT vulnerability taxonomy.
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A consolidated security finding from multiple evidence sources."""
    vulnerability_id: str
    title: str
    confirmed: bool  # True = targeted attack succeeded
    fuzzing_indicators: int  # How many fuzz tests pointed to this
    confidence: str  # HIGH / MEDIUM / LOW
    severity: str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    evidence: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    mitigation: str = ""


SEVERITY_MAP = {
    "V1_UNAUTHORIZED_WILL":    "HIGH",
    "V2_UNAUTHORIZED_RETAIN":  "MEDIUM",
    "V3_CLIENTID_HIJACKING":   "HIGH",
    "V4_TOPIC_AUTH_BYPASS":    "HIGH",
    "V5_QOS2_TIMING":          "MEDIUM",
    "V6_SYS_TOPIC_EXPOSURE":   "LOW",
    "V7_ZERO_LENGTH_CLIENTID": "MEDIUM",
    "V8_WILL_DELAY_EXPLOIT":   "LOW",
    "CRASH":                   "CRITICAL",
    "SPEC_VIOLATION":          "MEDIUM",
}


class ResultAnalyzer:
    """Correlates fuzzing and attack results into consolidated findings."""

    def __init__(self):
        self._fuzz_anomalies = []
        self._attack_results = []

    def ingest_fuzz_results(self, anomalies: list):
        self._fuzz_anomalies.extend(anomalies)

    def ingest_attack_result(self, result):
        self._attack_results.append(result)

    def ingest_all_attack_results(self, results: list):
        self._attack_results.extend(results)

    def get_findings(self) -> List[Finding]:
        """Produce consolidated findings list."""
        findings: Dict[str, Finding] = {}

        # Count fuzzing indicators per vulnerability class
        fuzz_counts: Dict[str, int] = {}
        for anom in self._fuzz_anomalies:
            vc = getattr(anom.test_case, "vulnerability_class", None) or anom.anomaly_type or "UNKNOWN"
            fuzz_counts[vc] = fuzz_counts.get(vc, 0) + 1

        # Process confirmed attacks
        for result in self._attack_results:
            vid = result.vulnerability_id
            findings[vid] = Finding(
                vulnerability_id=vid,
                title=result.vulnerability_name,
                confirmed=result.success,
                fuzzing_indicators=fuzz_counts.get(vid, 0),
                confidence=result.confidence,
                severity=SEVERITY_MAP.get(vid, "MEDIUM"),
                evidence=result.evidence,
                reproduction_steps=result.reproduction_steps,
                mitigation=result.mitigation,
            )

        # Add fuzzing-only findings (no targeted attack run)
        for vc, count in fuzz_counts.items():
            if vc not in findings and count > 0:
                findings[vc] = Finding(
                    vulnerability_id=vc,
                    title=f"Potential: {vc}",
                    confirmed=False,
                    fuzzing_indicators=count,
                    confidence="LOW",
                    severity=SEVERITY_MAP.get(vc, "LOW"),
                    evidence=[f"{count} fuzzing anomalies suggest {vc}"],
                )

        return sorted(
            findings.values(),
            key=lambda f: (0 if f.confirmed else 1, SEVERITY_MAP.get(f.vulnerability_id, "LOW")),
        )

    def risk_summary(self) -> Dict:
        findings = self.get_findings()
        confirmed = [f for f in findings if f.confirmed]
        return {
            "total_findings": len(findings),
            "confirmed_vulnerabilities": len(confirmed),
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in findings if f.severity == "HIGH"),
            "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity == "LOW"),
            "top_finding": confirmed[0].title if confirmed else "None confirmed",
        }
