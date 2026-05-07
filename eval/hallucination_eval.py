"""
Hallucination Evaluator for the Knowledge Graph Reasoning Engine.

Hallucination is defined as content in the model's answer that is NOT
supported by the evidence retrieved from the knowledge graph or vector
store.  This module evaluates three dimensions:

1. Technique-ID fidelity
   Does every ATT&CK technique ID mentioned in the answer (T\d{4}...) also
   appear in the set of retrieved graph/vector results?

2. Group-name fidelity
   Does every threat-group name mentioned in the answer appear in the graph
   results returned by the API?

3. Tactic-name fidelity
   Are ATT&CK tactic names referenced in the answer supported by the
   retrieved context?

Usage
-----
    python -m eval.hallucination_eval
    python -m eval.hallucination_eval --url http://my-server:8000 --k 5 --output report.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from eval.benchmark import BENCHMARK_QUERIES  # reuse ground-truth query list


# ---------------------------------------------------------------------------
# ATT&CK vocabulary helpers
# ---------------------------------------------------------------------------

# Canonical MITRE ATT&CK tactic names
MITRE_TACTICS: frozenset[str] = frozenset(
    [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]
)

# Known threat-group names drawn from MITRE ATT&CK groups catalogue
# (kept small and representative — extend as needed)
KNOWN_GROUPS: frozenset[str] = frozenset(
    [
        "APT1",
        "APT10",
        "APT28",
        "APT29",
        "APT32",
        "APT33",
        "APT34",
        "APT41",
        "Cobalt Group",
        "FIN6",
        "FIN7",
        "FIN8",
        "Fancy Bear",
        "Kimsuky",
        "Lazarus Group",
        "Mustang Panda",
        "OilRig",
        "Scattered Spider",
        "Sandworm Team",
        "TA505",
        "Turla",
        "Volt Typhoon",
        "Wizard Spider",
    ]
)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_technique_ids(text: str) -> list[str]:
    """Return unique ATT&CK technique IDs found in *text* (order-preserving)."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _TECHNIQUE_RE.finditer(text):
        t = m.group()
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def extract_groups(text: str) -> list[str]:
    """Return KNOWN_GROUPS names that appear (case-insensitive) in *text*."""
    text_lower = text.lower()
    return [g for g in sorted(KNOWN_GROUPS) if g.lower() in text_lower]


def extract_tactics(text: str) -> list[str]:
    """Return MITRE tactic names mentioned in *text* (case-insensitive)."""
    text_lower = text.lower()
    return [t for t in sorted(MITRE_TACTICS) if t.lower() in text_lower]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class HallucinationResult:
    query: str
    answer: str

    # Mentioned vs. supported
    mentioned_technique_ids: list[str]
    supported_technique_ids: list[str]
    hallucinated_technique_ids: list[str]

    mentioned_groups: list[str]
    supported_groups: list[str]
    hallucinated_groups: list[str]

    mentioned_tactics: list[str]
    supported_tactics: list[str]
    hallucinated_tactics: list[str]

    # Aggregate score: fraction of mentioned entities that are hallucinated
    hallucination_rate: float
    latency_ms: float
    error: str | None = None


@dataclass
class HallucinationReport:
    total_queries: int
    successful_queries: int
    avg_hallucination_rate: float
    avg_latency_ms: float
    technique_hallucination_rate: float
    group_hallucination_rate: float
    tactic_hallucination_rate: float
    results: list[HallucinationResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Evidence extraction from API response
# ---------------------------------------------------------------------------


def _evidence_from_response(response_data: dict[str, Any]) -> dict[str, set[str]]:
    """
    Extract supported technique IDs, group names, and tactic names from the
    raw API response, looking in all common response fields.

    Returns a dict with keys "techniques", "groups", "tactics".
    """
    techniques: set[str] = set()
    groups: set[str] = set()
    tactics: set[str] = set()

    # ---- Explicit technique_ids list ----
    for tid in response_data.get("technique_ids") or []:
        if isinstance(tid, str):
            techniques.add(tid)

    # ---- graph_results (list of node dicts) ----
    for node in response_data.get("graph_results") or []:
        if not isinstance(node, dict):
            continue
        # Technique IDs
        for key in ("id", "technique_id", "external_id"):
            val = node.get(key)
            if isinstance(val, str) and _TECHNIQUE_RE.match(val):
                techniques.add(val)
        # Group names
        node_type = (node.get("type") or node.get("label") or "").lower()
        name = node.get("name") or node.get("group") or ""
        if isinstance(name, str) and ("group" in node_type or "actor" in node_type):
            for g in KNOWN_GROUPS:
                if g.lower() in name.lower():
                    groups.add(g)
        # Tactics
        tactic_val = node.get("tactic") or node.get("phase_name") or ""
        if isinstance(tactic_val, str):
            for t in MITRE_TACTICS:
                if t.lower() == tactic_val.lower():
                    tactics.add(t)

    # ---- vector_results (list of chunk dicts with metadata) ----
    for chunk in response_data.get("vector_results") or []:
        if not isinstance(chunk, dict):
            continue
        content = chunk.get("content") or chunk.get("text") or chunk.get("document") or ""
        meta = chunk.get("metadata") or {}

        # Technique IDs from content and metadata
        for tid in extract_technique_ids(str(content)):
            techniques.add(tid)
        for key in ("technique_id", "external_id", "id"):
            val = meta.get(key)
            if isinstance(val, str) and _TECHNIQUE_RE.match(val):
                techniques.add(val)

        # Group names from metadata
        for key in ("group", "actor", "source"):
            val = meta.get(key, "")
            if isinstance(val, str):
                for g in KNOWN_GROUPS:
                    if g.lower() in val.lower():
                        groups.add(g)

        # Tactics from metadata
        for key in ("tactic", "phase_name", "tactic_name"):
            val = meta.get(key, "")
            if isinstance(val, str):
                for t in MITRE_TACTICS:
                    if t.lower() == val.lower():
                        tactics.add(t)

    # ---- Parse answer text itself as last-resort evidence ----
    # (Only do this for groups/tactics since technique IDs in the answer
    #  are what we are evaluating for hallucination.)
    answer = response_data.get("answer") or ""
    if isinstance(answer, str):
        # Techniques explicitly mentioned in graph_path / path_trace sections
        path_trace = response_data.get("path_trace") or response_data.get("graph_path") or ""
        for tid in extract_technique_ids(str(path_trace)):
            techniques.add(tid)

    return {"techniques": techniques, "groups": groups, "tactics": tactics}


# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------


class HallucinationEvaluator:
    """
    Evaluates hallucination rate of the Knowledge Graph Reasoning Engine by
    comparing what the model says against what the retrieval system returned.

    Parameters
    ----------
    api_base_url : str
        Base URL of the FastAPI service.
    timeout : float
        HTTP timeout per request in seconds.
    """

    def __init__(
        self,
        api_base_url: str = "http://localhost:8000",
        timeout: float = 60.0,
    ) -> None:
        self.api_base_url = api_base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.api_base_url,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    # ------------------------------------------------------------------
    # Single-query hallucination check
    # ------------------------------------------------------------------

    def evaluate_query(self, query_data: dict[str, Any]) -> HallucinationResult:
        """
        POST a query to /api/v1/query, then compare the model's answer
        against the retrieved evidence.
        """
        query_text: str = query_data["query"]

        payload = {
            "query": query_text,
            "max_results": 10,
            "include_graph_path": True,
        }

        t0 = time.perf_counter()
        try:
            resp = self._client.post("/api/v1/query", json=payload)
            latency_ms = (time.perf_counter() - t0) * 1000

            if resp.status_code != 200:
                return self._error_result(
                    query_text,
                    latency_ms,
                    f"HTTP {resp.status_code}: {resp.text[:200]}",
                )

            data: dict[str, Any] = resp.json()
        except httpx.RequestError as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            return self._error_result(query_text, latency_ms, str(exc))

        answer: str = data.get("answer") or ""
        evidence = _evidence_from_response(data)

        # --- Technique ID analysis ---
        mentioned_techniques = extract_technique_ids(answer)
        supported_techniques = [
            t
            for t in mentioned_techniques
            if t in evidence["techniques"]
            or t.split(".")[0] in {e.split(".")[0] for e in evidence["techniques"]}
        ]
        hallucinated_techniques = [
            t for t in mentioned_techniques if t not in supported_techniques
        ]

        # --- Group name analysis ---
        mentioned_groups = extract_groups(answer)
        supported_groups = [g for g in mentioned_groups if g in evidence["groups"]]
        hallucinated_groups = [g for g in mentioned_groups if g not in supported_groups]

        # --- Tactic analysis ---
        mentioned_tactics = extract_tactics(answer)
        supported_tactics = [t for t in mentioned_tactics if t in evidence["tactics"]]
        hallucinated_tactics = [t for t in mentioned_tactics if t not in supported_tactics]

        # --- Aggregate hallucination rate ---
        total_mentioned = (
            len(mentioned_techniques) + len(mentioned_groups) + len(mentioned_tactics)
        )
        total_hallucinated = (
            len(hallucinated_techniques)
            + len(hallucinated_groups)
            + len(hallucinated_tactics)
        )
        hallucination_rate = (
            total_hallucinated / total_mentioned if total_mentioned > 0 else 0.0
        )

        return HallucinationResult(
            query=query_text,
            answer=answer,
            mentioned_technique_ids=mentioned_techniques,
            supported_technique_ids=supported_techniques,
            hallucinated_technique_ids=hallucinated_techniques,
            mentioned_groups=mentioned_groups,
            supported_groups=supported_groups,
            hallucinated_groups=hallucinated_groups,
            mentioned_tactics=mentioned_tactics,
            supported_tactics=supported_tactics,
            hallucinated_tactics=hallucinated_tactics,
            hallucination_rate=hallucination_rate,
            latency_ms=latency_ms,
        )

    # ------------------------------------------------------------------
    # Full benchmark run
    # ------------------------------------------------------------------

    def run_evaluation(
        self,
        queries: list[dict[str, Any]] | None = None,
    ) -> HallucinationReport:
        """
        Run the hallucination evaluation across all benchmark queries.

        Returns a HallucinationReport with per-dimension and aggregate rates.
        """
        query_list = queries if queries is not None else BENCHMARK_QUERIES
        results: list[HallucinationResult] = []

        print(f"\nRunning hallucination evaluation  |  {len(query_list)} queries")
        print("=" * 70)

        for i, qdata in enumerate(query_list, start=1):
            short_q = qdata["query"][:58] + ("…" if len(qdata["query"]) > 58 else "")
            print(f"[{i:02d}/{len(query_list)}] {short_q}", end=" ... ", flush=True)
            result = self.evaluate_query(qdata)
            results.append(result)

            if result.error:
                print(f"ERR ({result.latency_ms:.0f} ms) — {result.error}")
            else:
                print(
                    f"hall={result.hallucination_rate:.1%}  "
                    f"({result.latency_ms:.0f} ms)"
                )

        successful = [r for r in results if r.error is None]

        # ---- Aggregate metrics ----
        avg_hall = (
            sum(r.hallucination_rate for r in successful) / len(successful)
            if successful
            else 0.0
        )
        avg_latency = (
            sum(r.latency_ms for r in successful) / len(successful)
            if successful
            else 0.0
        )

        def _dim_rate(
            mentioned_attr: str, hallucinated_attr: str, results: list[HallucinationResult]
        ) -> float:
            total_m = sum(len(getattr(r, mentioned_attr)) for r in results)
            total_h = sum(len(getattr(r, hallucinated_attr)) for r in results)
            return total_h / total_m if total_m > 0 else 0.0

        technique_rate = _dim_rate(
            "mentioned_technique_ids", "hallucinated_technique_ids", successful
        )
        group_rate = _dim_rate("mentioned_groups", "hallucinated_groups", successful)
        tactic_rate = _dim_rate("mentioned_tactics", "hallucinated_tactics", successful)

        return HallucinationReport(
            total_queries=len(query_list),
            successful_queries=len(successful),
            avg_hallucination_rate=avg_hall,
            avg_latency_ms=avg_latency,
            technique_hallucination_rate=technique_rate,
            group_hallucination_rate=group_rate,
            tactic_hallucination_rate=tactic_rate,
            results=results,
        )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def print_report(self, report: HallucinationReport) -> None:
        """Print a human-readable hallucination evaluation report."""
        width = 70
        print()
        print("=" * width)
        print("  HALLUCINATION EVALUATION — Agentic Knowledge Graph Reasoning Engine")
        print("=" * width)
        print(f"  Overall hallucination rate  : {report.avg_hallucination_rate:.1%}")
        print(f"  Technique-ID hallucination  : {report.technique_hallucination_rate:.1%}")
        print(f"  Group-name hallucination    : {report.group_hallucination_rate:.1%}")
        print(f"  Tactic-name hallucination   : {report.tactic_hallucination_rate:.1%}")
        print(f"  Avg latency (ms)            : {report.avg_latency_ms:.0f} ms")
        print(f"  Queries (total/successful)  : {report.total_queries}/{report.successful_queries}")
        print("-" * width)

        for i, r in enumerate(report.results, start=1):
            short_q = r.query[:50] + ("…" if len(r.query) > 50 else "")
            print(f"\n  [{i:02d}] {short_q}")
            if r.error:
                print(f"        ERROR: {r.error}")
                continue
            print(f"        Hallucination rate : {r.hallucination_rate:.1%}")
            if r.hallucinated_technique_ids:
                print(f"        Hallucinated IDs   : {', '.join(r.hallucinated_technique_ids)}")
            if r.hallucinated_groups:
                print(f"        Hallucinated groups: {', '.join(r.hallucinated_groups)}")
            if r.hallucinated_tactics:
                print(f"        Hallucinated tactics: {', '.join(r.hallucinated_tactics)}")

        print()
        print("=" * width)

    def save_report_json(self, report: HallucinationReport, path: str) -> None:
        """Write the full report to a JSON file."""
        data = {
            "total_queries": report.total_queries,
            "successful_queries": report.successful_queries,
            "avg_hallucination_rate": report.avg_hallucination_rate,
            "avg_latency_ms": report.avg_latency_ms,
            "technique_hallucination_rate": report.technique_hallucination_rate,
            "group_hallucination_rate": report.group_hallucination_rate,
            "tactic_hallucination_rate": report.tactic_hallucination_rate,
            "results": [
                {
                    "query": r.query,
                    "hallucination_rate": r.hallucination_rate,
                    "mentioned_technique_ids": r.mentioned_technique_ids,
                    "supported_technique_ids": r.supported_technique_ids,
                    "hallucinated_technique_ids": r.hallucinated_technique_ids,
                    "mentioned_groups": r.mentioned_groups,
                    "hallucinated_groups": r.hallucinated_groups,
                    "mentioned_tactics": r.mentioned_tactics,
                    "hallucinated_tactics": r.hallucinated_tactics,
                    "latency_ms": r.latency_ms,
                    "error": r.error,
                }
                for r in report.results
            ],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(f"\nReport saved → {path}")


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run hallucination evaluation against the Knowledge Graph Reasoning Engine."
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Base URL of the FastAPI service (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="HTTP request timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to save JSON report (e.g. hallucination_report.json)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    evaluator = HallucinationEvaluator(api_base_url=args.url, timeout=args.timeout)

    report = evaluator.run_evaluation()
    evaluator.print_report(report)

    if args.output:
        evaluator.save_report_json(report, args.output)

    # Non-zero exit if overall hallucination rate exceeds 50 %
    sys.exit(0 if report.avg_hallucination_rate < 0.5 else 1)
