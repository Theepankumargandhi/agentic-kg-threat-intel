"""
Hit@K evaluation for the Knowledge Graph Reasoning Engine.

Measures retrieval accuracy against a ground truth dataset of MITRE ATT&CK
queries by calling the live /api/v1/query endpoint and comparing returned
technique IDs against a manually curated expected set.

Metrics produced
----------------
hit_at_k        : fraction of queries where at least one expected technique ID
                  appears in the top-K retrieved results  (primary metric)
avg_latency_ms  : mean end-to-end query latency in milliseconds
per_query       : per-query breakdown (hit, retrieved_ids, latency_ms)

Usage
-----
    python -m eval.benchmark                         # defaults: k=5, base=localhost:8000
    python -m eval.benchmark --k 10 --url http://...
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


# ---------------------------------------------------------------------------
# Ground-truth benchmark dataset (MITRE ATT&CK)
# ---------------------------------------------------------------------------

BENCHMARK_QUERIES: list[dict[str, Any]] = [
    {
        "query": "What techniques does APT29 use for initial access?",
        "expected_technique_ids": ["T1566", "T1078", "T1195"],
        "expected_tactics": ["Initial Access"],
        "group": "APT29",
    },
    {
        "query": "How does Lazarus Group use spearphishing for credential theft?",
        "expected_technique_ids": ["T1566.001", "T1078", "T1555"],
        "expected_tactics": ["Initial Access", "Credential Access"],
        "group": "Lazarus Group",
    },
    {
        "query": "What are common lateral movement techniques using valid accounts?",
        "expected_technique_ids": ["T1078", "T1021", "T1550"],
        "expected_tactics": ["Lateral Movement"],
        "group": None,
    },
    {
        "query": "Which techniques bypass Windows Defender?",
        "expected_technique_ids": ["T1562.001", "T1027", "T1553"],
        "expected_tactics": ["Defense Evasion"],
        "group": None,
    },
    {
        "query": "What persistence mechanisms does FIN7 use?",
        "expected_technique_ids": ["T1547", "T1053", "T1098"],
        "expected_tactics": ["Persistence"],
        "group": "FIN7",
    },
    {
        "query": "Which cloud techniques does Scattered Spider use for collection?",
        "expected_technique_ids": ["T1530", "T1213", "T1114"],
        "expected_tactics": ["Collection"],
        "group": "Scattered Spider",
    },
    {
        "query": "How does ransomware achieve impact on victim systems?",
        "expected_technique_ids": ["T1486", "T1490", "T1489"],
        "expected_tactics": ["Impact"],
        "group": None,
    },
    {
        "query": "What command and control techniques use encrypted channels?",
        "expected_technique_ids": ["T1071", "T1573", "T1132"],
        "expected_tactics": ["Command and Control"],
        "group": None,
    },
    {
        "query": "How does Volt Typhoon achieve living off the land?",
        "expected_technique_ids": ["T1036", "T1218", "T1059.003"],
        "expected_tactics": ["Defense Evasion", "Execution"],
        "group": "Volt Typhoon",
    },
    {
        "query": "What discovery techniques reveal Active Directory structure?",
        "expected_technique_ids": ["T1087", "T1069", "T1482"],
        "expected_tactics": ["Discovery"],
        "group": None,
    },
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class QueryResult:
    query: str
    group: str | None
    hit: bool
    retrieved_ids: list[str]
    expected_ids: list[str]
    latency_ms: float
    error: str | None = None


@dataclass
class BenchmarkReport:
    k: int
    hit_at_k: float
    avg_latency_ms: float
    total_queries: int
    successful_queries: int
    results: list[QueryResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

# Regex that matches bare ATT&CK IDs such as T1566 or T1566.001
_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_technique_ids(text: str) -> list[str]:
    """Return all unique ATT&CK technique IDs found in *text* (preserving order)."""
    seen: set[str] = set()
    ids: list[str] = []
    for m in _TECHNIQUE_ID_RE.finditer(text):
        tid = m.group()
        if tid not in seen:
            seen.add(tid)
            ids.append(tid)
    return ids


def ids_from_api_response(response_json: dict[str, Any]) -> list[str]:
    """
    Extract technique IDs from the API response payload.

    Looks in several places to be resilient to schema variations:
      - response_json["technique_ids"]      (list[str])
      - response_json["graph_results"]      (list of node dicts with "id")
      - response_json["answer"]             (free-text fallback)
    """
    ids: list[str] = []

    # Explicit list from the API schema
    explicit = response_json.get("technique_ids") or []
    for tid in explicit:
        if isinstance(tid, str):
            ids.append(tid)

    # Graph node results
    graph_results = response_json.get("graph_results") or []
    for node in graph_results:
        if isinstance(node, dict):
            for key in ("id", "technique_id", "external_id"):
                val = node.get(key)
                if isinstance(val, str) and _TECHNIQUE_ID_RE.match(val):
                    ids.append(val)

    # Fallback: parse free-text answer
    answer = response_json.get("answer", "")
    if isinstance(answer, str):
        ids.extend(extract_technique_ids(answer))

    # Deduplicate while preserving insertion order
    seen: set[str] = set()
    unique: list[str] = []
    for tid in ids:
        if tid not in seen:
            seen.add(tid)
            unique.append(tid)
    return unique


# ---------------------------------------------------------------------------
# Main evaluator class
# ---------------------------------------------------------------------------


class BenchmarkEvaluator:
    """
    Evaluates the Knowledge Graph Reasoning Engine against BENCHMARK_QUERIES.

    Parameters
    ----------
    api_base_url:
        Base URL of the running FastAPI service (no trailing slash).
    timeout:
        HTTP request timeout in seconds.
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
    # Core metric
    # ------------------------------------------------------------------

    def hit_at_k(
        self,
        retrieved_ids: list[str],
        expected_ids: list[str],
        k: int,
    ) -> bool:
        """
        Return True if any *expected_ids* appear within the first *k*
        elements of *retrieved_ids*.

        The comparison is prefix-aware: retrieved ID T1566 satisfies
        expected ID T1566.001 (parent–child match) and vice-versa so that
        sub-technique vs. technique granularity differences do not
        artificially penalise the engine.
        """
        top_k = retrieved_ids[:k]

        def _base(tid: str) -> str:
            """Strip sub-technique suffix, e.g. T1566.001 → T1566."""
            return tid.split(".")[0]

        top_k_bases = {_base(t) for t in top_k}
        top_k_full = set(top_k)

        for exp in expected_ids:
            if exp in top_k_full:
                return True
            if _base(exp) in top_k_bases:
                return True
        return False

    # ------------------------------------------------------------------
    # Single query evaluation
    # ------------------------------------------------------------------

    def evaluate_query(self, query_data: dict[str, Any], k: int = 5) -> QueryResult:
        """
        POST one query to /api/v1/query, measure latency, and compute hit@k.

        Returns a QueryResult with all relevant metadata for downstream
        aggregation and reporting.
        """
        query_text: str = query_data["query"]
        expected_ids: list[str] = query_data.get("expected_technique_ids", [])
        group: str | None = query_data.get("group")

        payload = {
            "query": query_text,
            "max_results": max(k, 10),   # ask for at least k results
            "include_graph_path": True,
        }

        t0 = time.perf_counter()
        try:
            response = self._client.post("/api/v1/query", json=payload)
            latency_ms = (time.perf_counter() - t0) * 1000

            if response.status_code != 200:
                return QueryResult(
                    query=query_text,
                    group=group,
                    hit=False,
                    retrieved_ids=[],
                    expected_ids=expected_ids,
                    latency_ms=latency_ms,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )

            data: dict[str, Any] = response.json()
            retrieved_ids = ids_from_api_response(data)
            hit = self.hit_at_k(retrieved_ids, expected_ids, k)

            return QueryResult(
                query=query_text,
                group=group,
                hit=hit,
                retrieved_ids=retrieved_ids,
                expected_ids=expected_ids,
                latency_ms=latency_ms,
            )

        except httpx.RequestError as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            return QueryResult(
                query=query_text,
                group=group,
                hit=False,
                retrieved_ids=[],
                expected_ids=expected_ids,
                latency_ms=latency_ms,
                error=f"Request error: {exc}",
            )

    # ------------------------------------------------------------------
    # Full benchmark run
    # ------------------------------------------------------------------

    def run_benchmark(
        self,
        k: int = 5,
        queries: list[dict[str, Any]] | None = None,
    ) -> BenchmarkReport:
        """
        Run all benchmark queries (or a custom list) and compute aggregate
        Hit@K and average latency.

        Parameters
        ----------
        k:
            Cutoff for Hit@K metric.
        queries:
            Optional override list; defaults to BENCHMARK_QUERIES.

        Returns
        -------
        BenchmarkReport with per-query results and aggregate metrics.
        """
        query_list = queries if queries is not None else BENCHMARK_QUERIES
        results: list[QueryResult] = []

        print(f"\nRunning benchmark  |  k={k}  |  {len(query_list)} queries")
        print("=" * 70)

        for i, qdata in enumerate(query_list, start=1):
            short_q = qdata["query"][:60] + ("…" if len(qdata["query"]) > 60 else "")
            print(f"[{i:02d}/{len(query_list)}] {short_q}", end=" ... ", flush=True)
            result = self.evaluate_query(qdata, k=k)
            results.append(result)

            status = "HIT" if result.hit else ("ERR" if result.error else "MISS")
            print(f"{status}  ({result.latency_ms:.0f} ms)")
            if result.error:
                print(f"         ERROR: {result.error}")

        successful = [r for r in results if r.error is None]
        hit_count = sum(1 for r in successful if r.hit)
        hit_at_k = hit_count / len(query_list) if query_list else 0.0
        avg_latency = (
            sum(r.latency_ms for r in successful) / len(successful)
            if successful
            else 0.0
        )

        return BenchmarkReport(
            k=k,
            hit_at_k=hit_at_k,
            avg_latency_ms=avg_latency,
            total_queries=len(query_list),
            successful_queries=len(successful),
            results=results,
        )

    # ------------------------------------------------------------------
    # Human-readable report
    # ------------------------------------------------------------------

    def print_report(self, report: BenchmarkReport) -> None:
        """Print a formatted benchmark report to stdout."""
        width = 70
        print()
        print("=" * width)
        print("  BENCHMARK REPORT — Agentic Knowledge Graph Reasoning Engine")
        print("=" * width)
        print(f"  Hit@{report.k}               : {report.hit_at_k:.1%}")
        print(f"  Avg latency (ms)     : {report.avg_latency_ms:.0f} ms")
        print(f"  Queries (total/ok)   : {report.total_queries}/{report.successful_queries}")
        print("-" * width)

        # Per-query table
        header = f"  {'#':>2}  {'Hit':^4}  {'Latency':>9}  Query"
        print(header)
        print("-" * width)
        for i, r in enumerate(report.results, start=1):
            hit_label = "YES" if r.hit else ("ERR" if r.error else "no ")
            q_short = r.query[:48] + ("…" if len(r.query) > 48 else "")
            print(f"  {i:>2}  {hit_label:^4}  {r.latency_ms:>7.0f}ms  {q_short}")
            if not r.hit and not r.error:
                print(f"        Expected : {', '.join(r.expected_ids)}")
                print(f"        Retrieved: {', '.join(r.retrieved_ids[:5])}")
            if r.error:
                print(f"        Error    : {r.error}")

        print("=" * width)

    def save_report_json(self, report: BenchmarkReport, path: str) -> None:
        """Persist the full benchmark report to a JSON file."""
        data = {
            "k": report.k,
            "hit_at_k": report.hit_at_k,
            "avg_latency_ms": report.avg_latency_ms,
            "total_queries": report.total_queries,
            "successful_queries": report.successful_queries,
            "results": [
                {
                    "query": r.query,
                    "group": r.group,
                    "hit": r.hit,
                    "retrieved_ids": r.retrieved_ids,
                    "expected_ids": r.expected_ids,
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
        description="Run Hit@K benchmark against the Knowledge Graph Reasoning Engine."
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Base URL of the FastAPI service (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--k",
        type=int,
        default=5,
        help="K cutoff for Hit@K metric (default: 5)",
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
        help="Optional path to save JSON report (e.g. eval_results.json)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    evaluator = BenchmarkEvaluator(api_base_url=args.url, timeout=args.timeout)

    report = evaluator.run_benchmark(k=args.k)
    evaluator.print_report(report)

    if args.output:
        evaluator.save_report_json(report, args.output)

    # Non-zero exit code if Hit@K < 50 % so CI can fail on regressions
    sys.exit(0 if report.hit_at_k >= 0.5 else 1)
