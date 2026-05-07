import operator
from typing import Annotated, TypedDict


class AgentState(TypedDict):
    # ── Input ──────────────────────────────────────────────────────────────
    query: str
    top_k: int
    include_mitigations: bool
    max_hops: int

    # ── Planning ───────────────────────────────────────────────────────────
    sub_queries: list[str]

    # ── Retrieval (Annotated with operator.add so parallel nodes can append)
    vector_results: Annotated[list[dict], operator.add]
    graph_results: Annotated[list[dict], operator.add]
    hybrid_results: list[dict]

    # ── Explainability ─────────────────────────────────────────────────────
    path_trace: dict  # serialised PathTrace {nodes, edges}

    # ── Reasoning chain ────────────────────────────────────────────────────
    reasoning_steps: Annotated[list[dict], operator.add]

    # ── Output ─────────────────────────────────────────────────────────────
    answer: str
    sources: list[dict]
    confidence: float

    # ── Control ────────────────────────────────────────────────────────────
    iteration: int
    hallucination_detected: bool
    error: str | None
