"""
LangGraph node functions for the Agentic Knowledge Graph Reasoning Engine.
Each function takes AgentState and returns a partial state update dict.

Module-level references (hybrid_retriever, graph_store) are set by graph.py
before the graph is compiled.
"""

import logging
import re
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from app.agent.state import AgentState
from app.config import settings

logger = logging.getLogger(__name__)

# Set by graph.py at build time
hybrid_retriever: Any = None
graph_store: Any = None

_llm = ChatAnthropic(
    model=settings.LLM_MODEL,
    api_key=settings.ANTHROPIC_API_KEY,
    max_tokens=2048,
)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# ---------------------------------------------------------------------------
# 1. Query Planner
# ---------------------------------------------------------------------------


def query_planner(state: AgentState) -> dict:
    query = state["query"]
    step = len(state.get("reasoning_steps", [])) + 1

    messages = [
        SystemMessage(
            content=(
                "You are a cybersecurity expert specializing in MITRE ATT&CK. "
                "Decompose the user's query into 2-4 focused sub-queries that will "
                "help retrieve the most relevant MITRE ATT&CK information. "
                "Also identify any explicit technique IDs (T1xxx), tactic names, "
                "or threat actor names in the query. "
                "Respond with ONLY a JSON object: "
                '{"sub_queries": ["...", "..."], "entities": {"techniques": [], "tactics": [], "groups": []}}'
            )
        ),
        HumanMessage(content=f"Query: {query}"),
    ]

    try:
        response = _llm.invoke(messages)
        import json

        content = response.content.strip()
        # Extract JSON from response
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            sub_queries = parsed.get("sub_queries", [query])
        else:
            sub_queries = [query]
    except Exception as exc:
        logger.warning("query_planner LLM call failed: %s", exc)
        sub_queries = [query]

    return {
        "sub_queries": sub_queries,
        "reasoning_steps": [
            {
                "step": step,
                "action": "Query Planning",
                "observation": f"Decomposed into {len(sub_queries)} sub-queries: {sub_queries}",
                "source": "llm",
            }
        ],
    }


# ---------------------------------------------------------------------------
# 2. Vector Retriever
# ---------------------------------------------------------------------------


def vector_retriever(state: AgentState) -> dict:
    if hybrid_retriever is None:
        return {"vector_results": [], "reasoning_steps": []}

    step = len(state.get("reasoning_steps", [])) + 1
    top_k = state.get("top_k", settings.TOP_K_VECTOR)
    all_results: list[dict] = []
    seen_ids: set[str] = set()

    queries = [state["query"]] + state.get("sub_queries", [])
    for q in queries:
        retrieval = hybrid_retriever.retrieve(
            query=q,
            top_k=top_k,
            vector_weight=0.7,
            graph_weight=0.3,
            include_mitigations=state.get("include_mitigations", True),
        )
        for r in retrieval.get("vector_results", []):
            uid = r.get("id", "")
            if uid and uid not in seen_ids:
                all_results.append(r)
                seen_ids.add(uid)

    return {
        "vector_results": all_results,
        "reasoning_steps": [
            {
                "step": step,
                "action": "Vector Retrieval",
                "observation": f"Retrieved {len(all_results)} unique documents from ChromaDB",
                "source": "vector",
            }
        ],
    }


# ---------------------------------------------------------------------------
# 3. Graph Retriever
# ---------------------------------------------------------------------------


def graph_retriever(state: AgentState) -> dict:
    if graph_store is None:
        return {"graph_results": [], "reasoning_steps": []}

    step = len(state.get("reasoning_steps", [])) + 1
    query = state["query"]
    results: list[dict] = []
    seen_ids: set[str] = set()

    # Attack paths for mentioned groups
    group_hints = _extract_group_names(query)
    for group in group_hints:
        path = graph_store.get_attack_path(group)
        for node in path.get("nodes", []):
            nid = node.get("id", "")
            if nid and nid not in seen_ids:
                results.append({**node, "source": "graph", "score": 0.85})
                seen_ids.add(nid)

    # Technique IDs mentioned explicitly
    for tech_id in _TECHNIQUE_RE.findall(query):
        node = graph_store.get_node_by_external_id(tech_id)
        if node and node.get("id") not in seen_ids:
            results.append({**node, "source": "graph", "score": 0.9})
            seen_ids.add(node["id"])
            # Get related techniques (N-hop)
            for rel in graph_store.get_related_techniques(tech_id, hops=state.get("max_hops", 2)):
                rid = rel.get("id", "")
                if rid and rid not in seen_ids:
                    results.append({**rel, "source": "graph", "score": 0.6})
                    seen_ids.add(rid)

    return {
        "graph_results": results,
        "reasoning_steps": [
            {
                "step": step,
                "action": "Graph Traversal",
                "observation": f"Retrieved {len(results)} nodes via Neo4j traversal",
                "source": "graph",
            }
        ],
    }


# ---------------------------------------------------------------------------
# 4. Hybrid Fuser
# ---------------------------------------------------------------------------


def hybrid_fuser(state: AgentState) -> dict:
    step = len(state.get("reasoning_steps", [])) + 1
    vector_results = state.get("vector_results", [])
    graph_results = state.get("graph_results", [])

    # RRF fusion
    k = 60
    scores: dict[str, float] = {}
    merged: dict[str, dict] = {}

    for rank, item in enumerate(vector_results):
        uid = item.get("external_id") or item.get("id", "")
        scores[uid] = scores.get(uid, 0.0) + 0.6 / (k + rank + 1)
        merged[uid] = {**item, "fusion_sources": ["vector"]}

    for rank, item in enumerate(graph_results):
        uid = item.get("external_id") or item.get("id", "")
        scores[uid] = scores.get(uid, 0.0) + 0.4 / (k + rank + 1)
        if uid in merged:
            merged[uid]["fusion_sources"] = list(set(merged[uid].get("fusion_sources", []) + ["graph"]))
        else:
            merged[uid] = {**item, "fusion_sources": ["graph"]}

    for uid, item in merged.items():
        item["rrf_score"] = scores[uid]

    fused = sorted(merged.values(), key=lambda x: x["rrf_score"], reverse=True)

    # Build path trace from top graph hits
    top_node_ids = [r.get("id") for r in fused[:15] if r.get("id") and "graph" in r.get("fusion_sources", [])]
    path_trace = (
        graph_store.build_path_trace(top_node_ids) if graph_store and top_node_ids else {"nodes": [], "edges": []}
    )

    return {
        "hybrid_results": fused,
        "path_trace": path_trace,
        "reasoning_steps": [
            {
                "step": step,
                "action": "Hybrid Fusion (RRF)",
                "observation": (
                    f"Fused {len(vector_results)} vector + {len(graph_results)} graph results "
                    f"→ {len(fused)} merged results"
                ),
                "source": "vector+graph",
            }
        ],
    }


# ---------------------------------------------------------------------------
# 5. Path Tracer
# ---------------------------------------------------------------------------


def path_tracer(state: AgentState) -> dict:
    if graph_store is None:
        return {"path_trace": state.get("path_trace", {"nodes": [], "edges": []}), "reasoning_steps": []}

    step = len(state.get("reasoning_steps", [])) + 1
    existing_trace = state.get("path_trace", {"nodes": [], "edges": []})

    # Enrich: get external_ids from hybrid results and traverse max_hops
    tech_ids = [
        r.get("external_id")
        for r in state.get("hybrid_results", [])[:10]
        if r.get("external_id") and re.match(r"T\d{4}", r.get("external_id", ""))
    ]

    extra_nodes: list[dict] = []
    extra_edges: list[dict] = []

    for ext_id in tech_ids[:5]:
        related = graph_store.get_related_techniques(ext_id, hops=state.get("max_hops", 2))
        for r in related:
            extra_nodes.append(
                {
                    "id": r.get("id", ""),
                    "type": r.get("node_type", "Technique"),
                    "name": r.get("name", ""),
                    "properties": {"external_id": r.get("external_id", "")},
                }
            )

    # Merge with existing trace
    all_nodes = {n["id"]: n for n in existing_trace.get("nodes", []) + extra_nodes if n.get("id")}
    enriched_trace = {
        "nodes": list(all_nodes.values()),
        "edges": existing_trace.get("edges", []) + extra_edges,
    }

    return {
        "path_trace": enriched_trace,
        "reasoning_steps": [
            {
                "step": step,
                "action": "Path Tracing",
                "observation": (
                    f"Traced {len(all_nodes)} nodes and "
                    f"{len(enriched_trace['edges'])} edges across {state.get('max_hops', 2)} hops"
                ),
                "source": "graph",
            }
        ],
    }


# ---------------------------------------------------------------------------
# 6. Answer Generator
# ---------------------------------------------------------------------------


def answer_generator(state: AgentState) -> dict:
    step = len(state.get("reasoning_steps", [])) + 1
    query = state["query"]
    hybrid_results = state.get("hybrid_results", [])
    path_trace = state.get("path_trace", {})

    # Build context
    context_parts = []
    sources = []

    for i, result in enumerate(hybrid_results[:12]):
        name = result.get("name", "")
        ext_id = result.get("external_id", "")
        desc = result.get("description", "")[:500]
        node_type = result.get("node_type", result.get("type", "Technique"))
        mitigations = result.get("mitigations", [])

        context_parts.append(
            f"[{i + 1}] {node_type}: {name} ({ext_id})\n"
            f"Description: {desc}\n"
            + (f"Mitigations: {', '.join(m['name'] for m in mitigations[:3])}" if mitigations else "")
        )
        sources.append({"name": name, "external_id": ext_id, "type": node_type})

    # Graph path summary
    nodes_summary = ", ".join(f"{n.get('name', '')} ({n.get('type', '')})" for n in path_trace.get("nodes", [])[:8])

    context = "\n\n".join(context_parts)

    messages = [
        SystemMessage(
            content=(
                "You are a senior cybersecurity analyst with deep expertise in MITRE ATT&CK. "
                "Answer the user's threat intelligence question using ONLY the provided context. "
                "Cite technique IDs (T1xxx) explicitly. Structure your response:\n"
                "1. **Direct Answer**: Clear, concise response to the query\n"
                "2. **Relevant Techniques**: List key MITRE techniques with IDs\n"
                "3. **Threat Actors**: Relevant groups if applicable\n"
                "4. **Mitigations**: Recommended defensive measures\n\n"
                "If the context doesn't contain enough information, say so explicitly. "
                "Never fabricate technique IDs or group names."
            )
        ),
        HumanMessage(
            content=(
                f"Query: {query}\n\nGraph Path (reasoning chain): {nodes_summary}\n\nRetrieved Context:\n{context}"
            )
        ),
    ]

    try:
        response = _llm.invoke(messages)
        answer = response.content
    except Exception as exc:
        logger.error("answer_generator LLM call failed: %s", exc)
        answer = f"Error generating answer: {exc}"

    # Confidence: based on result count and source diversity
    has_vector = any("vector" in r.get("fusion_sources", r.get("sources", [])) for r in hybrid_results)
    has_graph = any("graph" in r.get("fusion_sources", r.get("sources", [])) for r in hybrid_results)
    result_count = len(hybrid_results)
    confidence = min(
        0.5 + (0.1 if has_vector else 0) + (0.2 if has_graph else 0) + min(result_count * 0.02, 0.2),
        1.0,
    )

    return {
        "answer": answer,
        "sources": sources,
        "confidence": round(confidence, 2),
        "iteration": state.get("iteration", 0) + 1,
        "reasoning_steps": [
            {
                "step": step,
                "action": "Answer Generation",
                "observation": f"Generated answer ({len(answer)} chars) with confidence {confidence:.2f}",
                "source": "llm",
            }
        ],
    }


# ---------------------------------------------------------------------------
# 7. Hallucination Checker
# ---------------------------------------------------------------------------


def hallucination_checker(state: AgentState) -> dict:
    step = len(state.get("reasoning_steps", [])) + 1
    answer = state.get("answer", "")
    sources = state.get("sources", [])
    iteration = state.get("iteration", 1)

    cited_ids = set(_TECHNIQUE_RE.findall(answer))
    source_ids = {s.get("external_id", "") for s in sources}

    unsupported = cited_ids - source_ids
    hallucination_detected = len(unsupported) > 2 and iteration < settings.MAX_ITERATIONS

    observation = (
        f"Cited IDs: {cited_ids}, Source IDs: {source_ids}, "
        f"Unsupported: {unsupported}, Hallucination: {hallucination_detected}"
    )

    return {
        "hallucination_detected": hallucination_detected,
        "reasoning_steps": [
            {
                "step": step,
                "action": "Hallucination Check",
                "observation": observation,
                "source": "llm",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Conditional edge
# ---------------------------------------------------------------------------


def should_retry(state: AgentState) -> str:
    if state.get("hallucination_detected") and state.get("iteration", 1) < settings.MAX_ITERATIONS:
        logger.info("Hallucination detected — retrying answer generation (iteration %d)", state["iteration"])
        return "answer_generator"
    return "end"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KNOWN_GROUPS = [
    "apt29",
    "apt28",
    "apt41",
    "lazarus",
    "fin7",
    "carbanak",
    "cozy bear",
    "fancy bear",
    "sandworm",
    "kimsuky",
    "turla",
]


def _extract_group_names(query: str) -> list[str]:
    query_lower = query.lower()
    found = []
    for group in _KNOWN_GROUPS:
        if group in query_lower:
            found.append(group)
    return found
