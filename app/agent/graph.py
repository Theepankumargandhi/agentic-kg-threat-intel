"""
LangGraph StateGraph definition for the Agentic Knowledge Graph Reasoning Engine.
"""

import logging
import time
from typing import Any

from langgraph.graph import END, START, StateGraph

import app.agent.nodes as nodes_module
import app.agent.tools as tools_module
from app.agent.nodes import (
    answer_generator,
    graph_retriever,
    hallucination_checker,
    hybrid_fuser,
    path_tracer,
    query_planner,
    should_retry,
    vector_retriever,
)
from app.agent.state import AgentState

logger = logging.getLogger(__name__)


def build_graph(hybrid_retriever: Any, graph_store: Any):
    """Build and compile the LangGraph reasoning graph."""
    # Inject shared retrieval objects into node and tool modules
    nodes_module.hybrid_retriever = hybrid_retriever
    nodes_module.graph_store = graph_store
    tools_module.graph_store = graph_store
    tools_module.vector_store = getattr(hybrid_retriever, "vector_store", None)

    graph = StateGraph(AgentState)

    graph.add_node("query_planner", query_planner)
    graph.add_node("vector_retriever", vector_retriever)
    graph.add_node("graph_retriever", graph_retriever)
    graph.add_node("hybrid_fuser", hybrid_fuser)
    graph.add_node("path_tracer", path_tracer)
    graph.add_node("answer_generator", answer_generator)
    graph.add_node("hallucination_checker", hallucination_checker)

    graph.add_edge(START, "query_planner")
    graph.add_edge("query_planner", "vector_retriever")
    graph.add_edge("vector_retriever", "graph_retriever")
    graph.add_edge("graph_retriever", "hybrid_fuser")
    graph.add_edge("hybrid_fuser", "path_tracer")
    graph.add_edge("path_tracer", "answer_generator")
    graph.add_edge("answer_generator", "hallucination_checker")

    graph.add_conditional_edges(
        "hallucination_checker",
        should_retry,
        {"answer_generator": "answer_generator", "end": END},
    )

    return graph.compile()


async def run_agent(
    query: str,
    hybrid_retriever: Any,
    graph_store: Any,
    top_k: int = 10,
    include_mitigations: bool = True,
    max_hops: int = 3,
) -> dict:
    """Run the full agentic reasoning pipeline and return a result dict."""
    start_time = time.time()

    compiled_graph = build_graph(hybrid_retriever, graph_store)

    initial_state: AgentState = {
        "query": query,
        "top_k": top_k,
        "include_mitigations": include_mitigations,
        "max_hops": max_hops,
        "sub_queries": [],
        "vector_results": [],
        "graph_results": [],
        "hybrid_results": [],
        "path_trace": {"nodes": [], "edges": []},
        "reasoning_steps": [],
        "answer": "",
        "sources": [],
        "confidence": 0.0,
        "iteration": 0,
        "hallucination_detected": False,
        "error": None,
    }

    try:
        result = await compiled_graph.ainvoke(initial_state)
    except Exception as exc:
        logger.exception("LangGraph execution failed for query: %r", query)
        result = {
            **initial_state,
            "answer": f"Agent execution failed: {exc}",
            "error": str(exc),
        }

    latency_ms = (time.time() - start_time) * 1000
    result["latency_ms"] = round(latency_ms, 2)
    return result
