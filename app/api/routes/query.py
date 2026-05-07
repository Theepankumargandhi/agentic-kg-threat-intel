import logging

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.agent.graph import run_agent
from app.models.schemas import (
    GraphExploreResponse,
    PathEdge,
    PathNode,
    PathTrace,
    QueryRequest,
    QueryResponse,
    ReasoningStep,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["query"])


def _to_path_trace(raw: dict) -> PathTrace:
    nodes = []
    for n in raw.get("nodes", []):
        try:
            nodes.append(PathNode(**n) if isinstance(n, dict) else n)
        except Exception:
            pass
    edges = []
    for e in raw.get("edges", []):
        try:
            edges.append(PathEdge(**e) if isinstance(e, dict) else e)
        except Exception:
            pass
    return PathTrace(nodes=nodes, edges=edges)


def _to_reasoning_steps(raw: list[dict]) -> list[ReasoningStep]:
    steps = []
    for r in raw or []:
        try:
            steps.append(ReasoningStep(**r) if isinstance(r, dict) else r)
        except Exception:
            pass
    return steps


@router.post("/query", response_model=QueryResponse, summary="Run agentic threat-intelligence query")
async def query_endpoint(body: QueryRequest, request: Request) -> QueryResponse:
    app_state = request.app.state.app_state

    try:
        result = await run_agent(
            query=body.query,
            hybrid_retriever=app_state.hybrid_retriever,
            graph_store=app_state.graph_store,
            top_k=body.top_k,
            include_mitigations=body.include_mitigations,
            max_hops=body.max_hops,
        )
    except Exception as exc:
        logger.exception("Agent failed for query: %r", body.query)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    return QueryResponse(
        query=result.get("query", body.query),
        answer=result.get("answer", ""),
        path_trace=_to_path_trace(result.get("path_trace") or {}),
        reasoning_steps=_to_reasoning_steps(result.get("reasoning_steps")),
        sources=result.get("sources") or [],
        confidence=result.get("confidence", 0.0),
        latency_ms=result.get("latency_ms", 0.0),
    )


@router.get("/graph/explore", response_model=GraphExploreResponse, summary="Explore graph neighbourhood")
async def graph_explore(
    request: Request,
    node_id: str = Query(..., description="MITRE ATT&CK node ID or external_id (e.g. T1059)"),
    hops: int = Query(default=1, ge=1, le=4),
) -> GraphExploreResponse:
    graph_store = request.app.state.app_state.graph_store

    try:
        raw = graph_store.build_path_trace([node_id])
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    if not raw or not raw.get("nodes"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Node '{node_id}' not found.")

    path_trace = _to_path_trace(raw)
    return GraphExploreResponse(
        path_trace=path_trace,
        node_count=len(path_trace.nodes),
        edge_count=len(path_trace.edges),
    )
