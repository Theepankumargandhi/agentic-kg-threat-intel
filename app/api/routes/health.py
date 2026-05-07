import logging
import os

from fastapi import APIRouter, Request

from app.models.schemas import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Service health check")
async def health_check(request: Request) -> HealthResponse:
    app_state = request.app.state.app_state

    neo4j_ok = False
    try:
        neo4j_ok = app_state.graph_store.health_check()
    except Exception as exc:
        logger.warning("Neo4j health check failed: %s", exc)

    chroma_ok = False
    try:
        chroma_ok = app_state.vector_store.is_populated()
    except Exception as exc:
        logger.warning("ChromaDB health check failed: %s", exc)

    llm_ok = bool(os.environ.get("ANTHROPIC_API_KEY", ""))

    overall = "healthy" if (neo4j_ok and chroma_ok and llm_ok) else "degraded"
    return HealthResponse(status=overall, neo4j=neo4j_ok, chromadb=chroma_ok, llm=llm_ok)
