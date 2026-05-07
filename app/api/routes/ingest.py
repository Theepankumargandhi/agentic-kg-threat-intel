import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException, Request, status

from app.config import settings
from app.ingestion.embedder import MitreEmbedder
from app.ingestion.mitre_loader import MitreLoader
from app.models.schemas import IngestRequest, IngestResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ingestion"])

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ingest")
_ingest_lock = asyncio.Lock()


def _run_ingestion(force_refresh: bool) -> dict:
    loader = MitreLoader(settings.NEO4J_URI, settings.NEO4J_USER, settings.NEO4J_PASSWORD)
    embedder = MitreEmbedder(
        settings.NEO4J_URI,
        settings.NEO4J_USER,
        settings.NEO4J_PASSWORD,
        settings.CHROMA_PATH,
        settings.EMBEDDING_MODEL,
    )
    try:
        load_stats = loader.load(force_refresh=force_refresh)
        embed_count = embedder.embed(force_refresh=force_refresh)
        return {
            "nodes_created": load_stats.get("nodes_created", 0),
            "edges_created": load_stats.get("edges_created", 0),
            "embeddings_created": embed_count,
            "error": None,
        }
    except Exception as exc:
        logger.exception("Ingestion pipeline failed")
        return {"nodes_created": 0, "edges_created": 0, "embeddings_created": 0, "error": str(exc)}
    finally:
        loader.close()
        embedder.close()


@router.post("/ingest", response_model=IngestResponse, summary="Ingest MITRE ATT&CK data")
async def ingest(body: IngestRequest, request: Request) -> IngestResponse:
    if _ingest_lock.locked():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ingestion already running.")

    async with _ingest_lock:
        t0 = time.perf_counter()
        loop = asyncio.get_running_loop()
        stats = await loop.run_in_executor(_executor, _run_ingestion, body.force_refresh)
        duration_s = round(time.perf_counter() - t0, 2)

        if stats["error"]:
            raise HTTPException(  # noqa: B904 — no exc in scope here; stats["error"] is a string
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Ingestion failed: {stats['error']}",
            )

        return IngestResponse(
            status="success",
            nodes_created=stats["nodes_created"],
            edges_created=stats["edges_created"],
            embeddings_created=stats["embeddings_created"],
            duration_s=duration_s,
        )
