"""
Agentic Knowledge Graph Reasoning Engine — FastAPI entry point.
Run: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

import logging
import time
from collections.abc import Callable
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import health, ingest, query
from app.config import settings
from app.retrieval.graph_store import GraphStore
from app.retrieval.hybrid_retriever import HybridRetriever
from app.retrieval.vector_store import VectorStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


class AppState:
    vector_store: VectorStore | None = None
    graph_store: GraphStore | None = None
    hybrid_retriever: HybridRetriever | None = None


app_state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up — connecting to Neo4j at %s", settings.NEO4J_URI)
    app_state.graph_store = GraphStore(settings.NEO4J_URI, settings.NEO4J_USER, settings.NEO4J_PASSWORD)
    app_state.vector_store = VectorStore(settings.CHROMA_PATH, settings.EMBEDDING_MODEL)
    app_state.hybrid_retriever = HybridRetriever(app_state.vector_store, app_state.graph_store)
    app.state.app_state = app_state
    logger.info("All subsystems ready.")
    yield
    logger.info("Shutting down — closing connections")
    if app_state.graph_store:
        app_state.graph_store.close()


app = FastAPI(
    title="Agentic Knowledge Graph Reasoning Engine",
    description=("Cybersecurity Threat Intelligence powered by MITRE ATT&CK, LangGraph, Neo4j, and ChromaDB."),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next: Callable) -> Response:
    t0 = time.perf_counter()
    response: Response = await call_next(request)
    ms = (time.perf_counter() - t0) * 1000
    logger.info("%s %s → %d (%.1f ms)", request.method, request.url.path, response.status_code, ms)
    return response


API_PREFIX = "/api/v1"
app.include_router(health.router, prefix=API_PREFIX)
app.include_router(ingest.router, prefix=API_PREFIX)
app.include_router(query.router, prefix=API_PREFIX)


@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Agentic Knowledge Graph API — see /docs"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.API_HOST, port=settings.API_PORT, reload=True)
