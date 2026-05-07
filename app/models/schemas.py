from pydantic import BaseModel, Field
from typing import Any
from enum import Enum


class NodeType(str, Enum):
    TACTIC = "Tactic"
    TECHNIQUE = "Technique"
    SUB_TECHNIQUE = "SubTechnique"
    GROUP = "Group"
    SOFTWARE = "Software"
    MITIGATION = "Mitigation"


class QueryRequest(BaseModel):
    query: str = Field(..., description="Natural language threat intelligence query")
    top_k: int = Field(default=10, ge=1, le=50)
    include_mitigations: bool = Field(default=True)
    max_hops: int = Field(default=3, ge=1, le=5)


class PathNode(BaseModel):
    id: str
    type: NodeType
    name: str
    properties: dict[str, Any] = {}


class PathEdge(BaseModel):
    source: str
    target: str
    relation: str


class PathTrace(BaseModel):
    nodes: list[PathNode] = []
    edges: list[PathEdge] = []


class ReasoningStep(BaseModel):
    step: int
    action: str
    observation: str
    source: str  # "vector" | "graph" | "llm"


class QueryResponse(BaseModel):
    query: str
    answer: str
    path_trace: PathTrace
    reasoning_steps: list[ReasoningStep] = []
    sources: list[dict[str, Any]] = []
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: float


class IngestRequest(BaseModel):
    source: str = Field(default="mitre")
    force_refresh: bool = Field(default=False)


class IngestResponse(BaseModel):
    status: str
    nodes_created: int
    edges_created: int
    embeddings_created: int
    duration_s: float


class HealthResponse(BaseModel):
    status: str
    neo4j: bool
    chromadb: bool
    llm: bool
    version: str = "1.0.0"


class GraphExploreRequest(BaseModel):
    node_id: str
    hops: int = Field(default=2, ge=1, le=5)


class GraphExploreResponse(BaseModel):
    path_trace: PathTrace
    node_count: int
    edge_count: int
