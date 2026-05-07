"""
pytest test suite for the Agentic Knowledge Graph Reasoning Engine API.

All external dependencies (Neo4j, ChromaDB, SentenceTransformer, the
LangGraph agent, and the MITRE data loaders) are mocked so the tests
run offline and fast with no model downloads.

Run:
    pytest tests/test_api.py -v
    pytest tests/test_api.py -v --cov=app --cov-report=term-missing
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Build a FastAPI TestClient with all external services mocked."""
    neo4j_mock = MagicMock()
    neo4j_mock.verify_connectivity.return_value = None

    chroma_mock = MagicMock()
    chroma_mock.get_or_create_collection.return_value = MagicMock()

    st_mock = MagicMock()

    with (
        patch("neo4j.GraphDatabase.driver", return_value=neo4j_mock),
        patch("chromadb.PersistentClient", return_value=chroma_mock),
        patch("app.retrieval.vector_store.SentenceTransformer", return_value=st_mock),
    ):
        from app.main import app  # noqa: PLC0415

        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


def _agent_result(
    answer: str = "APT29 uses T1566 for Initial Access.",
    confidence: float = 0.87,
) -> dict[str, Any]:
    """Return a dict matching the structure that run_agent actually produces."""
    return {
        "query": "test query",
        "answer": answer,
        "path_trace": {
            "nodes": [
                {"id": "apt29", "type": "Group", "name": "APT29", "properties": {}},
                {
                    "id": "t1566",
                    "type": "Technique",
                    "name": "Phishing",
                    "properties": {"external_id": "T1566"},
                },
            ],
            "edges": [{"source": "apt29", "target": "t1566", "relation": "USES"}],
        },
        "reasoning_steps": [
            {
                "step": 1,
                "action": "Query Planning",
                "observation": "Decomposed query into sub-queries",
                "source": "llm",
            },
        ],
        "sources": [{"name": "Phishing", "external_id": "T1566", "type": "Technique"}],
        "confidence": confidence,
        "latency_ms": 943.2,
    }


# ---------------------------------------------------------------------------
# 1. Health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """GET /api/v1/health"""

    def test_health_returns_200(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_health_response_schema(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        data = resp.json()
        assert "status" in data
        assert data["status"] in ("healthy", "degraded", "unhealthy")

    def test_health_includes_service_flags(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        data = resp.json()
        assert "neo4j" in data
        assert "chromadb" in data
        assert "llm" in data
        assert isinstance(data["neo4j"], bool)
        assert isinstance(data["chromadb"], bool)
        assert isinstance(data["llm"], bool)

    def test_health_content_type_json(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        assert "application/json" in resp.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# 2. Query endpoint
# ---------------------------------------------------------------------------


class TestQueryEndpoint:
    """POST /api/v1/query"""

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_returns_200(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post(
            "/api/v1/query",
            json={"query": "What techniques does APT29 use for initial access?"},
        )
        assert resp.status_code == 200

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_response_contains_answer(self, mock_run: AsyncMock, client: TestClient) -> None:
        expected = "APT29 uses spearphishing (T1566) for Initial Access."
        mock_run.return_value = _agent_result(answer=expected)
        resp = client.post(
            "/api/v1/query",
            json={"query": "What techniques does APT29 use for initial access?"},
        )
        data = resp.json()
        assert "answer" in data
        assert data["answer"] == expected

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_response_contains_path_trace(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post("/api/v1/query", json={"query": "Phishing techniques"})
        data = resp.json()
        assert "path_trace" in data
        assert "nodes" in data["path_trace"]
        assert "edges" in data["path_trace"]
        assert isinstance(data["path_trace"]["nodes"], list)
        assert isinstance(data["path_trace"]["edges"], list)

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_response_contains_reasoning_steps(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post("/api/v1/query", json={"query": "APT29 techniques"})
        data = resp.json()
        assert "reasoning_steps" in data
        assert isinstance(data["reasoning_steps"], list)

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_response_contains_confidence(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result(confidence=0.92)
        resp = client.post("/api/v1/query", json={"query": "Lateral movement techniques"})
        data = resp.json()
        assert "confidence" in data
        assert data["confidence"] == pytest.approx(0.92)

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_response_contains_latency_ms(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post("/api/v1/query", json={"query": "FIN7 techniques"})
        data = resp.json()
        assert "latency_ms" in data
        assert isinstance(data["latency_ms"], int | float)

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_response_contains_sources(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post("/api/v1/query", json={"query": "FIN7 persistence"})
        data = resp.json()
        assert "sources" in data
        assert isinstance(data["sources"], list)

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_agent_called_with_correct_query(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        query_text = "What persistence mechanisms does FIN7 use?"
        client.post("/api/v1/query", json={"query": query_text})
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs["query"] == query_text

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_with_top_k_parameter(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post(
            "/api/v1/query",
            json={"query": "Lateral movement via valid accounts", "top_k": 5},
        )
        assert resp.status_code == 200
        assert mock_run.call_args.kwargs["top_k"] == 5


# ---------------------------------------------------------------------------
# 3. Ingest endpoint
# ---------------------------------------------------------------------------


class TestIngestEndpoint:
    """POST /api/v1/ingest"""

    @patch("app.api.routes.ingest.MitreEmbedder")
    @patch("app.api.routes.ingest.MitreLoader")
    def test_ingest_returns_200(
        self,
        mock_loader_cls: MagicMock,
        mock_embedder_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_loader = MagicMock()
        mock_loader.load.return_value = {"nodes_created": 100, "edges_created": 500}
        mock_loader_cls.return_value = mock_loader

        mock_embedder = MagicMock()
        mock_embedder.embed.return_value = 100
        mock_embedder_cls.return_value = mock_embedder

        resp = client.post("/api/v1/ingest", json={"source": "mitre"})
        assert resp.status_code == 200

    @patch("app.api.routes.ingest.MitreEmbedder")
    @patch("app.api.routes.ingest.MitreLoader")
    def test_ingest_response_schema(
        self,
        mock_loader_cls: MagicMock,
        mock_embedder_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_loader = MagicMock()
        mock_loader.load.return_value = {"nodes_created": 50, "edges_created": 200}
        mock_loader_cls.return_value = mock_loader

        mock_embedder = MagicMock()
        mock_embedder.embed.return_value = 50
        mock_embedder_cls.return_value = mock_embedder

        resp = client.post("/api/v1/ingest", json={"source": "mitre"})
        data = resp.json()
        assert data["status"] == "success"
        assert "nodes_created" in data
        assert "edges_created" in data
        assert "embeddings_created" in data
        assert "duration_s" in data
        assert isinstance(data["nodes_created"], int)
        assert isinstance(data["embeddings_created"], int)

    @patch("app.api.routes.ingest.MitreEmbedder")
    @patch("app.api.routes.ingest.MitreLoader")
    def test_ingest_loader_called_once(
        self,
        mock_loader_cls: MagicMock,
        mock_embedder_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_loader = MagicMock()
        mock_loader.load.return_value = {"nodes_created": 0, "edges_created": 0}
        mock_loader_cls.return_value = mock_loader

        mock_embedder = MagicMock()
        mock_embedder.embed.return_value = 0
        mock_embedder_cls.return_value = mock_embedder

        client.post("/api/v1/ingest", json={"source": "mitre"})
        mock_loader.load.assert_called_once()


# ---------------------------------------------------------------------------
# 4. Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    """Ensure the API rejects malformed requests properly."""

    def test_empty_query_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={"query": ""})
        assert resp.status_code == 422

    def test_missing_query_field_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={})
        assert resp.status_code == 422

    def test_query_too_long_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={"query": "x" * 5001})
        assert resp.status_code == 422

    def test_non_json_body_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/query",
            data="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_null_query_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={"query": None})
        assert resp.status_code == 422

    def test_top_k_out_of_range_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={"query": "valid query", "top_k": 0})
        assert resp.status_code == 422

    def test_max_hops_out_of_range_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={"query": "valid query", "max_hops": 10})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 5. Path trace structure
# ---------------------------------------------------------------------------


class TestPathTrace:
    """Tests for path trace structure in query responses."""

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_path_trace_nodes_have_required_fields(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post("/api/v1/query", json={"query": "APT29 techniques"})
        nodes = resp.json()["path_trace"]["nodes"]
        assert len(nodes) > 0
        for node in nodes:
            assert "id" in node
            assert "type" in node
            assert "name" in node

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_path_trace_edges_have_required_fields(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result()
        resp = client.post("/api/v1/query", json={"query": "APT29 techniques"})
        edges = resp.json()["path_trace"]["edges"]
        assert len(edges) > 0
        for edge in edges:
            assert "source" in edge
            assert "target" in edge
            assert "relation" in edge

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_empty_path_trace_handled_gracefully(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = {
            "query": "obscure query",
            "answer": "No relevant techniques found.",
            "path_trace": {"nodes": [], "edges": []},
            "reasoning_steps": [],
            "sources": [],
            "confidence": 0.0,
            "latency_ms": 100.0,
        }
        resp = client.post("/api/v1/query", json={"query": "some obscure query"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["path_trace"]["nodes"] == []
        assert data["path_trace"]["edges"] == []

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock)
    def test_query_with_group_filter(self, mock_run: AsyncMock, client: TestClient) -> None:
        mock_run.return_value = _agent_result(answer="FIN7 uses T1547 for persistence.")
        resp = client.post(
            "/api/v1/query",
            json={"query": "What persistence mechanisms does FIN7 use?"},
        )
        assert resp.status_code == 200
        assert "answer" in resp.json()


# ---------------------------------------------------------------------------
# 6. Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Verify the API returns structured error responses on failures."""

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock, side_effect=RuntimeError("Agent crashed"))
    def test_agent_error_returns_500(self, mock_run: AsyncMock, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={"query": "What is lateral movement?"})
        assert resp.status_code == 500

    @patch("app.api.routes.query.run_agent", new_callable=AsyncMock, side_effect=RuntimeError("Agent crashed"))
    def test_error_response_is_json(self, mock_run: AsyncMock, client: TestClient) -> None:
        resp = client.post("/api/v1/query", json={"query": "What is lateral movement?"})
        assert resp.headers.get("content-type", "").startswith("application/json")

    def test_method_not_allowed_on_query(self, client: TestClient) -> None:
        resp = client.get("/api/v1/query")
        assert resp.status_code == 405

    def test_unknown_route_returns_404(self, client: TestClient) -> None:
        resp = client.get("/api/v1/nonexistent")
        assert resp.status_code == 404
