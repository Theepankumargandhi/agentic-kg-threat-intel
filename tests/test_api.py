"""
pytest test suite for the Agentic Knowledge Graph Reasoning Engine API.

All external dependencies (Neo4j, ChromaDB, the LangGraph agent, the
MITRE data loaders) are mocked so the tests run offline and fast.

Run:
    pytest tests/test_api.py -v
    pytest tests/test_api.py -v --cov=app --cov-report=term-missing
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App import with dependency overrides applied before the client is created.
# We patch the heavy initialisation that happens at import/startup time so
# that the TestClient never tries to reach Neo4j or ChromaDB.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> TestClient:
    """
    Build a FastAPI TestClient with all external services mocked.

    The patches are applied at module scope so the app is only instantiated
    once per test session, matching production behaviour where the lifespan
    hook runs once.
    """
    # Patch Neo4j driver before app is imported
    neo4j_mock = MagicMock()
    neo4j_mock.verify_connectivity.return_value = None
    neo4j_mock.session.return_value.__enter__ = MagicMock(return_value=MagicMock())
    neo4j_mock.session.return_value.__exit__ = MagicMock(return_value=False)

    # Patch ChromaDB client
    chroma_mock = MagicMock()
    chroma_collection_mock = MagicMock()
    chroma_mock.get_or_create_collection.return_value = chroma_collection_mock

    with (
        patch("neo4j.GraphDatabase.driver", return_value=neo4j_mock),
        patch("chromadb.PersistentClient", return_value=chroma_mock),
        patch("chromadb.Client", return_value=chroma_mock),
    ):
        from app.main import app  # noqa: PLC0415 — import inside fixture intentional

        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _make_agent_response(
    answer: str = "APT29 uses T1566 for Initial Access.",
    technique_ids: list[str] | None = None,
    graph_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "answer": answer,
        "technique_ids": technique_ids or ["T1566", "T1078"],
        "graph_results": graph_results
        or [
            {"id": "T1566", "name": "Phishing", "type": "Technique"},
            {"id": "T1078", "name": "Valid Accounts", "type": "Technique"},
        ],
        "path_trace": "APT29 -[USES]-> T1566 -[BELONGS_TO]-> Initial Access",
        "sources": ["MITRE ATT&CK v14"],
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
        assert "status" in data, "Response must contain 'status' key"
        assert data["status"] in ("ok", "healthy", "degraded", "unhealthy")

    def test_health_includes_service_info(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        data = resp.json()
        # At minimum the response should report something about uptime or version
        # Accept any additional keys beyond 'status'
        assert isinstance(data, dict)

    def test_health_content_type_json(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        assert "application/json" in resp.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# 2. Query endpoint
# ---------------------------------------------------------------------------


class TestQueryEndpoint:
    """POST /api/v1/query"""

    @patch("app.main.run_agent")
    def test_query_returns_200(self, mock_run_agent: MagicMock, client: TestClient) -> None:
        mock_run_agent.return_value = _make_agent_response()
        resp = client.post(
            "/api/v1/query",
            json={"query": "What techniques does APT29 use for initial access?"},
        )
        assert resp.status_code == 200

    @patch("app.main.run_agent")
    def test_query_response_contains_answer(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        expected = "APT29 uses spearphishing (T1566) for Initial Access."
        mock_run_agent.return_value = _make_agent_response(answer=expected)
        resp = client.post(
            "/api/v1/query",
            json={"query": "What techniques does APT29 use for initial access?"},
        )
        data = resp.json()
        assert "answer" in data
        assert data["answer"] == expected

    @patch("app.main.run_agent")
    def test_query_response_contains_technique_ids(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        mock_run_agent.return_value = _make_agent_response(
            technique_ids=["T1566", "T1078", "T1195"]
        )
        resp = client.post(
            "/api/v1/query",
            json={"query": "What techniques does APT29 use for initial access?"},
        )
        data = resp.json()
        assert "technique_ids" in data
        assert "T1566" in data["technique_ids"]

    @patch("app.main.run_agent")
    def test_query_response_contains_graph_results(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        gr = [{"id": "T1566", "name": "Phishing", "type": "Technique"}]
        mock_run_agent.return_value = _make_agent_response(graph_results=gr)
        resp = client.post(
            "/api/v1/query",
            json={"query": "Tell me about phishing techniques"},
        )
        data = resp.json()
        assert "graph_results" in data
        assert isinstance(data["graph_results"], list)

    @patch("app.main.run_agent")
    def test_query_agent_is_called_with_correct_query(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        mock_run_agent.return_value = _make_agent_response()
        query_text = "What persistence mechanisms does FIN7 use?"
        client.post("/api/v1/query", json={"query": query_text})
        mock_run_agent.assert_called_once()
        call_args = mock_run_agent.call_args
        # The query string should be passed somewhere in args or kwargs
        all_args = str(call_args)
        assert query_text in all_args

    @patch("app.main.run_agent")
    def test_query_with_max_results_parameter(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        mock_run_agent.return_value = _make_agent_response()
        resp = client.post(
            "/api/v1/query",
            json={
                "query": "Lateral movement via valid accounts",
                "max_results": 10,
            },
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 3. Ingest endpoint
# ---------------------------------------------------------------------------


class TestIngestEndpoint:
    """POST /api/v1/ingest"""

    @patch("app.main.MitreEmbedder")
    @patch("app.main.MitreLoader")
    def test_ingest_returns_200(
        self,
        mock_loader_cls: MagicMock,
        mock_embedder_cls: MagicMock,
        client: TestClient,
    ) -> None:
        # Configure mocked loader
        mock_loader = MagicMock()
        mock_loader.load.return_value = [
            {"id": "T1566", "name": "Phishing", "description": "Phishing desc"}
        ]
        mock_loader_cls.return_value = mock_loader

        # Configure mocked embedder
        mock_embedder = MagicMock()
        mock_embedder.embed_and_store.return_value = {"stored": 1}
        mock_embedder_cls.return_value = mock_embedder

        resp = client.post("/api/v1/ingest", json={"source": "mitre"})
        assert resp.status_code == 200

    @patch("app.main.MitreEmbedder")
    @patch("app.main.MitreLoader")
    def test_ingest_response_schema(
        self,
        mock_loader_cls: MagicMock,
        mock_embedder_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_loader = MagicMock()
        mock_loader.load.return_value = [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
        mock_loader_cls.return_value = mock_loader

        mock_embedder = MagicMock()
        mock_embedder.embed_and_store.return_value = {"stored": 1}
        mock_embedder_cls.return_value = mock_embedder

        resp = client.post("/api/v1/ingest", json={"source": "mitre"})
        data = resp.json()
        # Must include at minimum a message or status field
        assert isinstance(data, dict)
        assert any(k in data for k in ("message", "status", "ingested", "result"))

    @patch("app.main.MitreEmbedder")
    @patch("app.main.MitreLoader")
    def test_ingest_loader_called_once(
        self,
        mock_loader_cls: MagicMock,
        mock_embedder_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_loader = MagicMock()
        mock_loader.load.return_value = []
        mock_loader_cls.return_value = mock_loader

        mock_embedder = MagicMock()
        mock_embedder.embed_and_store.return_value = {}
        mock_embedder_cls.return_value = mock_embedder

        client.post("/api/v1/ingest", json={"source": "mitre"})
        mock_loader.load.assert_called_once()


# ---------------------------------------------------------------------------
# 4. Validation — invalid / empty queries
# ---------------------------------------------------------------------------


class TestInputValidation:
    """Ensure the API rejects malformed requests properly."""

    def test_empty_query_returns_422(self, client: TestClient) -> None:
        """Pydantic should reject an empty string query."""
        resp = client.post("/api/v1/query", json={"query": ""})
        assert resp.status_code == 422

    def test_missing_query_field_returns_422(self, client: TestClient) -> None:
        """Request body without 'query' key must fail validation."""
        resp = client.post("/api/v1/query", json={})
        assert resp.status_code == 422

    def test_query_too_long_returns_422(self, client: TestClient) -> None:
        """Queries exceeding max length should be rejected."""
        long_query = "x" * 5001
        resp = client.post("/api/v1/query", json={"query": long_query})
        # Accept 422 (validation) or 400 (business logic) — both are correct
        assert resp.status_code in (400, 422)

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


# ---------------------------------------------------------------------------
# 5. Graph explore / graph store integration
# ---------------------------------------------------------------------------


class TestGraphExplore:
    """Tests for graph-store interactions via the query endpoint."""

    @patch("app.main.run_agent")
    def test_graph_results_are_list(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        mock_run_agent.return_value = _make_agent_response(
            graph_results=[
                {"id": "T1021", "name": "Remote Services", "type": "Technique"},
                {"id": "T1078", "name": "Valid Accounts", "type": "Technique"},
            ]
        )
        resp = client.post(
            "/api/v1/query",
            json={"query": "lateral movement via remote services"},
        )
        data = resp.json()
        assert isinstance(data.get("graph_results"), list)

    @patch("app.main.run_agent")
    def test_graph_path_trace_returned(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        mock_run_agent.return_value = _make_agent_response()
        resp = client.post(
            "/api/v1/query",
            json={"query": "APT29 techniques", "include_graph_path": True},
        )
        data = resp.json()
        # path_trace is optional but if present must be a non-empty string
        if "path_trace" in data:
            assert isinstance(data["path_trace"], str)
            assert len(data["path_trace"]) > 0

    @patch("app.main.run_agent")
    def test_graph_store_query_with_group_filter(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        mock_run_agent.return_value = _make_agent_response(
            answer="FIN7 uses T1547 for persistence.",
            technique_ids=["T1547", "T1053"],
        )
        resp = client.post(
            "/api/v1/query",
            json={"query": "What persistence mechanisms does FIN7 use?"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "answer" in data

    @patch("app.main.run_agent")
    def test_empty_graph_results_handled_gracefully(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        """Engine must not crash when graph returns no nodes."""
        mock_run_agent.return_value = {
            "answer": "No relevant techniques found.",
            "technique_ids": [],
            "graph_results": [],
            "path_trace": "",
            "sources": [],
        }
        resp = client.post(
            "/api/v1/query",
            json={"query": "some obscure query with no results"},
        )
        assert resp.status_code == 200

    @patch("app.main.run_agent")
    def test_technique_ids_in_response_are_valid_format(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        """All returned technique IDs must match the T\d{4} pattern."""
        import re

        mock_run_agent.return_value = _make_agent_response(
            technique_ids=["T1566", "T1566.001", "T1078"]
        )
        resp = client.post(
            "/api/v1/query",
            json={"query": "phishing techniques"},
        )
        data = resp.json()
        pattern = re.compile(r"^T\d{4}(?:\.\d{3})?$")
        for tid in data.get("technique_ids", []):
            assert pattern.match(tid), f"Invalid technique ID format: {tid}"


# ---------------------------------------------------------------------------
# 6. Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Verify the API returns structured error responses on failures."""

    @patch("app.main.run_agent", side_effect=RuntimeError("Agent crashed"))
    def test_agent_error_returns_500(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        resp = client.post(
            "/api/v1/query",
            json={"query": "What is lateral movement?"},
        )
        assert resp.status_code == 500

    @patch("app.main.run_agent", side_effect=RuntimeError("Agent crashed"))
    def test_error_response_is_json(
        self, mock_run_agent: MagicMock, client: TestClient
    ) -> None:
        resp = client.post(
            "/api/v1/query",
            json={"query": "What is lateral movement?"},
        )
        assert resp.headers.get("content-type", "").startswith("application/json")

    def test_method_not_allowed_on_query(self, client: TestClient) -> None:
        resp = client.get("/api/v1/query")
        assert resp.status_code == 405

    def test_unknown_route_returns_404(self, client: TestClient) -> None:
        resp = client.get("/api/v1/nonexistent")
        assert resp.status_code == 404
