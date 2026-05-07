"""
Hybrid retriever combining dense vector search (ChromaDB) and
graph traversal (Neo4j) via Reciprocal Rank Fusion (RRF).
"""
import logging
import re

from app.retrieval.vector_store import VectorStore
from app.retrieval.graph_store import GraphStore

logger = logging.getLogger(__name__)

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_TACTIC_KEYWORDS = [
    "initial access", "execution", "persistence", "privilege escalation",
    "defense evasion", "credential access", "discovery", "lateral movement",
    "collection", "command and control", "exfiltration", "impact",
]


class HybridRetriever:
    def __init__(self, vector_store: VectorStore, graph_store: GraphStore):
        self.vector_store = vector_store
        self.graph_store = graph_store

    def retrieve(
        self,
        query: str,
        top_k: int = 10,
        vector_weight: float = 0.6,
        graph_weight: float = 0.4,
        include_mitigations: bool = True,
    ) -> dict:
        vector_results = self.vector_store.query(query, top_k=top_k)
        graph_results = self._extract_graph_context(query, top_k=top_k)

        fused = self._rrf_fusion(vector_results, graph_results)
        path_trace = self._build_path_trace_from_results(graph_results)

        if include_mitigations:
            self._enrich_with_mitigations(fused)

        return {
            "results": fused[:top_k],
            "vector_results": vector_results,
            "graph_results": graph_results,
            "path_trace": path_trace,
        }

    # ------------------------------------------------------------------
    # RRF fusion
    # ------------------------------------------------------------------

    def _rrf_fusion(
        self,
        vector_results: list[dict],
        graph_results: list[dict],
        k: int = 60,
    ) -> list[dict]:
        scores: dict[str, float] = {}
        merged: dict[str, dict] = {}

        for rank, item in enumerate(vector_results):
            item_id = item.get("external_id") or item.get("id", "")
            scores[item_id] = scores.get(item_id, 0.0) + 1.0 / (k + rank + 1)
            merged[item_id] = {**item, "sources": ["vector"]}

        for rank, item in enumerate(graph_results):
            item_id = item.get("external_id") or item.get("id", "")
            scores[item_id] = scores.get(item_id, 0.0) + 1.0 / (k + rank + 1)
            if item_id in merged:
                merged[item_id]["sources"] = list(set(merged[item_id].get("sources", []) + ["graph"]))
            else:
                merged[item_id] = {**item, "sources": ["graph"]}

        for item_id, item in merged.items():
            item["rrf_score"] = scores[item_id]

        return sorted(merged.values(), key=lambda x: x["rrf_score"], reverse=True)

    # ------------------------------------------------------------------
    # Graph context extraction
    # ------------------------------------------------------------------

    def _extract_graph_context(self, query: str, top_k: int = 10) -> list[dict]:
        results: list[dict] = []
        seen_ids: set[str] = set()

        # Technique IDs (T1059, T1566.001, etc.)
        for tech_id in _TECHNIQUE_ID_RE.findall(query):
            node = self.graph_store.get_node_by_external_id(tech_id)
            if node and node.get("id") not in seen_ids:
                results.append({
                    "id": node["id"],
                    "name": node.get("name", ""),
                    "external_id": tech_id,
                    "description": node.get("properties", {}).get("description", ""),
                    "node_type": node.get("type", "Technique"),
                    "source": "graph",
                    "score": 0.9,
                })
                seen_ids.add(node["id"])

        # Tactic keywords
        query_lower = query.lower()
        for tactic_kw in _TACTIC_KEYWORDS:
            if tactic_kw in query_lower:
                for tech in self.graph_store.get_techniques_by_tactic(tactic_kw, limit=5):
                    if tech.get("id") not in seen_ids:
                        tech["source"] = "graph"
                        tech["score"] = 0.7
                        results.append(tech)
                        seen_ids.add(tech["id"])

        # General keyword search
        words = [w for w in query.split() if len(w) > 4]
        for word in words[:3]:
            for tech in self.graph_store.query_techniques_by_keyword(word, limit=3):
                if tech.get("id") not in seen_ids:
                    tech["source"] = "graph"
                    tech["score"] = 0.5
                    results.append(tech)
                    seen_ids.add(tech["id"])

        return results[:top_k]

    # ------------------------------------------------------------------
    # Path trace
    # ------------------------------------------------------------------

    def _build_path_trace_from_results(self, graph_results: list[dict]) -> dict:
        node_ids = [r.get("id") for r in graph_results if r.get("id")]
        if not node_ids:
            return {"nodes": [], "edges": []}
        return self.graph_store.build_path_trace(node_ids[:10])

    # ------------------------------------------------------------------
    # Mitigation enrichment
    # ------------------------------------------------------------------

    def _enrich_with_mitigations(self, results: list[dict]) -> None:
        for item in results[:5]:
            ext_id = item.get("external_id", "")
            if not ext_id:
                continue
            mitigations = self.graph_store.get_technique_mitigations(ext_id)
            if mitigations:
                item["mitigations"] = mitigations
