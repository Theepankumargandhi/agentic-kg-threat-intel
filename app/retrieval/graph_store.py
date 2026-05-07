"""
Neo4j graph store wrapper with Cypher queries for MITRE ATT&CK traversal.
"""
import logging
import re

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


class GraphStore:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    # ------------------------------------------------------------------
    # Keyword / entity search
    # ------------------------------------------------------------------

    def query_techniques_by_keyword(self, keyword: str, limit: int = 10) -> list[dict]:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (t)
                WHERE (t:Technique OR t:SubTechnique)
                  AND (toLower(t.name) CONTAINS toLower($kw)
                    OR toLower(t.description) CONTAINS toLower($kw))
                RETURN t.id AS id, t.name AS name, t.external_id AS external_id,
                       t.description AS description,
                       CASE WHEN t:SubTechnique THEN 'SubTechnique' ELSE 'Technique' END AS node_type
                LIMIT $limit
                """,
                kw=keyword,
                limit=limit,
            )
            return [dict(r) for r in result]

    def get_techniques_by_tactic(self, tactic_name: str, limit: int = 20) -> list[dict]:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (t:Technique)-[:BELONGS_TO]->(ta:Tactic)
                WHERE toLower(ta.name) CONTAINS toLower($tactic_name)
                   OR toLower(ta.shortname) CONTAINS toLower($tactic_name)
                RETURN t.id AS id, t.name AS name, t.external_id AS external_id,
                       t.description AS description, ta.name AS tactic_name
                LIMIT $limit
                """,
                tactic_name=tactic_name,
                limit=limit,
            )
            return [dict(r) for r in result]

    def get_groups_using_technique(self, technique_external_id: str) -> list[dict]:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (g:Group)-[:USES]->(t)
                WHERE (t:Technique OR t:SubTechnique)
                  AND t.external_id = $ext_id
                RETURN g.id AS id, g.name AS name, g.external_id AS external_id,
                       g.aliases AS aliases
                """,
                ext_id=technique_external_id,
            )
            return [dict(r) for r in result]

    def get_technique_mitigations(self, technique_external_id: str) -> list[dict]:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
                WHERE (t:Technique OR t:SubTechnique)
                  AND t.external_id = $ext_id
                RETURN m.id AS id, m.name AS name, m.external_id AS external_id,
                       m.description AS description
                """,
                ext_id=technique_external_id,
            )
            return [dict(r) for r in result]

    def get_related_techniques(self, technique_external_id: str, hops: int = 2) -> list[dict]:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH path = (start)-[*1..$hops]-(related)
                WHERE (start:Technique OR start:SubTechnique)
                  AND start.external_id = $ext_id
                  AND (related:Technique OR related:SubTechnique
                       OR related:Tactic OR related:Group OR related:Software)
                WITH related, length(path) AS distance
                RETURN DISTINCT
                    related.id AS id,
                    related.name AS name,
                    related.external_id AS external_id,
                    related.description AS description,
                    labels(related)[0] AS node_type,
                    distance
                ORDER BY distance
                LIMIT 30
                """,
                ext_id=technique_external_id,
                hops=hops,
            )
            return [dict(r) for r in result]

    def get_attack_path(self, group_name: str, limit: int = 20) -> dict:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (g:Group)-[:USES]->(t)
                WHERE toLower(g.name) CONTAINS toLower($group_name)
                   OR toLower(g.aliases) CONTAINS toLower($group_name)
                  AND (t:Technique OR t:SubTechnique)
                OPTIONAL MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
                RETURN g.id AS group_id, g.name AS group_name,
                       t.id AS technique_id, t.name AS technique_name,
                       t.external_id AS technique_ext_id,
                       ta.id AS tactic_id, ta.name AS tactic_name
                LIMIT $limit
                """,
                group_name=group_name,
                limit=limit,
            )
            rows = [dict(r) for r in result]

        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        seen_edges: set = set()

        for row in rows:
            if row.get("group_id"):
                nodes[row["group_id"]] = {
                    "id": row["group_id"],
                    "type": "Group",
                    "name": row.get("group_name", ""),
                    "properties": {},
                }
            if row.get("technique_id"):
                nodes[row["technique_id"]] = {
                    "id": row["technique_id"],
                    "type": "Technique",
                    "name": row.get("technique_name", ""),
                    "properties": {"external_id": row.get("technique_ext_id", "")},
                }
            if row.get("tactic_id"):
                nodes[row["tactic_id"]] = {
                    "id": row["tactic_id"],
                    "type": "Tactic",
                    "name": row.get("tactic_name", ""),
                    "properties": {},
                }

            edge_key = (row.get("group_id"), row.get("technique_id"))
            if all(edge_key) and edge_key not in seen_edges:
                edges.append({"source": edge_key[0], "target": edge_key[1], "relation": "USES"})
                seen_edges.add(edge_key)

            edge_key2 = (row.get("technique_id"), row.get("tactic_id"))
            if all(edge_key2) and edge_key2 not in seen_edges:
                edges.append({"source": edge_key2[0], "target": edge_key2[1], "relation": "BELONGS_TO"})
                seen_edges.add(edge_key2)

        return {"nodes": list(nodes.values()), "edges": edges}

    # ------------------------------------------------------------------
    # Path trace builder
    # ------------------------------------------------------------------

    def build_path_trace(self, node_ids: list[str]) -> dict:
        if not node_ids:
            return {"nodes": [], "edges": []}

        with self.driver.session() as session:
            # Fetch the seed nodes
            result = session.run(
                """
                MATCH (n)
                WHERE n.id IN $ids OR n.external_id IN $ids
                RETURN n.id AS id, labels(n)[0] AS type, n.name AS name,
                       properties(n) AS props
                """,
                ids=node_ids,
            )
            seed_rows = [dict(r) for r in result]

            # Fetch one-hop neighbourhood
            result2 = session.run(
                """
                MATCH (n)-[r]-(m)
                WHERE n.id IN $ids OR n.external_id IN $ids
                RETURN n.id AS src_id, labels(n)[0] AS src_type, n.name AS src_name,
                       type(r) AS relation,
                       m.id AS tgt_id, labels(m)[0] AS tgt_type, m.name AS tgt_name,
                       properties(m) AS tgt_props
                LIMIT 50
                """,
                ids=node_ids,
            )
            hop_rows = [dict(r) for r in result2]

        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        seen_edges: set = set()

        for row in seed_rows:
            nid = row.get("id", "")
            nodes[nid] = {
                "id": nid,
                "type": row.get("type", "Technique"),
                "name": row.get("name", ""),
                "properties": {k: v for k, v in (row.get("props") or {}).items() if k not in ("id", "name")},
            }

        for row in hop_rows:
            src = row.get("src_id", "")
            tgt = row.get("tgt_id", "")
            if src:
                nodes[src] = {
                    "id": src,
                    "type": row.get("src_type", "Technique"),
                    "name": row.get("src_name", ""),
                    "properties": {},
                }
            if tgt:
                nodes[tgt] = {
                    "id": tgt,
                    "type": row.get("tgt_type", "Technique"),
                    "name": row.get("tgt_name", ""),
                    "properties": {k: v for k, v in (row.get("tgt_props") or {}).items() if k not in ("id", "name")},
                }
            edge_key = (src, tgt, row.get("relation", ""))
            if all([src, tgt]) and edge_key not in seen_edges:
                edges.append({"source": src, "target": tgt, "relation": row.get("relation", "RELATED")})
                seen_edges.add(edge_key)

        return {"nodes": list(nodes.values()), "edges": edges}

    def get_node_by_external_id(self, external_id: str) -> dict | None:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n)
                WHERE n.external_id = $ext_id
                RETURN n.id AS id, labels(n)[0] AS type, n.name AS name,
                       properties(n) AS props
                LIMIT 1
                """,
                ext_id=external_id,
            )
            row = result.single()
            if not row:
                return None
            return {
                "id": row["id"],
                "type": row["type"],
                "name": row["name"],
                "properties": dict(row.get("props") or {}),
            }

    def health_check(self) -> bool:
        try:
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception as exc:
            logger.warning("Neo4j health check failed: %s", exc)
            return False

    def close(self):
        self.driver.close()
