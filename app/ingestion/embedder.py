"""
Creates dense embeddings for MITRE ATT&CK techniques and stores them in ChromaDB.
"""

import logging

import chromadb
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

COLLECTION_NAME = "mitre_techniques"
BATCH_SIZE = 100


class MitreEmbedder:
    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        chroma_path: str,
        embedding_model: str,
    ):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.chroma_client = chromadb.PersistentClient(path=chroma_path)
        self.model = SentenceTransformer(embedding_model)

    def embed(self, force_refresh: bool = False) -> int:
        if force_refresh:
            try:
                self.chroma_client.delete_collection(COLLECTION_NAME)
                logger.info("Deleted existing ChromaDB collection")
            except Exception:
                pass

        collection = self.chroma_client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

        with self.driver.session() as session:
            techniques = self._fetch_techniques(session)

        if not techniques:
            logger.warning("No techniques found in Neo4j — run ingestion first")
            return 0

        count = self._create_embeddings(techniques, collection)
        logger.info("Created %d embeddings in ChromaDB", count)
        return count

    def _fetch_techniques(self, session) -> list[dict]:
        result = session.run(
            """
            MATCH (t)
            WHERE t:Technique OR t:SubTechnique
            OPTIONAL MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
            WITH t, collect(ta.shortname) AS tactic_refs
            RETURN
                t.id AS id,
                t.name AS name,
                t.description AS description,
                t.external_id AS external_id,
                t.is_subtechnique AS is_subtechnique,
                t.platforms AS platforms,
                t.detection AS detection,
                tactic_refs
            """
        )
        techniques = []
        for record in result:
            techniques.append(dict(record))
        return techniques

    def _build_embedding_text(self, technique: dict) -> str:
        parts = [
            technique.get("name", ""),
            technique.get("description", "") or "",
        ]
        if technique.get("platforms"):
            parts.append(f"Platforms: {technique['platforms']}")
        if technique.get("detection"):
            parts.append(f"Detection: {technique['detection']}")
        tactic_refs = technique.get("tactic_refs") or []
        if tactic_refs:
            parts.append(f"Tactics: {', '.join(tactic_refs)}")
        return ". ".join(p for p in parts if p)

    def _create_embeddings(self, techniques: list[dict], collection) -> int:
        total = 0
        for i in range(0, len(techniques), BATCH_SIZE):
            batch = techniques[i : i + BATCH_SIZE]

            ids = [t["id"] for t in batch]
            texts = [self._build_embedding_text(t) for t in batch]
            metadatas = [
                {
                    "name": t.get("name", ""),
                    "external_id": t.get("external_id", ""),
                    "is_subtechnique": str(t.get("is_subtechnique", False)),
                    "node_type": "SubTechnique" if t.get("is_subtechnique") else "Technique",
                    "tactic_refs": ",".join(t.get("tactic_refs") or []),
                }
                for t in batch
            ]

            embeddings = self.model.encode(texts, show_progress_bar=False).tolist()

            collection.upsert(
                ids=ids,
                documents=texts,
                embeddings=embeddings,
                metadatas=metadatas,
            )
            total += len(batch)
            logger.info(
                "Embedded batch %d/%d (%d techniques)", i // BATCH_SIZE + 1, -(-len(techniques) // BATCH_SIZE), total
            )

        return total

    def close(self):
        self.driver.close()
