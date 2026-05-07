"""
ChromaDB vector store wrapper for MITRE ATT&CK technique embeddings.
"""
import logging

import chromadb
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

COLLECTION_NAME = "mitre_techniques"


class VectorStore:
    def __init__(self, chroma_path: str, embedding_model: str):
        self.client = chromadb.PersistentClient(path=chroma_path)
        self.model = SentenceTransformer(embedding_model)
        self._collection = None

    @property
    def collection(self):
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collection

    def query(self, query_text: str, top_k: int = 10) -> list[dict]:
        embedding = self.model.encode([query_text], show_progress_bar=False).tolist()
        results = self.collection.query(
            query_embeddings=embedding,
            n_results=min(top_k, self.collection_size() or top_k),
            include=["documents", "metadatas", "distances"],
        )

        output = []
        ids = results.get("ids", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for i, doc_id in enumerate(ids):
            meta = metadatas[i] if i < len(metadatas) else {}
            distance = distances[i] if i < len(distances) else 1.0
            # cosine distance → similarity score
            score = float(1.0 - distance)
            output.append(
                {
                    "id": doc_id,
                    "name": meta.get("name", ""),
                    "description": documents[i] if i < len(documents) else "",
                    "external_id": meta.get("external_id", ""),
                    "node_type": meta.get("node_type", "Technique"),
                    "tactic_refs": meta.get("tactic_refs", ""),
                    "score": score,
                    "source": "vector",
                    "metadata": meta,
                }
            )

        return sorted(output, key=lambda x: x["score"], reverse=True)

    def get_by_ids(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        results = self.collection.get(
            ids=ids,
            include=["documents", "metadatas"],
        )
        output = []
        for i, doc_id in enumerate(results.get("ids", [])):
            meta = results["metadatas"][i] if results.get("metadatas") else {}
            doc = results["documents"][i] if results.get("documents") else ""
            output.append(
                {
                    "id": doc_id,
                    "name": meta.get("name", ""),
                    "description": doc,
                    "external_id": meta.get("external_id", ""),
                    "node_type": meta.get("node_type", "Technique"),
                    "metadata": meta,
                }
            )
        return output

    def collection_size(self) -> int:
        try:
            return self.collection.count()
        except Exception:
            return 0

    def is_populated(self) -> bool:
        return self.collection_size() > 0
