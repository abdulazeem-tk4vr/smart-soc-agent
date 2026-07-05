# Ported from soc_defender.
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import json
import os
from pathlib import Path
from typing import Any, Protocol

import requests

from .embeddings import build_embedder_from_manifest


@dataclass(frozen=True)
class RAGDocument:
    source: str
    title: str
    text: str
    score: float = 0.0


class RAGRetriever:
    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        raise NotImplementedError


class TextEmbedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...


@dataclass
class LocalKeywordRAGRetriever(RAGRetriever):
    documents: tuple[RAGDocument, ...] = ()

    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        terms = {term.casefold() for term in query.split() if len(term) > 2}
        scored: list[RAGDocument] = []
        for doc in self.documents:
            haystack = f"{doc.title} {doc.text}".casefold()
            score = sum(1 for term in terms if term in haystack)
            if score:
                scored.append(RAGDocument(doc.source, doc.title, doc.text, float(score)))
        scored.sort(key=lambda doc: doc.score, reverse=True)
        return tuple(scored[:limit])


@lru_cache(maxsize=4)
def load_keyword_documents(chunks_path: str, max_documents: int = 0) -> tuple[RAGDocument, ...]:
    path = Path(chunks_path)
    if not path.exists():
        return default_security_corpus()
    documents: list[RAGDocument] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if max_documents and len(documents) >= max_documents:
                break
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            text = str(payload.get("text") or "")
            if not text:
                continue
            title = str(payload.get("chunk_id") or payload.get("title") or "RAG chunk")
            source = str(payload.get("source_path") or payload.get("source") or path)
            documents.append(RAGDocument(source=source, title=title, text=text))
    return tuple(documents) or default_security_corpus()


@dataclass
class HTTPRAGRetriever(RAGRetriever):
    base_url: str
    timeout: float = 30.0

    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        response = requests.post(
            f"{self.base_url.rstrip('/')}/retrieve",
            json={"query": query, "limit": limit},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        docs = payload.get("documents", payload)
        if not isinstance(docs, list):
            raise RuntimeError("RAG service response must contain a documents list")
        return tuple(_document_from_payload(item) for item in docs if isinstance(item, dict))


def _document_from_payload(payload: dict[str, Any]) -> RAGDocument:
    return RAGDocument(
        source=str(payload.get("source") or payload.get("source_path") or "rag-service"),
        title=str(payload.get("title") or payload.get("chunk_id") or "RAG chunk"),
        text=str(payload.get("text") or ""),
        score=float(payload.get("score") or 0.0),
    )


@dataclass
class QdrantRAGRetriever(RAGRetriever):
    path: Path
    collection_name: str = "soc_defender_intel"
    embedder: TextEmbedder | None = None
    client: object | None = None

    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        if self.embedder is None:
            raise RuntimeError("QdrantRAGRetriever requires an embedder for query vectors")

        vector = self.embedder.embed([query])[0]
        if self.client is None:
            try:
                from qdrant_client import QdrantClient
            except ImportError as exc:
                raise RuntimeError("qdrant-client is required for Qdrant retrieval") from exc
            client = QdrantClient(path=str(self.path))
        else:
            client = self.client
        if hasattr(client, "search"):
            hits = client.search(collection_name=self.collection_name, query_vector=vector, limit=limit)
        else:
            response = client.query_points(collection_name=self.collection_name, query=vector, limit=limit)
            hits = getattr(response, "points", response)
        docs: list[RAGDocument] = []
        for hit in hits:
            payload = hit.payload or {}
            docs.append(
                RAGDocument(
                    source=str(payload.get("source_path") or payload.get("source") or "qdrant"),
                    title=str(payload.get("title") or payload.get("chunk_id") or "RAG chunk"),
                    text=str(payload.get("text") or ""),
                    score=float(hit.score),
                )
            )
        return tuple(docs)


def default_security_corpus() -> tuple[RAGDocument, ...]:
    return (
        RAGDocument("builtin", "Phishing Initial Access", "Phishing commonly yields compromised users and patient-zero hosts."),
        RAGDocument("builtin", "Exfiltration Evidence", "Exfiltration evidence often appears in alerts or netflow with dst_domain and bytes."),
        RAGDocument("builtin", "Data Staging Evidence", "Data staging evidence often appears in process events with target identifiers."),
        RAGDocument("builtin", "Containment", "Containment should isolate exact hosts, reset exact users, and block exact attacker domains only after support."),
    )


def default_rag_data_dir() -> Path | None:
    candidates = [
        Path.cwd() / "data" / "rag",
        Path(__file__).resolve().parents[2] / "data" / "rag",
    ]
    for candidate in candidates:
        if (candidate / "chunks.jsonl").exists() or (candidate / "qdrant" / "build_manifest.json").exists():
            return candidate
    return None


@dataclass
class RAGIntel:
    retriever: RAGRetriever = field(default_factory=lambda: LocalKeywordRAGRetriever(default_security_corpus()))

    def context_for(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        return self.retriever.retrieve(query, limit=limit)


def build_rag_intel(
    qdrant_path: str | Path | None = None,
    embedder: TextEmbedder | None = None,
    device: str | None = None,
    chunks_path: str | Path | None = None,
    backend: str | None = None,
) -> RAGIntel:
    backend = (backend or os.getenv("SMART_SOC_RAG_BACKEND") or os.getenv("SOC_DEFENDER_RAG_BACKEND") or "qdrant").casefold()
    service_url = os.getenv("SOC_DEFENDER_RAG_URL")
    if service_url and backend in {"auto", "http", "service", "keyword"}:
        return RAGIntel(HTTPRAGRetriever(service_url))
    if qdrant_path and str(qdrant_path).startswith(("http://", "https://")):
        return RAGIntel(HTTPRAGRetriever(str(qdrant_path)))

    data_dir = default_rag_data_dir()
    if qdrant_path is None and data_dir is not None:
        qdrant_path = data_dir / "qdrant"
    if chunks_path is None and data_dir is not None:
        chunks_path = data_dir / "chunks.jsonl"

    if backend in {"auto", "qdrant"} and qdrant_path and Path(qdrant_path).exists():
        path = Path(qdrant_path)
        manifest_path = path / "build_manifest.json"
        if manifest_path.exists():
            try:
                resolved_embedder = embedder
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if resolved_embedder is None:
                    resolved_embedder = build_embedder_from_manifest(manifest, device=device)
                if resolved_embedder is not None:
                    manifest_collection = str(manifest.get("collection") or "soc_defender_intel")
                    return RAGIntel(QdrantRAGRetriever(path, collection_name=manifest_collection, embedder=resolved_embedder))
            except Exception:
                if backend == "qdrant":
                    raise

    if chunks_path and Path(chunks_path).exists():
        max_docs = int(os.getenv("SMART_SOC_RAG_KEYWORD_MAX_DOCS", "0") or "0")
        return RAGIntel(LocalKeywordRAGRetriever(load_keyword_documents(str(Path(chunks_path)), max_docs)))
    return RAGIntel()
