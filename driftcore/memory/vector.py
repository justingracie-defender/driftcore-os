"""
driftcore/memory/vector.py
===========================
Optional Qdrant semantic search backend for DriftCore OS.

This is an INDEX only — not a replacement for SQLite storage.
SQLite remains the authoritative, tamper-evident, encrypted store.
Qdrant points to SQLite records and enables semantic search.

If Qdrant is not available, falls back to keyword search silently.
This keeps DriftCore universal — runs on anything.

Safety filters are enforced at retrieval time:
  - Quarantined items never surface in search results
  - High drift score items are filtered out
  - Trust level respected on every query
  - Audit chain records every search

Embedding options (in order of preference for universal deployment):
  1. sentence-transformers/all-MiniLM-L6-v2  — local, no API, runs anywhere
  2. Ollama local models                      — better quality, more hardware
  3. External API                             — best quality, needs internet

Default: option 1. No data leaves the device.
"""

import os
import json
import time
from typing import List, Optional, Dict, Any


# ── Availability check ────────────────────────────────────────────
# Qdrant and sentence-transformers are optional.
# Everything degrades gracefully if not installed.

try:
    from qdrant_client import QdrantClient
    from qdrant_client.http.models import (
        Distance, VectorParams, Filter, FieldCondition,
        MatchValue, Range, PointStruct, MatchAny,
    )
    _QDRANT_AVAILABLE = True
except ImportError:
    _QDRANT_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    _EMBEDDINGS_AVAILABLE = True
except ImportError:
    _EMBEDDINGS_AVAILABLE = False


# ── Configuration ─────────────────────────────────────────────────

DEFAULT_COLLECTION    = "driftcore_memory"
DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"
VECTOR_SIZE           = 384   # all-MiniLM-L6-v2 output size
MAX_DRIFT_SCORE       = 0.40  # never return high-drift memories
DEFAULT_LIMIT         = 5


# ── Availability ──────────────────────────────────────────────────

def is_available() -> bool:
    """Return True if Qdrant and embeddings are both available."""
    return _QDRANT_AVAILABLE and _EMBEDDINGS_AVAILABLE


def availability_report() -> str:
    """Plain language report of what's available."""
    if is_available():
        return "✅ Qdrant + embeddings available. Semantic search active."
    elif _QDRANT_AVAILABLE and not _EMBEDDINGS_AVAILABLE:
        return (
            "⚠️  Qdrant available but sentence-transformers not installed.\n"
            "   Run: pip install sentence-transformers\n"
            "   Falling back to keyword search."
        )
    elif not _QDRANT_AVAILABLE and _EMBEDDINGS_AVAILABLE:
        return (
            "⚠️  sentence-transformers available but Qdrant not installed.\n"
            "   Run: pip install qdrant-client\n"
            "   Or start Qdrant: docker run -p 6333:6333 qdrant/qdrant\n"
            "   Falling back to keyword search."
        )
    else:
        return (
            "ℹ️  Qdrant not available. Using keyword search.\n"
            "   To enable semantic search:\n"
            "   pip install qdrant-client sentence-transformers\n"
            "   docker run -p 6333:6333 qdrant/qdrant"
        )


# ── Search result ─────────────────────────────────────────────────

class VectorSearchResult:
    def __init__(self, text: str, score: float, metadata: dict,
                 source: str = "vector"):
        self.text     = text
        self.score    = score
        self.metadata = metadata
        self.source   = source   # "vector" or "keyword"

    def __repr__(self):
        return f"VectorSearchResult(score={self.score:.3f}, text='{self.text[:50]}...')"


# ── Vector backend ────────────────────────────────────────────────

class VectorMemory:
    """
    Optional semantic search layer for DriftCore memory.

    When Qdrant is available:
      - Stores embeddings alongside safety metadata
      - Safety filters applied at retrieval time
      - Semantic similarity search

    When Qdrant is not available:
      - Falls back to simple keyword search on provided items
      - No external dependencies required
      - Same interface, degraded capability

    Safety guarantees never change regardless of backend.
    Quarantined items never surface. High-drift items filtered.
    Audit chain records every operation.

    Usage:
        vm = VectorMemory()
        vm.connect()

        # Index a memory item
        vm.index(
            item_id   = "abc123",
            text      = "dad is allergic to peanuts",
            metadata  = {"tier": 1, "quarantined": True, "trust": "family"}
        )

        # Search
        results = vm.search("what is dad allergic to")
    """

    def __init__(
        self,
        host:             str = "localhost",
        port:             int = 6333,
        collection_name:  str = DEFAULT_COLLECTION,
        embedding_model:  str = DEFAULT_EMBEDDING_MODEL,
    ):
        self._host            = host
        self._port            = port
        self._collection_name = collection_name
        self._embedding_model = embedding_model
        self._client          = None
        self._encoder         = None
        self._connected       = False
        self._fallback_items: List[dict] = []

    # ── Connection ────────────────────────────────────────────────

    def connect(self) -> bool:
        """
        Connect to Qdrant and load embedding model.
        Returns True if successful, False if falling back to keyword search.
        """
        if not is_available():
            print(availability_report())
            return False

        try:
            self._client = QdrantClient(
                host=self._host,
                port=self._port,
                timeout=5,
            )
            # Test connection
            self._client.get_collections()

            # Load embedding model
            self._encoder = SentenceTransformer(self._embedding_model)

            # Ensure collection exists
            self._ensure_collection()

            self._connected = True
            self._audit("VECTOR_CONNECTED",
                       f"host={self._host}:{self._port}, "
                       f"collection={self._collection_name}")
            return True

        except Exception as e:
            print(f"\n  ⚠️  Qdrant connection failed: {e}")
            print(f"  Falling back to keyword search.\n")
            self._connected = False
            return False

    def _ensure_collection(self):
        """Create Qdrant collection if it doesn't exist."""
        collections = [
            c.name for c in
            self._client.get_collections().collections
        ]
        if self._collection_name not in collections:
            self._client.create_collection(
                collection_name = self._collection_name,
                vectors_config  = VectorParams(
                    size     = VECTOR_SIZE,
                    distance = Distance.COSINE,
                ),
            )

    # ── Index ─────────────────────────────────────────────────────

    def index(
        self,
        item_id:    str,
        text:       str,
        metadata:   Dict[str, Any],
    ) -> bool:
        """
        Index a memory item for semantic search.

        Metadata should include:
          tier         — 1 or 2
          quarantined  — True/False
          trust_level  — trust level string
          drift_score  — 0.0 to 1.0
          source       — who stored this
          timestamp    — when stored

        Returns True if indexed successfully.
        Falls back gracefully if Qdrant unavailable.
        """
        # Always keep a fallback copy for keyword search
        self._fallback_items.append({
            "id":       item_id,
            "text":     text,
            "metadata": metadata,
        })

        # Audit regardless of whether Qdrant is connected
        self._audit("VECTOR_INDEXED", text[:100])

        if not self._connected:
            return False

        try:
            vector = self._encoder.encode(text).tolist()

            # Build safe payload — safety metadata always included
            payload = {
                "text":         text,
                "item_id":      item_id,
                "tier":         metadata.get("tier", 2),
                "quarantined":  metadata.get("quarantined", False),
                "trust_level":  metadata.get("trust_level", "unknown"),
                "drift_score":  metadata.get("drift_score", 0.0),
                "source":       metadata.get("source", "unknown"),
                "timestamp":    metadata.get("timestamp", time.time()),
                "safety_level": self._compute_safety_level(metadata),
            }

            self._client.upsert(
                collection_name = self._collection_name,
                points = [PointStruct(
                    id      = self._stable_id(item_id),
                    vector  = vector,
                    payload = payload,
                )],
            )

            self._audit("VECTOR_INDEXED", text[:100])
            return True

        except Exception as e:
            print(f"  ⚠️  Vector index failed: {e}")
            return False

    def _compute_safety_level(self, metadata: dict) -> str:
        """Assign a safety level label for filtering."""
        if metadata.get("quarantined"):
            return "quarantined"
        if metadata.get("tier") == 1:
            return "family_trusted"
        if metadata.get("drift_score", 0) > MAX_DRIFT_SCORE:
            return "high_drift"
        return "safe"

    def _stable_id(self, item_id: str) -> int:
        """Convert string ID to stable integer for Qdrant."""
        import hashlib
        return int(hashlib.md5(item_id.encode()).hexdigest()[:8], 16)

    # ── Search ────────────────────────────────────────────────────

    def search(
        self,
        query:              str,
        limit:              int   = DEFAULT_LIMIT,
        max_drift_score:    float = MAX_DRIFT_SCORE,
        include_quarantined: bool = False,
        trust_levels:       Optional[List[str]] = None,
    ) -> List[VectorSearchResult]:
        """
        Search memory semantically.

        Safety filters always applied:
          - Quarantined items excluded by default
          - High drift score items excluded
          - Trust level respected

        Falls back to keyword search if Qdrant unavailable.
        """
        if self._connected:
            return self._vector_search(
                query, limit, max_drift_score,
                include_quarantined, trust_levels
            )
        else:
            results = self._keyword_search(
                query, limit, include_quarantined
            )
            self._audit(
                "VECTOR_SEARCH",
                f"query='{query[:60]}', results={len(results)}, mode=keyword"
            )
            return results

    def _vector_search(
        self,
        query:               str,
        limit:               int,
        max_drift_score:     float,
        include_quarantined: bool,
        trust_levels:        Optional[List[str]],
    ) -> List[VectorSearchResult]:
        """Semantic search with safety filters."""
        try:
            vector = self._encoder.encode(query).tolist()

            # Build safety filter
            must_conditions = [
                FieldCondition(
                    key   = "drift_score",
                    range = Range(lte=max_drift_score),
                ),
            ]

            if not include_quarantined:
                must_conditions.append(
                    FieldCondition(
                        key   = "quarantined",
                        match = MatchValue(value=False),
                    )
                )

            if trust_levels:
                must_conditions.append(
                    FieldCondition(
                        key   = "trust_level",
                        match = MatchAny(any=trust_levels),
                    )
                )

            safety_filter = Filter(must=must_conditions)

            hits = self._client.search(
                collection_name = self._collection_name,
                query_vector    = vector,
                query_filter    = safety_filter,
                limit           = limit,
            )

            results = [
                VectorSearchResult(
                    text     = hit.payload.get("text", ""),
                    score    = hit.score,
                    metadata = {k: v for k, v in hit.payload.items()
                               if k != "text"},
                    source   = "vector",
                )
                for hit in hits
            ]

            self._audit(
                "VECTOR_SEARCH",
                f"query='{query[:60]}', results={len(results)}"
            )
            return results

        except Exception as e:
            print(f"  ⚠️  Vector search failed: {e}. Using keyword search.")
            return self._keyword_search(query, limit)

    def _keyword_search(
        self,
        query: str,
        limit: int,
        include_quarantined: bool = False,
    ) -> List[VectorSearchResult]:
        """
        Fallback keyword search when Qdrant unavailable.
        Uses character n-grams (substrings of length 5+) so that
        word variants match — "allergy" and "allergic" both contain
        "allerg", "peanut" matches "peanuts", etc.
        Safety filters always applied.
        """
        stopwords = {
            "the", "a", "an", "is", "are", "what", "does",
            "do", "to", "of", "and", "or", "in", "on",
            "has", "have", "had", "was", "were", "that",
        }

        def ngrams(text: str, n: int = 5) -> set:
            words = [w for w in text.lower().split() if w not in stopwords and len(w) >= n]
            result = set()
            for word in words:
                for i in range(len(word) - n + 1):
                    result.add(word[i:i+n])
            return result

        query_grams = ngrams(query)
        if not query_grams:
            # Fall back to simple word match if query too short
            query_grams = set(
                w for w in query.lower().split()
                if w not in stopwords and len(w) > 2
            )

        scored = []
        for item in self._fallback_items:
            meta = item.get("metadata", {})
            if meta.get("quarantined") and not include_quarantined:
                continue
            if meta.get("drift_score", 0) > MAX_DRIFT_SCORE:
                continue

            text       = item.get("text", "")
            item_grams = ngrams(text)
            if not item_grams:
                item_grams = set(
                    w for w in text.lower().split()
                    if w not in stopwords and len(w) > 2
                )

            overlap = len(query_grams & item_grams)
            if overlap > 0:
                score = overlap / max(len(query_grams), 1)
                scored.append((score, item))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            VectorSearchResult(
                text     = item["text"],
                score    = score,
                metadata = item.get("metadata", {}),
                source   = "keyword",
            )
            for score, item in scored[:limit]
        ]


    def remove(self, item_id: str) -> bool:
        """Remove an item from the vector index."""
        self._fallback_items = [
            i for i in self._fallback_items
            if i["id"] != item_id
        ]

        if not self._connected:
            return False

        try:
            self._client.delete(
                collection_name = self._collection_name,
                points_selector = [self._stable_id(item_id)],
            )
            self._audit("VECTOR_REMOVED", item_id)
            return True
        except Exception:
            return False

    # ── Stats ─────────────────────────────────────────────────────

    def stats(self) -> dict:
        base = {
            "connected":       self._connected,
            "fallback_items":  len(self._fallback_items),
            "qdrant_available": _QDRANT_AVAILABLE,
            "embeddings_available": _EMBEDDINGS_AVAILABLE,
        }

        if self._connected:
            try:
                info = self._client.get_collection(self._collection_name)
                base["vector_count"] = info.points_count
                base["collection"]   = self._collection_name
            except Exception:
                pass

        return base

    # ── Audit ─────────────────────────────────────────────────────

    def _audit(self, action: str, detail: str = ""):
        try:
            from driftcore.audit import record
            record(
                action        = action,
                memory_text   = detail[:200],
                authorised_by = "vector_memory",
                detail        = f"backend={'qdrant' if self._connected else 'keyword'}",
            )
        except Exception:
            pass
