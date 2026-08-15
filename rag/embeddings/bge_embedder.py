"""
SentinelX AI — BGE Embedding Model
=====================================
Local sentence-transformer wrapper for BAAI/bge-large-en-v1.5.

Key design decisions:
  - NO external API calls. The model runs entirely locally inside the container.
  - Model is downloaded at FIRST STARTUP into EMBEDDING_MODEL_CACHE_DIR
    (Docker volume: sentinelx_models). Subsequent startups use the cache.
  - The application FAILS CLEARLY (raises RuntimeError) if the model
    cannot be loaded or downloaded. There is no silent fallback to another model.
  - BGE models require a specific query instruction prefix for retrieval tasks.
    Document embeddings use plain text; query embeddings use the prefix.
  - Embeddings are L2-normalised (unit vectors). This makes cosine similarity
    equivalent to dot-product and is required for Qdrant Cosine distance.
  - A module-level singleton (get_embedder()) is provided so the ~1.3 GB
    model is loaded once per process, not once per request.
  - Batch encoding is used for throughput; the batch_size is configurable.

Model specs (BAAI/bge-large-en-v1.5):
  - Embedding dimension:    1024
  - Max sequence length:    512 tokens
  - Licence:                MIT
  - HuggingFace page:       https://huggingface.co/BAAI/bge-large-en-v1.5

Requires: sentence-transformers>=3.0.0
"""
from __future__ import annotations

import logging
import os
import threading

from backend.config import settings

logger = logging.getLogger(__name__)

# BGE retrieval query instruction (prepended to queries, NOT to documents)
# Reference: https://huggingface.co/BAAI/bge-large-en-v1.5#usage
_BGE_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "

# Module-level singleton and lock
_embedder_instance: BGEEmbedder | None = None
_embedder_lock = threading.Lock()


# =============================================================================
# BGE Embedder
# =============================================================================

class BGEEmbedder:
    """
    Local embedding model wrapper for BAAI/bge-large-en-v1.5.

    Loads the model from EMBEDDING_MODEL_CACHE_DIR (the sentinelx_models
    Docker volume). If the model is not cached, sentence-transformers will
    download it from HuggingFace Hub on first call.

    The application will raise RuntimeError if the model fails to load.
    No silent fallback to another model is permitted.

    Args:
        model_name:   HuggingFace model ID. Default: settings.EMBEDDING_MODEL
        cache_dir:    Directory to store / load the model from.
                      Default: settings.EMBEDDING_MODEL_CACHE_DIR
        device:       'cpu' | 'cuda' | 'mps'. Auto-detected if not provided.
        batch_size:   Number of texts to embed per forward pass.

    Usage:
        embedder = BGEEmbedder()
        doc_vecs  = embedder.embed_texts(["SQL injection attack pattern..."])
        query_vec = embedder.embed_query("What is a SQL injection attack?")
    """

    def __init__(
        self,
        model_name: str | None = None,
        cache_dir: str | None = None,
        device: str | None = None,
        batch_size: int = 32,
    ) -> None:
        self.model_name = model_name or settings.EMBEDDING_MODEL
        self.cache_dir = cache_dir or settings.EMBEDDING_MODEL_CACHE_DIR
        self.batch_size = batch_size
        self._model = None
        self._device = device or self._detect_device()
        self._dim: int | None = None

    # ── Device detection ──────────────────────────────────────────────────────

    @staticmethod
    def _detect_device() -> str:
        """Return 'cuda' if a GPU is available, 'mps' on Apple Silicon, else 'cpu'."""
        try:
            import torch
            if torch.cuda.is_available():
                return "cuda"
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
        except ImportError:
            pass
        return "cpu"

    # ── Model loading ─────────────────────────────────────────────────────────

    def load(self) -> None:
        """
        Load the embedding model from cache or download from HuggingFace.

        Called automatically on first embed call, or explicitly at startup.

        Raises:
            RuntimeError: If the model cannot be loaded or downloaded.
                          The application must not continue without embeddings.
        """
        if self._model is not None:
            return

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "sentence-transformers is required for the embedding model. "
                "Add 'sentence-transformers>=3.0.0' to requirements.txt and rebuild."
            ) from exc

        # Set HuggingFace cache directory from config
        os.environ["HF_HOME"] = self.cache_dir
        os.environ["TRANSFORMERS_CACHE"] = self.cache_dir
        os.environ["SENTENCE_TRANSFORMERS_HOME"] = self.cache_dir

        logger.info(
            "Loading embedding model '%s' (device=%s, cache=%s)…",
            self.model_name,
            self._device,
            self.cache_dir,
        )

        try:
            self._model = SentenceTransformer(
                model_name_or_path=self.model_name,
                device=self._device,
                cache_folder=self.cache_dir,
            )
            # Verify dimension matches configuration
            self._dim = self._model.get_sentence_embedding_dimension()
            expected_dim = settings.EMBEDDING_DIM

            if self._dim != expected_dim:
                raise RuntimeError(
                    f"Embedding dimension mismatch: model '{self.model_name}' "
                    f"produces {self._dim}-dim vectors, but EMBEDDING_DIM={expected_dim}. "
                    f"Update EMBEDDING_DIM in config or switch to the correct model."
                )

            logger.info(
                "✅ Embedding model loaded — model=%s, dim=%d, device=%s",
                self.model_name,
                self._dim,
                self._device,
            )

        except RuntimeError:
            raise  # Re-raise our own RuntimeError
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load embedding model '{self.model_name}' "
                f"from cache '{self.cache_dir}': {exc}. "
                f"Check that EMBEDDING_MODEL is a valid sentence-transformers model "
                f"and that the container has internet access on first startup."
            ) from exc

    # ── Embedding API ─────────────────────────────────────────────────────────

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """
        Embed a list of document texts (corpus side).

        Document texts are encoded WITHOUT the query instruction prefix.
        Embeddings are L2-normalised (unit vectors).

        Args:
            texts: List of document text strings to embed.

        Returns:
            List of embedding vectors (each a list of floats, length=EMBEDDING_DIM).

        Raises:
            RuntimeError: If the model is not loaded and cannot be loaded.
            ValueError:   If texts is empty.
        """
        if not texts:
            raise ValueError("texts must not be empty")

        self._ensure_loaded()

        logger.debug("Embedding %d document text(s) in batches of %d", len(texts), self.batch_size)

        embeddings = self._model.encode(
            texts,
            batch_size=self.batch_size,
            normalize_embeddings=True,   # L2-normalise for cosine similarity
            show_progress_bar=False,
            convert_to_numpy=True,
        )

        return [vec.tolist() for vec in embeddings]

    def embed_query(self, query: str) -> list[float]:
        """
        Embed a single search query (query side).

        BGE models are trained with an instruction prefix for query encoding.
        This prefix is prepended automatically. Do NOT add it manually.

        Args:
            query: The search query string.

        Returns:
            A single embedding vector (list of floats, length=EMBEDDING_DIM).

        Raises:
            RuntimeError: If the model is not loaded and cannot be loaded.
            ValueError:   If query is empty or whitespace-only.
        """
        if not query or not query.strip():
            raise ValueError("query must not be empty")

        self._ensure_loaded()

        # BGE query instruction — critical for retrieval quality
        prefixed = f"{_BGE_QUERY_INSTRUCTION}{query.strip()}"

        embedding = self._model.encode(
            [prefixed],
            batch_size=1,
            normalize_embeddings=True,
            show_progress_bar=False,
            convert_to_numpy=True,
        )

        return embedding[0].tolist()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def embedding_dim(self) -> int:
        """Return the embedding dimension. Loads the model if not already loaded."""
        self._ensure_loaded()
        return self._dim  # type: ignore[return-value]

    @property
    def is_loaded(self) -> bool:
        """Return True if the model is loaded and ready."""
        return self._model is not None

    # ── Private ───────────────────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        """Load the model if it hasn't been loaded yet."""
        if self._model is None:
            self.load()


# =============================================================================
# Module-level singleton
# =============================================================================

def get_embedder() -> BGEEmbedder:
    """
    Return the shared BGEEmbedder singleton.

    Thread-safe. The model is loaded on first call and reused for the lifetime
    of the process. This avoids loading the ~1.3 GB model multiple times.

    Raises:
        RuntimeError: If the model cannot be loaded (propagated from BGEEmbedder.load()).
    """
    global _embedder_instance

    if _embedder_instance is None:
        with _embedder_lock:
            if _embedder_instance is None:  # Double-checked locking
                _embedder_instance = BGEEmbedder()
                _embedder_instance.load()

    return _embedder_instance


def reset_embedder() -> None:
    """
    Reset the singleton. For use in tests only.
    Do NOT call this in production code.
    """
    global _embedder_instance
    with _embedder_lock:
        _embedder_instance = None
