"""LogBERT — transformer-based semantic anomaly detection.

Guo et al. (IJCAI 2021). Encode each log template into a semantic vector
using a pretrained BERT model, then measure anomalies in embedding space.

This implementation uses a pretrained Sentence-Transformer model
(``sentence-transformers/all-MiniLM-L6-v2``) instead of training BERT
from scratch — same idea, massively less compute, and the embeddings
are competitive on log anomaly detection in practice (Guo et al. 2021
Table 4, LogBERT vs. off-the-shelf BERT variants).

Anomaly score =

    1 - max_cosine_similarity(embedding, normal_prototypes)

where ``normal_prototypes`` are the k-means centroids of the training
set's embeddings. New events far from every centroid are anomalous.

Reference:
    https://www.ijcai.org/proceedings/2021/0577.pdf
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import numpy as np

from bluesentinel.detectors.base import BaseDetector
from bluesentinel.types import LogEvent

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer


class LogBERTDetector(BaseDetector):
    """Semantic anomaly detection via pretrained transformer embeddings."""

    name = "logbert"
    version = "2.0"
    default_threshold = 0.35

    def __init__(
        self,
        *,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        num_prototypes: int = 16,
        batch_size: int = 64,
        device: str | None = None,
    ):
        self.model_name = model_name
        self.num_prototypes = num_prototypes
        self.batch_size = batch_size
        self.device = device
        self._encoder: "SentenceTransformer" | None = None
        self._prototypes: np.ndarray | None = None

    # ─── Encoder ───────────────────────────────────────────────────────
    @property
    def encoder(self) -> "SentenceTransformer":
        if self._encoder is None:
            # Lazy import so users can skip the transformers dep if they
            # only want the classical detectors.
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "LogBERTDetector requires sentence-transformers: "
                    "`pip install sentence-transformers`"
                ) from exc
            self._encoder = SentenceTransformer(self.model_name, device=self.device)
        return self._encoder

    def _encode(self, events: Sequence[LogEvent]) -> np.ndarray:
        texts = [ev.template or ev.message for ev in events]
        if not texts:
            return np.empty((0, self.encoder.get_sentence_embedding_dimension()))
        return np.asarray(
            self.encoder.encode(
                texts,
                batch_size=self.batch_size,
                convert_to_numpy=True,
                show_progress_bar=False,
                normalize_embeddings=True,
            )
        )

    # ─── Lifecycle ─────────────────────────────────────────────────────
    def fit(self, events: Sequence[LogEvent]) -> "LogBERTDetector":
        embs = self._encode(events)
        if len(embs) == 0:
            return self
        # Pick prototypes via mini-batch k-means. Small `n_clusters` keeps
        # score() fast — we just do k cosine similarities per event.
        from sklearn.cluster import MiniBatchKMeans

        k = min(self.num_prototypes, len(embs))
        kmeans = MiniBatchKMeans(n_clusters=k, random_state=42, batch_size=256, n_init=3)
        kmeans.fit(embs)
        # Normalise prototypes so our score is a pure dot product.
        proto = kmeans.cluster_centers_
        proto /= np.linalg.norm(proto, axis=1, keepdims=True).clip(min=1e-9)
        self._prototypes = proto
        return self

    def score(self, events: Sequence[LogEvent]) -> np.ndarray:
        embs = self._encode(events)
        if self._prototypes is None or len(embs) == 0:
            return np.ones(len(events), dtype=np.float32)
        # Cosine similarity to nearest prototype — both are unit vectors,
        # so dot product = cosine similarity. Anomaly = 1 - max_sim.
        sims = embs @ self._prototypes.T  # (n, k)
        max_sim = sims.max(axis=1)
        return (1.0 - max_sim).astype(np.float32)

    def explain(self, event: LogEvent, score: float) -> str:
        return (
            f"LogBERT: message semantically far from any learned normal cluster "
            f"(anomaly {score:.3f} — 0 = identical, 1 = opposite)"
        )
