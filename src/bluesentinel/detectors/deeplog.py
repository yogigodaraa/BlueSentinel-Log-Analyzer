"""DeepLog — LSTM next-template prediction.

Du et al. (CCS 2017). The idea is simple and powerful: treat parsed log
templates as a vocabulary, then train an LSTM to predict the next
template given a fixed-size window. At inference time, if the actual
next template is not in the model's top-k predictions, flag the event
as anomalous.

This implementation is PyTorch-based and runs fine on CPU for
evaluation-scale datasets. Training at internet scale (HDFS has 11M
events) wants a GPU, but for portfolio-grade benchmarks and auth.log
traffic it's plenty fast on CPU.

Reference:
    https://acmccs.github.io/papers/p1285-duA.pdf
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

from bluesentinel.detectors.base import BaseDetector
from bluesentinel.types import LogEvent

if TYPE_CHECKING:
    import torch
    import torch.nn as nn


class _DeepLogLSTM:
    """Thin wrapper around a PyTorch LSTM. Lazy-imported so that
    users who only want the IF baseline don't pay the torch import cost."""

    def __init__(self, vocab_size: int, hidden: int, layers: int):
        import torch
        import torch.nn as nn

        self.torch = torch
        self.model = nn.Sequential(
            _Embed(vocab_size, hidden),
            _LSTMOnly(hidden, hidden, layers),
            nn.Linear(hidden, vocab_size),
        )
        self.vocab_size = vocab_size


class _Embed:  # pragma: no cover — tiny wrapper
    def __init__(self, vocab: int, dim: int):
        import torch.nn as nn

        self.mod = nn.Embedding(vocab, dim)

    def __call__(self, x):
        return self.mod(x)


class _LSTMOnly:  # pragma: no cover — tiny wrapper
    def __init__(self, in_dim: int, hidden: int, layers: int):
        import torch.nn as nn

        self.mod = nn.LSTM(in_dim, hidden, num_layers=layers, batch_first=True)

    def __call__(self, x):
        out, _ = self.mod(x)
        return out[:, -1, :]


class DeepLogDetector(BaseDetector):
    """Sequence-based anomaly detection via next-template prediction.

    Training:
        For each sliding window of ``window`` template IDs, train the LSTM
        to predict the next template ID.

    Inference:
        Given the same sliding window, get the top-k predicted next
        templates. If the real next template is not in top-k, flag as
        anomalous. Anomaly score = ``1 - rank / vocab``.
    """

    name = "deeplog"
    version = "2.0"
    default_threshold = 0.5

    def __init__(
        self,
        *,
        window: int = 10,
        top_k: int = 9,
        hidden_size: int = 128,
        num_layers: int = 2,
        epochs: int = 5,
        batch_size: int = 256,
        lr: float = 1e-3,
        device: str | None = None,
    ):
        self.window = window
        self.top_k = top_k
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.device = device
        self._vocab: OrderedDict[int, int] = OrderedDict()  # template_id → vocab index
        self._model: _DeepLogLSTM | None = None

    # ─── Vocab ─────────────────────────────────────────────────────────
    def _vocab_index(self, template_id: int) -> int:
        if template_id not in self._vocab:
            self._vocab[template_id] = len(self._vocab)
        return self._vocab[template_id]

    def _event_to_ids(self, events: Sequence[LogEvent]) -> list[int]:
        return [self._vocab_index(ev.template_id) for ev in events if ev.template_id is not None]

    # ─── Lifecycle ─────────────────────────────────────────────────────
    def fit(self, events: Sequence[LogEvent]) -> "DeepLogDetector":
        ids = self._event_to_ids(events)
        if len(ids) <= self.window + 1:
            # Not enough data to train — fall back to a degenerate model
            # that flags everything as unknown on first sight.
            return self

        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset

        device = torch.device(
            self.device or ("cuda" if torch.cuda.is_available() else "cpu")
        )
        vocab = len(self._vocab)
        self._model = _DeepLogLSTM(vocab, self.hidden_size, self.num_layers)
        model = nn.Sequential(
            self._model.model[0].mod,
            self._model.model[1].mod,  # LSTM returns (out, hidden)
        ).to(device)
        head = self._model.model[2].to(device)

        X, y = [], []
        for i in range(len(ids) - self.window):
            X.append(ids[i : i + self.window])
            y.append(ids[i + self.window])
        X_t = torch.tensor(X, dtype=torch.long, device=device)
        y_t = torch.tensor(y, dtype=torch.long, device=device)

        loader = DataLoader(TensorDataset(X_t, y_t), batch_size=self.batch_size, shuffle=True)
        opt = torch.optim.Adam(list(model.parameters()) + list(head.parameters()), lr=self.lr)
        loss_fn = nn.CrossEntropyLoss()

        model.train()
        head.train()
        for _epoch in range(self.epochs):
            for xb, yb in loader:
                opt.zero_grad()
                emb = model[0](xb)
                out, _ = model[1](emb)
                logits = head(out[:, -1, :])
                loss = loss_fn(logits, yb)
                loss.backward()
                opt.step()
        self._model = _TrainedDeepLog(model, head, device)  # type: ignore[assignment]
        return self

    def score(self, events: Sequence[LogEvent]) -> np.ndarray:
        ids = self._event_to_ids(events)
        scores = np.zeros(len(events), dtype=np.float32)
        if self._model is None or len(ids) <= self.window:
            # No model — everything is maximally anomalous.
            scores.fill(1.0)
            return scores

        import torch

        device = self._model.device  # type: ignore[attr-defined]
        for i in range(self.window, len(ids)):
            window = torch.tensor([ids[i - self.window : i]], dtype=torch.long, device=device)
            with torch.no_grad():
                emb = self._model.embed(window)  # type: ignore[attr-defined]
                out, _ = self._model.lstm(emb)  # type: ignore[attr-defined]
                logits = self._model.head(out[:, -1, :])  # type: ignore[attr-defined]
                ranked = logits.argsort(dim=-1, descending=True)[0].cpu().numpy()
            actual = ids[i]
            try:
                rank = int(np.where(ranked == actual)[0][0])
            except IndexError:
                rank = len(self._vocab)
            # anomaly if actual is not in top-k
            if rank >= self.top_k:
                scores[i] = 1.0 - (self.top_k / max(len(self._vocab), 1))
            else:
                scores[i] = rank / max(len(self._vocab), 1)
        return scores

    def explain(self, event: LogEvent, score: float) -> str:
        return (
            f"DeepLog: template {event.template_id} was not in top-{self.top_k} "
            f"predictions given the preceding {self.window} events "
            f"(score {score:.3f})"
        )

    # ─── Persistence ───────────────────────────────────────────────────
    def save(self, path: str) -> None:
        if self._model is None:
            return
        import torch

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "vocab": list(self._vocab.items()),
                "hidden": self.hidden_size,
                "layers": self.num_layers,
                "window": self.window,
                "top_k": self.top_k,
                "embed": self._model.embed.state_dict(),  # type: ignore[attr-defined]
                "lstm": self._model.lstm.state_dict(),  # type: ignore[attr-defined]
                "head": self._model.head.state_dict(),  # type: ignore[attr-defined]
            },
            p,
        )


class _TrainedDeepLog:
    """Holds the trained modules in one place. Keeps the main class clean."""

    def __init__(self, seq, head, device):
        # seq is nn.Sequential(embed, lstm)
        self.embed = seq[0]
        self.lstm = seq[1]
        self.head = head
        self.device = device
