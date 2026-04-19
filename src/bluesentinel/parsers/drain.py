"""Drain3-based log template extraction.

Drain (He et al., 2017) is the standard log template mining algorithm —
it learns recurring structure in unstructured logs and assigns each line
a template ID + parameter list. Drain3 is the maintained Python port.

We layer Drain on top of a base parser (usually `SyslogParser`) so events
get *both*:

    message       = "Failed password for root from 1.2.3.4 port 22"
    template_id   = 42
    template      = "Failed password for <*> from <*> port <*>"
    template_params = ["root", "1.2.3.4", "22"]

Template IDs are what sequence detectors (DeepLog) actually learn on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from bluesentinel.parsers.base import BaseParser
from bluesentinel.parsers.syslog import SyslogParser
from bluesentinel.types import LogEvent

if TYPE_CHECKING:
    from drain3 import TemplateMiner


class DrainParser(BaseParser):
    """Wrap a base parser and add Drain3 template extraction.

    Usage::

        parser = DrainParser()              # defaults to SyslogParser underneath
        for event in parser.parse_file("auth.log"):
            print(event.template_id, event.template)

        parser.save("drain_state.bin")      # persist the learned templates
        parser2 = DrainParser.load("drain_state.bin")
    """

    def __init__(
        self,
        base_parser: BaseParser | None = None,
        *,
        similarity_threshold: float = 0.4,
        max_children: int = 100,
    ):
        self.base = base_parser or SyslogParser()
        self._miner: TemplateMiner | None = None
        self._similarity_threshold = similarity_threshold
        self._max_children = max_children

    @property
    def miner(self) -> "TemplateMiner":
        """Lazy-initialise Drain3 so the import cost is paid on first use."""
        if self._miner is None:
            from drain3 import TemplateMiner
            from drain3.template_miner_config import TemplateMinerConfig

            config = TemplateMinerConfig()
            config.drain_sim_th = self._similarity_threshold
            config.drain_max_children = self._max_children
            self._miner = TemplateMiner(config=config)
        return self._miner

    def parse_line(self, line: str) -> LogEvent | None:
        event = self.base.parse_line(line)
        if event is None:
            return None
        # Feed only the message portion to Drain — the timestamp / host
        # prefix isn't useful for template mining.
        result = self.miner.add_log_message(event.message)
        event.template_id = int(result["cluster_id"])
        event.template = result["template_mined"]
        # Drain3 doesn't always expose extracted params cleanly; extract by diff
        event.template_params = _extract_params(event.message, event.template)
        return event

    # ─── Persistence ────────────────────────────────────────────────────
    def save(self, path: str) -> None:
        from drain3.file_persistence import FilePersistence

        persistence = FilePersistence(path)
        persistence.save_state(self.miner.drain.to_json())  # type: ignore[no-untyped-call]

    @classmethod
    def load(cls, path: str, base_parser: BaseParser | None = None) -> "DrainParser":
        parser = cls(base_parser=base_parser)
        # Touch miner to initialise, then load state
        _ = parser.miner
        try:
            with open(path, "rb") as f:
                state = f.read()
                parser.miner.drain.from_json(state)  # type: ignore[no-untyped-call]
        except FileNotFoundError:
            pass
        return parser

    # ─── Inspection ─────────────────────────────────────────────────────
    def template_count(self) -> int:
        """Current number of distinct templates the miner has seen."""
        return len(self.miner.drain.id_to_cluster)  # type: ignore[attr-defined]

    def top_templates(self, n: int = 20) -> list[tuple[int, str, int]]:
        """Return the `n` most frequent templates as (id, template, count)."""
        clusters = self.miner.drain.id_to_cluster.values()  # type: ignore[attr-defined]
        ranked = sorted(clusters, key=lambda c: c.size, reverse=True)[:n]
        return [(c.cluster_id, c.get_template(), c.size) for c in ranked]


def _extract_params(message: str, template: str | None) -> list[str]:
    """Best-effort extraction of the values Drain masked with <*>."""
    if not template or "<*>" not in template:
        return []
    # Split the template on the wildcards, then walk through the message.
    parts = template.split("<*>")
    params: list[str] = []
    idx = 0
    for i, part in enumerate(parts):
        if i == 0:
            if not message.startswith(part):
                return []
            idx = len(part)
            continue
        # Find the next literal part starting at idx
        if part == "":
            # Last segment — grab from idx to end
            params.append(message[idx:])
            continue
        next_idx = message.find(part, idx)
        if next_idx < 0:
            return []
        params.append(message[idx:next_idx])
        idx = next_idx + len(part)
    return params
