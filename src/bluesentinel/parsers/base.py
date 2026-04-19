"""Parser interface. All parsers turn raw log lines into `LogEvent`s."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from pathlib import Path

from bluesentinel.types import LogEvent


class BaseParser(ABC):
    """Streaming parser base class.

    Implementations should be memory-safe: yield events, don't collect
    a full `list` unless the caller asks for it.
    """

    @abstractmethod
    def parse_line(self, line: str) -> LogEvent | None:
        """Parse one raw log line. Return None if the line is not recognised."""

    def parse_lines(self, lines: Iterable[str]) -> Iterator[LogEvent]:
        """Parse many lines, skipping unrecognised ones."""
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            event = self.parse_line(line)
            if event is not None:
                yield event

    def parse_file(self, path: str | Path) -> Iterator[LogEvent]:
        """Parse a file one line at a time (streaming — constant memory)."""
        path = Path(path)
        with path.open("r", encoding="utf-8", errors="replace") as f:
            yield from self.parse_lines(f)

    def parse_to_list(self, path: str | Path) -> list[LogEvent]:
        """Helper for when callers want the whole result in memory."""
        return list(self.parse_file(path))
