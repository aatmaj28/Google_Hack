"""Event-grouped sliding window over parsed log lines.

A "burst" is a contiguous run of lines whose timestamps cluster tightly,
plus any untimed continuation lines (stack traces, multi-line messages)
that immediately follow them. Bursts have hard caps so a steady-state
flood doesn't produce an unbounded window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from .profiles import ParsedLine, Profile


@dataclass
class Burst:
    lines: list[ParsedLine] = field(default_factory=list)
    start_ts: datetime | None = None
    end_ts: datetime | None = None

    def add(self, line: ParsedLine) -> None:
        self.lines.append(line)
        if line.timestamp is not None:
            if self.start_ts is None:
                self.start_ts = line.timestamp
            self.end_ts = line.timestamp

    def as_text(self) -> str:
        return "".join(
            ln.raw if ln.raw.endswith("\n") else ln.raw + "\n"
            for ln in self.lines
        )


def bursts(
    lines: Iterable[str],
    profile: Profile,
    *,
    gap_seconds: float = 5.0,
    max_lines: int = 200,
    max_span_seconds: float = 30.0,
) -> Iterator[Burst]:
    """Stream `Burst` objects from a line iterable. Yields as soon as a burst closes."""
    gap = timedelta(seconds=gap_seconds)
    max_span = timedelta(seconds=max_span_seconds)
    current = Burst()

    for raw in lines:
        parsed = profile.parse(raw.rstrip("\n"))

        # Decide whether this line starts a new burst.
        start_new = False
        if parsed.timestamp is not None and current.end_ts is not None:
            delta = parsed.timestamp - current.end_ts
            if delta > gap or delta < timedelta(0):
                start_new = True
            elif (
                current.start_ts is not None
                and parsed.timestamp - current.start_ts > max_span
            ):
                start_new = True
        if len(current.lines) >= max_lines:
            start_new = True

        if start_new and current.lines:
            yield current
            current = Burst()

        current.add(parsed)

    if current.lines:
        yield current
