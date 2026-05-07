from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock


@dataclass
class Metrics:
    counters: dict[str, int] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def inc(self, name: str, delta: int = 1) -> None:
        with self._lock:
            self.counters[name] = self.counters.get(name, 0) + delta

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.counters)
