from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from hunter.settings import HunterSettings


@contextmanager
def maybe_start_span(name: str, settings: HunterSettings | None = None) -> Iterator[None]:
    if settings and settings.otel_enabled:
        try:
            from opentelemetry import trace  # type: ignore[import-not-found]

            tracer = trace.get_tracer("hunter")
            with tracer.start_as_current_span(name):
                yield
            return
        except Exception:
            pass
    yield
