from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from typing import TypeVar
from concurrent.futures import ThreadPoolExecutor, as_completed

from hunter.concurrency.resources import SystemResources, detect_system_resources

T = TypeVar("T")
R = TypeVar("R")

_MAX_AUTO_WORKERS = 16


def resolve_scan_workers_auto(resources: SystemResources) -> int:
    """Scale workers from CPU and RAM without user config."""
    cpu_cap = max(1, resources.cpu_count - 2)
    ram_cap = max(1, resources.ram_gb // 2)
    return max(1, min(cpu_cap, ram_cap, _MAX_AUTO_WORKERS))


def resolve_max_inflight_auto(workers: int, ram_gb: int) -> int:
    if workers <= 1:
        return 1
    cap = min(workers * 2, ram_gb * 2, 32)
    return max(workers, cap)


def resolve_scan_workers(requested: int, *, resources: SystemResources | None = None) -> int:
    """Resolve worker count. 0 = auto from hardware. 1 = serial."""
    if requested == 1:
        return 1
    if requested > 0:
        return requested
    res = resources or detect_system_resources()
    return resolve_scan_workers_auto(res)


def resolve_max_inflight(
    requested: int,
    workers: int,
    *,
    ram_gb: int | None = None,
) -> int:
    """Cap concurrent parse jobs. 0 = auto from workers and RAM."""
    if workers <= 1:
        return 1
    if requested > 0:
        return max(workers, requested)
    gb = ram_gb if ram_gb is not None else detect_system_resources().ram_gb
    return resolve_max_inflight_auto(workers, gb)


def run_threaded_map(
    items: Iterable[T],
    fn: Callable[[T], R],
    *,
    workers: int,
    progress: Callable[[R], None] | None = None,
) -> list[R]:
    """Run fn over items in a thread pool; return results in submission order."""
    item_list = list(items)
    if not item_list or workers <= 1:
        out: list[R] = []
        for item in item_list:
            result = fn(item)
            out.append(result)
            if progress:
                progress(result)
        return out

    results: list[R | None] = [None] * len(item_list)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {pool.submit(fn, item): i for i, item in enumerate(item_list)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            results[idx] = future.result()
            if progress:
                progress(results[idx])  # type: ignore[arg-type]

    return [r for r in results if r is not None]
