from __future__ import annotations


def build_line_starts(source: bytes) -> list[int]:
    """Byte offset of each line start (line 0 begins at 0)."""
    starts = [0]
    for i, b in enumerate(source):
        if b == 10:  # newline
            starts.append(i + 1)
    return starts


def _line_col_from_byte(source: bytes, byte_offset: int) -> tuple[int, int]:
    """1-based line, 0-based column."""
    byte_offset = max(0, min(byte_offset, len(source)))
    line_starts = build_line_starts(source)
    lo, hi = 0, len(line_starts) - 1
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if line_starts[mid] <= byte_offset:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    line_idx = best
    col = byte_offset - line_starts[line_idx]
    return line_idx + 1, col


def span_to_line_col(source: bytes, start_byte: int, end_byte: int) -> tuple[int, int, int, int]:
    """(start_line, start_col, end_line, end_col) for [start_byte, end_byte)."""
    sl, sc = _line_col_from_byte(source, start_byte)
    end_b = max(start_byte, end_byte - 1)
    el, ec = _line_col_from_byte(source, end_b)
    return sl, sc, el, ec
