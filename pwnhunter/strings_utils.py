"""String extraction helpers, shared by the loader and several detectors."""

from __future__ import annotations

import re
from typing import List, Tuple

_PRINTABLE_RE_CACHE = {}


def extract_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
    """Return a list of (offset, string) for every run of printable ASCII
    of at least `min_length` characters found in `data`."""
    pattern = _PRINTABLE_RE_CACHE.get(min_length)
    if pattern is None:
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        _PRINTABLE_RE_CACHE[min_length] = pattern

    strings = []
    for match in pattern.finditer(data):
        strings.append((match.start(), match.group().decode("ascii", errors="ignore")))
    return strings


def get_context(data: bytes, offset: int, window: int = 100) -> str:
    """Return a small window of raw bytes around `offset`, decoded loosely.
    Used to check whether a format specifier sits near a printf-family call."""
    start = max(0, offset - window)
    end = min(len(data), offset + window)
    return data[start:end].decode("latin-1", errors="ignore")
