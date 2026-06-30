from __future__ import annotations

import re
from typing import List

from ..constants import HEAP_FUNCTIONS
from ..models import Vulnerability, VulnType
from ..scan_context import Detector, ScanContext


class HeapDetector(Detector):
    """Reports heap-related signals.

    The original script flagged *every* binary that imports both malloc and
    free as a 'potential UAF', and every binary that imports free at all as
    a 'potential double-free'. Since that describes essentially all C
    programs, it produced a guaranteed false positive on every single scan.
    This version reports heap usage as a single informational note (so the
    analyst knows to look closer) instead of manufacturing two fake
    'vulnerabilities' out of normal libc usage.
    """

    name = "heap"

    ALLOC_SIZE_RE = re.compile(r"(malloc|calloc|realloc)\s*\(\s*(\d+)")

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        info = ctx.binary_info
        if info is None:
            return findings

        heap_funcs = [imp for imp in info.imports if any(h == imp.split("@")[0] for h in HEAP_FUNCTIONS)]
        if heap_funcs:
            findings.append(self._make(
                ctx, VulnType.HEAP_USAGE, "<heap>",
                "Binary performs dynamic memory management "
                f"({', '.join(sorted(set(heap_funcs)))}). Review allocation/free "
                "pairing manually for use-after-free or double-free bugs - this "
                "is informational, not a confirmed finding.",
                "INFO", details={"heap_functions": sorted(set(heap_funcs))},
            ))

        for offset, string in info.strings:
            match = self.ALLOC_SIZE_RE.search(string)
            if match:
                size = int(match.group(2))
                if size > 0x1000:
                    findings.append(self._make(
                        ctx, VulnType.HEAP_OVERFLOW, "<heap>",
                        f"String suggests a large heap allocation: {size} bytes.",
                        "LOW", offset=offset, details={"allocation_size": size},
                    ))

        return findings
