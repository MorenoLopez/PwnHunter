from __future__ import annotations

from typing import List

from ..constants import INFO_LEAK_PATTERNS
from ..models import Vulnerability, VulnType
from ..scan_context import Detector, ScanContext


class InfoLeakDetector(Detector):
    """Flags strings that look like sensitive references (flags, secrets,
    raw addresses). Always INFO severity - this is a pointer for the
    analyst to go look, not a confirmed vulnerability."""

    name = "info_leak"

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        info = ctx.binary_info
        if info is None:
            return findings

        for offset, string in info.strings:
            lowered = string.lower().encode()
            for pattern, desc in INFO_LEAK_PATTERNS:
                if pattern in lowered:
                    findings.append(self._make(
                        ctx, VulnType.INFO_LEAK, "<strings>",
                        f"{desc} found at {offset:#x}: {string[:50]!r}",
                        "INFO", offset=offset, details={"matched_string": string},
                    ))
                    break  # one match per string is enough
        return findings
