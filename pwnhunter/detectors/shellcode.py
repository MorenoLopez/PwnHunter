from __future__ import annotations

import re
from typing import List

from ..constants import SHELLCODE_SIGNATURES
from ..models import Vulnerability, VulnType
from ..scan_context import Detector, ScanContext


class ShellcodeDetector(Detector):
    """Scans raw bytes for well-known shellcode/syscall signatures."""

    name = "shellcode"

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        for sig, desc in SHELLCODE_SIGNATURES:
            for match in re.finditer(re.escape(sig), ctx.raw_data):
                offset = match.start()
                findings.append(self._make(
                    ctx, VulnType.SHELLCODE_EXEC, "<shellcode>",
                    f"Shellcode/syscall signature found: {desc} at {offset:#x}.",
                    "CRITICAL" if len(sig) > 2 else "INFO",
                    offset=offset, details={"signature": sig.hex(), "description": desc},
                ))
        return findings
