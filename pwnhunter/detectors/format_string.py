from __future__ import annotations

from typing import List

from ..constants import FORMAT_FUNCTIONS, FORMAT_SPECIFIERS
from ..models import Vulnerability, VulnType
from ..scan_context import Detector, ScanContext
from ..strings_utils import get_context


class FormatStringDetector(Detector):
    """Looks for format-string vulnerability patterns.

    Two passes, with different confidence levels:
      * static: a format specifier sits near a printf-family function name
        in the raw bytes. This is a coarse proximity heuristic (the
        original script's approach) so it stays at MEDIUM, not HIGH.
      * disassembly: a non-constant (register/memory) value is loaded right
        before a call to a printf-family function - this is a much more
        specific signal (the format string itself is not a literal) so it
        stays at HIGH.
    """

    name = "format_string"

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        info = ctx.binary_info
        if info is None:
            return findings

        for offset, string in info.strings:
            encoded = string.encode()
            if not any(spec in encoded for spec in FORMAT_SPECIFIERS):
                continue
            context = get_context(ctx.raw_data, offset)
            if any(f in context for f in FORMAT_FUNCTIONS):
                findings.append(self._make(
                    ctx, VulnType.FORMAT_STRING, "<static>",
                    f"Format specifier near a printf-family reference at {offset:#x}: "
                    f"{string[:50]!r} (heuristic - verify manually).",
                    "MEDIUM", offset=offset,
                    details={"format_string": string},
                ))

        disasm = ctx.disassembly
        for i, (addr, mnem, ops) in enumerate(disasm):
            if mnem not in ("mov", "lea") or i + 1 >= len(disasm):
                continue
            next_addr, next_mnem, next_ops = disasm[i + 1]
            if next_mnem != "call" or not any(f in next_ops for f in FORMAT_FUNCTIONS):
                continue
            if "rip" in ops or "[" in ops:
                findings.append(self._make(
                    ctx, VulnType.FORMAT_STRING, "<disassembly>",
                    f"Non-literal value passed as format string at {addr:#x} "
                    f"(call to {next_ops.strip()}).",
                    "HIGH", offset=addr, instruction=f"{mnem} {ops}",
                ))

        return findings
