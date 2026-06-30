from __future__ import annotations

import re
from typing import List

from ..models import Vulnerability, VulnType
from ..scan_context import Detector, ScanContext

_HEX_RE = re.compile(r"0x([0-9a-f]+)")


class IntegerOverflowDetector(Detector):
    """Heuristic: a multiply with no overflow check nearby, or arithmetic
    against a suspiciously large immediate. Compilers very rarely emit
    explicit jo/jno checks for normal code, so this is LOW severity and
    explicitly framed as heuristic to avoid drowning real findings."""

    name = "integer_overflow"
    OVERFLOW_JUMP_MNEMONICS = ("jo", "jno", "jc", "jnc", "into")

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        disasm = ctx.disassembly
        if not disasm:
            return findings

        for i, (addr, mnem, ops) in enumerate(disasm):
            if mnem in ("imul", "mul"):
                window = disasm[i + 1:i + 10]
                has_check = any(m in self.OVERFLOW_JUMP_MNEMONICS for _, m, _ in window)
                if not has_check:
                    findings.append(self._make(
                        ctx, VulnType.INTEGER_OVERFLOW, "<disassembly>",
                        f"Multiplication at {addr:#x} with no overflow check nearby "
                        "(heuristic - compilers often omit this check legitimately).",
                        "LOW", offset=addr, instruction=f"{mnem} {ops}",
                    ))

            if mnem in ("add", "sub") and any(r in ops for r in ("eax", "rax", "ebx", "rbx")):
                match = _HEX_RE.search(ops)
                if match:
                    val = int(match.group(1), 16)
                    if val > 0x7FFFFFFF:
                        findings.append(self._make(
                            ctx, VulnType.INTEGER_OVERFLOW, "<disassembly>",
                            f"Suspiciously large immediate in arithmetic at {addr:#x}: {val:#x}.",
                            "LOW", offset=addr, instruction=f"{mnem} {ops}",
                        ))

        return findings


class OffByOneDetector(Detector):
    """Heuristic: a comparison against a small boundary right before a
    boundary-style jump. Stays LOW severity for the same reason as above."""

    name = "off_by_one"
    BOUNDARY_JUMPS = ("jle", "jge", "jbe", "jae", "je", "jne")

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        disasm = ctx.disassembly

        for i, (addr, mnem, ops) in enumerate(disasm):
            if mnem not in ("cmp", "test") or i + 1 >= len(disasm):
                continue
            next_mnem = disasm[i + 1][1]
            if next_mnem not in self.BOUNDARY_JUMPS:
                continue
            match = _HEX_RE.search(ops)
            if match:
                bound = int(match.group(1), 16)
                if bound <= 0x100:
                    findings.append(self._make(
                        ctx, VulnType.OFF_BY_ONE, "<disassembly>",
                        f"Boundary check against a small value ({bound}) at {addr:#x} "
                        "(heuristic, verify the comparison operator: <= vs < is the "
                        "classic off-by-one).",
                        "LOW", offset=addr, instruction=f"{mnem} {ops}",
                        details={"boundary": bound},
                    ))

        return findings
