from __future__ import annotations

import re
from typing import List

from ..constants import ROP_GADGET_PATTERNS, TERMINAL_MNEMONICS
from ..models import Vulnerability, VulnType
from ..scan_context import Detector, ScanContext


class RopGadgetDetector(Detector):
    """Finds useful ROP gadgets ending in a return-equivalent instruction.

    Fixes vs the original script:
      * This logic existed TWICE in the original (once inline in the
        disassembly analysis pass, once in a dedicated method), each with
        different patterns, producing duplicate/inconsistent findings.
        There is now exactly one implementation.
      * Gadget regexes are selected by `ctx.arch_family` instead of always
        using x86 register names - running 'pop rdi' patterns against ARM
        disassembly silently found nothing in the original and gave a
        false sense of coverage.
      * The instruction(s) that can END a gadget window are ALSO selected
        per architecture (`TERMINAL_MNEMONICS`). An earlier version of this
        fix still only looked for "ret"/"retn" - which doesn't exist as a
        mnemonic in 32-bit ARM, whose functions return via "pop {.., pc}",
        "bx lr", etc. That made the ARM patterns above unreachable dead code.
    """

    name = "rop_gadgets"
    WINDOW = 4  # instructions to look back from the terminal instruction, inclusive

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        disasm = ctx.disassembly
        if not disasm:
            return findings

        patterns = ROP_GADGET_PATTERNS.get(ctx.arch_family)
        terminal_mnemonics = TERMINAL_MNEMONICS.get(ctx.arch_family)
        if not patterns or not terminal_mnemonics:
            # Unknown/unsupported architecture for gadget classification -
            # nothing meaningful to do rather than guess with x86 regexes.
            return findings

        found_types: set = set()
        for i, (addr, mnem, ops) in enumerate(disasm):
            if mnem not in terminal_mnemonics:
                continue
            start = max(0, i - self.WINDOW)
            window_instrs = disasm[start:i + 1]
            gadget_str = " ; ".join(f"{m} {o}".strip() for _, m, o in window_instrs)

            for gadget_type, pattern in patterns.items():
                if gadget_type in found_types:
                    continue
                if re.search(pattern, gadget_str):
                    found_types.add(gadget_type)
                    findings.append(self._make(
                        ctx, VulnType.ROP_GADGET, "<gadget>",
                        f"Useful ROP gadget found: {gadget_type} at {addr:#x}.",
                        "INFO", offset=addr, instruction=gadget_str,
                        details={"gadget_type": gadget_type},
                    ))

        return findings
