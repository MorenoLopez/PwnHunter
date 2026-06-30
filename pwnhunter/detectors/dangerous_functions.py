from __future__ import annotations

from typing import List

from ..constants import DANGEROUS_FUNCTIONS
from ..models import Vulnerability
from ..scan_context import Detector, ScanContext


class DangerousFunctionDetector(Detector):
    """Flags imports of, and disassembly calls to, known risky libc functions."""

    name = "dangerous_functions"

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        info = ctx.binary_info
        if info is None:
            return findings

        seen = set()  # avoid reporting the same (function) twice via import + disasm

        for imp in info.imports:
            base_name = imp.split("@")[0]
            if base_name in DANGEROUS_FUNCTIONS and base_name not in seen:
                vtype, severity = DANGEROUS_FUNCTIONS[base_name]
                seen.add(base_name)
                findings.append(self._make(
                    ctx, vtype, base_name,
                    f"Binary imports the dangerous function '{base_name}'.",
                    severity, details={"import": imp, "source": "imports"},
                ))

        # Disassembly gives us the actual call sites, which is strictly more
        # useful than the import list alone (and works for statically linked
        # binaries where there is no PLT/import to look at).
        for addr, mnem, ops in ctx.disassembly:
            if mnem != "call":
                continue
            for func_name, (vtype, severity) in DANGEROUS_FUNCTIONS.items():
                if func_name in ops:
                    findings.append(self._make(
                        ctx, vtype, func_name,
                        f"Call to dangerous function '{func_name}' at {addr:#x}.",
                        severity, offset=addr, instruction=f"{mnem} {ops}",
                        details={"source": "disassembly"},
                    ))

        return findings
