from __future__ import annotations

from typing import List

from ..models import Vulnerability, VulnType
from ..scan_context import Detector, ScanContext


class SecurityBypassDetector(Detector):
    """Flags missing binary-hardening mitigations (the 'checksec' part)."""

    name = "security_bypass"

    def run(self, ctx: ScanContext) -> List[Vulnerability]:
        info = ctx.binary_info
        if info is None or info.format != "ELF":
            return []

        findings = []

        if not info.pie:
            findings.append(self._make(
                ctx, VulnType.PIE_BYPASS, "N/A",
                "Binary does NOT have PIE enabled. Base address is fixed.",
                "HIGH", details={"base_address": "Fixed", "exploitability": "Easy ROP/ret2libc"},
            ))

        if not info.nx:
            findings.append(self._make(
                ctx, VulnType.NX_BYPASS, "N/A",
                "Binary does NOT have NX enabled. Stack/heap may be executable.",
                "CRITICAL", details={"exploitability": "Direct shellcode execution"},
            ))

        if not info.canary:
            findings.append(self._make(
                ctx, VulnType.STACK_CANARY, "N/A",
                "Binary does NOT have stack canaries enabled.",
                "HIGH", details={"exploitability": "Stack overflow without canary bypass"},
            ))

        if info.relro in ("No", "Partial"):
            findings.append(self._make(
                ctx, VulnType.RELRO_BYPASS, "N/A",
                f"Binary has {info.relro} RELRO. The GOT may be writable.",
                "HIGH" if info.relro == "No" else "MEDIUM",
                details={"exploitability": "GOT overwrite / ret2plt"},
            ))

        if not info.fortify:
            findings.append(self._make(
                ctx, VulnType.FORTIFY_BYPASS, "N/A",
                "Binary does NOT have FORTIFY_SOURCE enabled.",
                "MEDIUM", details={"exploitability": "Standard library functions are unhardened"},
            ))

        if info.rpath or info.runpath:
            findings.append(self._make(
                ctx, VulnType.RELRO_BYPASS, "N/A",
                "Binary embeds an RPATH/RUNPATH, which can enable library hijacking.",
                "LOW", details={"rpath": info.rpath, "runpath": info.runpath},
            ))

        return findings
