"""
ScanContext is the single object passed to every detector. Detectors are
small, independent, and only read from the context - they never mutate
shared state directly, which makes them trivially unit-testable with fake
data (no capstone/ELF file needed, see tests/test_detectors.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .constants import ELF_MACHINE_TO_FAMILY
from .disassembler import Instruction
from .models import BinaryInfo, Vulnerability


@dataclass
class ScanContext:
    binary_path: str
    raw_data: bytes
    binary_info: Optional[BinaryInfo] = None
    disassembly: List[Instruction] = field(default_factory=list)
    verbose: bool = False

    @property
    def arch_family(self) -> str:
        """Coarse architecture family ('x86_64', 'x86', 'arm', 'arm64', or
        '' if unknown) - used to pick the right ROP gadget patterns instead
        of blindly applying x86 regexes to every architecture."""
        if self.binary_info is None:
            return ""
        return ELF_MACHINE_TO_FAMILY.get(self.binary_info.arch, "")

    def log(self, msg: str) -> None:
        if self.verbose:
            import sys
            print(f"[*] {msg}", file=sys.stderr)


class Detector:
    """Base class for all vulnerability detectors.

    Subclasses must set `name` and implement `run`. Returning an empty list
    is always valid (e.g. when a prerequisite like disassembly is missing).
    """

    name: str = "base"

    def run(self, ctx: ScanContext) -> List[Vulnerability]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _make(self, ctx: ScanContext, vuln_type, function, description, severity,
              offset=None, instruction=None, details=None) -> Vulnerability:
        return Vulnerability(
            vuln_type=vuln_type,
            function=function,
            location=ctx.binary_path,
            description=description,
            severity=severity,
            offset=offset,
            instruction=instruction,
            details=details or {},
            detector=self.name,
        )
