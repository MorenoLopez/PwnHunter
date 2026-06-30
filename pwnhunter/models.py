"""
Data models shared across the whole pwnhunter package.

Kept dependency-free (stdlib only) on purpose: every other module imports
from here, so this module must never import capstone / pyelftools / pefile.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple


class VulnType(Enum):
    BUFFER_OVERFLOW = auto()
    USE_AFTER_FREE = auto()
    FORMAT_STRING = auto()
    INTEGER_OVERFLOW = auto()
    DOUBLE_FREE = auto()
    STACK_CANARY = auto()
    NX_BYPASS = auto()
    PIE_BYPASS = auto()
    RELRO_BYPASS = auto()
    FORTIFY_BYPASS = auto()
    HEAP_OVERFLOW = auto()
    OFF_BY_ONE = auto()
    TYPE_CONFUSION = auto()
    ARBITRARY_WRITE = auto()
    INFO_LEAK = auto()
    ROP_GADGET = auto()
    SHELLCODE_EXEC = auto()
    HEAP_USAGE = auto()
    UNCATEGORIZED = auto()


# Order used for sorting/filtering by severity everywhere in the project.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Vulnerability:
    vuln_type: VulnType
    function: str
    location: str
    description: str
    severity: str
    details: Dict = field(default_factory=dict)
    offset: Optional[int] = None
    instruction: Optional[str] = None
    detector: Optional[str] = None  # which detector produced this finding

    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type.name,
            "function": self.function,
            "location": self.location,
            "description": self.description,
            "severity": self.severity,
            # BUG FIX: the original code used `if self.offset else None`, which
            # silently turned a perfectly valid offset of 0 into None (0 is
            # falsy in Python). We must check identity with None instead.
            "offset": hex(self.offset) if self.offset is not None else None,
            "instruction": self.instruction,
            "details": self.details,
            "detector": self.detector,
        }

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, len(SEVERITY_ORDER))


@dataclass
class BinaryInfo:
    path: str
    arch: str = ""
    bits: int = 0
    endian: str = ""
    os: str = ""
    format: str = "Unknown"
    pie: bool = False
    nx: bool = False
    canary: bool = False
    relro: str = "No"
    fortify: bool = False
    rpath: bool = False
    runpath: bool = False
    stripped: bool = False
    entry_point: int = 0
    symbols: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    sections: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    strings: List[Tuple[int, str]] = field(default_factory=list)
    functions: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "architecture": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "os": self.os,
            "format": self.format,
            "entry_point": hex(self.entry_point) if self.entry_point else None,
            "security": {
                "PIE": self.pie,
                "NX": self.nx,
                "Canary": self.canary,
                "RELRO": self.relro,
                "FORTIFY": self.fortify,
                "RPATH": self.rpath,
                "RUNPATH": self.runpath,
                "Stripped": self.stripped,
            },
            "symbols_count": len(self.symbols),
            "imports_count": len(self.imports),
            "sections": {k: f"{v[0]:#x}-{v[0] + v[1]:#x}" for k, v in self.sections.items()},
            "functions": {k: f"{v:#x}" for k, v in self.functions.items()},
        }
