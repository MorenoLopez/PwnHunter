"""
Thin wrapper around capstone. Every detector that needs disassembly reads
`disassembly`, a flat list of (address, mnemonic, ops) tuples - capstone
itself is never imported anywhere else, so the rest of the codebase, and
all of its tests, work whether or not capstone is installed.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .elf_parser import MinimalELF, ELFParseError
from .models import BinaryInfo

try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64
    from capstone import CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

Instruction = Tuple[int, str, str]


def _capstone_engine(binary_info: BinaryInfo):
    arch_map = {
        "EM_386": (CS_ARCH_X86, CS_MODE_32),
        "EM_X86_64": (CS_ARCH_X86, CS_MODE_64),
        "EM_ARM": (CS_ARCH_ARM, CS_MODE_ARM),
        "EM_AARCH64": (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
    }
    arch, mode = arch_map.get(binary_info.arch, (CS_ARCH_X86, CS_MODE_64))
    md = Cs(arch, mode)
    md.detail = False
    return md


def disassemble(binary_path: str, raw_data: bytes, binary_info: Optional[BinaryInfo]) -> List[Instruction]:
    """Disassemble every executable section (ELF) or the whole buffer as a
    fallback. Returns [] silently if capstone is not installed."""
    if not CAPSTONE_AVAILABLE or binary_info is None:
        return []

    md = _capstone_engine(binary_info)
    disassembly: List[Instruction] = []

    if binary_info.format == "ELF":
        try:
            elf = MinimalELF(raw_data)
            for sec in elf.sections:
                if sec.is_executable and sec.size:
                    data = elf.section_data(sec)
                    for insn in md.disasm(data, sec.addr):
                        disassembly.append((insn.address, insn.mnemonic, insn.op_str))
        except ELFParseError:
            pass
    else:
        base_addr = 0x400000 if binary_info.bits == 64 else 0x8048000
        for insn in md.disasm(raw_data, base_addr):
            disassembly.append((insn.address, insn.mnemonic, insn.op_str))

    return disassembly
