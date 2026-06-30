"""
Builds a BinaryInfo from raw file bytes.

Design notes (fixes vs the original script):
  * We read the file ONCE into memory (raw_data) and every parser works off
    that buffer - no repeated `open(path, 'rb')` calls left dangling without
    being closed (the original code leaked a file handle per call to
    `_parse_elf_info`, `_manual_security_check`, `_disassemble_binary`, ...).
  * ELF parsing no longer requires pyelftools (see elf_parser.py). PE parsing
    still uses `pefile` if available, since reimplementing the PE format is
    out of scope here; without it we just degrade gracefully like upstream.
  * The dead `_parse_elf()` method from the original (opened the file and
    did nothing with it) has been removed entirely.
"""

from __future__ import annotations

import json
import subprocess
from typing import Optional

from .elf_parser import (
    MinimalELF, ELFParseError, PT_GNU_STACK, PT_GNU_RELRO,
)
from .models import BinaryInfo
from .strings_utils import extract_strings

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
)


def load_binary_info(path: str, raw_data: bytes, verbose: bool = False) -> BinaryInfo:
    info = BinaryInfo(path=path)

    magic = raw_data[:4]
    if magic == b"\x7fELF":
        info.format = "ELF"
        info.os = "Linux"
        _load_elf(info, raw_data)
    elif magic[:2] == b"MZ":
        info.format = "PE"
        info.os = "Windows"
        _load_pe(info, raw_data)
    elif magic in MACHO_MAGICS:
        info.format = "Mach-O"
        info.os = "macOS"
        # Minimal Mach-O support: we don't have a dependency-free parser for
        # it yet, so we fall back to string/byte heuristics only.
    else:
        info.format = "Unknown"

    info.strings = extract_strings(raw_data)

    # checksec gives the most reliable answer when it's installed; we still
    # run our own ELF-based checks first so the report is fully populated
    # even on systems without the `checksec` binary (most CI/sandbox setups).
    _try_checksec(info, path)

    return info


def _load_elf(info: BinaryInfo, raw_data: bytes) -> None:
    try:
        elf = MinimalELF(raw_data)
    except ELFParseError:
        return

    info.bits = 64 if elf.is_64 else 32
    info.endian = "little" if elf.little_endian else "big"
    info.arch = elf.machine_name
    info.entry_point = elf.e_entry
    info.pie = elf.is_pie_or_shared

    for sec in elf.sections:
        if sec.name:
            info.sections[sec.name] = (sec.addr, sec.size)

    # NX: look at the GNU_STACK segment's execute flag. No such segment at
    # all is the older default (no PT_GNU_STACK marker = stack assumed RWX).
    stack_seg = elf.get_segment(PT_GNU_STACK)
    info.nx = (stack_seg is not None) and not bool(stack_seg.p_flags & 0x1)

    # RELRO: partial if the GNU_RELRO segment exists, full if BIND_NOW is
    # also set (either via DT_BIND_NOW or the DF_BIND_NOW/DF_1_NOW flags).
    relro_seg = elf.get_segment(PT_GNU_RELRO)
    if relro_seg is not None and elf.has_bind_now():
        info.relro = "Full"
    elif relro_seg is not None:
        info.relro = "Partial"
    else:
        info.relro = "No"

    info.rpath = elf.rpath() is not None
    info.runpath = elf.runpath() is not None
    info.stripped = not elf.has_symtab()

    dynsyms = elf.dynamic_symbols()
    imports = sorted({s.name for s in dynsyms if s.is_undefined and s.name})
    info.imports = imports

    all_names = {s.name for s in dynsyms if s.name}
    info.canary = "__stack_chk_fail" in all_names or b"__stack_chk_fail" in raw_data
    info.fortify = any(n.endswith("_chk") and n != "__stack_chk_fail" for n in all_names)

    info.symbols = sorted({s.name for s in dynsyms if s.name})
    for sym in elf.static_symbols():
        if sym.name and sym.is_function and sym.shndx != 0:
            info.functions[sym.name] = sym.value
            if sym.name not in info.symbols:
                info.symbols.append(sym.name)


def _load_pe(info: BinaryInfo, raw_data: bytes) -> None:
    if not PEFILE_AVAILABLE:
        # Best-effort fallback without pefile: read just enough of the
        # COFF header ourselves to at least get the architecture right.
        try:
            pe_offset = int.from_bytes(raw_data[0x3C:0x40], "little")
            machine = int.from_bytes(raw_data[pe_offset + 4:pe_offset + 6], "little")
            info.bits = 32 if machine == 0x14C else 64
            info.arch = "x86" if info.bits == 32 else "x86_64"
        except Exception:
            info.bits, info.arch = 32, "x86"
        return

    try:
        pe = pefile.PE(data=raw_data)
        info.bits = 32 if pe.FILE_HEADER.Machine == 0x14C else 64
        info.arch = "x86" if info.bits == 32 else "x86_64"
        info.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        info.pie = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040)  # DYNAMIC_BASE
        info.nx = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)   # NX_COMPAT
        info.stripped = not hasattr(pe, "DIRECTORY_ENTRY_DEBUG")

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name
                        info.imports.append(name)
        pe.close()
    except Exception:
        pass


def _try_checksec(info: BinaryInfo, path: str) -> None:
    """Cross-check (and override) with the real `checksec` tool when present
    - it understands more edge cases than our minimal parser. Failure here
    is expected on most systems and is not an error."""
    try:
        result = subprocess.run(
            ["checksec", "--file=" + path, "--output=json"],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return

    if result.returncode != 0 or not result.stdout.strip():
        return
    try:
        data = json.loads(result.stdout)
        prog = next(iter(data))
        sec = data[prog]
    except (json.JSONDecodeError, StopIteration):
        return

    def _bool(key: str, default: bool) -> bool:
        val = sec.get(key)
        if val is None:
            return default
        return str(val).lower() not in ("no", "false", "0")

    info.pie = _bool("pie", info.pie)
    info.nx = _bool("nx", info.nx)
    info.canary = _bool("canary", info.canary)
    info.relro = sec.get("relro", info.relro)
    info.fortify = _bool("fortify_source", info.fortify)
    info.rpath = _bool("rpath", info.rpath)
    info.runpath = _bool("runpath", info.runpath)
    info.stripped = _bool("stripped", info.stripped)
