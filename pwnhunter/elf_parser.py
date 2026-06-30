"""
Minimal pure-stdlib ELF32/ELF64 parser.

Why this exists: the original project *required* pyelftools to get any
architecture/section/import/security information at all, and silently
produced an almost-empty report without it. This module implements just
enough of the ELF spec (header, sections, segments, symbol tables, dynamic
section) to drive every detector, with zero third-party dependencies.

If `pyelftools` happens to be installed it is not needed and not used -
one less moving part to keep in sync.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

ELF_MAGIC = b"\x7fELF"

ET_EXEC = 2
ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

SHN_UNDEF = 0

DT_NEEDED = 1
DT_STRTAB = 5
DT_RPATH = 15
DT_RUNPATH = 29
DT_FLAGS = 30
DT_BIND_NOW = 24
DT_FLAGS_1 = 0x6FFFFFFB

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

EM_MACHINE_NAMES = {
    3: "EM_386",
    8: "EM_MIPS",
    20: "EM_PPC",
    21: "EM_PPC64",
    40: "EM_ARM",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}


class ELFParseError(Exception):
    """Raised when the buffer is not a parseable ELF file."""


@dataclass
class ELFSection:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & 0x4)


@dataclass
class ELFSegment:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int


@dataclass
class ELFSymbol:
    name: str
    value: int
    size: int
    info: int
    shndx: int

    @property
    def is_undefined(self) -> bool:
        return self.shndx == SHN_UNDEF

    @property
    def is_function(self) -> bool:
        return (self.info & 0xF) == 2  # STT_FUNC


class MinimalELF:
    """Parses just enough of an ELF file's structure for static analysis."""

    def __init__(self, data: bytes):
        if data[:4] != ELF_MAGIC:
            raise ELFParseError("Not an ELF file (bad magic)")
        self.data = data

        ei_class = data[4]
        ei_data = data[5]
        if ei_class not in (1, 2):
            raise ELFParseError(f"Unknown EI_CLASS: {ei_class}")
        if ei_data not in (1, 2):
            raise ELFParseError(f"Unknown EI_DATA: {ei_data}")

        self.is_64 = ei_class == 2
        self.little_endian = ei_data == 1
        self.endian = "<" if self.little_endian else ">"

        self.sections: List[ELFSection] = []
        self.segments: List[ELFSegment] = []

        self._parse_ehdr()
        self._parse_shdrs()
        self._parse_phdrs()

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------
    def _parse_ehdr(self):
        e = self.endian
        if self.is_64:
            fmt = e + "HHIQQQIHHHHHH"
        else:
            fmt = e + "HHIIIIIHHHHHH"
        size = struct.calcsize(fmt)
        (self.e_type, self.e_machine, self.e_version, self.e_entry,
         self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack_from(fmt, self.data, 16)
        if size + 16 > len(self.data):
            raise ELFParseError("Truncated ELF header")

    @property
    def machine_name(self) -> str:
        return EM_MACHINE_NAMES.get(self.e_machine, f"EM_UNKNOWN_{self.e_machine}")

    @property
    def is_pie_or_shared(self) -> bool:
        return self.e_type == ET_DYN

    # ------------------------------------------------------------------
    # Section headers
    # ------------------------------------------------------------------
    def _parse_shdrs(self):
        if self.e_shoff == 0 or self.e_shnum == 0:
            return
        e = self.endian
        fmt = e + ("IIQQQQIIQQ" if self.is_64 else "IIIIIIIIII")
        entsize = struct.calcsize(fmt)

        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if off + entsize > len(self.data):
                break
            fields = struct.unpack_from(fmt, self.data, off)
            raw.append(fields)

        # Resolve section name strings using the shstrtab section itself.
        shstrtab_off = shstrtab_size = 0
        if raw and self.e_shstrndx < len(raw):
            shstrtab_off = raw[self.e_shstrndx][4]
            shstrtab_size = raw[self.e_shstrndx][5]
        shstrtab = self.data[shstrtab_off:shstrtab_off + shstrtab_size]

        def name_at(offset: int) -> str:
            end = shstrtab.find(b"\x00", offset)
            if end == -1:
                end = len(shstrtab)
            return shstrtab[offset:end].decode("utf-8", errors="replace")

        for fields in raw:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info = fields[:8]
            name = name_at(sh_name) if shstrtab else ""
            self.sections.append(ELFSection(
                name=name, sh_type=sh_type, flags=sh_flags, addr=sh_addr,
                offset=sh_offset, size=sh_size, link=sh_link, info=sh_info,
            ))

    def get_section(self, name: str) -> Optional[ELFSection]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_data(self, section: ELFSection) -> bytes:
        return self.data[section.offset:section.offset + section.size]

    # ------------------------------------------------------------------
    # Program headers (segments)
    # ------------------------------------------------------------------
    def _parse_phdrs(self):
        if self.e_phoff == 0 or self.e_phnum == 0:
            return
        e = self.endian
        if self.is_64:
            fmt = e + "IIQQQQQQ"  # type,flags,offset,vaddr,paddr,filesz,memsz,align
        else:
            fmt = e + "IIIIIIII"  # type,offset,vaddr,paddr,filesz,memsz,flags,align
        entsize = struct.calcsize(fmt)

        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if off + entsize > len(self.data):
                break
            fields = struct.unpack_from(fmt, self.data, off)
            if self.is_64:
                p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = fields
            else:
                p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = fields
            self.segments.append(ELFSegment(
                p_type=p_type, p_flags=p_flags, p_offset=p_offset,
                p_vaddr=p_vaddr, p_filesz=p_filesz, p_memsz=p_memsz,
            ))

    def get_segment(self, p_type: int) -> Optional[ELFSegment]:
        for seg in self.segments:
            if seg.p_type == p_type:
                return seg
        return None

    # ------------------------------------------------------------------
    # Symbol tables (.symtab / .dynsym)
    # ------------------------------------------------------------------
    def _parse_symtab(self, symtab_name: str, strtab_name: str) -> List[ELFSymbol]:
        symtab = self.get_section(symtab_name)
        if symtab is None or symtab.size == 0:
            return []

        strtab = None
        if 0 <= symtab.link < len(self.sections):
            strtab = self.sections[symtab.link]
        if strtab is None:
            strtab = self.get_section(strtab_name)
        if strtab is None:
            return []

        strtab_data = self.section_data(strtab)
        e = self.endian
        fmt = e + ("IBBHQQ" if self.is_64 else "IIIBBH")
        entsize = struct.calcsize(fmt)
        if entsize == 0:
            return []

        symbols = []
        data = self.section_data(symtab)
        count = len(data) // entsize
        for i in range(count):
            chunk = data[i * entsize:(i + 1) * entsize]
            if len(chunk) < entsize:
                break
            if self.is_64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(fmt, chunk)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(fmt, chunk)

            end = strtab_data.find(b"\x00", st_name)
            if end == -1:
                end = len(strtab_data)
            name = strtab_data[st_name:end].decode("utf-8", errors="replace")
            symbols.append(ELFSymbol(name=name, value=st_value, size=st_size,
                                      info=st_info, shndx=st_shndx))
        return symbols

    def dynamic_symbols(self) -> List[ELFSymbol]:
        return self._parse_symtab(".dynsym", ".dynstr")

    def static_symbols(self) -> List[ELFSymbol]:
        return self._parse_symtab(".symtab", ".strtab")

    def has_symtab(self) -> bool:
        sec = self.get_section(".symtab")
        return sec is not None and sec.size > 0

    # ------------------------------------------------------------------
    # Dynamic section (.dynamic) -> RPATH/RUNPATH/BIND_NOW
    # ------------------------------------------------------------------
    def dynamic_entries(self) -> List[tuple]:
        dyn = self.get_section(".dynamic")
        if dyn is None or dyn.size == 0:
            return []
        e = self.endian
        fmt = e + ("qQ" if self.is_64 else "iI")
        entsize = struct.calcsize(fmt)
        data = self.section_data(dyn)
        entries = []
        for i in range(len(data) // entsize):
            chunk = data[i * entsize:(i + 1) * entsize]
            if len(chunk) < entsize:
                break
            tag, val = struct.unpack(fmt, chunk)
            if tag == 0:  # DT_NULL terminator
                break
            entries.append((tag, val))
        return entries

    def dynstr_table(self) -> bytes:
        strtab = self.get_section(".dynstr")
        if strtab is None:
            return b""
        return self.section_data(strtab)

    def _dynstr_at(self, offset: int) -> str:
        table = self.dynstr_table()
        end = table.find(b"\x00", offset)
        if end == -1:
            end = len(table)
        return table[offset:end].decode("utf-8", errors="replace")

    def rpath(self) -> Optional[str]:
        for tag, val in self.dynamic_entries():
            if tag == DT_RPATH:
                return self._dynstr_at(val)
        return None

    def runpath(self) -> Optional[str]:
        for tag, val in self.dynamic_entries():
            if tag == DT_RUNPATH:
                return self._dynstr_at(val)
        return None

    def has_bind_now(self) -> bool:
        for tag, val in self.dynamic_entries():
            if tag == DT_BIND_NOW:
                return True
            if tag == DT_FLAGS and (val & DF_BIND_NOW):
                return True
            if tag == DT_FLAGS_1 and (val & DF_1_NOW):
                return True
        return False


def parse(data: bytes) -> MinimalELF:
    """Convenience wrapper, mirrors the rest of the codebase's style."""
    return MinimalELF(data)
