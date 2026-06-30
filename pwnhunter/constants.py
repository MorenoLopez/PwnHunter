"""
Static knowledge tables used by the detectors. Centralised here so they are
easy to extend without touching detector logic.
"""

from .models import VulnType

# function_name -> (VulnType, severity)
DANGEROUS_FUNCTIONS = {
    "gets": (VulnType.BUFFER_OVERFLOW, "CRITICAL"),
    "gets_s": (VulnType.BUFFER_OVERFLOW, "LOW"),
    "strcpy": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "strcat": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "sprintf": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "vsprintf": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "wcscpy": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "wcscat": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "swprintf": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "alloca": (VulnType.BUFFER_OVERFLOW, "HIGH"),
    "scanf": (VulnType.BUFFER_OVERFLOW, "MEDIUM"),
    "fscanf": (VulnType.BUFFER_OVERFLOW, "MEDIUM"),
    "sscanf": (VulnType.BUFFER_OVERFLOW, "MEDIUM"),
    "vscanf": (VulnType.BUFFER_OVERFLOW, "MEDIUM"),
    "strtok": (VulnType.BUFFER_OVERFLOW, "MEDIUM"),
    "wcsncpy": (VulnType.BUFFER_OVERFLOW, "MEDIUM"),
    # NOTE: these next ones are NOT inherently dangerous - they only become a
    # problem if the size argument is attacker-controlled or miscalculated.
    # We still flag them (CTF binaries love to misuse them) but at a low
    # severity and with wording that makes clear it needs manual review.
    "read": (VulnType.BUFFER_OVERFLOW, "LOW"),
    "recv": (VulnType.BUFFER_OVERFLOW, "LOW"),
    "recvfrom": (VulnType.BUFFER_OVERFLOW, "LOW"),
    "memcpy": (VulnType.BUFFER_OVERFLOW, "LOW"),
    "memmove": (VulnType.BUFFER_OVERFLOW, "LOW"),
    "bcopy": (VulnType.BUFFER_OVERFLOW, "LOW"),
    "strncpy": (VulnType.BUFFER_OVERFLOW, "INFO"),
    "strncat": (VulnType.BUFFER_OVERFLOW, "INFO"),
    "snprintf": (VulnType.BUFFER_OVERFLOW, "INFO"),
    "printf": (VulnType.FORMAT_STRING, "HIGH"),
    "fprintf": (VulnType.FORMAT_STRING, "HIGH"),
    "dprintf": (VulnType.FORMAT_STRING, "HIGH"),
    "vprintf": (VulnType.FORMAT_STRING, "HIGH"),
    "vfprintf": (VulnType.FORMAT_STRING, "HIGH"),
    "vsnprintf": (VulnType.FORMAT_STRING, "MEDIUM"),
    "syslog": (VulnType.FORMAT_STRING, "MEDIUM"),
    "setproctitle": (VulnType.FORMAT_STRING, "MEDIUM"),
    "system": (VulnType.SHELLCODE_EXEC, "HIGH"),
    "execve": (VulnType.SHELLCODE_EXEC, "HIGH"),
    "execl": (VulnType.SHELLCODE_EXEC, "HIGH"),
    "popen": (VulnType.SHELLCODE_EXEC, "HIGH"),
    "strtol": (VulnType.INTEGER_OVERFLOW, "INFO"),
    "strtoul": (VulnType.INTEGER_OVERFLOW, "INFO"),
    "atoi": (VulnType.INTEGER_OVERFLOW, "INFO"),
    "atol": (VulnType.INTEGER_OVERFLOW, "INFO"),
    "atoll": (VulnType.INTEGER_OVERFLOW, "INFO"),
}

# Functions that allocate/free heap memory - used by the heap detector.
HEAP_FUNCTIONS = {"malloc", "free", "realloc", "calloc"}

# Functions that interpret a format string - used by the format-string detector.
FORMAT_FUNCTIONS = {
    "printf", "fprintf", "sprintf", "snprintf", "vprintf",
    "vfprintf", "vsprintf", "vsnprintf", "dprintf", "syslog",
}

FORMAT_SPECIFIERS = (
    b"%s", b"%x", b"%p", b"%n", b"%d", b"%u",
    b"%c", b"%f", b"%e", b"%g", b"%o", b"%X",
    b"%lld", b"%llx", b"%hhn", b"%hn", b"%ln",
    b"%lln", b"%.*s", b"%*s", b"%*.*s",
)

SHELLCODE_SIGNATURES = (
    (b"\x31\xc0\x50\x68", "Classic execve shellcode"),
    (b"\x6a\x0b\x58\x99\x52", "Linux execve shellcode"),
    (b"/bin/sh", "/bin/sh string"),
    (b"/bin/bash", "/bin/bash string"),
    (b"cmd.exe", "Windows cmd string"),
    (b"powershell", "PowerShell string"),
    (b"\xcd\x80", "int 0x80 syscall"),
    (b"\x0f\x05", "syscall instruction"),
)

INFO_LEAK_PATTERNS = (
    (b"stack", "Stack address reference"),
    (b"heap", "Heap address reference"),
    (b"0x7f", "Potential libc/heap address"),
    (b"0x55", "Potential heap address (x64 PIE base)"),
    (b"0x56", "Potential heap address (x64)"),
    (b"flag", "Flag reference"),
    (b"password", "Password reference"),
    (b"secret", "Secret reference"),
    (b"key", "Key reference"),
    (b"token", "Token reference"),
)

# ROP gadget patterns, kept per-architecture-family because register names
# (and thus the regexes) differ. Applying x86 patterns to ARM disassembly
# (as the original script did) silently finds nothing and gives a false
# sense of coverage, so we key everything by arch family explicitly.
ROP_GADGET_PATTERNS = {
    "x86_64": {
        "pop_rdi": r"pop\s+rdi.*ret",
        "pop_rsi": r"pop\s+rsi.*ret",
        "pop_rdx": r"pop\s+rdx.*ret",
        "pop_rcx": r"pop\s+rcx.*ret",
        "pop_rax": r"pop\s+rax.*ret",
        "pop_rbx": r"pop\s+rbx.*ret",
        "pop_rbp": r"pop\s+rbp.*ret",
        "pop_r8": r"pop\s+r8.*ret",
        "pop_r9": r"pop\s+r9.*ret",
        "syscall": r"syscall.*ret",
        "leave_ret": r"leave.*ret",
        "one_gadget": r"execve|system.*\/bin\/sh",
    },
    "x86": {
        "pop_eax": r"pop\s+eax.*ret",
        "pop_ebx": r"pop\s+ebx.*ret",
        "pop_ecx": r"pop\s+ecx.*ret",
        "pop_edx": r"pop\s+edx.*ret",
        "pop_ebp": r"pop\s+ebp.*ret",
        "int_0x80": r"int\s+0x80",
        "xchg_eax_esp": r"xchg\s+eax.*esp.*ret",
        "leave_ret": r"leave.*ret",
        "one_gadget": r"execve|system.*\/bin\/sh",
    },
    "arm": {
        "pop_pc": r"pop\s+\{[^}]*pc\}",
        "ldr_pc": r"ldr\s+pc",
        "bx_lr": r"bx\s+lr",
        "blx_reg": r"blx\s+r\d+",
    },
    "arm64": {
        "ldp_ret": r"ldp\s+.*ret",
        "br_x": r"br\s+x\d+",
    },
}

# Mnemonics that can END a gadget window, per architecture family. The
# original script (and an earlier pass of this rewrite) only ever looked
# for x86's "ret"/"retn" - which simply does not exist as a mnemonic in
# 32-bit ARM. ARM functions return via "pop {.., pc}", "bx lr", "ldr pc, ...",
# etc., so the *terminal* instruction itself is one of those, not something
# that follows a separate "ret". Gating the whole detector behind "ret"/"retn"
# meant the ARM patterns above were dead code that could never match anything.
TERMINAL_MNEMONICS = {
    "x86_64": ("ret", "retn"),
    "x86": ("ret", "retn"),
    "arm": ("pop", "ldr", "bx", "blx"),
    "arm64": ("ret", "br"),
}

# Map ELF e_machine -> arch family key used in ROP_GADGET_PATTERNS / capstone setup.
ELF_MACHINE_TO_FAMILY = {
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_ARM": "arm",
    "EM_AARCH64": "arm64",
}
