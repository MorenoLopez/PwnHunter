"""
PwnHunter - Modular static binary vulnerability analyzer for CTF/pwn use.

Public API:
    from pwnhunter import PwnHunter
    hunter = PwnHunter("/path/to/binary")
    report = hunter.analyze()
"""

from .models import BinaryInfo, SEVERITY_ORDER, Vulnerability, VulnType
from .scanner import PwnHunter

__version__ = "2.0.0"

__all__ = [
    "PwnHunter",
    "Vulnerability",
    "VulnType",
    "BinaryInfo",
    "SEVERITY_ORDER",
    "__version__",
]
