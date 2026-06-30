"""
Detector registry. Adding a new check to the project means writing a class
with a `run(ctx) -> List[Vulnerability]` method and adding one line here -
nothing else in the codebase needs to change.
"""

from typing import List

from ..scan_context import Detector
from .dangerous_functions import DangerousFunctionDetector
from .format_string import FormatStringDetector
from .heap import HeapDetector
from .info_leak import InfoLeakDetector
from .integer_overflow import IntegerOverflowDetector, OffByOneDetector
from .rop_gadgets import RopGadgetDetector
from .security_bypass import SecurityBypassDetector
from .shellcode import ShellcodeDetector

ALL_DETECTORS: List[Detector] = [
    SecurityBypassDetector(),
    DangerousFunctionDetector(),
    FormatStringDetector(),
    HeapDetector(),
    IntegerOverflowDetector(),
    OffByOneDetector(),
    InfoLeakDetector(),
    RopGadgetDetector(),
    ShellcodeDetector(),
]

__all__ = ["ALL_DETECTORS", "Detector"]
