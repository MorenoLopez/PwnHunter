"""
The PwnHunter class is now a thin orchestrator: it loads the binary, runs
the disassembler, runs every registered detector, and builds the report.
All the actual analysis logic lives in pwnhunter.detectors.* so it can be
tested and extended independently of this class.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional

from .binary_loader import load_binary_info
from .detectors import ALL_DETECTORS
from .disassembler import CAPSTONE_AVAILABLE, disassemble
from .models import BinaryInfo, Vulnerability
from .report import build_report, print_report
from .scan_context import ScanContext


class PwnHunter:
    """Main vulnerability detection engine."""

    def __init__(self, binary_path: str, verbose: bool = False):
        self.binary_path = os.path.abspath(binary_path)
        self.verbose = verbose
        self.vulnerabilities: List[Vulnerability] = []
        self.binary_info: Optional[BinaryInfo] = None
        self.disassembly = []

        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
        if not os.path.isfile(self.binary_path):
            raise ValueError(f"Not a file: {self.binary_path}")

        # Read once; every downstream component works off this buffer
        # instead of re-opening the file (this is what fixes the original
        # script's file-handle leaks).
        with open(self.binary_path, "rb") as f:
            self.raw_data: bytes = f.read()

    def log(self, msg: str) -> None:
        # Diagnostic-only output: always stderr, so stdout stays clean for
        # `--json` consumers piping/redirecting the report.
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    def analyze(self) -> Dict:
        """Run the complete analysis pipeline and return the report dict."""
        self.log(f"Loading binary properties for {self.binary_path}")
        self.binary_info = load_binary_info(self.binary_path, self.raw_data, self.verbose)
        self.log(f"Format={self.binary_info.format} arch={self.binary_info.arch} "
                 f"bits={self.binary_info.bits}")

        if CAPSTONE_AVAILABLE:
            self.disassembly = disassemble(self.binary_path, self.raw_data, self.binary_info)
            self.log(f"Disassembled {len(self.disassembly)} instructions")
        else:
            print("[!] capstone not installed - disassembly-based checks "
                  "(ROP gadgets, integer overflow, off-by-one, some format-string "
                  "checks) are skipped. Install with: pip install capstone",
                  file=sys.stderr)

        ctx = ScanContext(
            binary_path=self.binary_path,
            raw_data=self.raw_data,
            binary_info=self.binary_info,
            disassembly=self.disassembly,
            verbose=self.verbose,
        )

        self.vulnerabilities = []
        for detector in ALL_DETECTORS:
            self.log(f"Running detector: {detector.name}")
            try:
                self.vulnerabilities.extend(detector.run(ctx))
            except Exception as exc:  # a single bad detector must not kill the whole scan
                self.log(f"Detector '{detector.name}' raised {exc!r} - skipping its findings")

        return build_report(self.binary_info, self.vulnerabilities)

    def print_report(self, report: Dict) -> None:
        print_report(report)
