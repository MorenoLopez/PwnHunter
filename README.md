# PwnHunter

> Static binary vulnerability analyzer for CTF / pwn challenges.

A modular Python tool that scans ELF (primary) and PE binaries for common exploitation primitives: stack overflows, format strings, ROP gadgets, heap misuse, integer overflows, and more.

---

## Author

**4n0ny_m0**

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Detectors](#detectors)
- [Tests](#tests)
- [License](#license)

---

## Requirements

- Python 3.8+
- No mandatory external dependencies (pure stdlib core)
- `capstone` — optional, enables disassembly-based detection (ROP, integer overflow, off-by-one)
- `pefile` — optional, enables richer PE import parsing (Windows binaries)

---

## Installation

```bash
# Core only — no dependencies, stdlib only
pip install -e .

# With disassembly support (ROP gadgets, integer overflow, off-by-one)
pip install -e ".[disasm]"

# With richer PE import parsing (Windows imports)
pip install -e ".[pe]"

# Everything
pip install -e ".[full]"
```

> **Offline environments:** if `setuptools >= 61` is already available locally,
> add `--no-build-isolation` to skip the build backend fetch:
> ```bash
> pip install -e . --no-build-isolation
> ```

---

## Usage

### CLI

```bash
pwnhunter /path/to/binary
pwnhunter /path/to/binary --json -o report.json
pwnhunter /path/to/binary --min-severity HIGH   # suppress LOW/INFO noise
pwnhunter /path/to/binary --strings
pwnhunter /path/to/binary --rop-only
pwnhunter /path/to/binary --strict              # more thorough, more false positives
```

### As a library

```python
from pwnhunter import PwnHunter

hunter = PwnHunter("/path/to/binary")
report = hunter.analyze()
print(report["summary"])
```

---

## Architecture

```
pwnhunter/
├── models.py               # VulnType, Vulnerability, BinaryInfo (dataclasses)
├── constants.py            # static tables (dangerous functions, signatures…)
├── elf_parser.py           # pure-stdlib ELF32/64 parser (no external dependency)
├── binary_loader.py        # builds BinaryInfo (ELF/PE) + checksec integration
├── disassembler.py         # optional Capstone wrapper
├── strings_utils.py        # string extraction / context helpers
├── scan_context.py         # ScanContext + Detector base class
├── detectors/              # one detector = one responsibility, testable in isolation
│   ├── security_bypass.py
│   ├── dangerous_functions.py
│   ├── format_string.py
│   ├── heap.py
│   ├── integer_overflow.py
│   ├── info_leak.py
│   ├── rop_gadgets.py
│   └── shellcode.py
├── report.py               # aggregation, exploitation vectors, rendering
├── scanner.py              # orchestrator (PwnHunter)
├── cli.py                  # argparse / entry point
└── __main__.py              # python -m pwnhunter entry point
```

Adding a new detector is a one-liner: create a class with a `run(ctx) -> List[Vulnerability]` method and register it in `detectors/__init__.py`. Nothing else to touch.

---

## Detectors

| Detector | What it catches |
|---|---|
| `security_bypass` | Missing PIE, NX, canary, RELRO, FORTIFY |
| `dangerous_functions` | `gets`, `strcpy`, `printf` (user-controlled), `system`, … |
| `format_string` | `%n`/`%p`/`%x` patterns near format function calls |
| `heap` | UAF, double-free, oversized allocations |
| `integer_overflow` | `imul`/`mul` without `jo`/`jno`, large arithmetic constants |
| `info_leak` | Stack/heap/libc addresses, flags, secrets in strings |
| `rop_gadgets` | Architecture-aware gadget search (x86-64 and ARM) |
| `shellcode` | Known shellcode byte signatures, `/bin/sh`, `syscall` |

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

| Test file | What it covers |
|---|---|
| `test_models.py` | Dataclass integrity, severity sorting |
| `test_elf_parser.py` | Compiles two real binaries with `gcc` and validates ELF parsing — skipped if `gcc` is absent |
| `test_detectors.py` | Each detector tested in isolation with synthetic data — no Capstone or real ELF required |
| `test_integration.py` | Full end-to-end scan + CLI, JSON report consistency |

Disassembly-based detectors (ROP, integer overflow, off-by-one) require `capstone`. If it is not installed they are automatically disabled with an explicit message on stderr; the rest of the report remains fully functional.

---

## License

This project is licensed under the [MIT License](LICENSE).
