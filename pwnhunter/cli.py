from __future__ import annotations

import argparse
import json
import sys

from .models import SEVERITY_ORDER, VulnType
from .scanner import PwnHunter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnhunter",
        description="PwnHunter - Static binary vulnerability analyzer for CTF/pwn use.",
    )
    parser.add_argument("binary", help="Path to the binary to analyze")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Save report to file")
    parser.add_argument("--strings", action="store_true", help="Show extracted strings and exit")
    parser.add_argument("--rop-only", action="store_true", help="Show only ROP gadgets and exit")
    parser.add_argument(
        "--min-severity", choices=list(SEVERITY_ORDER.keys()),
        help="Only show findings at or above this severity (e.g. MEDIUM hides LOW/INFO noise)",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        hunter = PwnHunter(args.binary, verbose=args.verbose)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        return 1

    try:
        report = hunter.analyze()
    except Exception as e:
        print(f"Error during analysis: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    if args.min_severity:
        from .report import build_report
        report = build_report(hunter.binary_info, hunter.vulnerabilities, min_severity=args.min_severity)

    if args.strings:
        print("\nExtracted Strings:")
        for offset, string in hunter.binary_info.strings[:100]:
            print(f"  {offset:#x}: {string[:80]}")
        return 0

    if args.rop_only:
        rop_vulns = [v for v in hunter.vulnerabilities if v.vuln_type == VulnType.ROP_GADGET]
        print(f"\nFound {len(rop_vulns)} ROP gadgets:")
        for v in rop_vulns:
            print(f"  {v.offset:#x}: {v.instruction}")
        return 0

    if args.json:
        output = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
    else:
        hunter.print_report(report)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"JSON report saved to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
