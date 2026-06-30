from __future__ import annotations

from typing import Dict, List

from .models import SEVERITY_ORDER, Vulnerability, VulnType


def build_report(binary_info, vulnerabilities: List[Vulnerability],
                  min_severity: str = None) -> Dict:
    vulns = sorted(vulnerabilities, key=lambda v: v.severity_rank())
    if min_severity:
        threshold = SEVERITY_ORDER.get(min_severity, len(SEVERITY_ORDER))
        vulns = [v for v in vulns if v.severity_rank() <= threshold]

    report = {
        "binary_info": binary_info.to_dict() if binary_info else {},
        "summary": {"total_vulnerabilities": len(vulns), "by_severity": {}, "by_type": {}},
        "vulnerabilities": [v.to_dict() for v in vulns],
        "exploitation_vectors": get_exploitation_vectors(vulns),
    }

    for v in vulns:
        report["summary"]["by_severity"][v.severity] = report["summary"]["by_severity"].get(v.severity, 0) + 1
        report["summary"]["by_type"][v.vuln_type.name] = report["summary"]["by_type"].get(v.vuln_type.name, 0) + 1

    return report


def get_exploitation_vectors(vulnerabilities: List[Vulnerability]) -> List[Dict]:
    types_present = {v.vuln_type for v in vulnerabilities}
    vectors = []

    has = lambda t: t in types_present  # noqa: E731

    if has(VulnType.BUFFER_OVERFLOW) and not has(VulnType.STACK_CANARY):
        vectors.append({
            "vector": "Stack Buffer Overflow",
            "difficulty": "Easy",
            "steps": [
                "1. Find the offset to the return address (cyclic pattern).",
                "2. Overwrite the return address with the target.",
                "3. If NX is disabled: inject shellcode directly.",
                "4. If NX is enabled: build a ROP chain (ret2libc or ret2plt).",
            ],
        })

    if has(VulnType.FORMAT_STRING):
        vectors.append({
            "vector": "Format String Exploitation",
            "difficulty": "Medium",
            "steps": [
                "1. Leak stack/canary/libc addresses with %p / %x.",
                "2. Write to arbitrary memory with %n / %hn / %hhn.",
                "3. Overwrite a GOT entry or function pointer.",
                "4. Trigger shell execution.",
            ],
        })

    if has(VulnType.HEAP_USAGE) or has(VulnType.USE_AFTER_FREE) or has(VulnType.DOUBLE_FREE):
        vectors.append({
            "vector": "Use-After-Free / Heap Exploitation",
            "difficulty": "Hard",
            "steps": [
                "1. Confirm an actual UAF/double-free exists (this binary only shows heap usage).",
                "2. Allocate and free a chunk, then reallocate to control its contents.",
                "3. Overwrite chunk metadata or a function pointer.",
                "4. Trigger use of the dangling/freed pointer.",
            ],
        })

    if has(VulnType.NX_BYPASS):
        vectors.append({
            "vector": "Direct Shellcode Execution",
            "difficulty": "Easy",
            "steps": [
                "1. Find a writable+executable region.",
                "2. Inject shellcode.",
                "3. Jump to the shellcode.",
            ],
        })

    if has(VulnType.PIE_BYPASS):
        vectors.append({
            "vector": "Fixed Address Exploitation",
            "difficulty": "Easy",
            "steps": [
                "1. Use the known, fixed base address (no ASLR for this binary).",
                "2. Calculate exact gadget/function addresses.",
                "3. Build a ROP chain with fixed addresses.",
            ],
        })

    if has(VulnType.RELRO_BYPASS):
        vectors.append({
            "vector": "GOT Overwrite",
            "difficulty": "Medium",
            "steps": [
                "1. Find a writable GOT entry.",
                "2. Overwrite it with system()'s address or a shellcode pointer.",
                "3. Trigger a call to the hijacked function.",
            ],
        })

    return vectors


def print_report(report: Dict) -> None:
    print(f"\n{'=' * 60}")
    print("  BINARY INFORMATION")
    print(f"{'=' * 60}")
    info = report["binary_info"]
    print(f"  Path:       {info.get('path')}")
    print(f"  Format:     {info.get('format')}")
    print(f"  Arch:       {info.get('architecture')} ({info.get('bits')}-bit)")
    print(f"  OS:         {info.get('os')}")

    if info.get("format") in ("ELF", "PE"):
        print("\n  Security Features:")
        for feat, val in info.get("security", {}).items():
            if feat == "Stripped":
                # Not an "enabled/disabled" mitigation - phrase it as a plain yes/no.
                status = "YES" if val else "NO"
            else:
                status = "ENABLED" if val in (True, "Full") else "DISABLED"
            print(f"    {feat:12s}: {status}")
    else:
        print(f"\n  (Format '{info.get('format')}' not recognized - security "
              f"flags unavailable, falling back to string/byte heuristics only.)")

    print(f"\n{'=' * 60}")
    print("  VULNERABILITY SUMMARY")
    print(f"{'=' * 60}")
    summary = report["summary"]
    print(f"  Total Findings: {summary['total_vulnerabilities']}")
    for sev, count in sorted(summary["by_severity"].items(),
                              key=lambda x: SEVERITY_ORDER.get(x[0], 5)):
        print(f"    {sev:10s}: {count}")

    print(f"\n{'=' * 60}")
    print("  DETAILED VULNERABILITIES")
    print(f"{'=' * 60}")
    for v in report["vulnerabilities"]:
        print(f"\n  [{v['severity']}] {v['type']}")
        print(f"    Function:   {v['function']}")
        print(f"    Details:    {v['description']}")
        if v["offset"]:
            print(f"    Offset:     {v['offset']}")
        if v["instruction"]:
            print("    Instruction:")
            for line in v["instruction"].split("\n"):
                print(f"      {line}")

    if report["exploitation_vectors"]:
        print(f"\n{'=' * 60}")
        print("  SUGGESTED EXPLOITATION VECTORS")
        print(f"{'=' * 60}")
        for vec in report["exploitation_vectors"]:
            print(f"\n  [{vec['difficulty']}] {vec['vector']}")
            for step in vec["steps"]:
                print(f"    {step}")

    print(f"\n{'=' * 60}")
    print("  END OF REPORT")
    print(f"{'=' * 60}\n")
