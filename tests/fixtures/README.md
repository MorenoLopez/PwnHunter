# Test fixtures

`vuln.c` is compiled on the fly by `tests/test_integration.py` (two ways:
one deliberately unprotected build and one fully-hardened build) so the
integration tests exercise the real ELF parsing / security-flag logic
against real binaries. No binaries are checked into the repo since they're
architecture/compiler-dependent; gcc is required to run these specific
tests (they are skipped automatically if gcc is not found).
