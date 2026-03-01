"""
Smoke test for a2a-settlement-auth.

Exercises the full token lifecycle by running the end-to-end example:
create → validate → scope check → counterparty policy → spending limits
→ revocation. This catches integration issues that import-only checks miss.

Usage:
    python smoke_test.py           # Run full lifecycle (quiet)
    python smoke_test.py --verbose # Run with example output
"""

import argparse
import asyncio
import os
import sys


def _ensure_project_root():
    """Ensure project root is on sys.path for examples import."""
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)


def run_smoke_test(verbose: bool = False) -> int:
    """Run the full lifecycle smoke test via end_to_end example."""
    _ensure_project_root()

    try:
        from a2a_settlement_auth import __version__
        print(f"a2a_settlement_auth v{__version__}: OK")
    except Exception as e:
        print(f"a2a_settlement_auth import failed: {e}")
        return 1

    if verbose:
        # Run with full example output
        from examples.end_to_end import main
        print("\n--- Full token lifecycle (end_to_end) ---\n")
        asyncio.run(main())
        print("\nSmoke test: OK")
        return 0

    # Quiet mode: run the example but capture output, assert key outcomes
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    try:
        from examples.end_to_end import main

        with redirect_stdout(buf):
            asyncio.run(main())

        output = buf.getvalue()
        # Key assertions that the full lifecycle completed
        assert "Token issued for agent:" in output
        assert "Token validated successfully" in output
        assert "Can create escrow: True" in output
        assert "ALLOWED" in output and "DENIED" in output  # counterparty checks
        assert "Transaction 1 (200 tokens): ALLOWED" in output
        assert "Transaction 4 (600 tokens): DENIED" in output  # per-tx limit
        assert "Token spending authority has been revoked" in output
        assert "Post-revocation check (1 token): DENIED" in output

        print("Full lifecycle (create→validate→scope→counterparty→spending→revoke): OK")
        return 0

    except AssertionError as e:
        print(f"Smoke test assertion failed: {e}")
        print("Example output:\n", buf.getvalue())
        return 1
    except Exception as e:
        print(f"Smoke test failed: {e}")
        print("Example output:\n", buf.getvalue())
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smoke test: full token lifecycle via end_to_end example"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full example output instead of quiet pass/fail",
    )
    args = parser.parse_args()
    return run_smoke_test(verbose=args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
