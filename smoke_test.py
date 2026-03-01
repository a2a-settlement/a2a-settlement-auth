"""
Smoke test for a2a-settlement-auth.

Verifies that the package imports correctly and core functionality works:
- Package import and version
- Token creation and validation
- Spending tracker
- End-to-end example (optional, via --full)
"""

import argparse
import asyncio
import os
import subprocess
import sys


def test_imports() -> bool:
    """Verify package imports."""
    try:
        from a2a_settlement_auth import (
            SettlementClaims,
            SettlementScope,
            SpendingLimit,
            create_settlement_token,
            validate_settlement_token,
            SpendingTracker,
        )
        from a2a_settlement_auth import __version__
        print(f"a2a_settlement_auth v{__version__}: OK")
        return True
    except Exception as e:
        print(f"a2a_settlement_auth import failed: {e}")
        return False


def test_token_roundtrip() -> bool:
    """Verify token creation and validation."""
    try:
        from a2a_settlement_auth import (
            SettlementClaims,
            SettlementScope,
            SpendingLimit,
            create_settlement_token,
            validate_settlement_token,
        )

        claims = SettlementClaims(
            agent_id="smoke-test-bot",
            org_id="org-smoke",
            spending_limits=SpendingLimit(per_transaction=100, per_day=1000),
        )
        # Use 32+ byte key to satisfy RFC 7518 (PyJWT warns on shorter keys)
        key = "smoke-test-key-32-bytes-long-for-hmac-sha256"
        token = create_settlement_token(
            claims=claims,
            scopes={SettlementScope.TRANSACT},
            signing_key=key,
            issuer="https://idp.smoke.test",
            audience="https://exchange.smoke.test",
        )
        validated = validate_settlement_token(
            token=token,
            verification_key=key,
            audience="https://exchange.smoke.test",
            issuer="https://idp.smoke.test",
        )
        assert validated.settlement_claims.agent_id == "smoke-test-bot"
        assert SettlementScope.TRANSACT in validated.scopes
        print("Token create/validate: OK")
        return True
    except Exception as e:
        print(f"Token roundtrip failed: {e}")
        return False


async def test_spending_tracker() -> bool:
    """Verify spending tracker."""
    try:
        from a2a_settlement_auth import SpendingTracker, SpendingLimit

        tracker = SpendingTracker()
        limits = SpendingLimit(per_transaction=50, per_day=200)

        result = await tracker.check("smoke-jti", 30, limits)
        if not result.allowed:
            print(f"Spending tracker check failed: {result.reason}")
            return False

        await tracker.record("smoke-jti", 30, "escrow-smoke", "counterparty-smoke")
        print("Spending tracker: OK")
        return True
    except Exception as e:
        print(f"Spending tracker failed: {e}")
        return False


def run_end_to_end_example() -> bool:
    """Run the full end-to-end example."""
    try:
        root = os.path.dirname(os.path.abspath(__file__))
        print("\n--- Running end-to-end example ---")
        result = subprocess.run(
            [sys.executable, "examples/end_to_end.py"],
            capture_output=True,
            text=True,
            cwd=root,
        )
        if result.returncode != 0:
            print(f"End-to-end example failed:\n{result.stderr}")
            return False
        print("End-to-end example: OK")
        return True
    except Exception as e:
        print(f"End-to-end example failed: {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test for a2a-settlement-auth")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Also run the full end-to-end example",
    )
    args = parser.parse_args()

    ok = True
    ok &= test_imports()
    ok &= test_token_roundtrip()
    ok &= asyncio.run(test_spending_tracker())

    if args.full:
        ok &= run_end_to_end_example()

    if ok:
        print("\nAll smoke tests passed.")
        return 0
    print("\nSome smoke tests failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
