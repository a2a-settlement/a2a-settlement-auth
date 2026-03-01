"""
End-to-end example: OAuth settlement scopes with A2A-SE.

This example demonstrates:
1. An identity provider issuing a settlement-scoped token to an agent
2. The agent using that token to create an escrow on the exchange
3. The middleware validating scopes, spending limits, and counterparty policy
4. The spending tracker enforcing cumulative limits across transactions

Run:
    pip install a2a-settlement-auth
    python examples/end_to_end.py
"""

import asyncio
import json

from a2a_settlement_auth import (
    # Claims
    SettlementClaims,
    SpendingLimit,
    CounterpartyPolicy,
    DelegationChain,
    DelegationLink,
    # Scopes
    SettlementScope,
    # Tokens
    create_settlement_token,
    validate_settlement_token,
    # Spending
    SpendingTracker,
)
from a2a_settlement_auth.tokens import check_counterparty, CounterpartyDeniedError
from a2a_settlement_auth.scopes import parse_scopes, scope_satisfies

# ─── Configuration ─────────────────────────────────────────────────────────
# In production, use asymmetric keys (RS256/ES256) with JWKS discovery.
# This example uses a symmetric key for simplicity.

SECRET_KEY = "demo-secret-key-replace-in-production"
ISSUER = "https://idp.acme-corp.example.com"
EXCHANGE = "https://exchange.a2a-settlement.org"


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


async def main():
    # ─── Step 1: Identity Provider Issues a Settlement Token ───────────

    section("Step 1: IdP Issues Settlement-Scoped Token")

    # The human principal (Julie from procurement) delegates economic
    # authority to the analytics-procurement agent
    claims = SettlementClaims(
        agent_id="analytics-proc-bot-7f3a",
        org_id="org-acme-corp",
        spending_limits=SpendingLimit(
            per_transaction=500,    # Max 500 tokens per escrow
            per_session=2000,       # Max 2000 tokens for this token's lifetime
            per_day=5000,           # Max 5000 tokens in rolling 24h
            per_hour=1000,          # Max 1000 tokens in rolling 1h
        ),
        counterparty_policy=CounterpartyPolicy(
            allowed_categories=["analytics", "nlp", "data-science"],
            blocked_agents=["known-bad-bot-xyz"],
            require_min_reputation=0.7,
            require_certified=False,
        ),
        settlement_methods=["token"],
        environment="production",
        delegation=DelegationChain(
            chain=[
                DelegationLink(
                    principal="user:julie.smith@acme-corp.com",
                    delegated_at="2026-03-01T09:00:00Z",
                    purpose="Q1 analytics vendor procurement",
                ),
            ],
            transferable=False,  # Agent cannot sub-delegate
        ),
    )

    token = create_settlement_token(
        claims=claims,
        scopes={SettlementScope.TRANSACT},  # Can create, release, and refund
        signing_key=SECRET_KEY,
        issuer=ISSUER,
        audience=EXCHANGE,
        expires_in=3600,  # 1 hour
    )

    print(f"Token issued for agent: {claims.agent_id}")
    print(f"Delegated by: {claims.delegation.human_principal}")
    print(f"Spending limit (per tx): {claims.spending_limits.per_transaction}")
    print(f"Spending limit (daily): {claims.spending_limits.per_day}")
    print(f"Allowed categories: {claims.counterparty_policy.allowed_categories}")
    print(f"Token length: {len(token)} chars")

    # ─── Step 2: Agent Presents Token to Exchange ──────────────────────

    section("Step 2: Exchange Validates Token")

    validated = validate_settlement_token(
        token=token,
        verification_key=SECRET_KEY,
        audience=EXCHANGE,
        issuer=ISSUER,
    )

    print(f"Token validated successfully")
    print(f"Subject: {validated.subject}")
    print(f"Issuer: {validated.issuer}")
    print(f"Scopes: {[s.value for s in validated.scopes]}")
    print(f"Agent ID: {validated.settlement_claims.agent_id}")
    print(f"Org ID: {validated.settlement_claims.org_id}")

    # ─── Step 3: Scope Check for Escrow Creation ───────────────────────

    section("Step 3: Scope Check")

    can_create = scope_satisfies(validated.scopes, SettlementScope.ESCROW_CREATE)
    can_dispute = scope_satisfies(validated.scopes, SettlementScope.DISPUTE_RESOLVE)
    print(f"Can create escrow: {can_create}")    # True (TRANSACT includes it)
    print(f"Can resolve disputes: {can_dispute}") # False (TRANSACT doesn't include it)

    # ─── Step 4: Counterparty Policy Check ─────────────────────────────

    section("Step 4: Counterparty Policy Checks")

    # Good counterparty
    print("Checking 'analytics-bot-acme' (category: analytics, rep: 0.85)...")
    try:
        check_counterparty(
            validated.settlement_claims,
            counterparty_id="analytics-bot-acme",
            counterparty_org="org-partner-inc",
            counterparty_categories=["analytics"],
            counterparty_reputation=0.85,
        )
        print("  ALLOWED")
    except CounterpartyDeniedError as e:
        print(f"  DENIED: {e}")

    # Blocked agent
    print("Checking 'known-bad-bot-xyz'...")
    try:
        check_counterparty(
            validated.settlement_claims,
            counterparty_id="known-bad-bot-xyz",
        )
        print("  ALLOWED")
    except CounterpartyDeniedError as e:
        print(f"  DENIED: {e}")

    # Low reputation
    print("Checking 'sketchy-bot' (rep: 0.3)...")
    try:
        check_counterparty(
            validated.settlement_claims,
            counterparty_id="sketchy-bot",
            counterparty_reputation=0.3,
        )
        print("  ALLOWED")
    except CounterpartyDeniedError as e:
        print(f"  DENIED: {e}")

    # Wrong category
    print("Checking 'gaming-bot' (category: gaming)...")
    try:
        check_counterparty(
            validated.settlement_claims,
            counterparty_id="gaming-bot",
            counterparty_categories=["gaming", "entertainment"],
        )
        print("  ALLOWED")
    except CounterpartyDeniedError as e:
        print(f"  DENIED: {e}")

    # ─── Step 5: Spending Limit Enforcement ────────────────────────────

    section("Step 5: Spending Limit Enforcement")

    tracker = SpendingTracker()
    limits = validated.settlement_claims.spending_limits

    # Transaction 1: 200 tokens — within limits
    result = await tracker.check(validated.jti, 200, limits)
    print(f"Transaction 1 (200 tokens): {'ALLOWED' if result.allowed else 'DENIED'}")
    if result.allowed:
        await tracker.record(validated.jti, 200, "escrow-001", "analytics-bot-acme")
        print(f"  Remaining per-session: {result.remaining_per_session}")

    # Transaction 2: 400 tokens — within per-tx but getting close to session
    result = await tracker.check(validated.jti, 400, limits)
    print(f"Transaction 2 (400 tokens): {'ALLOWED' if result.allowed else 'DENIED'}")
    if result.allowed:
        await tracker.record(validated.jti, 400, "escrow-002", "nlp-bot-partner")
        print(f"  Remaining per-session: {result.remaining_per_session}")

    # Transaction 3: 500 tokens — per-tx OK but exceeds hourly limit
    result = await tracker.check(validated.jti, 500, limits)
    print(f"Transaction 3 (500 tokens): {'ALLOWED' if result.allowed else 'DENIED'}")
    if not result.allowed:
        print(f"  Reason: {result.reason}")

    # Transaction 4: 600 tokens — exceeds per-transaction limit
    result = await tracker.check(validated.jti, 600, limits)
    print(f"Transaction 4 (600 tokens): {'ALLOWED' if result.allowed else 'DENIED'}")
    if not result.allowed:
        print(f"  Reason: {result.reason}")

    # ─── Step 6: Spending Summary ──────────────────────────────────────

    section("Step 6: Spending Summary")

    summary = await tracker.get_summary(validated.jti, limits)
    print(f"Total spent (session): {summary['spent_session']}")
    print(f"Total spent (hour):    {summary['spent_hour']}")
    print(f"Total spent (day):     {summary['spent_day']}")
    print(f"Remaining (session):   {summary['remaining']['per_session']}")
    print(f"Remaining (hour):      {summary['remaining']['per_hour']}")
    print(f"Remaining (day):       {summary['remaining']['per_day']}")
    print(f"Revoked:               {summary['revoked']}")

    # ─── Step 7: Emergency Revocation ──────────────────────────────────

    section("Step 7: Emergency Kill Switch")

    print("Revoking token spending authority...")
    await tracker.revoke(validated.jti)

    result = await tracker.check(validated.jti, 1, limits)  # Even 1 token
    print(f"Post-revocation check (1 token): {'ALLOWED' if result.allowed else 'DENIED'}")
    print(f"  Reason: {result.reason}")

    # ─── Step 8: Delegation Chain Audit ────────────────────────────────

    section("Step 8: Delegation Chain (Non-Repudiation)")

    delegation = validated.settlement_claims.delegation
    print(f"Human principal: {delegation.human_principal}")
    print(f"Delegation chain:")
    for i, link in enumerate(delegation.chain):
        print(f"  [{i}] {link.principal}")
        print(f"      Delegated at: {link.delegated_at}")
        print(f"      Purpose: {link.purpose}")
    print(f"Sub-delegation allowed: {delegation.transferable}")
    print()
    print("Every escrow created with this token traces back to:")
    print(f"  {delegation.human_principal} -> agent:{validated.settlement_claims.agent_id}")
    print("This chain is cryptographically signed in the JWT.")


if __name__ == "__main__":
    asyncio.run(main())
