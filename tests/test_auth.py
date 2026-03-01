"""Tests for a2a-settlement-auth."""

import time
import pytest
import asyncio

from a2a_settlement_auth import (
    SettlementClaims,
    SettlementScope,
    SpendingLimit,
    CounterpartyPolicy,
    DelegationChain,
    DelegationLink,
    create_settlement_token,
    validate_settlement_token,
    SettlementTokenError,
    TokenExpiredError,
    InsufficientScopeError,
    SpendingLimitExceededError,
)
from a2a_settlement_auth.scopes import parse_scopes, scope_satisfies, format_scopes
from a2a_settlement_auth.spending import SpendingTracker, SpendingRecord
from a2a_settlement_auth.tokens import check_counterparty, CounterpartyDeniedError

SECRET_KEY = "test-secret-key-do-not-use-in-production"
ISSUER = "https://idp.test.example.com"
AUDIENCE = "https://exchange.a2a-settlement.org"


# ─── Scope Tests ───────────────────────────────────────────────────────────

class TestScopes:
    def test_parse_settlement_scopes(self):
        scopes = parse_scopes("openid profile settlement:transact")
        assert SettlementScope.TRANSACT in scopes
        assert SettlementScope.ESCROW_CREATE in scopes  # expanded
        assert SettlementScope.ESCROW_RELEASE in scopes
        assert SettlementScope.ESCROW_REFUND in scopes
        assert SettlementScope.READ in scopes

    def test_parse_ignores_non_settlement(self):
        scopes = parse_scopes("openid profile email")
        assert len(scopes) == 0

    def test_admin_expands_to_all(self):
        scopes = parse_scopes("settlement:admin")
        assert SettlementScope.READ in scopes
        assert SettlementScope.ESCROW_CREATE in scopes
        assert SettlementScope.DISPUTE_FILE in scopes
        assert SettlementScope.DISPUTE_RESOLVE in scopes

    def test_scope_satisfies_direct(self):
        granted = {SettlementScope.ESCROW_CREATE}
        assert scope_satisfies(granted, SettlementScope.ESCROW_CREATE) is True
        assert scope_satisfies(granted, SettlementScope.ESCROW_RELEASE) is False

    def test_scope_satisfies_via_composite(self):
        granted = {SettlementScope.TRANSACT}
        assert scope_satisfies(granted, SettlementScope.ESCROW_CREATE) is True
        assert scope_satisfies(granted, SettlementScope.DISPUTE_FILE) is False

    def test_format_scopes(self):
        scopes = {SettlementScope.READ, SettlementScope.ESCROW_CREATE}
        formatted = format_scopes(scopes)
        assert "settlement:read" in formatted
        assert "settlement:escrow:create" in formatted


# ─── Claims Tests ──────────────────────────────────────────────────────────

class TestClaims:
    def test_spending_limit_conservative(self):
        limits = SpendingLimit.conservative()
        assert limits.per_transaction == 100
        assert limits.per_day == 1000

    def test_spending_limit_roundtrip(self):
        limits = SpendingLimit(per_transaction=500, per_day=5000)
        d = limits.to_dict()
        restored = SpendingLimit.from_dict(d)
        assert restored.per_transaction == 500
        assert restored.per_day == 5000
        assert restored.per_session is None

    def test_counterparty_policy_roundtrip(self):
        policy = CounterpartyPolicy(
            allowed_categories=["analytics", "nlp"],
            blocked_agents=["bad-bot-1"],
            require_min_reputation=0.7,
        )
        d = policy.to_dict()
        restored = CounterpartyPolicy.from_dict(d)
        assert restored.allowed_categories == ["analytics", "nlp"]
        assert restored.blocked_agents == ["bad-bot-1"]
        assert restored.require_min_reputation == 0.7

    def test_delegation_chain(self):
        chain = DelegationChain(
            chain=[
                DelegationLink(
                    principal="user:jsmith@acme.com",
                    delegated_at="2026-03-01T10:00:00Z",
                    purpose="Q1 analytics",
                ),
            ],
            transferable=False,
        )
        assert chain.human_principal == "user:jsmith@acme.com"
        assert chain.transferable is False

        d = chain.to_dict()
        restored = DelegationChain.from_dict(d)
        assert restored.human_principal == "user:jsmith@acme.com"

    def test_settlement_claims_full_roundtrip(self):
        claims = SettlementClaims(
            agent_id="bot-7f3a",
            org_id="org-acme",
            spending_limits=SpendingLimit(per_transaction=500, per_day=5000),
            counterparty_policy=CounterpartyPolicy(
                allowed_categories=["analytics"],
                require_min_reputation=0.6,
            ),
            settlement_methods=["token", "fiat"],
            environment="production",
            certification_id="cert-abc-123",
            delegation=DelegationChain(
                chain=[
                    DelegationLink(
                        principal="user:admin@acme.com",
                        delegated_at="2026-03-01T00:00:00Z",
                    )
                ],
                transferable=False,
            ),
        )
        jwt_claims = claims.to_jwt_claims()
        assert "https://a2a-settlement.org/claims" in jwt_claims

        restored = SettlementClaims.from_jwt_claims(jwt_claims)
        assert restored is not None
        assert restored.agent_id == "bot-7f3a"
        assert restored.spending_limits.per_transaction == 500
        assert restored.counterparty_policy.require_min_reputation == 0.6
        assert restored.certification_id == "cert-abc-123"
        assert restored.delegation.human_principal == "user:admin@acme.com"

    def test_from_jwt_claims_returns_none_when_missing(self):
        assert SettlementClaims.from_jwt_claims({"sub": "test"}) is None


# ─── Token Tests ───────────────────────────────────────────────────────────

class TestTokens:
    def _make_claims(self, **kwargs):
        defaults = dict(agent_id="test-bot", org_id="org-test")
        defaults.update(kwargs)
        return SettlementClaims(**defaults)

    def test_create_and_validate(self):
        claims = self._make_claims()
        token = create_settlement_token(
            claims=claims,
            scopes={SettlementScope.TRANSACT},
            signing_key=SECRET_KEY,
            issuer=ISSUER,
            audience=AUDIENCE,
        )
        validated = validate_settlement_token(
            token=token,
            verification_key=SECRET_KEY,
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        assert validated.settlement_claims.agent_id == "test-bot"
        assert validated.subject == "agent:test-bot"
        assert SettlementScope.TRANSACT in validated.scopes

    def test_expired_token_raises(self):
        claims = self._make_claims()
        token = create_settlement_token(
            claims=claims,
            scopes={SettlementScope.READ},
            signing_key=SECRET_KEY,
            issuer=ISSUER,
            expires_in=-1,  # Already expired
        )
        with pytest.raises(TokenExpiredError):
            validate_settlement_token(token, SECRET_KEY, audience=AUDIENCE)

    def test_wrong_key_raises(self):
        claims = self._make_claims()
        token = create_settlement_token(
            claims=claims,
            scopes={SettlementScope.READ},
            signing_key=SECRET_KEY,
            issuer=ISSUER,
        )
        with pytest.raises(SettlementTokenError):
            validate_settlement_token(token, "wrong-key", audience=AUDIENCE)

    def test_require_scopes_enforced(self):
        claims = self._make_claims()
        token = create_settlement_token(
            claims=claims,
            scopes={SettlementScope.READ},
            signing_key=SECRET_KEY,
            issuer=ISSUER,
        )
        # Should pass — READ is granted
        validate_settlement_token(
            token, SECRET_KEY,
            audience=AUDIENCE,
            require_scopes={SettlementScope.READ},
        )
        # Should fail — ESCROW_CREATE not granted
        with pytest.raises(InsufficientScopeError):
            validate_settlement_token(
                token, SECRET_KEY,
                audience=AUDIENCE,
                require_scopes={SettlementScope.ESCROW_CREATE},
            )


# ─── Counterparty Policy Tests ────────────────────────────────────────────

class TestCounterpartyPolicy:
    def _make_claims(self, **policy_kwargs):
        return SettlementClaims(
            agent_id="test-bot",
            org_id="org-test",
            counterparty_policy=CounterpartyPolicy(**policy_kwargs),
        )

    def test_blocked_agent_denied(self):
        claims = self._make_claims(blocked_agents=["bad-bot"])
        with pytest.raises(CounterpartyDeniedError, match="blocked agents"):
            check_counterparty(claims, "bad-bot")

    def test_blocked_org_denied(self):
        claims = self._make_claims(blocked_orgs=["evil-corp"])
        with pytest.raises(CounterpartyDeniedError, match="blocked organizations"):
            check_counterparty(claims, "some-bot", counterparty_org="evil-corp")

    def test_category_mismatch_denied(self):
        claims = self._make_claims(allowed_categories=["analytics"])
        with pytest.raises(CounterpartyDeniedError, match="not in allowed"):
            check_counterparty(
                claims, "nlp-bot", counterparty_categories=["translation"]
            )

    def test_category_match_allowed(self):
        claims = self._make_claims(allowed_categories=["analytics", "nlp"])
        # Should not raise
        check_counterparty(
            claims, "nlp-bot", counterparty_categories=["nlp", "text"]
        )

    def test_reputation_floor_enforced(self):
        claims = self._make_claims(require_min_reputation=0.7)
        with pytest.raises(CounterpartyDeniedError, match="below minimum"):
            check_counterparty(claims, "sketchy-bot", counterparty_reputation=0.5)

    def test_reputation_above_floor_allowed(self):
        claims = self._make_claims(require_min_reputation=0.7)
        check_counterparty(claims, "good-bot", counterparty_reputation=0.85)

    def test_certification_required(self):
        claims = self._make_claims(require_certified=True)
        with pytest.raises(CounterpartyDeniedError, match="not certified"):
            check_counterparty(claims, "uncertified-bot", counterparty_certified=False)


# ─── Spending Tracker Tests ───────────────────────────────────────────────

class TestSpendingTracker:
    @pytest.fixture
    def tracker(self):
        return SpendingTracker()

    @pytest.mark.asyncio
    async def test_within_limits(self, tracker):
        limits = SpendingLimit(per_transaction=100, per_day=500)
        result = await tracker.check("token-1", 50, limits)
        assert result.allowed is True
        assert result.remaining_per_transaction == 50

    @pytest.mark.asyncio
    async def test_exceeds_per_transaction(self, tracker):
        limits = SpendingLimit(per_transaction=100)
        result = await tracker.check("token-1", 150, limits)
        assert result.allowed is False
        assert "per-transaction" in result.reason

    @pytest.mark.asyncio
    async def test_cumulative_daily_limit(self, tracker):
        limits = SpendingLimit(per_transaction=100, per_day=200)

        # First spend: OK
        result = await tracker.check("token-1", 80, limits)
        assert result.allowed is True
        await tracker.record("token-1", 80, "escrow-1", "counterparty-1")

        # Second spend: OK
        result = await tracker.check("token-1", 80, limits)
        assert result.allowed is True
        await tracker.record("token-1", 80, "escrow-2", "counterparty-2")

        # Third spend: exceeds daily limit
        result = await tracker.check("token-1", 80, limits)
        assert result.allowed is False
        assert "per-day" in result.reason

    @pytest.mark.asyncio
    async def test_session_limit(self, tracker):
        limits = SpendingLimit(per_transaction=100, per_session=150)

        await tracker.record("token-1", 100, "escrow-1", "cp-1")
        result = await tracker.check("token-1", 60, limits)
        assert result.allowed is False
        assert "per-session" in result.reason

    @pytest.mark.asyncio
    async def test_revocation(self, tracker):
        limits = SpendingLimit(per_transaction=1000)

        # Before revocation: OK
        result = await tracker.check("token-1", 10, limits)
        assert result.allowed is True

        # Revoke
        await tracker.revoke("token-1")

        # After revocation: denied
        result = await tracker.check("token-1", 10, limits)
        assert result.allowed is False
        assert "revoked" in result.reason

    @pytest.mark.asyncio
    async def test_summary(self, tracker):
        limits = SpendingLimit(per_transaction=100, per_day=500, per_session=1000)
        await tracker.record("token-1", 50, "e-1", "cp-1")
        await tracker.record("token-1", 75, "e-2", "cp-2")

        summary = await tracker.get_summary("token-1", limits)
        assert summary["spent_session"] == 125
        assert summary["remaining"]["per_day"] == 375
        assert summary["revoked"] is False
