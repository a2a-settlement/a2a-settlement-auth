"""
Token Utilities — Create and validate OAuth tokens with settlement claims.

Provides functions for:
- Creating settlement-scoped JWTs (for IdP integration and testing)
- Validating settlement tokens against JWKS endpoints
- Extracting and verifying settlement claims from tokens

Supports both symmetric (HMAC) and asymmetric (RSA/EC) signing.
Production deployments should use asymmetric keys with JWKS discovery.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

import jwt as pyjwt

from .claims import (
    SettlementClaims,
    SpendingLimit,
    CounterpartyPolicy,
    DelegationChain,
    DelegationLink,
    CLAIMS_NAMESPACE,
)
from .scopes import SettlementScope, parse_scopes, format_scopes

if TYPE_CHECKING:
    from .spending import SpendingTracker


# ─── Exceptions ────────────────────────────────────────────────────────────

class SettlementTokenError(Exception):
    """Base exception for settlement token errors."""

    pass


class TokenExpiredError(SettlementTokenError):
    """Token has expired."""

    pass


class InsufficientScopeError(SettlementTokenError):
    """Token does not have the required settlement scope."""

    def __init__(self, required: SettlementScope, granted: set[SettlementScope]):
        self.required = required
        self.granted = granted
        super().__init__(
            f"Required scope '{required.value}' not in granted scopes: "
            f"{format_scopes(granted)}"
        )


class SpendingLimitExceededError(SettlementTokenError):
    """Proposed transaction exceeds the token's spending limits."""

    pass


class CounterpartyDeniedError(SettlementTokenError):
    """Counterparty is not permitted by the token's counterparty policy."""

    pass


class DelegationViolationError(SettlementTokenError):
    """Agent attempted to sub-delegate non-transferable authority."""

    pass


# ─── Token Data ────────────────────────────────────────────────────────────

@dataclass
class ValidatedToken:
    """Result of successful token validation.

    Contains the decoded JWT payload, extracted settlement claims,
    and parsed scopes for use by the middleware and spending tracker.
    """

    payload: dict
    """Full decoded JWT payload."""

    settlement_claims: SettlementClaims
    """Extracted and parsed settlement claims."""

    scopes: set[SettlementScope]
    """Parsed settlement scopes from the token."""

    jti: str
    """Token identifier (for spending tracking)."""

    subject: str
    """Token subject (agent identity)."""

    issuer: str
    """Token issuer (identity provider)."""

    expires_at: float
    """Token expiration as Unix timestamp."""


# ─── Token Creation ───────────────────────────────────────────────────────

def create_settlement_token(
    claims: SettlementClaims,
    scopes: set[SettlementScope],
    signing_key: str | bytes,
    issuer: str,
    audience: str = "https://exchange.a2a-settlement.org",
    expires_in: int = 3600,
    algorithm: str = "HS256",
    additional_claims: Optional[dict] = None,
) -> str:
    """Create a signed JWT with settlement claims and scopes.

    This function is used by identity providers to issue settlement-scoped
    tokens, and by test/demo code to generate tokens for development.

    Args:
        claims: Settlement claims defining economic authorization.
        scopes: Set of settlement scopes to grant.
        signing_key: Key for signing (secret for HMAC, private key for RSA/EC).
        issuer: Token issuer URI (the identity provider).
        audience: Token audience (the settlement exchange).
        expires_in: Token lifetime in seconds.
        algorithm: JWT signing algorithm.
        additional_claims: Extra claims to include (e.g., standard OIDC claims).

    Returns:
        Encoded JWT string.

    Example:
        token = create_settlement_token(
            claims=SettlementClaims(
                agent_id="bot-7f3a",
                org_id="org-acme",
                spending_limits=SpendingLimit(per_transaction=500, per_day=5000),
            ),
            scopes={SettlementScope.TRANSACT},
            signing_key="your-secret-key",
            issuer="https://idp.acme.com",
        )
    """
    now = time.time()
    jti = str(uuid.uuid4())

    payload = {
        "sub": f"agent:{claims.agent_id}",
        "iss": issuer,
        "aud": audience,
        "iat": int(now),
        "exp": int(now + expires_in),
        "jti": jti,
        "scope": format_scopes(scopes),
        CLAIMS_NAMESPACE: claims.to_dict(),
    }

    if additional_claims:
        payload.update(additional_claims)

    return pyjwt.encode(payload, signing_key, algorithm=algorithm)


def create_delegated_token(
    parent: ValidatedToken,
    child_agent_id: str,
    child_limits: SpendingLimit,
    signing_key: str | bytes,
    issuer: str,
    audience: str = "https://exchange.a2a-settlement.org",
    expires_in: int = 3600,
    algorithm: str = "HS256",
    child_counterparty_policy: Optional[CounterpartyPolicy] = None,
    purpose: Optional[str] = None,
    transferable: bool = False,
) -> tuple[str, str]:
    """Create a delegated token for a sub-agent with carved-out spending limits.

    The parent must have transferable=True. Child limits can only narrow,
    never expand, the parent's limits. The sum of delegated allocations
    cannot exceed the parent's limit per dimension.

    Args:
        parent: The delegating agent's validated token.
        child_agent_id: The sub-agent's identifier.
        child_limits: Spending limits for the child (must be <= parent per dimension).
        signing_key: Key for signing the new token.
        issuer: Issuer for the delegated token (typically the exchange).
        audience: Token audience.
        expires_in: Token lifetime in seconds.
        algorithm: JWT signing algorithm.
        child_counterparty_policy: Optional counterparty policy for the child.
        purpose: Optional purpose for the delegation link.
        transferable: Whether the child can sub-delegate (default False).

    Returns:
        Tuple of (token_string, child_jti). Caller must call
        tracker.allocate_delegation(parent.jti, child_jti, child_limits)
        to reserve budget from the parent. Use create_delegated_token_async
        for atomic creation with allocation.

    Raises:
        DelegationViolationError: Parent cannot sub-delegate.
        ValueError: Child limits exceed parent or parent's remaining budget.
    """
    if parent.settlement_claims.delegation is None:
        raise DelegationViolationError(
            "Parent token has no delegation chain; cannot sub-delegate"
        )
    if not parent.settlement_claims.delegation.transferable:
        raise DelegationViolationError(
            "Parent token does not allow sub-delegation (transferable=False)"
        )

    parent_limits = parent.settlement_claims.spending_limits

    # Validate child limits <= parent per dimension (when parent has a limit)
    if parent_limits.per_transaction is not None:
        c = child_limits.per_transaction
        if c is None or c > parent_limits.per_transaction:
            raise DelegationViolationError(
                f"Child per_transaction {c} exceeds "
                f"parent limit {parent_limits.per_transaction}"
            )
    if parent_limits.per_session is not None:
        c = child_limits.per_session
        if c is None or c > parent_limits.per_session:
            raise DelegationViolationError(
                f"Child per_session {c} exceeds "
                f"parent limit {parent_limits.per_session}"
            )
    if parent_limits.per_hour is not None:
        c = child_limits.per_hour
        if c is None or c > parent_limits.per_hour:
            raise DelegationViolationError(
                f"Child per_hour {c} exceeds "
                f"parent limit {parent_limits.per_hour}"
            )
    if parent_limits.per_day is not None:
        c = child_limits.per_day
        if c is None or c > parent_limits.per_day:
            raise DelegationViolationError(
                f"Child per_day {c} exceeds "
                f"parent limit {parent_limits.per_day}"
            )

    # Build extended delegation chain
    new_link = DelegationLink(
        principal=f"agent:{parent.settlement_claims.agent_id}",
        delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        purpose=purpose,
    )
    parent_chain = parent.settlement_claims.delegation.chain
    child_chain = DelegationChain(
        chain=parent_chain + [new_link],
        transferable=transferable,
    )

    child_claims = SettlementClaims(
        agent_id=child_agent_id,
        org_id=parent.settlement_claims.org_id,
        spending_limits=child_limits,
        counterparty_policy=child_counterparty_policy or parent.settlement_claims.counterparty_policy,
        settlement_methods=parent.settlement_claims.settlement_methods,
        delegation=child_chain,
        parent_jti=parent.jti,
        environment=parent.settlement_claims.environment,
        certification_id=parent.settlement_claims.certification_id,
    )

    token = create_settlement_token(
        claims=child_claims,
        scopes=parent.scopes,
        signing_key=signing_key,
        issuer=issuer,
        audience=audience,
        expires_in=expires_in,
        algorithm=algorithm,
    )

    # Extract child jti from the token (decode without audience verification)
    payload = pyjwt.decode(
        token, signing_key, algorithms=[algorithm], options={"verify_aud": False}
    )
    child_jti = payload.get("jti", "unknown")

    return (token, child_jti)


async def create_delegated_token_async(
    parent: ValidatedToken,
    child_agent_id: str,
    child_limits: SpendingLimit,
    signing_key: str | bytes,
    issuer: str,
    spending_tracker: "SpendingTracker",
    audience: str = "https://exchange.a2a-settlement.org",
    expires_in: int = 3600,
    algorithm: str = "HS256",
    child_counterparty_policy: Optional[CounterpartyPolicy] = None,
    purpose: Optional[str] = None,
    transferable: bool = False,
) -> tuple[str, str]:
    """Async version that validates budget and allocates delegation atomically.

    Use this when you have a SpendingTracker and want the allocation
    to be recorded automatically.
    """
    await spending_tracker.validate_delegation_budget(
        parent.jti, parent.settlement_claims.spending_limits, child_limits
    )
    token, child_jti = create_delegated_token(
        parent=parent,
        child_agent_id=child_agent_id,
        child_limits=child_limits,
        signing_key=signing_key,
        issuer=issuer,
        audience=audience,
        expires_in=expires_in,
        algorithm=algorithm,
        child_counterparty_policy=child_counterparty_policy,
        purpose=purpose,
        transferable=transferable,
    )
    # Re-extract jti from token (decode without audience verification)
    payload = pyjwt.decode(
        token, signing_key, algorithms=[algorithm], options={"verify_aud": False}
    )
    child_jti = payload.get("jti", "unknown")
    await spending_tracker.allocate_delegation(parent.jti, child_jti, child_limits)
    return (token, child_jti)

def validate_settlement_token(
    token: str,
    verification_key: str | bytes,
    audience: str = "https://exchange.a2a-settlement.org",
    issuer: Optional[str] = None,
    algorithms: list[str] | None = None,
    require_scopes: Optional[set[SettlementScope]] = None,
) -> ValidatedToken:
    """Validate a settlement JWT and extract claims.

    Performs the following checks:
    1. Signature verification
    2. Expiration check
    3. Audience and issuer verification (if provided)
    4. Settlement claims extraction and parsing
    5. Scope sufficiency check (if required scopes specified)

    Args:
        token: The encoded JWT string.
        verification_key: Key for verification (secret for HMAC, public key for RSA/EC).
        audience: Expected audience claim.
        issuer: Expected issuer claim (if None, any issuer accepted).
        algorithms: Accepted signing algorithms.
        require_scopes: If provided, verify the token has these scopes.

    Returns:
        ValidatedToken with decoded payload, claims, and scopes.

    Raises:
        TokenExpiredError: Token has expired.
        InsufficientScopeError: Token lacks required scopes.
        SettlementTokenError: Token is invalid (bad signature, missing claims, etc.)
    """
    if algorithms is None:
        algorithms = ["HS256", "RS256", "ES256"]

    # Decode and verify signature + expiration
    try:
        decode_options = {}
        decode_kwargs: dict = {
            "algorithms": algorithms,
            "audience": audience,
            "options": decode_options,
        }
        if issuer:
            decode_kwargs["issuer"] = issuer

        payload = pyjwt.decode(token, verification_key, **decode_kwargs)

    except pyjwt.ExpiredSignatureError:
        raise TokenExpiredError("Settlement token has expired")
    except pyjwt.InvalidTokenError as e:
        raise SettlementTokenError(f"Invalid settlement token: {e}")

    # Extract settlement claims
    settlement_data = payload.get(CLAIMS_NAMESPACE)
    if settlement_data is None:
        raise SettlementTokenError(
            "Token does not contain settlement claims "
            f"(missing '{CLAIMS_NAMESPACE}' claim)"
        )

    try:
        settlement_claims = SettlementClaims.from_dict(settlement_data)
    except (KeyError, TypeError, ValueError) as e:
        raise SettlementTokenError(f"Invalid settlement claims structure: {e}")

    # Parse scopes
    scope_string = payload.get("scope", "")
    scopes = parse_scopes(scope_string)

    # Check required scopes
    if require_scopes:
        from .scopes import scope_satisfies
        for required in require_scopes:
            if not scope_satisfies(scopes, required):
                raise InsufficientScopeError(required, scopes)

    # Build result
    return ValidatedToken(
        payload=payload,
        settlement_claims=settlement_claims,
        scopes=scopes,
        jti=payload.get("jti", "unknown"),
        subject=payload.get("sub", "unknown"),
        issuer=payload.get("iss", "unknown"),
        expires_at=payload.get("exp", 0),
    )


def check_counterparty(
    claims: SettlementClaims,
    counterparty_id: str,
    counterparty_org: Optional[str] = None,
    counterparty_categories: Optional[list[str]] = None,
    counterparty_reputation: Optional[float] = None,
    counterparty_certified: bool = False,
) -> None:
    """Verify a proposed counterparty against the token's counterparty policy.

    Args:
        claims: The agent's settlement claims.
        counterparty_id: The counterparty agent's ID.
        counterparty_org: The counterparty's organization ID.
        counterparty_categories: The counterparty's skill categories.
        counterparty_reputation: The counterparty's reputation score.
        counterparty_certified: Whether the counterparty is certified.

    Raises:
        CounterpartyDeniedError: Counterparty is not permitted.
    """
    policy = claims.counterparty_policy

    # Check block lists
    if counterparty_id in policy.blocked_agents:
        raise CounterpartyDeniedError(
            f"Agent '{counterparty_id}' is on the blocked agents list"
        )

    if counterparty_org and counterparty_org in policy.blocked_orgs:
        raise CounterpartyDeniedError(
            f"Organization '{counterparty_org}' is on the blocked organizations list"
        )

    # Check category allowlist
    if policy.allowed_categories and counterparty_categories:
        overlap = set(policy.allowed_categories) & set(counterparty_categories)
        if not overlap:
            raise CounterpartyDeniedError(
                f"Counterparty categories {counterparty_categories} not in "
                f"allowed categories {policy.allowed_categories}"
            )

    # Check reputation floor
    if policy.require_min_reputation is not None:
        if counterparty_reputation is None:
            raise CounterpartyDeniedError(
                "Counterparty reputation score is required but not provided"
            )
        if counterparty_reputation < policy.require_min_reputation:
            raise CounterpartyDeniedError(
                f"Counterparty reputation {counterparty_reputation:.2f} is below "
                f"minimum required {policy.require_min_reputation:.2f}"
            )

    # Check certification
    if policy.require_certified and not counterparty_certified:
        raise CounterpartyDeniedError(
            "Counterparty is not certified (certification required by policy)"
        )
