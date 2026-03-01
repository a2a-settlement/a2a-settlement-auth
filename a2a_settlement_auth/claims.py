"""
Settlement Claims — JWT claim structures for agent economic authorization.

Defines the `settlement` claim namespace that OAuth tokens carry to express
economic authorization constraints: spending limits, counterparty policies,
settlement method restrictions, and delegation chains.

These claims sit alongside standard OAuth/OIDC claims (sub, iss, aud, exp)
and are namespaced under `https://a2a-settlement.org/claims` to avoid
collision with other claim types per RFC 7519 Section 4.2.

Example JWT payload:
    {
        "sub": "agent:analytics-bot-7f3a",
        "iss": "https://idp.example.com",
        "aud": "https://exchange.a2a-settlement.org",
        "exp": 1740000000,
        "scope": "settlement:transact",
        "https://a2a-settlement.org/claims": {
            "agent_id": "analytics-bot-7f3a",
            "org_id": "org-acme-corp",
            "spending_limits": {
                "per_transaction": 500,
                "per_session": 2000,
                "per_day": 10000
            },
            "counterparty_policy": {
                "allowed_categories": ["analytics", "nlp", "translation"],
                "blocked_agents": [],
                "require_min_reputation": 0.7
            },
            "settlement_methods": ["token"],
            "delegation": {
                "principal": "user:jsmith@acme.com",
                "delegated_at": "2026-03-01T10:00:00Z",
                "purpose": "Q1 analytics procurement",
                "transferable": false
            }
        }
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

# Namespaced claim key per RFC 7519 Section 4.2
CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"


@dataclass
class SpendingLimit:
    """Economic authorization bounds for an agent's settlement activity.

    All values are in the exchange's token denomination (ATE by default).
    A value of None means no limit is imposed for that dimension.
    """

    per_transaction: Optional[float] = None
    """Maximum tokens per individual escrow/settlement."""

    per_session: Optional[float] = None
    """Maximum cumulative tokens for the lifetime of this token."""

    per_day: Optional[float] = None
    """Maximum cumulative tokens in a rolling 24-hour window."""

    per_hour: Optional[float] = None
    """Maximum cumulative tokens in a rolling 1-hour window."""

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> SpendingLimit:
        return cls(
            per_transaction=data.get("per_transaction"),
            per_session=data.get("per_session"),
            per_day=data.get("per_day"),
            per_hour=data.get("per_hour"),
        )

    @classmethod
    def unrestricted(cls) -> SpendingLimit:
        """No spending limits. Use with caution — typically only for admin."""
        return cls()

    @classmethod
    def conservative(cls) -> SpendingLimit:
        """Restrictive defaults for newly deployed agents."""
        return cls(
            per_transaction=100,
            per_session=500,
            per_day=1000,
            per_hour=250,
        )


@dataclass
class CounterpartyPolicy:
    """Constraints on which agents this agent is authorized to transact with.

    Policies are evaluated in order: blocked_agents first (deny list),
    then allowed_categories (allow list), then reputation floor.
    """

    allowed_categories: list[str] = field(default_factory=list)
    """If non-empty, only transact with agents in these skill categories."""

    blocked_agents: list[str] = field(default_factory=list)
    """Agent IDs this agent is explicitly forbidden from transacting with."""

    blocked_orgs: list[str] = field(default_factory=list)
    """Organization IDs this agent is forbidden from transacting with."""

    require_min_reputation: Optional[float] = None
    """Minimum reputation score (0.0–1.0) required for counterparties."""

    require_certified: bool = False
    """If True, only transact with agents that hold a valid certification."""

    def to_dict(self) -> dict:
        result = {}
        if self.allowed_categories:
            result["allowed_categories"] = self.allowed_categories
        if self.blocked_agents:
            result["blocked_agents"] = self.blocked_agents
        if self.blocked_orgs:
            result["blocked_orgs"] = self.blocked_orgs
        if self.require_min_reputation is not None:
            result["require_min_reputation"] = self.require_min_reputation
        if self.require_certified:
            result["require_certified"] = True
        return result

    @classmethod
    def from_dict(cls, data: dict) -> CounterpartyPolicy:
        return cls(
            allowed_categories=data.get("allowed_categories", []),
            blocked_agents=data.get("blocked_agents", []),
            blocked_orgs=data.get("blocked_orgs", []),
            require_min_reputation=data.get("require_min_reputation"),
            require_certified=data.get("require_certified", False),
        )


@dataclass
class DelegationLink:
    """A single link in the delegation chain from human to agent."""

    principal: str
    """Identity of the delegator (e.g., 'user:jsmith@acme.com' or 'agent:coordinator-9x')."""

    delegated_at: str
    """ISO 8601 timestamp of when delegation was granted."""

    purpose: Optional[str] = None
    """Human-readable description of why authority was delegated."""

    def to_dict(self) -> dict:
        result = {"principal": self.principal, "delegated_at": self.delegated_at}
        if self.purpose:
            result["purpose"] = self.purpose
        return result

    @classmethod
    def from_dict(cls, data: dict) -> DelegationLink:
        return cls(
            principal=data["principal"],
            delegated_at=data["delegated_at"],
            purpose=data.get("purpose"),
        )


@dataclass
class DelegationChain:
    """Complete delegation chain from human principal to agent.

    Establishes non-repudiation: every economic action by the agent
    can be traced back to the human who authorized it through a
    cryptographically verifiable chain.

    The chain is ordered from the original human principal (index 0)
    to the most recent delegator (last index). The agent holding
    this token is the final delegate.
    """

    chain: list[DelegationLink] = field(default_factory=list)
    """Ordered list of delegation links."""

    transferable: bool = False
    """If False, this agent cannot sub-delegate its economic authority."""

    def to_dict(self) -> dict:
        return {
            "chain": [link.to_dict() for link in self.chain],
            "transferable": self.transferable,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DelegationChain:
        return cls(
            chain=[DelegationLink.from_dict(link) for link in data.get("chain", [])],
            transferable=data.get("transferable", False),
        )

    @property
    def human_principal(self) -> Optional[str]:
        """The originating human identity, if present."""
        if self.chain:
            return self.chain[0].principal
        return None


@dataclass
class SettlementClaims:
    """Complete settlement claims payload for an OAuth token.

    This is the content of the `https://a2a-settlement.org/claims`
    claim in the JWT.
    """

    agent_id: str
    """The agent's identifier on the settlement exchange."""

    org_id: str
    """The organization that owns/operates this agent."""

    spending_limits: SpendingLimit = field(default_factory=SpendingLimit.conservative)
    """Economic authorization bounds."""

    counterparty_policy: CounterpartyPolicy = field(default_factory=CounterpartyPolicy)
    """Constraints on permitted counterparties."""

    settlement_methods: list[str] = field(default_factory=lambda: ["token"])
    """Permitted settlement methods (e.g., 'token', 'fiat', 'credit')."""

    delegation: Optional[DelegationChain] = None
    """Delegation chain from human principal to this agent."""

    parent_jti: Optional[str] = None
    """JTI of the delegating parent's token. Creates a tree for hierarchical delegation."""

    environment: Optional[str] = None
    """Deployment environment classification (e.g., 'production', 'sandbox', 'classified')."""

    certification_id: Optional[str] = None
    """Reference to this agent's certification/ATO record, if certified."""

    def to_dict(self) -> dict:
        """Serialize to a dict suitable for JWT claim embedding."""
        result: dict = {
            "agent_id": self.agent_id,
            "org_id": self.org_id,
            "spending_limits": self.spending_limits.to_dict(),
            "settlement_methods": self.settlement_methods,
        }
        cp = self.counterparty_policy.to_dict()
        if cp:
            result["counterparty_policy"] = cp
        if self.delegation:
            result["delegation"] = self.delegation.to_dict()
        if self.parent_jti:
            result["parent_jti"] = self.parent_jti
        if self.environment:
            result["environment"] = self.environment
        if self.certification_id:
            result["certification_id"] = self.certification_id
        return result

    @classmethod
    def from_dict(cls, data: dict) -> SettlementClaims:
        """Deserialize from a JWT claims dict."""
        return cls(
            agent_id=data["agent_id"],
            org_id=data["org_id"],
            spending_limits=SpendingLimit.from_dict(
                data.get("spending_limits", {})
            ),
            counterparty_policy=CounterpartyPolicy.from_dict(
                data.get("counterparty_policy", {})
            ),
            settlement_methods=data.get("settlement_methods", ["token"]),
            delegation=(
                DelegationChain.from_dict(data["delegation"])
                if "delegation" in data
                else None
            ),
            parent_jti=data.get("parent_jti"),
            environment=data.get("environment"),
            certification_id=data.get("certification_id"),
        )

    def to_jwt_claims(self) -> dict:
        """Wrap in the namespaced claim key for JWT embedding."""
        return {CLAIMS_NAMESPACE: self.to_dict()}

    @classmethod
    def from_jwt_claims(cls, jwt_payload: dict) -> Optional[SettlementClaims]:
        """Extract settlement claims from a decoded JWT payload.

        Returns None if the JWT does not contain settlement claims.
        """
        data = jwt_payload.get(CLAIMS_NAMESPACE)
        if data is None:
            return None
        return cls.from_dict(data)
