"""
Spending Tracker — Enforces cumulative spending limits for agent tokens.

Tracks per-session, per-hour, and per-day spending against the limits
declared in the token's SettlementClaims. The tracker is consulted by
the middleware before any settlement action is authorized.

The tracker uses an in-memory store by default, with an abstract base
that can be backed by Redis or a database for production deployments.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Awaitable, Optional

from .claims import SpendingLimit

logger = logging.getLogger("a2a_settlement_auth")


@dataclass
class SpendingRecord:
    """A single spending event recorded against an agent's token."""

    amount: float
    timestamp: float  # Unix epoch
    escrow_id: str
    counterparty_id: str


class SpendingStore(ABC):
    """Abstract interface for spending record persistence."""

    @abstractmethod
    async def record_spend(self, token_jti: str, record: SpendingRecord) -> None:
        """Record a spending event for a token."""
        ...

    @abstractmethod
    async def get_spending(
        self, token_jti: str, since: Optional[float] = None
    ) -> list[SpendingRecord]:
        """Get all spending records for a token, optionally filtered by time."""
        ...

    @abstractmethod
    async def get_total(
        self, token_jti: str, since: Optional[float] = None
    ) -> float:
        """Get total amount spent for a token since a given time."""
        ...

    @abstractmethod
    async def revoke(self, token_jti: str) -> None:
        """Revoke all spending authority for a token (emergency kill switch)."""
        ...

    @abstractmethod
    async def is_revoked(self, token_jti: str) -> bool:
        """Check if a token's spending authority has been revoked."""
        ...

    async def record_delegation(
        self, parent_jti: str, child_jti: str, limits: SpendingLimit
    ) -> None:
        """Record that parent allocated these limits to child (reserves budget from parent)."""
        raise NotImplementedError(
            "SpendingStore subclass must implement record_delegation for hierarchical delegation"
        )

    async def get_delegated_allocations(self, parent_jti: str) -> SpendingLimit:
        """Sum of delegated limits per dimension for all active (non-revoked) children."""
        raise NotImplementedError(
            "SpendingStore subclass must implement get_delegated_allocations for hierarchical delegation"
        )

    async def release_delegation(self, parent_jti: str, child_jti: str) -> None:
        """When child is revoked, return allocation to parent's pool."""
        raise NotImplementedError(
            "SpendingStore subclass must implement release_delegation for hierarchical delegation"
        )

    async def get_children(self, parent_jti: str) -> list[str]:
        """Return child JTIs for cascade revocation."""
        raise NotImplementedError(
            "SpendingStore subclass must implement get_children for hierarchical delegation"
        )


def _effective_limits(
    limits: SpendingLimit, delegated: SpendingLimit
) -> SpendingLimit:
    """Subtract delegated allocations from limits to get effective budget."""
    def sub(a: Optional[float], b: Optional[float]) -> Optional[float]:
        if a is None:
            return None
        return a - (b or 0)

    return SpendingLimit(
        per_transaction=sub(limits.per_transaction, delegated.per_transaction),
        per_session=sub(limits.per_session, delegated.per_session),
        per_hour=sub(limits.per_hour, delegated.per_hour),
        per_day=sub(limits.per_day, delegated.per_day),
    )


def _sum_limits(limits_list: list[SpendingLimit]) -> SpendingLimit:
    """Sum spending limits per dimension (treats None as 0)."""
    per_tx = sum(l.per_transaction or 0 for l in limits_list)
    per_sess = sum(l.per_session or 0 for l in limits_list)
    per_hr = sum(l.per_hour or 0 for l in limits_list)
    per_day = sum(l.per_day or 0 for l in limits_list)
    return SpendingLimit(
        per_transaction=per_tx if per_tx else None,
        per_session=per_sess if per_sess else None,
        per_hour=per_hr if per_hr else None,
        per_day=per_day if per_day else None,
    )


class InMemorySpendingStore(SpendingStore):
    """In-memory spending store for development and testing."""

    def __init__(self):
        self._records: dict[str, list[SpendingRecord]] = {}
        self._revoked: set[str] = set()
        # child_jti -> (parent_jti, SpendingLimit)
        self._delegations: dict[str, tuple[str, SpendingLimit]] = {}

    async def record_spend(self, token_jti: str, record: SpendingRecord) -> None:
        if token_jti not in self._records:
            self._records[token_jti] = []
        self._records[token_jti].append(record)

    async def get_spending(
        self, token_jti: str, since: Optional[float] = None
    ) -> list[SpendingRecord]:
        records = self._records.get(token_jti, [])
        if since is not None:
            records = [r for r in records if r.timestamp >= since]
        return records

    async def get_total(
        self, token_jti: str, since: Optional[float] = None
    ) -> float:
        records = await self.get_spending(token_jti, since)
        return sum(r.amount for r in records)

    async def record_delegation(
        self, parent_jti: str, child_jti: str, limits: SpendingLimit
    ) -> None:
        self._delegations[child_jti] = (parent_jti, limits)

    async def get_delegated_allocations(self, parent_jti: str) -> SpendingLimit:
        limits_list = [
            limits
            for child_jti, (p, limits) in self._delegations.items()
            if p == parent_jti and child_jti not in self._revoked
        ]
        return _sum_limits(limits_list)

    async def release_delegation(self, parent_jti: str, child_jti: str) -> None:
        if child_jti in self._delegations:
            p, _ = self._delegations[child_jti]
            if p == parent_jti:
                del self._delegations[child_jti]

    async def get_children(self, parent_jti: str) -> list[str]:
        return [
            child_jti
            for child_jti, (p, _) in self._delegations.items()
            if p == parent_jti
        ]

    async def revoke(self, token_jti: str) -> None:
        # Cascade: revoke all children first
        for child_jti in await self.get_children(token_jti):
            await self.revoke(child_jti)
        # Release our parent's allocation of us
        if token_jti in self._delegations:
            parent_jti, _ = self._delegations[token_jti]
            await self.release_delegation(parent_jti, token_jti)
        self._revoked.add(token_jti)

    async def is_revoked(self, token_jti: str) -> bool:
        return token_jti in self._revoked


@dataclass
class SpendingCheckResult:
    """Result of a spending limit check."""

    allowed: bool
    reason: Optional[str] = None
    remaining_per_transaction: Optional[float] = None
    remaining_per_session: Optional[float] = None
    remaining_per_hour: Optional[float] = None
    remaining_per_day: Optional[float] = None


class SpendingTracker:
    """Enforces spending limits declared in settlement claims.

    Consulted by the middleware before authorizing escrow creation.
    Tracks cumulative spending per token (identified by JWT `jti` claim)
    and enforces per-transaction, per-session, per-hour, and per-day limits.

    Usage:
        tracker = SpendingTracker()

        # Before authorizing an escrow:
        result = await tracker.check(token_jti, amount, limits)
        if not result.allowed:
            raise SpendingLimitExceededError(result.reason)

        # After escrow is created:
        await tracker.record(token_jti, amount, escrow_id, counterparty_id)
    """

    def __init__(
        self,
        store: Optional[SpendingStore] = None,
        on_revoke: Optional[Callable[[str], Awaitable[None]]] = None,
    ):
        self._store = store or InMemorySpendingStore()
        self._on_revoke = on_revoke

    async def check(
        self,
        token_jti: str,
        amount: float,
        limits: SpendingLimit,
    ) -> SpendingCheckResult:
        """Check if a proposed spend is within the token's limits.

        Args:
            token_jti: The JWT token identifier.
            amount: The proposed transaction amount.
            limits: The spending limits from the token's settlement claims.

        Returns:
            SpendingCheckResult indicating whether the spend is allowed.
        """
        # Check revocation first
        if await self._store.is_revoked(token_jti):
            return SpendingCheckResult(
                allowed=False,
                reason="Token spending authority has been revoked",
            )

        # Effective limits = declared limits - delegated allocations (for parent tokens)
        try:
            delegated = await self._store.get_delegated_allocations(token_jti)
            limits = _effective_limits(limits, delegated)
        except NotImplementedError:
            pass  # Store doesn't support delegation, use declared limits

        now = time.time()
        result = SpendingCheckResult(allowed=True)

        # Per-transaction limit
        if limits.per_transaction is not None:
            if amount > limits.per_transaction:
                return SpendingCheckResult(
                    allowed=False,
                    reason=(
                        f"Transaction amount {amount} exceeds per-transaction "
                        f"limit of {limits.per_transaction}"
                    ),
                    remaining_per_transaction=limits.per_transaction,
                )
            result.remaining_per_transaction = limits.per_transaction - amount

        # Per-hour limit
        if limits.per_hour is not None:
            hour_ago = now - 3600
            spent_hour = await self._store.get_total(token_jti, since=hour_ago)
            if spent_hour + amount > limits.per_hour:
                return SpendingCheckResult(
                    allowed=False,
                    reason=(
                        f"Hourly spending {spent_hour + amount:.2f} would exceed "
                        f"per-hour limit of {limits.per_hour}"
                    ),
                    remaining_per_hour=max(0, limits.per_hour - spent_hour),
                )
            result.remaining_per_hour = limits.per_hour - spent_hour - amount

        # Per-day limit
        if limits.per_day is not None:
            day_ago = now - 86400
            spent_day = await self._store.get_total(token_jti, since=day_ago)
            if spent_day + amount > limits.per_day:
                return SpendingCheckResult(
                    allowed=False,
                    reason=(
                        f"Daily spending {spent_day + amount:.2f} would exceed "
                        f"per-day limit of {limits.per_day}"
                    ),
                    remaining_per_day=max(0, limits.per_day - spent_day),
                )
            result.remaining_per_day = limits.per_day - spent_day - amount

        # Per-session limit (lifetime of the token)
        if limits.per_session is not None:
            spent_session = await self._store.get_total(token_jti)
            if spent_session + amount > limits.per_session:
                return SpendingCheckResult(
                    allowed=False,
                    reason=(
                        f"Session spending {spent_session + amount:.2f} would exceed "
                        f"per-session limit of {limits.per_session}"
                    ),
                    remaining_per_session=max(0, limits.per_session - spent_session),
                )
            result.remaining_per_session = limits.per_session - spent_session - amount

        return result

    async def record(
        self,
        token_jti: str,
        amount: float,
        escrow_id: str,
        counterparty_id: str,
    ) -> SpendingRecord:
        """Record a completed spend against the token's running totals.

        Call this AFTER the exchange confirms the escrow was created.
        """
        record = SpendingRecord(
            amount=amount,
            timestamp=time.time(),
            escrow_id=escrow_id,
            counterparty_id=counterparty_id,
        )
        await self._store.record_spend(token_jti, record)
        return record

    async def allocate_delegation(
        self, parent_jti: str, child_jti: str, limits: SpendingLimit
    ) -> None:
        """Record that parent allocated these limits to child (reserves budget from parent)."""
        await self._store.record_delegation(parent_jti, child_jti, limits)

    async def validate_delegation_budget(
        self,
        parent_jti: str,
        parent_limits: SpendingLimit,
        child_limits: SpendingLimit,
    ) -> None:
        """Verify that proposed child limits fit within parent's remaining budget.

        Raises:
            ValueError: If child limits exceed parent or exceed parent's remaining
                delegated budget (parent limit minus already-delegated amounts).
        """
        try:
            delegated = await self._store.get_delegated_allocations(parent_jti)
        except NotImplementedError:
            delegated = SpendingLimit()
        # Child cannot exceed parent per dimension
        if parent_limits.per_transaction is not None and (
            child_limits.per_transaction is None
            or child_limits.per_transaction > parent_limits.per_transaction
        ):
            raise ValueError(
                f"Child per_transaction {child_limits.per_transaction} exceeds "
                f"parent limit {parent_limits.per_transaction}"
            )
        if parent_limits.per_session is not None and (
            child_limits.per_session is None
            or child_limits.per_session > parent_limits.per_session
        ):
            raise ValueError(
                f"Child per_session {child_limits.per_session} exceeds "
                f"parent limit {parent_limits.per_session}"
            )
        if parent_limits.per_hour is not None and (
            child_limits.per_hour is None
            or child_limits.per_hour > parent_limits.per_hour
        ):
            raise ValueError(
                f"Child per_hour {child_limits.per_hour} exceeds "
                f"parent limit {parent_limits.per_hour}"
            )
        if parent_limits.per_day is not None and (
            child_limits.per_day is None
            or child_limits.per_day > parent_limits.per_day
        ):
            raise ValueError(
                f"Child per_day {child_limits.per_day} exceeds "
                f"parent limit {parent_limits.per_day}"
            )
        # Sum of delegated + proposed must not exceed parent
        effective = _effective_limits(parent_limits, delegated)
        if effective.per_transaction is not None and (
            child_limits.per_transaction or 0
        ) > effective.per_transaction:
            raise ValueError(
                f"Child per_transaction {child_limits.per_transaction} exceeds "
                f"parent remaining delegated budget {effective.per_transaction}"
            )
        if effective.per_session is not None and (
            child_limits.per_session or 0
        ) > effective.per_session:
            raise ValueError(
                f"Child per_session {child_limits.per_session} exceeds "
                f"parent remaining delegated budget {effective.per_session}"
            )
        if effective.per_hour is not None and (
            child_limits.per_hour or 0
        ) > effective.per_hour:
            raise ValueError(
                f"Child per_hour {child_limits.per_hour} exceeds "
                f"parent remaining delegated budget {effective.per_hour}"
            )
        if effective.per_day is not None and (
            child_limits.per_day or 0
        ) > effective.per_day:
            raise ValueError(
                f"Child per_day {child_limits.per_day} exceeds "
                f"parent remaining delegated budget {effective.per_day}"
            )

    async def revoke(self, token_jti: str) -> None:
        """Immediately revoke all spending authority for a token.

        This is the kill switch. Once revoked, no further spending
        is authorized for this token regardless of remaining limits.
        If on_revoke is set, invokes it after revocation (callback failures
        do not block revocation).
        """
        await self._store.revoke(token_jti)
        if self._on_revoke:
            try:
                await self._on_revoke(token_jti)
            except Exception as e:
                logger.warning(
                    "on_revoke callback failed for jti=%s: %s",
                    token_jti,
                    e,
                    exc_info=True,
                )

    async def get_summary(
        self, token_jti: str, limits: SpendingLimit
    ) -> dict:
        """Get a summary of spending against limits for monitoring/display."""
        now = time.time()
        spent_session = await self._store.get_total(token_jti)
        spent_hour = await self._store.get_total(token_jti, since=now - 3600)
        spent_day = await self._store.get_total(token_jti, since=now - 86400)

        return {
            "spent_session": spent_session,
            "spent_hour": spent_hour,
            "spent_day": spent_day,
            "limits": limits.to_dict(),
            "remaining": {
                "per_session": (
                    max(0, limits.per_session - spent_session)
                    if limits.per_session is not None
                    else None
                ),
                "per_hour": (
                    max(0, limits.per_hour - spent_hour)
                    if limits.per_hour is not None
                    else None
                ),
                "per_day": (
                    max(0, limits.per_day - spent_day)
                    if limits.per_day is not None
                    else None
                ),
            },
            "revoked": await self._store.is_revoked(token_jti),
        }
