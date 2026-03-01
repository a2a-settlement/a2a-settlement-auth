"""
Spending Tracker — Enforces cumulative spending limits for agent tokens.

Tracks per-session, per-hour, and per-day spending against the limits
declared in the token's SettlementClaims. The tracker is consulted by
the middleware before any settlement action is authorized.

The tracker uses an in-memory store by default, with an abstract base
that can be backed by Redis or a database for production deployments.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from .claims import SpendingLimit


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


class InMemorySpendingStore(SpendingStore):
    """In-memory spending store for development and testing."""

    def __init__(self):
        self._records: dict[str, list[SpendingRecord]] = {}
        self._revoked: set[str] = set()

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

    async def revoke(self, token_jti: str) -> None:
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

    def __init__(self, store: Optional[SpendingStore] = None):
        self._store = store or InMemorySpendingStore()

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

    async def revoke(self, token_jti: str) -> None:
        """Immediately revoke all spending authority for a token.

        This is the kill switch. Once revoked, no further spending
        is authorized for this token regardless of remaining limits.
        """
        await self._store.revoke(token_jti)

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
