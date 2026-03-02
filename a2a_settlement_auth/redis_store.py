"""
Redis SpendingStore — Production-grade persistence for spending tracking.

Backed by Redis sorted sets and hash maps for O(1) lookups and
efficient time-windowed aggregation.

Usage:
    import redis.asyncio as redis
    from a2a_settlement_auth import SettlementAuthConfig
    from a2a_settlement_auth.redis_store import RedisSpendingStore

    pool = redis.from_url("redis://localhost:6379/0")
    store = RedisSpendingStore(pool)
    config = SettlementAuthConfig(
        verification_key="...",
        spending_store=store,
    )
"""

from __future__ import annotations

import json
import time
from typing import Optional

from .claims import SpendingLimit
from .spending import SpendingRecord, SpendingStore


class RedisSpendingStore(SpendingStore):
    """Redis-backed spending store using sorted sets for time-windowed queries."""

    def __init__(self, redis_client, *, prefix: str = "a2ase:spending:"):
        self._redis = redis_client
        self._prefix = prefix

    def _key(self, token_jti: str) -> str:
        return f"{self._prefix}records:{token_jti}"

    def _revoked_key(self) -> str:
        return f"{self._prefix}revoked"

    def _delegation_key(self) -> str:
        return f"{self._prefix}delegations"

    def _children_key(self, parent_jti: str) -> str:
        return f"{self._prefix}children:{parent_jti}"

    async def record_spend(self, token_jti: str, record: SpendingRecord) -> None:
        key = self._key(token_jti)
        member = json.dumps({
            "amount": record.amount,
            "timestamp": record.timestamp,
            "escrow_id": record.escrow_id,
            "counterparty_id": record.counterparty_id,
        })
        await self._redis.zadd(key, {member: record.timestamp})

    async def get_spending(
        self, token_jti: str, since: Optional[float] = None
    ) -> list[SpendingRecord]:
        key = self._key(token_jti)
        min_score = since if since is not None else "-inf"
        raw = await self._redis.zrangebyscore(key, min_score, "+inf")
        records = []
        for item in raw:
            data = json.loads(item)
            records.append(SpendingRecord(
                amount=data["amount"],
                timestamp=data["timestamp"],
                escrow_id=data["escrow_id"],
                counterparty_id=data["counterparty_id"],
            ))
        return records

    async def get_total(
        self, token_jti: str, since: Optional[float] = None
    ) -> float:
        records = await self.get_spending(token_jti, since)
        return sum(r.amount for r in records)

    async def revoke(self, token_jti: str) -> None:
        for child_jti in await self.get_children(token_jti):
            await self.revoke(child_jti)
        if await self._redis.hexists(self._delegation_key(), token_jti):
            data = json.loads(await self._redis.hget(self._delegation_key(), token_jti))
            parent_jti = data["parent_jti"]
            await self.release_delegation(parent_jti, token_jti)
        await self._redis.sadd(self._revoked_key(), token_jti)

    async def is_revoked(self, token_jti: str) -> bool:
        return bool(await self._redis.sismember(self._revoked_key(), token_jti))

    async def record_delegation(
        self, parent_jti: str, child_jti: str, limits: SpendingLimit
    ) -> None:
        data = json.dumps({
            "parent_jti": parent_jti,
            "limits": limits.to_dict(),
        })
        await self._redis.hset(self._delegation_key(), child_jti, data)
        await self._redis.sadd(self._children_key(parent_jti), child_jti)

    async def get_delegated_allocations(self, parent_jti: str) -> SpendingLimit:
        children = await self._redis.smembers(self._children_key(parent_jti))
        per_tx = 0.0
        per_sess = 0.0
        per_hr = 0.0
        per_day = 0.0
        for child_jti_bytes in children:
            child_jti = child_jti_bytes if isinstance(child_jti_bytes, str) else child_jti_bytes.decode()
            if await self.is_revoked(child_jti):
                continue
            raw = await self._redis.hget(self._delegation_key(), child_jti)
            if not raw:
                continue
            data = json.loads(raw)
            limits = data["limits"]
            per_tx += limits.get("per_transaction") or 0
            per_sess += limits.get("per_session") or 0
            per_hr += limits.get("per_hour") or 0
            per_day += limits.get("per_day") or 0

        return SpendingLimit(
            per_transaction=per_tx if per_tx else None,
            per_session=per_sess if per_sess else None,
            per_hour=per_hr if per_hr else None,
            per_day=per_day if per_day else None,
        )

    async def release_delegation(self, parent_jti: str, child_jti: str) -> None:
        await self._redis.hdel(self._delegation_key(), child_jti)
        await self._redis.srem(self._children_key(parent_jti), child_jti)

    async def get_children(self, parent_jti: str) -> list[str]:
        children = await self._redis.smembers(self._children_key(parent_jti))
        return [
            c if isinstance(c, str) else c.decode()
            for c in children
        ]
