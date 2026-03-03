"""
Vault Store -- Persistence layer for the Secret Vault.

Abstract base class and in-memory implementation for storing encrypted
secrets. Production deployments should use a database-backed store.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SecretEntry:
    """A stored secret in the vault."""

    secret_id: str
    """Opaque identifier exposed to agents (e.g., sec_a1b2c3...)."""

    owner_id: str
    """Organization ID that owns this secret."""

    encrypted_value: str
    """Fernet-encrypted credential value."""

    label: str = ""
    """Human-readable label (e.g., 'GitHub deploy key')."""

    agent_ids: list[str] = field(default_factory=list)
    """If non-empty, only these agents can resolve this secret."""

    created_at: float = field(default_factory=time.time)
    rotated_at: Optional[float] = None
    revoked: bool = False
    revoked_at: Optional[float] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ResolveAuditEntry:
    """Audit record for a secret resolution attempt.

    Feeds into the Merkle tree for SEC 17a-4 compliance.
    """

    secret_id: str
    resolver_id: str
    """Identity of the caller that resolved (e.g., shim instance ID)."""

    agent_id: str
    """Agent the resolution was performed on behalf of."""

    escrow_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    success: bool = True
    denial_reason: Optional[str] = None


class VaultStore(ABC):
    """Abstract interface for secret persistence."""

    @abstractmethod
    async def store(self, entry: SecretEntry) -> None: ...

    @abstractmethod
    async def get(self, secret_id: str) -> Optional[SecretEntry]: ...

    @abstractmethod
    async def list_by_owner(self, owner_id: str) -> list[SecretEntry]: ...

    @abstractmethod
    async def update(self, entry: SecretEntry) -> None: ...

    @abstractmethod
    async def delete(self, secret_id: str) -> None: ...

    @abstractmethod
    async def record_audit(self, audit: ResolveAuditEntry) -> None: ...

    @abstractmethod
    async def get_audits(
        self, secret_id: str, since: Optional[float] = None
    ) -> list[ResolveAuditEntry]: ...


class InMemoryVaultStore(VaultStore):
    """In-memory vault store for development and testing."""

    def __init__(self) -> None:
        self._secrets: dict[str, SecretEntry] = {}
        self._audits: list[ResolveAuditEntry] = []

    async def store(self, entry: SecretEntry) -> None:
        self._secrets[entry.secret_id] = entry

    async def get(self, secret_id: str) -> Optional[SecretEntry]:
        return self._secrets.get(secret_id)

    async def list_by_owner(self, owner_id: str) -> list[SecretEntry]:
        return [e for e in self._secrets.values() if e.owner_id == owner_id]

    async def update(self, entry: SecretEntry) -> None:
        self._secrets[entry.secret_id] = entry

    async def delete(self, secret_id: str) -> None:
        self._secrets.pop(secret_id, None)

    async def record_audit(self, audit: ResolveAuditEntry) -> None:
        self._audits.append(audit)

    async def get_audits(
        self, secret_id: str, since: Optional[float] = None
    ) -> list[ResolveAuditEntry]:
        entries = [a for a in self._audits if a.secret_id == secret_id]
        if since is not None:
            entries = [a for a in entries if a.timestamp >= since]
        return entries
