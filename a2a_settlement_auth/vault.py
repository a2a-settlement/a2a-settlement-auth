"""
Secret Vault -- Encrypted credential storage for the Economic Air Gap.

Stores real credentials (API keys, PATs, tokens) encrypted at rest.
Agents never see actual credential values; they only reference secrets
by a ``secret_id`` placeholder. The Security Shim resolves secret IDs
to real values via an internal-only API.

Usage::

    from a2a_settlement_auth.vault import SecretVault
    from a2a_settlement_auth.vault_crypto import VaultCipher

    cipher = VaultCipher(VaultCipher.generate_key())
    vault = SecretVault(cipher=cipher)

    secret_id = await vault.register(
        owner_id="org-acme",
        value="ghp_real_github_pat_here",
        label="GitHub deploy key",
    )

    # Internal-only: shim resolves the secret
    value = await vault.resolve(
        secret_id=secret_id,
        resolver_id="shim-instance-1",
        agent_id="bot-7f3a",
        escrow_id="escrow-uuid",
    )
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .vault_crypto import VaultCipher
from .vault_store import (
    InMemoryVaultStore,
    ResolveAuditEntry,
    SecretEntry,
    VaultStore,
)

logger = logging.getLogger("a2a_settlement_auth.vault")


# ─── Exceptions ────────────────────────────────────────────────────────────


class SecretVaultError(Exception):
    """Base exception for vault operations."""

    pass


class SecretNotFoundError(SecretVaultError):
    """Secret ID does not exist in the vault."""

    pass


class SecretRevokedError(SecretVaultError):
    """Secret has been revoked and can no longer be resolved."""

    pass


class SecretAccessDeniedError(SecretVaultError):
    """Caller is not authorized to resolve this secret."""

    pass


# ─── Public Data ───────────────────────────────────────────────────────────


@dataclass
class SecretPolicy:
    """Access policy attached to a secret at registration time."""

    allowed_agent_ids: list[str] = field(default_factory=list)
    """If non-empty, only these agents can resolve the secret."""

    allowed_scopes: list[str] = field(default_factory=list)
    """Reserved for future scope-based gating."""

    max_resolves_per_hour: Optional[int] = None
    """Rate limit on resolution (None = unlimited)."""

    def to_dict(self) -> dict:
        result: dict = {}
        if self.allowed_agent_ids:
            result["allowed_agent_ids"] = self.allowed_agent_ids
        if self.allowed_scopes:
            result["allowed_scopes"] = self.allowed_scopes
        if self.max_resolves_per_hour is not None:
            result["max_resolves_per_hour"] = self.max_resolves_per_hour
        return result

    @classmethod
    def from_dict(cls, data: dict) -> SecretPolicy:
        return cls(
            allowed_agent_ids=data.get("allowed_agent_ids", []),
            allowed_scopes=data.get("allowed_scopes", []),
            max_resolves_per_hour=data.get("max_resolves_per_hour"),
        )


@dataclass
class RegisteredSecret:
    """Public-facing metadata for a registered secret (never includes the value)."""

    secret_id: str
    owner_id: str
    label: str
    agent_ids: list[str]
    created_at: float
    rotated_at: Optional[float]
    revoked: bool


# ─── Vault ─────────────────────────────────────────────────────────────────


class SecretVault:
    """Encrypted credential vault for the Economic Air Gap.

    Agents never see real credentials. The vault stores encrypted values
    and only resolves them for authorized internal callers (the Security Shim).
    Every resolution attempt is audit-logged for SEC 17a-4 compliance.
    """

    def __init__(
        self,
        cipher: VaultCipher,
        store: Optional[VaultStore] = None,
    ):
        self._cipher = cipher
        self._store = store or InMemoryVaultStore()

    async def register(
        self,
        owner_id: str,
        value: str,
        label: str = "",
        agent_ids: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """Register a new secret and return its ``secret_id``.

        Args:
            owner_id: Organization that owns this credential.
            value: The real credential value (will be encrypted at rest).
            label: Human-readable description.
            agent_ids: If provided, only these agents may resolve the secret.
            metadata: Arbitrary key-value pairs for the caller's use.

        Returns:
            The generated ``secret_id`` (e.g., ``sec_a1b2c3d4e5f6...``).
        """
        secret_id = f"sec_{uuid.uuid4().hex[:24]}"
        encrypted = self._cipher.encrypt(value)

        entry = SecretEntry(
            secret_id=secret_id,
            owner_id=owner_id,
            encrypted_value=encrypted,
            label=label,
            agent_ids=agent_ids or [],
            metadata=metadata or {},
        )
        await self._store.store(entry)

        logger.info(
            "Secret registered: id=%s owner=%s label=%s",
            secret_id,
            owner_id,
            label,
        )
        return secret_id

    async def rotate(self, secret_id: str, new_value: str) -> None:
        """Replace the encrypted value of an existing secret.

        Raises:
            SecretNotFoundError: Secret does not exist.
            SecretRevokedError: Secret has been revoked.
        """
        entry = await self._store.get(secret_id)
        if entry is None:
            raise SecretNotFoundError(f"Secret {secret_id} not found")
        if entry.revoked:
            raise SecretRevokedError(f"Secret {secret_id} is revoked")

        entry.encrypted_value = self._cipher.encrypt(new_value)
        entry.rotated_at = time.time()
        await self._store.update(entry)

        logger.info("Secret rotated: id=%s", secret_id)

    async def revoke(self, secret_id: str) -> None:
        """Permanently revoke a secret. Future resolve calls will fail.

        Raises:
            SecretNotFoundError: Secret does not exist.
        """
        entry = await self._store.get(secret_id)
        if entry is None:
            raise SecretNotFoundError(f"Secret {secret_id} not found")

        entry.revoked = True
        entry.revoked_at = time.time()
        await self._store.update(entry)

        logger.info("Secret revoked: id=%s", secret_id)

    async def list_secrets(self, owner_id: str) -> list[RegisteredSecret]:
        """List all secrets for an organization (metadata only, no values)."""
        entries = await self._store.list_by_owner(owner_id)
        return [
            RegisteredSecret(
                secret_id=e.secret_id,
                owner_id=e.owner_id,
                label=e.label,
                agent_ids=e.agent_ids,
                created_at=e.created_at,
                rotated_at=e.rotated_at,
                revoked=e.revoked,
            )
            for e in entries
        ]

    async def resolve(
        self,
        secret_id: str,
        resolver_id: str,
        agent_id: str,
        escrow_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> str:
        """Resolve a secret_id to the real credential value.

        This is the internal-only API called by the Security Shim.
        Every call is audit-logged regardless of outcome.

        Args:
            secret_id: The placeholder ID the agent holds.
            resolver_id: Identity of the shim instance calling.
            agent_id: The agent on whose behalf the resolution is made.
            escrow_id: The active escrow funding this resolution.
            org_id: If provided, verify the secret belongs to this org.

        Returns:
            The decrypted credential value.

        Raises:
            SecretNotFoundError: Secret does not exist.
            SecretRevokedError: Secret has been revoked.
            SecretAccessDeniedError: Org mismatch or agent not authorized.
        """
        entry = await self._store.get(secret_id)

        if entry is None:
            await self._audit(
                secret_id, resolver_id, agent_id, escrow_id,
                success=False, denial_reason="not_found",
            )
            raise SecretNotFoundError(f"Secret {secret_id} not found")

        if entry.revoked:
            await self._audit(
                secret_id, resolver_id, agent_id, escrow_id,
                success=False, denial_reason="revoked",
            )
            raise SecretRevokedError(f"Secret {secret_id} is revoked")

        if org_id is not None and entry.owner_id != org_id:
            await self._audit(
                secret_id, resolver_id, agent_id, escrow_id,
                success=False, denial_reason="org_mismatch",
            )
            raise SecretAccessDeniedError(
                f"Secret {secret_id} belongs to {entry.owner_id}, not {org_id}"
            )

        if entry.agent_ids and agent_id not in entry.agent_ids:
            await self._audit(
                secret_id, resolver_id, agent_id, escrow_id,
                success=False, denial_reason="agent_not_allowed",
            )
            raise SecretAccessDeniedError(
                f"Agent {agent_id} is not authorized for secret {secret_id}"
            )

        value = self._cipher.decrypt(entry.encrypted_value)

        await self._audit(
            secret_id, resolver_id, agent_id, escrow_id, success=True,
        )
        logger.info(
            "Secret resolved: id=%s agent=%s escrow=%s",
            secret_id, agent_id, escrow_id,
        )
        return value

    async def get_audits(
        self,
        secret_id: str,
        since: Optional[float] = None,
    ) -> list[ResolveAuditEntry]:
        """Retrieve audit entries for a secret."""
        return await self._store.get_audits(secret_id, since)

    async def _audit(
        self,
        secret_id: str,
        resolver_id: str,
        agent_id: str,
        escrow_id: Optional[str],
        *,
        success: bool,
        denial_reason: Optional[str] = None,
    ) -> None:
        audit = ResolveAuditEntry(
            secret_id=secret_id,
            resolver_id=resolver_id,
            agent_id=agent_id,
            escrow_id=escrow_id,
            success=success,
            denial_reason=denial_reason,
        )
        await self._store.record_audit(audit)
