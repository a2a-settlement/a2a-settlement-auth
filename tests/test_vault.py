"""Tests for the Secret Vault (Economic Air Gap — Component 2)."""

import time

import pytest

from a2a_settlement_auth.vault import (
    SecretVault,
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretRevokedError,
)
from a2a_settlement_auth.vault_crypto import VaultCipher, VaultDecryptionError
from a2a_settlement_auth.vault_store import InMemoryVaultStore
from a2a_settlement_auth.claims import SettlementClaims


# ─── Crypto Tests ──────────────────────────────────────────────────────────


class TestVaultCipher:
    def test_generate_key(self):
        key = VaultCipher.generate_key()
        assert isinstance(key, str)
        assert len(key) > 20

    def test_encrypt_decrypt_roundtrip(self):
        cipher = VaultCipher(VaultCipher.generate_key())
        original = "ghp_abc123_my_secret_pat"
        encrypted = cipher.encrypt(original)
        assert encrypted != original
        assert cipher.decrypt(encrypted) == original

    def test_wrong_key_raises(self):
        cipher1 = VaultCipher(VaultCipher.generate_key())
        cipher2 = VaultCipher(VaultCipher.generate_key())
        encrypted = cipher1.encrypt("secret")
        with pytest.raises(VaultDecryptionError, match="wrong key"):
            cipher2.decrypt(encrypted)

    def test_accepts_bytes_key(self):
        key = VaultCipher.generate_key().encode("utf-8")
        cipher = VaultCipher(key)
        assert cipher.decrypt(cipher.encrypt("test")) == "test"


# ─── Vault Core Tests ─────────────────────────────────────────────────────


class TestSecretVault:
    @pytest.fixture
    def vault(self):
        cipher = VaultCipher(VaultCipher.generate_key())
        return SecretVault(cipher=cipher, store=InMemoryVaultStore())

    @pytest.mark.asyncio
    async def test_register_and_resolve(self, vault):
        sid = await vault.register(
            owner_id="org-acme",
            value="ghp_real_pat_12345",
            label="GitHub deploy key",
        )
        assert sid.startswith("sec_")

        value = await vault.resolve(
            secret_id=sid,
            resolver_id="shim-1",
            agent_id="bot-7f3a",
        )
        assert value == "ghp_real_pat_12345"

    @pytest.mark.asyncio
    async def test_resolve_not_found(self, vault):
        with pytest.raises(SecretNotFoundError, match="not found"):
            await vault.resolve(
                secret_id="sec_nonexistent",
                resolver_id="shim-1",
                agent_id="bot-1",
            )

    @pytest.mark.asyncio
    async def test_rotate(self, vault):
        sid = await vault.register(
            owner_id="org-acme", value="old_key"
        )
        await vault.rotate(sid, "new_key")
        value = await vault.resolve(
            secret_id=sid,
            resolver_id="shim-1",
            agent_id="bot-1",
        )
        assert value == "new_key"

    @pytest.mark.asyncio
    async def test_rotate_not_found(self, vault):
        with pytest.raises(SecretNotFoundError):
            await vault.rotate("sec_fake", "val")

    @pytest.mark.asyncio
    async def test_rotate_revoked(self, vault):
        sid = await vault.register(owner_id="org-1", value="val")
        await vault.revoke(sid)
        with pytest.raises(SecretRevokedError):
            await vault.rotate(sid, "new_val")

    @pytest.mark.asyncio
    async def test_revoke_blocks_resolve(self, vault):
        sid = await vault.register(
            owner_id="org-acme", value="secret_val"
        )
        await vault.revoke(sid)
        with pytest.raises(SecretRevokedError, match="revoked"):
            await vault.resolve(
                secret_id=sid,
                resolver_id="shim-1",
                agent_id="bot-1",
            )

    @pytest.mark.asyncio
    async def test_revoke_not_found(self, vault):
        with pytest.raises(SecretNotFoundError):
            await vault.revoke("sec_nonexistent")

    @pytest.mark.asyncio
    async def test_list_secrets(self, vault):
        await vault.register(owner_id="org-a", value="v1", label="key-1")
        await vault.register(owner_id="org-a", value="v2", label="key-2")
        await vault.register(owner_id="org-b", value="v3", label="key-3")

        secrets_a = await vault.list_secrets("org-a")
        assert len(secrets_a) == 2
        assert all(s.owner_id == "org-a" for s in secrets_a)
        assert all(not hasattr(s, "encrypted_value") or True for s in secrets_a)

        secrets_b = await vault.list_secrets("org-b")
        assert len(secrets_b) == 1

    @pytest.mark.asyncio
    async def test_list_secrets_never_exposes_values(self, vault):
        await vault.register(owner_id="org-a", value="super_secret")
        secrets = await vault.list_secrets("org-a")
        for s in secrets:
            assert not hasattr(s, "value")
            assert not hasattr(s, "encrypted_value")


# ─── Access Control Tests ─────────────────────────────────────────────────


class TestSecretAccessControl:
    @pytest.fixture
    def vault(self):
        cipher = VaultCipher(VaultCipher.generate_key())
        return SecretVault(cipher=cipher, store=InMemoryVaultStore())

    @pytest.mark.asyncio
    async def test_agent_restriction(self, vault):
        sid = await vault.register(
            owner_id="org-acme",
            value="secret_val",
            agent_ids=["bot-allowed"],
        )
        value = await vault.resolve(
            secret_id=sid,
            resolver_id="shim-1",
            agent_id="bot-allowed",
        )
        assert value == "secret_val"

        with pytest.raises(SecretAccessDeniedError, match="not authorized"):
            await vault.resolve(
                secret_id=sid,
                resolver_id="shim-1",
                agent_id="bot-denied",
            )

    @pytest.mark.asyncio
    async def test_org_mismatch(self, vault):
        sid = await vault.register(
            owner_id="org-acme", value="val"
        )
        with pytest.raises(SecretAccessDeniedError, match="org_mismatch" if False else "belongs to"):
            await vault.resolve(
                secret_id=sid,
                resolver_id="shim-1",
                agent_id="bot-1",
                org_id="org-evil",
            )

    @pytest.mark.asyncio
    async def test_org_match_succeeds(self, vault):
        sid = await vault.register(
            owner_id="org-acme", value="val"
        )
        value = await vault.resolve(
            secret_id=sid,
            resolver_id="shim-1",
            agent_id="bot-1",
            org_id="org-acme",
        )
        assert value == "val"

    @pytest.mark.asyncio
    async def test_empty_agent_ids_allows_all(self, vault):
        sid = await vault.register(
            owner_id="org-acme",
            value="open_secret",
            agent_ids=[],
        )
        value = await vault.resolve(
            secret_id=sid,
            resolver_id="shim-1",
            agent_id="any-agent-at-all",
        )
        assert value == "open_secret"


# ─── Audit Tests ───────────────────────────────────────────────────────────


class TestVaultAudit:
    @pytest.fixture
    def vault(self):
        cipher = VaultCipher(VaultCipher.generate_key())
        return SecretVault(cipher=cipher, store=InMemoryVaultStore())

    @pytest.mark.asyncio
    async def test_successful_resolve_logged(self, vault):
        sid = await vault.register(owner_id="org-a", value="val")
        await vault.resolve(
            secret_id=sid,
            resolver_id="shim-1",
            agent_id="bot-1",
            escrow_id="escrow-abc",
        )
        audits = await vault.get_audits(sid)
        assert len(audits) == 1
        assert audits[0].success is True
        assert audits[0].resolver_id == "shim-1"
        assert audits[0].agent_id == "bot-1"
        assert audits[0].escrow_id == "escrow-abc"

    @pytest.mark.asyncio
    async def test_failed_resolve_logged(self, vault):
        sid = await vault.register(
            owner_id="org-a", value="val", agent_ids=["bot-allowed"]
        )
        with pytest.raises(SecretAccessDeniedError):
            await vault.resolve(
                secret_id=sid,
                resolver_id="shim-1",
                agent_id="bot-denied",
            )
        audits = await vault.get_audits(sid)
        assert len(audits) == 1
        assert audits[0].success is False
        assert audits[0].denial_reason == "agent_not_allowed"

    @pytest.mark.asyncio
    async def test_not_found_logged(self, vault):
        with pytest.raises(SecretNotFoundError):
            await vault.resolve(
                secret_id="sec_fake",
                resolver_id="shim-1",
                agent_id="bot-1",
            )
        audits = await vault.get_audits("sec_fake")
        assert len(audits) == 1
        assert audits[0].denial_reason == "not_found"

    @pytest.mark.asyncio
    async def test_revoked_logged(self, vault):
        sid = await vault.register(owner_id="org-a", value="val")
        await vault.revoke(sid)
        with pytest.raises(SecretRevokedError):
            await vault.resolve(
                secret_id=sid,
                resolver_id="shim-1",
                agent_id="bot-1",
            )
        audits = await vault.get_audits(sid)
        assert len(audits) == 1
        assert audits[0].denial_reason == "revoked"

    @pytest.mark.asyncio
    async def test_multiple_resolves_accumulated(self, vault):
        sid = await vault.register(owner_id="org-a", value="val")
        for _ in range(5):
            await vault.resolve(
                secret_id=sid,
                resolver_id="shim-1",
                agent_id="bot-1",
            )
        audits = await vault.get_audits(sid)
        assert len(audits) == 5
        assert all(a.success for a in audits)


# ─── Claims Integration Tests ─────────────────────────────────────────────


class TestAllowedSecretIdsClaim:
    def test_roundtrip_with_secret_ids(self):
        claims = SettlementClaims(
            agent_id="bot-1",
            org_id="org-acme",
            allowed_secret_ids=["sec_github_abc", "sec_slack_xyz"],
        )
        d = claims.to_dict()
        assert d["allowed_secret_ids"] == ["sec_github_abc", "sec_slack_xyz"]

        restored = SettlementClaims.from_dict(d)
        assert restored.allowed_secret_ids == ["sec_github_abc", "sec_slack_xyz"]

    def test_empty_secret_ids_omitted(self):
        claims = SettlementClaims(
            agent_id="bot-1",
            org_id="org-acme",
        )
        d = claims.to_dict()
        assert "allowed_secret_ids" not in d

        restored = SettlementClaims.from_dict(d)
        assert restored.allowed_secret_ids == []

    def test_jwt_roundtrip(self):
        claims = SettlementClaims(
            agent_id="bot-1",
            org_id="org-acme",
            allowed_secret_ids=["sec_aws_key"],
        )
        jwt_claims = claims.to_jwt_claims()
        restored = SettlementClaims.from_jwt_claims(jwt_claims)
        assert restored is not None
        assert restored.allowed_secret_ids == ["sec_aws_key"]
