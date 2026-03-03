"""
A2A Settlement Auth — OAuth 2.0 Settlement Scopes for Agent Economic Authorization.

Extends OAuth 2.0 tokens with economic authorization metadata so that
identity providers can express not just what an agent can *access* but
what an agent can *spend*.

Usage:
    from a2a_settlement_auth import (
        SettlementClaims,
        SettlementScope,
        SettlementMiddleware,
        validate_settlement_token,
        create_settlement_token,
    )
"""

__version__ = "0.1.0"

from .scopes import SettlementScope, parse_scopes, scope_satisfies, format_scopes
from .claims import (
    SettlementClaims,
    CounterpartyPolicy,
    SpendingLimit,
    DelegationChain,
    DelegationLink,
)
from .tokens import (
    create_settlement_token,
    create_delegated_token,
    create_delegated_token_async,
    validate_settlement_token,
    check_counterparty,
    SettlementTokenError,
    TokenExpiredError,
    InsufficientScopeError,
    SpendingLimitExceededError,
    CounterpartyDeniedError,
    DelegationViolationError,
)
from .middleware import SettlementMiddleware, SettlementAuthConfig
from .spending import SpendingTracker, SpendingRecord, SpendingStore, InMemorySpendingStore
from .redis_store import RedisSpendingStore
from .vault import (
    SecretVault,
    SecretPolicy,
    RegisteredSecret,
    SecretVaultError,
    SecretNotFoundError,
    SecretRevokedError,
    SecretAccessDeniedError,
)
from .vault_crypto import VaultCipher, VaultDecryptionError
from .vault_store import VaultStore, InMemoryVaultStore, SecretEntry, ResolveAuditEntry

__all__ = [
    # Scopes
    "SettlementScope",
    "parse_scopes",
    "scope_satisfies",
    "format_scopes",
    # Claims
    "SettlementClaims",
    "CounterpartyPolicy",
    "SpendingLimit",
    "DelegationChain",
    "DelegationLink",
    # Tokens
    "create_settlement_token",
    "validate_settlement_token",
    "check_counterparty",
    "SettlementTokenError",
    "CounterpartyDeniedError",
    "TokenExpiredError",
    "InsufficientScopeError",
    "SpendingLimitExceededError",
    "DelegationViolationError",
    "create_delegated_token",
    "create_delegated_token_async",
    # Middleware
    "SettlementMiddleware",
    "SettlementAuthConfig",
    # Spending
    "SpendingTracker",
    "SpendingRecord",
    "SpendingStore",
    "InMemorySpendingStore",
    "RedisSpendingStore",
    # Vault
    "SecretVault",
    "SecretPolicy",
    "RegisteredSecret",
    "SecretVaultError",
    "SecretNotFoundError",
    "SecretRevokedError",
    "SecretAccessDeniedError",
    "VaultCipher",
    "VaultDecryptionError",
    "VaultStore",
    "InMemoryVaultStore",
    "SecretEntry",
    "ResolveAuditEntry",
]
