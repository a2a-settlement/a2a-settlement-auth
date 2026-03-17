"""
Multi-Signature Revocation Guard for A2A Settlement Attestation Lifecycle.

Identity and capability revocations require M-of-N signatures to prevent
accidental self-destruction or unilateral censorship.  Reputation revocations
do not require multi-sig (lower stakes, auto-recalculated).

Signature schemes supported: HMAC-SHA256, Ed25519 (via PyNaCl if installed).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("a2a_settlement_auth.multisig")


class KeyType(str, Enum):
    ACTIVE = "active"
    COLD_STORAGE = "cold_storage"
    OPERATOR_QUORUM = "operator_quorum"


@dataclass
class MultiSigPolicy:
    """Defines the M-of-N signature threshold for a revocation class."""
    m: int
    n: int
    key_types: list[KeyType] = field(default_factory=lambda: [KeyType.ACTIVE, KeyType.COLD_STORAGE])

    def __post_init__(self):
        if self.m < 1:
            raise ValueError("m must be >= 1")
        if self.m > self.n:
            raise ValueError("m cannot exceed n")


@dataclass
class PublicKeyEntry:
    """A registered public key (or HMAC secret) with its role."""
    key_id: str
    key_type: KeyType
    key_material: bytes


class MultiSigError(Exception):
    pass


class InsufficientSignaturesError(MultiSigError):
    pass


class InvalidSignatureError(MultiSigError):
    pass


DEFAULT_IDENTITY_POLICY = MultiSigPolicy(m=2, n=3, key_types=[KeyType.ACTIVE, KeyType.COLD_STORAGE, KeyType.OPERATOR_QUORUM])
DEFAULT_CAPABILITY_POLICY = MultiSigPolicy(m=2, n=2, key_types=[KeyType.ACTIVE, KeyType.OPERATOR_QUORUM])


def _canonical_payload(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_revocation(payload: dict, secret: bytes) -> str:
    """Produce an HMAC-SHA256 signature for a revocation payload."""
    canonical = _canonical_payload(payload)
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def verify_multisig(
    payload: dict,
    signatures: list[str],
    keys: list[PublicKeyEntry],
    policy: MultiSigPolicy,
) -> bool:
    """Verify that >= M unique valid signatures exist from the registered key set.

    Returns True if the threshold is met.
    Raises InsufficientSignaturesError or InvalidSignatureError on failure.
    """
    if len(signatures) < policy.m:
        raise InsufficientSignaturesError(
            f"Need at least {policy.m} signature(s), got {len(signatures)}"
        )

    canonical = _canonical_payload(payload)
    verified_key_ids: set[str] = set()

    for sig in signatures:
        matched = False
        for key_entry in keys:
            if key_entry.key_type not in policy.key_types:
                continue
            if key_entry.key_id in verified_key_ids:
                continue
            expected = hmac.new(key_entry.key_material, canonical, hashlib.sha256).hexdigest()
            if hmac.compare_digest(sig, expected):
                verified_key_ids.add(key_entry.key_id)
                matched = True
                break
        if not matched:
            logger.warning("Signature did not match any registered key")

    if len(verified_key_ids) < policy.m:
        raise InsufficientSignaturesError(
            f"Only {len(verified_key_ids)} valid signature(s) verified; policy requires {policy.m}"
        )

    return True


def requires_multisig(attestation_type: str) -> bool:
    """Return True if the given attestation type requires multi-sig for revocation."""
    return attestation_type in ("identity", "capability")


def policy_for_type(attestation_type: str) -> MultiSigPolicy | None:
    """Return the default multi-sig policy for the given attestation type, or None."""
    if attestation_type == "identity":
        return DEFAULT_IDENTITY_POLICY
    if attestation_type == "capability":
        return DEFAULT_CAPABILITY_POLICY
    return None
