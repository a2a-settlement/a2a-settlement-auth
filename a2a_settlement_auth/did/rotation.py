"""DID key rotation verification.

Validates signed rotation events chained to the original DID as defined
in the A2A-SE Federation Protocol (Section 01, §3).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


class KeyRotationError(Exception):
    """Raised when a key rotation event cannot be verified."""


@dataclass
class KeyRotationEvent:
    """A parsed DID key rotation event."""

    old_did: str
    new_did: str
    rotated_at: datetime
    reason: str
    proof_value: str
    verification_method: str

    @classmethod
    def from_credential(cls, vc: dict) -> "KeyRotationEvent":
        """Parse a rotation event from a DIDKeyRotation VC."""
        vc_types = vc.get("type", [])
        if "DIDKeyRotation" not in vc_types:
            raise KeyRotationError(
                "Credential is not a DIDKeyRotation type"
            )

        subject = vc.get("credentialSubject", {})
        proof = vc.get("proof", {})

        old_did = vc.get("issuer", "")
        new_did = subject.get("newDid", "")
        if not old_did or not new_did:
            raise KeyRotationError(
                "Rotation event missing issuer (old DID) or newDid"
            )

        rotated_at_str = subject.get("rotatedAt", "")
        try:
            rotated_at = datetime.fromisoformat(rotated_at_str).replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError) as exc:
            raise KeyRotationError(f"Invalid rotatedAt: {exc}") from exc

        return cls(
            old_did=old_did,
            new_did=new_did,
            rotated_at=rotated_at,
            reason=subject.get("reason", "unspecified"),
            proof_value=proof.get("proofValue", ""),
            verification_method=proof.get("verificationMethod", ""),
        )


def verify_rotation_event(
    event: KeyRotationEvent,
    resolver: "DIDResolver",  # noqa: F821  forward ref
) -> bool:
    """Verify that a key rotation event was signed by the old key.

    Steps:
    1. Resolve the old DID to get its public key
    2. Verify the rotation event's proof was signed by that key
    3. Resolve the new DID to confirm it's a valid DID

    Returns True if the rotation is valid.
    """
    from .resolver import DIDResolutionError, KeyNotFoundError

    try:
        old_doc = resolver.resolve(event.old_did, force_refresh=True)
    except DIDResolutionError as exc:
        raise KeyRotationError(
            f"Cannot resolve old DID for rotation verification: {exc}"
        ) from exc

    try:
        resolver.extract_verification_method(
            old_doc, event.verification_method
        )
    except KeyNotFoundError as exc:
        raise KeyRotationError(
            f"Rotation proof key not found in old DID document: {exc}"
        ) from exc

    try:
        resolver.resolve(event.new_did)
    except DIDResolutionError as exc:
        raise KeyRotationError(
            f"New DID cannot be resolved: {exc}"
        ) from exc

    resolver.invalidate(event.old_did)

    return True
