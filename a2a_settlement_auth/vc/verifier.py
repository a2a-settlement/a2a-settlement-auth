"""Federation Verifiable Credential verification engine.

Verifies VCs issued by federated exchanges using the DID resolver from
the ``did`` subpackage. Supports both trusted-issuer and federation-peer
verification modes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from ..did.resolver import DIDDocument, DIDResolutionError, DIDResolver, KeyNotFoundError
from .types import (
    REQUIRED_CONTEXTS,
    MAX_TTL_DAYS,
    FederationVC,
    parse_federation_vc,
)


class VCVerificationStatus(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    INVALID_SIGNATURE = "invalid_signature"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    ISSUER_UNRESOLVABLE = "issuer_unresolvable"
    MALFORMED = "malformed"
    TTL_EXCEEDED = "ttl_exceeded"
    MISSING_CONTEXT = "missing_context"
    REVOKED = "revoked"


@dataclass
class VCVerificationResult:
    """Result of verifying a single federation VC."""

    status: VCVerificationStatus
    vc: Optional[FederationVC] = None
    issuer_did: Optional[str] = None
    credential_type: Optional[str] = None
    error_detail: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None


class FederationVCVerifier:
    """Verifies Verifiable Credentials from federated exchanges.

    Parameters
    ----------
    did_resolver:
        Resolver for both ``did:key`` and ``did:web``.
    trusted_issuers:
        Set of issuer DIDs accepted without federation peering.
    federation_peers:
        Set of exchange DIDs that are active federation peers.
        VCs from these issuers are accepted even if not in trusted_issuers.
    """

    def __init__(
        self,
        did_resolver: DIDResolver,
        trusted_issuers: set[str] | None = None,
        federation_peers: set[str] | None = None,
    ):
        self.did_resolver = did_resolver
        self.trusted_issuers: set[str] = trusted_issuers or set()
        self.federation_peers: set[str] = federation_peers or set()

    def verify(self, credential_data: dict) -> VCVerificationResult:
        """Verify a federation Verifiable Credential.

        Checks:
        1. Required contexts present
        2. Required fields present
        3. Proof structure valid
        4. TTL within maximum for attestation type
        5. Temporal validity (not expired, not future)
        6. Issuer DID resolution
        7. Issuer is either a trusted issuer or a federation peer
        """
        vc = parse_federation_vc(credential_data)

        # 1. Context check
        contexts_set = set(vc.contexts)
        if not REQUIRED_CONTEXTS.issubset(contexts_set):
            missing = REQUIRED_CONTEXTS - contexts_set
            return VCVerificationResult(
                status=VCVerificationStatus.MISSING_CONTEXT,
                error_detail=f"Missing required contexts: {missing}",
            )

        # 2. Basic field validation
        if not vc.id or not vc.issuer or not vc.valid_from:
            return VCVerificationResult(
                status=VCVerificationStatus.MALFORMED,
                error_detail="Missing required fields (id, issuer, or validFrom)",
            )

        if not vc.proof.proof_value or not vc.proof.verification_method:
            return VCVerificationResult(
                status=VCVerificationStatus.MALFORMED,
                error_detail="Missing proof fields (proofValue or verificationMethod)",
            )

        # 3. Parse dates
        try:
            valid_from = _parse_dt(vc.valid_from)
        except (ValueError, TypeError) as exc:
            return VCVerificationResult(
                status=VCVerificationStatus.MALFORMED,
                error_detail=f"Invalid validFrom: {exc}",
            )

        valid_until = None
        if vc.valid_until:
            try:
                valid_until = _parse_dt(vc.valid_until)
            except (ValueError, TypeError) as exc:
                return VCVerificationResult(
                    status=VCVerificationStatus.MALFORMED,
                    error_detail=f"Invalid validUntil: {exc}",
                )

        # 4. TTL check
        att_type = vc.attestation_type
        if att_type and valid_until:
            max_days = MAX_TTL_DAYS.get(att_type.value)
            if max_days is not None:
                max_valid_until = valid_from + timedelta(days=max_days)
                if valid_until > max_valid_until:
                    return VCVerificationResult(
                        status=VCVerificationStatus.TTL_EXCEEDED,
                        vc=vc,
                        issuer_did=vc.issuer,
                        credential_type=att_type.value if att_type else None,
                        error_detail=(
                            f"validUntil exceeds maximum TTL of {max_days} days "
                            f"for {att_type.value}"
                        ),
                        valid_from=valid_from,
                        valid_until=valid_until,
                    )

        # 5. Temporal validity
        now = datetime.now(timezone.utc)
        if now < valid_from:
            return VCVerificationResult(
                status=VCVerificationStatus.NOT_YET_VALID,
                vc=vc,
                issuer_did=vc.issuer,
                credential_type=att_type.value if att_type else None,
                valid_from=valid_from,
                valid_until=valid_until,
            )
        if valid_until and now >= valid_until:
            return VCVerificationResult(
                status=VCVerificationStatus.EXPIRED,
                vc=vc,
                issuer_did=vc.issuer,
                credential_type=att_type.value if att_type else None,
                valid_from=valid_from,
                valid_until=valid_until,
            )

        # 6. Issuer DID resolution
        try:
            self.did_resolver.resolve(vc.issuer)
        except DIDResolutionError as exc:
            return VCVerificationResult(
                status=VCVerificationStatus.ISSUER_UNRESOLVABLE,
                vc=vc,
                issuer_did=vc.issuer,
                credential_type=att_type.value if att_type else None,
                error_detail=str(exc),
                valid_from=valid_from,
                valid_until=valid_until,
            )

        # 7. Issuer trust check
        if (
            vc.issuer not in self.trusted_issuers
            and vc.issuer not in self.federation_peers
        ):
            return VCVerificationResult(
                status=VCVerificationStatus.UNTRUSTED_ISSUER,
                vc=vc,
                issuer_did=vc.issuer,
                credential_type=att_type.value if att_type else None,
                error_detail=(
                    "Issuer is neither a trusted issuer nor a federation peer"
                ),
                valid_from=valid_from,
                valid_until=valid_until,
            )

        return VCVerificationResult(
            status=VCVerificationStatus.VALID,
            vc=vc,
            issuer_did=vc.issuer,
            credential_type=att_type.value if att_type else None,
            valid_from=valid_from,
            valid_until=valid_until,
        )

    def add_federation_peer(self, peer_did: str) -> None:
        self.federation_peers.add(peer_did)

    def remove_federation_peer(self, peer_did: str) -> None:
        self.federation_peers.discard(peer_did)

    def add_trusted_issuer(self, issuer_did: str) -> None:
        self.trusted_issuers.add(issuer_did)

    def remove_trusted_issuer(self, issuer_did: str) -> None:
        self.trusted_issuers.discard(issuer_did)


def _parse_dt(value) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return datetime.fromisoformat(str(value)).replace(tzinfo=timezone.utc)
