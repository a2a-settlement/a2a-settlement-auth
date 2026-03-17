"""Verifiable Credential types and verification for the A2A-SE federation protocol."""

from .types import (
    FederationVC,
    IdentityAttestationVC,
    CapabilityAttestationVC,
    ReputationAttestationVC,
    EvidenceAttestationVC,
    TransactionAttestationVC,
    VCProof,
    parse_federation_vc,
)
from .verifier import FederationVCVerifier, VCVerificationResult, VCVerificationStatus

__all__ = [
    "FederationVC",
    "IdentityAttestationVC",
    "CapabilityAttestationVC",
    "ReputationAttestationVC",
    "EvidenceAttestationVC",
    "TransactionAttestationVC",
    "VCProof",
    "parse_federation_vc",
    "FederationVCVerifier",
    "VCVerificationResult",
    "VCVerificationStatus",
]
