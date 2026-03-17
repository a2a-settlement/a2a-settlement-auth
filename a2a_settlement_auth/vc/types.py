"""Pydantic models for A2A-SE federation Verifiable Credential types.

Maps to the JSON schemas defined in the a2a-federation-rfc repository.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional, Union

from dataclasses import dataclass, field


A2A_FEDERATION_CONTEXT = "https://a2a-settlement.org/ns/federation/v1"
W3C_VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"

REQUIRED_CONTEXTS = {W3C_VC_CONTEXT, A2A_FEDERATION_CONTEXT}

MAX_TTL_DAYS = {
    "IdentityAttestation": 365,
    "CapabilityAttestation": 180,
    "ReputationAttestation": 90,
    "EvidenceAttestation": None,  # permanent
    "TransactionAttestation": None,  # permanent
}


class AttestationType(str, Enum):
    IDENTITY = "IdentityAttestation"
    CAPABILITY = "CapabilityAttestation"
    REPUTATION = "ReputationAttestation"
    EVIDENCE = "EvidenceAttestation"
    TRANSACTION = "TransactionAttestation"


@dataclass
class VCProof:
    """Ed25519Signature2020 proof block."""

    type: str
    created: str
    verification_method: str
    proof_purpose: str
    proof_value: str

    @classmethod
    def from_dict(cls, data: dict) -> "VCProof":
        return cls(
            type=data.get("type", ""),
            created=data.get("created", ""),
            verification_method=data.get("verificationMethod", ""),
            proof_purpose=data.get("proofPurpose", ""),
            proof_value=data.get("proofValue", ""),
        )

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "created": self.created,
            "verificationMethod": self.verification_method,
            "proofPurpose": self.proof_purpose,
            "proofValue": self.proof_value,
        }


@dataclass
class FederationVC:
    """Base class for all federation Verifiable Credentials."""

    contexts: list[str]
    types: list[str]
    id: str
    issuer: str
    valid_from: str
    valid_until: Optional[str]
    credential_subject: dict
    proof: VCProof
    raw: dict = field(default_factory=dict)

    @property
    def attestation_type(self) -> Optional[AttestationType]:
        for t in self.types:
            try:
                return AttestationType(t)
            except ValueError:
                continue
        return None


@dataclass
class IdentityAttestationVC(FederationVC):
    """KYA identity verification attestation."""

    @property
    def kya_level(self) -> int:
        return self.credential_subject.get("kyaLevel", 0)

    @property
    def verification_method_name(self) -> str:
        return self.credential_subject.get("verificationMethod", "")

    @property
    def exchange_account_id(self) -> str:
        return self.credential_subject.get("exchangeAccountId", "")


@dataclass
class CapabilityAttestationVC(FederationVC):
    """Agent capability attestation."""

    @property
    def capabilities(self) -> list[str]:
        return self.credential_subject.get("capabilities", [])


@dataclass
class ReputationAttestationVC(FederationVC):
    """EMA reputation score attestation — primary cross-federation VC type."""

    @property
    def reputation_score(self) -> float:
        return self.credential_subject.get("reputationScore", 0.0)

    @property
    def algorithm(self) -> str:
        return self.credential_subject.get("algorithm", "")

    @property
    def parameters(self) -> dict:
        return self.credential_subject.get("parameters", {})

    @property
    def task_count(self) -> int:
        return self.parameters.get("taskCount", 0)

    @property
    def dispute_rate(self) -> float:
        return self.parameters.get("disputeRate", 0.0)


@dataclass
class EvidenceAttestationVC(FederationVC):
    """Evidence evaluation attestation — preserves Economic Air Gap."""

    @property
    def task_id(self) -> str:
        return self.credential_subject.get("taskId", "")

    @property
    def evaluation_outcome(self) -> str:
        return self.credential_subject.get("evaluationOutcome", "")

    @property
    def evaluator_type(self) -> str:
        return self.credential_subject.get("evaluatorType", "")

    @property
    def evidence_hash(self) -> str:
        return self.credential_subject.get("evidenceHash", "")


@dataclass
class TransactionAttestationVC(FederationVC):
    """Settlement transaction proof — permanent record."""

    @property
    def transaction_id(self) -> str:
        return self.credential_subject.get("transactionId", "")

    @property
    def role(self) -> str:
        return self.credential_subject.get("role", "")

    @property
    def amount_ate(self) -> float:
        return self.credential_subject.get("amountAte", 0.0)

    @property
    def outcome(self) -> str:
        return self.credential_subject.get("outcome", "")


_TYPE_MAP: dict[str, type] = {
    "IdentityAttestation": IdentityAttestationVC,
    "CapabilityAttestation": CapabilityAttestationVC,
    "ReputationAttestation": ReputationAttestationVC,
    "EvidenceAttestation": EvidenceAttestationVC,
    "TransactionAttestation": TransactionAttestationVC,
}


def parse_federation_vc(data: dict) -> FederationVC:
    """Parse a raw VC dict into the appropriate typed dataclass."""
    types = data.get("type", [])
    proof_data = data.get("proof", {})

    cls = FederationVC
    for t in types:
        if t in _TYPE_MAP:
            cls = _TYPE_MAP[t]
            break

    return cls(
        contexts=data.get("@context", []),
        types=types,
        id=data.get("id", ""),
        issuer=data.get("issuer", ""),
        valid_from=data.get("validFrom", ""),
        valid_until=data.get("validUntil"),
        credential_subject=data.get("credentialSubject", {}),
        proof=VCProof.from_dict(proof_data),
        raw=data,
    )
