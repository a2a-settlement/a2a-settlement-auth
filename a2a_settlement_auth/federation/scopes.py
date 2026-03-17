"""Federation OAuth scopes extending the settlement scope namespace.

Defines scopes for federation operations: peering, verification,
attestation import/export.
"""

from __future__ import annotations

from enum import Enum


class FederationScope(str, Enum):
    PEER = "federation:peer"
    VERIFY = "federation:verify"
    ATTESTATION_IMPORT = "federation:attestation:import"
    ATTESTATION_EXPORT = "federation:attestation:export"
    HEALTH_READ = "federation:health:read"
    ADMIN = "federation:admin"


FEDERATION_SCOPES: set[str] = {s.value for s in FederationScope}

FEDERATION_ENDPOINT_SCOPE_MAP: dict[tuple[str, str], set[str]] = {
    ("POST", "/federation/peer"): {FederationScope.PEER.value},
    ("POST", "/federation/verify"): {FederationScope.VERIFY.value},
    ("POST", "/federation/attestation/import"): {
        FederationScope.ATTESTATION_IMPORT.value
    },
    ("GET", "/.well-known/a2a-federation-health"): set(),
    ("GET", "/.well-known/a2a-trust-policy.json"): set(),
}
