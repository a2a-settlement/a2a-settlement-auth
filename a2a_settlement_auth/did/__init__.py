"""DID resolution for the A2A-SE federation protocol.

Supports ``did:key`` (Ed25519 multicodec) and ``did:web`` resolution with
TTL-based caching for pull-on-verification federation flows.
"""

from .resolver import (
    DIDDocument,
    DIDResolutionError,
    DIDResolver,
    KeyNotFoundError,
    VerificationMethod,
)
from .rotation import KeyRotationEvent, KeyRotationError, verify_rotation_event

__all__ = [
    "DIDDocument",
    "DIDResolutionError",
    "DIDResolver",
    "KeyNotFoundError",
    "VerificationMethod",
    "KeyRotationEvent",
    "KeyRotationError",
    "verify_rotation_event",
]
