"""Unified DID resolver supporting ``did:key`` (Ed25519) and ``did:web``.

Provides TTL-based caching for the pull-on-verification model defined in
the A2A-SE Federation Protocol (Section 01, §3.2).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import unquote

import httpx

DID_KEY_ED25519_PREFIX = b"\xed\x01"
MULTICODEC_ED25519 = 0xED


class DIDResolutionError(Exception):
    """Raised when DID resolution fails."""


class KeyNotFoundError(Exception):
    """Raised when a verification method key ID is not in the DID document."""


@dataclass
class VerificationMethod:
    """A single verification key from a DID document."""

    id: str
    type: str
    controller: str
    public_key_multibase: str


@dataclass
class DIDDocument:
    """Parsed DID document with extracted verification methods."""

    id: str
    verification_methods: list[VerificationMethod]
    service_endpoints: list[str]
    controller: Optional[str]
    raw: dict
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DIDResolver:
    """Resolves ``did:key`` and ``did:web`` identifiers to DID documents.

    Parameters
    ----------
    cache_ttl_seconds:
        How long resolved documents are cached. Federation spec recommends
        900–3600 (15–60 minutes) for pull-on-verification.
    http_timeout:
        Timeout in seconds for HTTP fetches (``did:web``).
    http_client:
        Optional pre-configured ``httpx.AsyncClient``.
    """

    def __init__(
        self,
        cache_ttl_seconds: int = 900,
        http_timeout: int = 10,
        http_client: httpx.Client | None = None,
    ):
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.http_timeout = http_timeout
        self._cache: dict[str, DIDDocument] = {}
        self._client = http_client

    def resolve(self, did: str, force_refresh: bool = False) -> DIDDocument:
        """Resolve a DID to a :class:`DIDDocument`.

        Dispatches to the appropriate method-specific resolver.
        """
        if not force_refresh:
            cached = self._cache.get(did)
            if cached is not None:
                age = datetime.now(timezone.utc) - cached.resolved_at
                if age < self.cache_ttl:
                    return cached

        if did.startswith("did:key:"):
            doc = self._resolve_did_key(did)
        elif did.startswith("did:web:"):
            doc = self._resolve_did_web(did)
        else:
            raise DIDResolutionError(f"Unsupported DID method: {did}")

        self._cache[did] = doc
        return doc

    def extract_verification_method(
        self, doc: DIDDocument, key_id: str
    ) -> VerificationMethod:
        """Look up a specific verification method by its full key ID."""
        for vm in doc.verification_methods:
            if vm.id == key_id:
                return vm
        raise KeyNotFoundError(
            f"Key {key_id!r} not found in DID document {doc.id}"
        )

    def invalidate(self, did: str) -> None:
        """Remove a DID from the cache (e.g. on key rotation detection)."""
        self._cache.pop(did, None)

    def clear_cache(self) -> None:
        self._cache.clear()

    def evict_expired(self) -> None:
        """Remove cache entries whose TTL has elapsed."""
        now = datetime.now(timezone.utc)
        expired = [
            k
            for k, v in self._cache.items()
            if (now - v.resolved_at) >= self.cache_ttl
        ]
        for k in expired:
            del self._cache[k]

    # ------------------------------------------------------------------
    # did:key resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_did_key(did: str) -> DIDDocument:
        """Resolve a ``did:key`` by decoding the multibase public key.

        ``did:key`` documents are self-contained — the public key is encoded
        directly in the identifier, so no network call is needed.
        """
        if not did.startswith("did:key:z"):
            raise DIDResolutionError(
                f"Invalid did:key format (expected 'z' multibase prefix): {did}"
            )

        multibase_value = did[len("did:key:"):]
        try:
            decoded = _decode_base58btc(multibase_value[1:])  # strip 'z' prefix
        except Exception as exc:
            raise DIDResolutionError(
                f"Failed to decode did:key multibase value: {exc}"
            ) from exc

        if len(decoded) < 2:
            raise DIDResolutionError("did:key decoded value too short")

        codec_prefix = decoded[:2]
        if codec_prefix != DID_KEY_ED25519_PREFIX:
            raise DIDResolutionError(
                f"Unsupported multicodec: expected Ed25519 (0xed01), "
                f"got {codec_prefix.hex()}"
            )

        public_key_bytes = decoded[2:]
        if len(public_key_bytes) != 32:
            raise DIDResolutionError(
                f"Invalid Ed25519 public key length: {len(public_key_bytes)}"
            )

        key_id = f"{did}#{multibase_value}"
        vm = VerificationMethod(
            id=key_id,
            type="Ed25519VerificationKey2020",
            controller=did,
            public_key_multibase=multibase_value,
        )

        raw = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": did,
            "verificationMethod": [
                {
                    "id": key_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": multibase_value,
                }
            ],
            "authentication": [key_id],
            "assertionMethod": [key_id],
        }

        return DIDDocument(
            id=did,
            verification_methods=[vm],
            service_endpoints=[],
            controller=None,
            raw=raw,
        )

    # ------------------------------------------------------------------
    # did:web resolution
    # ------------------------------------------------------------------

    def _resolve_did_web(self, did: str) -> DIDDocument:
        """Resolve a ``did:web`` by fetching the HTTPS DID document."""
        url = self.did_web_to_url(did)
        try:
            client = self._client or httpx.Client(
                verify=True, timeout=self.http_timeout
            )
            try:
                resp = client.get(url)
                resp.raise_for_status()
            finally:
                if self._client is None:
                    client.close()
        except httpx.HTTPStatusError as exc:
            raise DIDResolutionError(
                f"HTTP {exc.response.status_code} fetching DID document from {url}"
            ) from exc
        except httpx.RequestError as exc:
            raise DIDResolutionError(
                f"Failed to fetch DID document from {url}: {exc}"
            ) from exc

        try:
            data = resp.json()
        except ValueError as exc:
            raise DIDResolutionError(
                f"Invalid JSON in DID document from {url}"
            ) from exc

        return self._parse_document(did, data)

    @staticmethod
    def did_web_to_url(did: str) -> str:
        """Convert a ``did:web`` identifier to its HTTPS document URL."""
        if not did.startswith("did:web:"):
            raise DIDResolutionError(f"Not a did:web identifier: {did}")

        remainder = did[len("did:web:"):]
        parts = remainder.split(":")
        domain = unquote(parts[0])
        path_segments = [unquote(p) for p in parts[1:]]

        if path_segments:
            path = "/".join(path_segments) + "/did.json"
        else:
            path = ".well-known/did.json"

        return f"https://{domain}/{path}"

    @staticmethod
    def _parse_document(did: str, data: dict) -> DIDDocument:
        doc_id = data.get("id", did)
        vms: list[VerificationMethod] = []
        for vm_raw in data.get("verificationMethod", []):
            pkm = vm_raw.get("publicKeyMultibase", "")
            vms.append(
                VerificationMethod(
                    id=vm_raw.get("id", ""),
                    type=vm_raw.get("type", ""),
                    controller=vm_raw.get("controller", ""),
                    public_key_multibase=pkm,
                )
            )
        services: list[str] = []
        for svc in data.get("service", []):
            endpoint = svc.get("serviceEndpoint", "")
            if isinstance(endpoint, str):
                services.append(endpoint)
            elif isinstance(endpoint, list):
                services.extend(endpoint)
        controller = data.get("controller")
        return DIDDocument(
            id=doc_id,
            verification_methods=vms,
            service_endpoints=services,
            controller=controller,
            raw=data,
        )

    # ------------------------------------------------------------------
    # did:key generation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def generate_did_key(public_key_bytes: bytes) -> str:
        """Generate a ``did:key`` identifier from a raw Ed25519 public key."""
        if len(public_key_bytes) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        prefixed = DID_KEY_ED25519_PREFIX + public_key_bytes
        encoded = _encode_base58btc(prefixed)
        return f"did:key:z{encoded}"


# ------------------------------------------------------------------
# Base58btc encoding/decoding (Bitcoin alphabet)
# ------------------------------------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _encode_base58btc(data: bytes) -> str:
    """Encode bytes to base58btc (Bitcoin alphabet)."""
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(_B58_ALPHABET[rem:rem + 1])
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _decode_base58btc(s: str) -> bytes:
    """Decode a base58btc string to bytes."""
    num = 0
    for c in s.encode("ascii"):
        if c not in _B58_MAP:
            raise ValueError(f"Invalid base58btc character: {chr(c)}")
        num = num * 58 + _B58_MAP[c]
    leading_zeros = 0
    for c in s.encode("ascii"):
        if c == ord("1"):
            leading_zeros += 1
        else:
            break
    if num == 0:
        return b"\x00" * leading_zeros
    result = num.to_bytes((num.bit_length() + 7) // 8, "big")
    return b"\x00" * leading_zeros + result
