"""
Settlement Scopes — OAuth 2.0 scope definitions for agent economic authorization.

Extends standard OAuth scopes with a `settlement:` namespace that expresses
what economic actions an agent is authorized to perform.

Scope Hierarchy:
    settlement:read          — View balances, transaction history, reputation
    settlement:escrow:create — Create new escrow holds
    settlement:escrow:release — Release escrow funds to counterparty
    settlement:escrow:refund — Cancel/refund escrow back to requester
    settlement:dispute:file  — File a dispute on a transaction
    settlement:dispute:resolve — Resolve disputes (mediator role)
    settlement:transact      — Shorthand for create + release + refund
    settlement:admin         — Full settlement authority (includes all above)

Usage:
    from a2a_settlement_auth.scopes import SettlementScope, parse_scopes, scope_satisfies

    # Check if a token's scopes allow escrow creation
    token_scopes = parse_scopes("openid profile settlement:transact")
    assert scope_satisfies(token_scopes, SettlementScope.ESCROW_CREATE)
"""

from enum import Enum
from typing import Set


class SettlementScope(str, Enum):
    """OAuth 2.0 settlement scope values.

    These scopes are included in the `scope` parameter of OAuth token
    requests and appear in the `scope` claim of issued tokens.
    """

    # Read-only access to settlement data
    READ = "settlement:read"

    # Escrow lifecycle
    ESCROW_CREATE = "settlement:escrow:create"
    ESCROW_DELIVER = "settlement:escrow:deliver"
    ESCROW_RELEASE = "settlement:escrow:release"
    ESCROW_REFUND = "settlement:escrow:refund"

    # Dispute lifecycle
    DISPUTE_FILE = "settlement:dispute:file"
    DISPUTE_RESOLVE = "settlement:dispute:resolve"

    # Composite scopes
    TRANSACT = "settlement:transact"  # create + release + refund
    ADMIN = "settlement:admin"  # all settlement operations


# Scope expansion: composite scopes expand to their constituent parts
_SCOPE_EXPANSIONS: dict[SettlementScope, Set[SettlementScope]] = {
    SettlementScope.TRANSACT: {
        SettlementScope.READ,
        SettlementScope.ESCROW_CREATE,
        SettlementScope.ESCROW_DELIVER,
        SettlementScope.ESCROW_RELEASE,
        SettlementScope.ESCROW_REFUND,
    },
    SettlementScope.ADMIN: {
        SettlementScope.READ,
        SettlementScope.ESCROW_CREATE,
        SettlementScope.ESCROW_DELIVER,
        SettlementScope.ESCROW_RELEASE,
        SettlementScope.ESCROW_REFUND,
        SettlementScope.DISPUTE_FILE,
        SettlementScope.DISPUTE_RESOLVE,
        SettlementScope.TRANSACT,
    },
}

# Map exchange API endpoints to required scopes
ENDPOINT_SCOPE_MAP: dict[str, SettlementScope] = {
    # Balance & history (read)
    "GET /exchange/balance": SettlementScope.READ,
    "GET /exchange/transactions": SettlementScope.READ,
    "GET /exchange/escrows": SettlementScope.READ,
    # Escrow lifecycle
    "POST /exchange/escrow": SettlementScope.ESCROW_CREATE,
    "POST /exchange/escrow/batch": SettlementScope.ESCROW_CREATE,
    "POST /exchange/release": SettlementScope.ESCROW_RELEASE,
    "POST /exchange/refund": SettlementScope.ESCROW_REFUND,
    "POST /exchange/deposit": SettlementScope.ESCROW_CREATE,
    # Deliver (dynamic path: /exchange/escrow/{id}/deliver)
    "POST /exchange/escrow/*/deliver": SettlementScope.ESCROW_DELIVER,
    # Disputes
    "POST /exchange/dispute": SettlementScope.DISPUTE_FILE,
    "POST /exchange/resolve": SettlementScope.DISPUTE_RESOLVE,
}


def parse_scopes(scope_string: str) -> Set[SettlementScope]:
    """Parse an OAuth scope string and return the set of settlement scopes.

    Non-settlement scopes (e.g., 'openid', 'profile') are silently ignored.
    Composite scopes are expanded to their constituent parts.

    Args:
        scope_string: Space-delimited OAuth scope string.

    Returns:
        Set of SettlementScope values present in the string.

    Example:
        >>> parse_scopes("openid settlement:transact")
        {SettlementScope.READ, SettlementScope.TRANSACT,
         SettlementScope.ESCROW_CREATE, SettlementScope.ESCROW_RELEASE,
         SettlementScope.ESCROW_REFUND}
    """
    raw_scopes = scope_string.strip().split()
    settlement_scopes: Set[SettlementScope] = set()

    for raw in raw_scopes:
        try:
            scope = SettlementScope(raw)
            settlement_scopes.add(scope)
            # Expand composite scopes
            if scope in _SCOPE_EXPANSIONS:
                settlement_scopes.update(_SCOPE_EXPANSIONS[scope])
        except ValueError:
            # Not a settlement scope — ignore (e.g., 'openid', 'profile')
            continue

    return settlement_scopes


def scope_satisfies(granted: Set[SettlementScope], required: SettlementScope) -> bool:
    """Check whether a set of granted scopes satisfies a required scope.

    Handles composite scope expansion: if the granted set includes
    `settlement:transact`, it satisfies `settlement:escrow:create`.

    Args:
        granted: The scopes present in the agent's token.
        required: The scope required for the requested operation.

    Returns:
        True if the granted scopes include or expand to cover the required scope.
    """
    if required in granted:
        return True

    # Check if any granted composite scope expands to cover the required scope
    for scope in granted:
        expanded = _SCOPE_EXPANSIONS.get(scope, set())
        if required in expanded:
            return True

    return False


def scopes_for_endpoint(method: str, path: str) -> SettlementScope | None:
    """Look up the required settlement scope for an exchange API endpoint.

    Strips versioned prefixes (/v1/, /api/v1/) before matching so the
    scope map works regardless of how the exchange mounts its routes.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: URL path (e.g., '/v1/exchange/escrow' or '/exchange/escrow')

    Returns:
        The required SettlementScope, or None if the endpoint is not
        settlement-scoped (i.e., public or non-settlement).
    """
    normalized = path
    for prefix in ("/api/v1", "/v1"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break

    key = f"{method.upper()} {normalized}"
    result = ENDPOINT_SCOPE_MAP.get(key)
    if result:
        return result

    # Check wildcard patterns (e.g. POST /exchange/escrow/*/deliver)
    parts = normalized.strip("/").split("/")
    for pattern, scope in ENDPOINT_SCOPE_MAP.items():
        pat_method, pat_path = pattern.split(" ", 1)
        if pat_method != method.upper():
            continue
        pat_parts = pat_path.strip("/").split("/")
        if len(pat_parts) != len(parts):
            continue
        if all(pp == "*" or pp == rp for pp, rp in zip(pat_parts, parts)):
            return scope

    return None


def format_scopes(scopes: Set[SettlementScope]) -> str:
    """Format a set of settlement scopes back into an OAuth scope string.

    Args:
        scopes: Set of SettlementScope values.

    Returns:
        Space-delimited scope string.
    """
    return " ".join(sorted(s.value for s in scopes))
