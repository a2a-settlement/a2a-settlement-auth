"""
Settlement Middleware — FastAPI middleware for the A2A Settlement Exchange.

Intercepts requests to settlement endpoints, validates OAuth tokens
with settlement scopes, enforces spending limits, checks counterparty
policies, and logs economic authorization decisions.

Drop-in integration with the existing A2A-SE exchange:

    from a2a_settlement_auth import SettlementMiddleware, SettlementAuthConfig

    app = FastAPI()
    config = SettlementAuthConfig(
        verification_key="your-key",
        issuer="https://idp.example.com",
    )
    app.add_middleware(SettlementMiddleware, config=config)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from .claims import SettlementClaims, CLAIMS_NAMESPACE
from .scopes import (
    SettlementScope,
    parse_scopes,
    scope_satisfies,
    scopes_for_endpoint,
)
from .spending import SpendingTracker, SpendingStore
from .tokens import (
    validate_settlement_token,
    ValidatedToken,
    SettlementTokenError,
    TokenExpiredError,
    InsufficientScopeError,
    SpendingLimitExceededError,
    CounterpartyDeniedError,
    check_counterparty,
)

logger = logging.getLogger("a2a_settlement_auth")


def _make_webhook_callback(url: str):
    """Create an on_revoke callback that POSTs to the given webhook URL."""

    async def _post_revoke(token_jti: str) -> None:
        try:
            import httpx
        except ImportError:
            logger.error(
                "revoke_webhook_url is set but httpx is not installed. "
                "Install with: pip install a2a-settlement-auth[webhook]"
            )
            return
        payload = {"event": "settlement:token:revoked", "jti": token_jti}
        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, json=payload, timeout=5.0)
        except Exception as e:
            logger.warning("Revoke webhook POST failed: %s", e)

    return _post_revoke


@dataclass
class SettlementAuthConfig:
    """Configuration for the settlement authentication middleware."""

    verification_key: str | bytes
    """Key for JWT signature verification."""

    issuer: Optional[str] = None
    """Expected JWT issuer. If None, any issuer is accepted."""

    audience: str = "https://exchange.a2a-settlement.org"
    """Expected JWT audience claim."""

    algorithms: list[str] = field(default_factory=lambda: ["HS256", "RS256", "ES256"])
    """Accepted JWT signing algorithms."""

    spending_store: Optional[SpendingStore] = None
    """Persistent store for spending tracking. Uses in-memory if None."""

    exempt_paths: set[str] = field(default_factory=lambda: {
        "/",
        "/health",
        "/docs",
        "/openapi.json",
        "/api/v1/stats",
        "/api/v1/register",  # Registration is pre-auth
    })
    """Paths that do not require settlement authentication."""

    exempt_prefixes: list[str] = field(default_factory=lambda: [
        "/.well-known/",
    ])
    """Path prefixes that do not require settlement authentication."""

    enforce_spending_limits: bool = True
    """Whether to enforce spending limits from token claims."""

    enforce_counterparty_policy: bool = True
    """Whether to enforce counterparty restrictions from token claims."""

    log_decisions: bool = True
    """Whether to log authorization decisions for audit trail."""

    on_auth_failure: Optional[Callable[[Request, str], Awaitable[None]]] = None
    """Optional async callback invoked on authorization failure (for alerting)."""

    revoke_webhook_url: Optional[str] = None
    """If set, POST settlement:token:revoked events to this URL when the kill switch fires.
    Requires httpx: pip install a2a-settlement-auth[webhook]"""


class SettlementMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that enforces settlement OAuth scopes.

    Validates tokens, checks scopes, enforces spending limits,
    and verifies counterparty policies on settlement endpoints.

    The middleware attaches the validated token to the request state
    so downstream handlers can access settlement claims:

        @app.post("/exchange/escrow")
        async def create_escrow(request: Request):
            token: ValidatedToken = request.state.settlement_token
            claims = token.settlement_claims
            # ... use claims.spending_limits, claims.counterparty_policy, etc.
    """

    def __init__(self, app, config: SettlementAuthConfig):
        super().__init__(app)
        self.config = config
        on_revoke = None
        if config.revoke_webhook_url:
            on_revoke = _make_webhook_callback(config.revoke_webhook_url)
        self.spending_tracker = SpendingTracker(
            store=config.spending_store,
            on_revoke=on_revoke,
        )

    def _is_exempt(self, path: str) -> bool:
        """Check if a path is exempt from settlement authentication."""
        if path in self.config.exempt_paths:
            return True
        return any(path.startswith(prefix) for prefix in self.config.exempt_prefixes)

    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract the Bearer token from the Authorization header."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    async def _log_decision(
        self,
        request: Request,
        allowed: bool,
        reason: str,
        token: Optional[ValidatedToken] = None,
    ):
        """Log an authorization decision for the audit trail."""
        if not self.config.log_decisions:
            return

        entry = {
            "timestamp": time.time(),
            "method": request.method,
            "path": request.url.path,
            "allowed": allowed,
            "reason": reason,
            "client_ip": request.client.host if request.client else "unknown",
        }

        if token:
            entry.update({
                "agent_id": token.settlement_claims.agent_id,
                "org_id": token.settlement_claims.org_id,
                "subject": token.subject,
                "issuer": token.issuer,
                "token_jti": token.jti,
            })

        if allowed:
            logger.info("settlement_auth_decision", extra=entry)
        else:
            logger.warning("settlement_auth_denied", extra=entry)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path
        method = request.method

        # Skip exempt paths
        if self._is_exempt(path):
            return await call_next(request)

        # Extract token
        raw_token = self._extract_token(request)
        if raw_token is None:
            await self._log_decision(request, False, "No Bearer token provided")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "authentication_required",
                    "message": "Settlement endpoints require a Bearer token with settlement scopes",
                    "docs": "https://github.com/a2a-settlement/a2a-settlement-auth",
                },
                headers={"WWW-Authenticate": 'Bearer realm="a2a-settlement"'},
            )

        # Validate token
        try:
            validated = validate_settlement_token(
                token=raw_token,
                verification_key=self.config.verification_key,
                audience=self.config.audience,
                issuer=self.config.issuer,
                algorithms=self.config.algorithms,
            )
        except TokenExpiredError:
            await self._log_decision(request, False, "Token expired")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "token_expired",
                    "message": "Settlement token has expired. Request a new token from your identity provider.",
                },
            )
        except InsufficientScopeError as e:
            await self._log_decision(request, False, str(e))
            return JSONResponse(
                status_code=403,
                content={
                    "error": "insufficient_scope",
                    "message": str(e),
                    "required_scope": e.required.value,
                },
            )
        except SettlementTokenError as e:
            await self._log_decision(request, False, f"Token validation failed: {e}")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_token",
                    "message": str(e),
                },
            )

        # Check required scope for this endpoint
        required_scope = scopes_for_endpoint(method, path)
        if required_scope and not scope_satisfies(validated.scopes, required_scope):
            reason = (
                f"Endpoint {method} {path} requires scope '{required_scope.value}'"
            )
            await self._log_decision(request, False, reason, validated)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "insufficient_scope",
                    "message": reason,
                    "required_scope": required_scope.value,
                    "granted_scopes": [s.value for s in validated.scopes],
                },
            )

        # Check spending limits for escrow creation
        if (
            self.config.enforce_spending_limits
            and path.endswith("/escrow")
            and method == "POST"
        ):
            try:
                body = await request.body()
                body_json = json.loads(body) if body else {}
                amount = body_json.get("amount", 0)

                if amount > 0:
                    check = await self.spending_tracker.check(
                        token_jti=validated.jti,
                        amount=amount,
                        limits=validated.settlement_claims.spending_limits,
                    )
                    if not check.allowed:
                        await self._log_decision(
                            request, False, f"Spending limit: {check.reason}", validated
                        )
                        if self.config.on_auth_failure:
                            await self.config.on_auth_failure(request, check.reason)
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "spending_limit_exceeded",
                                "message": check.reason,
                                "remaining": {
                                    "per_transaction": check.remaining_per_transaction,
                                    "per_session": check.remaining_per_session,
                                    "per_hour": check.remaining_per_hour,
                                    "per_day": check.remaining_per_day,
                                },
                            },
                        )
            except (json.JSONDecodeError, AttributeError):
                pass  # If we can't parse the body, let the exchange handle validation

        # Attach validated token to request state
        request.state.settlement_token = validated

        # Log success
        await self._log_decision(request, True, "Authorized", validated)

        # Continue to the exchange handler
        return await call_next(request)
