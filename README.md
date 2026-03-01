# A2A Settlement Auth

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

**OAuth 2.0 settlement scopes for agent economic authorization.**

Extends OAuth tokens with the missing economic layer: not just *what can this agent access?* but **what can this agent spend?**

```
┌──────────────────┐       OAuth Token         ┌──────────────┐
│ Identity Provider│──── with settlement ─────►│  A2A-SE      │
│ (Keycloak, Auth0,│     scopes & claims       │  Exchange    │
│  Okta, Azure AD) │                           │              │
└──────────────────┘                           └──────┬───────┘
                                                      │
        Standard OAuth scopes:                        │ Middleware validates:
        settlement:transact                           │ ✓ Scope sufficiency
        settlement:escrow:create                      │ ✓ Spending limits
        settlement:escrow:release                     │ ✓ Counterparty policy
                                                      │ ✓ Delegation chain
        Settlement claims (JWT):                      │ ✓ Kill switch status
        - spending_limits                             │
        - counterparty_policy                         ▼
        - delegation_chain                     Agent transacts
```

## Why This Exists

The [NIST NCCoE Concept Paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf) on AI Agent Identity and Authorization evaluates OAuth 2.0, OpenID Connect, and SPIFFE as identity standards for agents. These standards answer *who is this agent?* and *what systems can it access?*

None of them answer: **what economic commitments can this agent make?**

This library bridges that gap. It extends OAuth tokens with a `settlement:` scope namespace and a structured claims payload that expresses spending limits, counterparty restrictions, delegation chains, and settlement method constraints. The [A2A Settlement Exchange](https://github.com/a2a-settlement/a2a-settlement) validates these tokens before processing any economic transaction.

## Install

```bash
pip install a2a-settlement-auth
```

## Quick Start

### 1. Issue a Settlement-Scoped Token

Your identity provider issues a token with settlement scopes and claims:

```python
from a2a_settlement_auth import (
    SettlementClaims,
    SettlementScope,
    SpendingLimit,
    CounterpartyPolicy,
    DelegationChain,
    DelegationLink,
    create_settlement_token,
)

claims = SettlementClaims(
    agent_id="analytics-bot-7f3a",
    org_id="org-acme-corp",
    spending_limits=SpendingLimit(
        per_transaction=500,   # Max 500 tokens per escrow
        per_day=5000,          # Max 5000 tokens in rolling 24h
    ),
    counterparty_policy=CounterpartyPolicy(
        allowed_categories=["analytics", "nlp"],
        require_min_reputation=0.7,
    ),
    delegation=DelegationChain(
        chain=[
            DelegationLink(
                principal="user:julie@acme.com",
                delegated_at="2026-03-01T09:00:00Z",
                purpose="Q1 analytics procurement",
            ),
        ],
        transferable=False,
    ),
)

token = create_settlement_token(
    claims=claims,
    scopes={SettlementScope.TRANSACT},
    signing_key="your-signing-key",
    issuer="https://idp.acme.com",
)
```

### 2. Validate on the Exchange

```python
from a2a_settlement_auth import validate_settlement_token

validated = validate_settlement_token(
    token=token,
    verification_key="your-signing-key",
    audience="https://exchange.a2a-settlement.org",
)

print(validated.settlement_claims.spending_limits.per_transaction)  # 500
print(validated.settlement_claims.delegation.human_principal)       # user:julie@acme.com
```

### 3. Add Middleware to the Exchange

```python
from fastapi import FastAPI
from a2a_settlement_auth import SettlementMiddleware, SettlementAuthConfig

app = FastAPI()

config = SettlementAuthConfig(
    verification_key="your-signing-key",
    issuer="https://idp.acme.com",
    enforce_spending_limits=True,
    enforce_counterparty_policy=True,
)

app.add_middleware(SettlementMiddleware, config=config)
```

The middleware automatically:
- Validates Bearer tokens on all settlement endpoints
- Checks scopes against endpoint requirements
- Enforces spending limits before escrow creation
- Logs authorization decisions for audit
- Attaches `request.state.settlement_token` for downstream handlers

### 4. Track Spending

```python
from a2a_settlement_auth import SpendingTracker

tracker = SpendingTracker()

# Before authorizing an escrow
result = await tracker.check(
    token_jti=validated.jti,
    amount=200,
    limits=validated.settlement_claims.spending_limits,
)
if not result.allowed:
    raise Exception(result.reason)

# After escrow confirmed
await tracker.record(validated.jti, 200, "escrow-001", "counterparty-bot")

# Emergency kill switch
await tracker.revoke(validated.jti)
```

## Settlement Scopes

| Scope | Description |
|-------|-------------|
| `settlement:read` | View balances, history, reputation |
| `settlement:escrow:create` | Create escrow holds |
| `settlement:escrow:release` | Release escrowed funds |
| `settlement:escrow:refund` | Refund escrowed funds |
| `settlement:dispute:file` | File a dispute |
| `settlement:dispute:resolve` | Resolve disputes (mediator) |
| `settlement:transact` | Composite: create + release + refund + read |
| `settlement:admin` | All settlement operations |

Scopes follow OAuth 2.0 conventions. The `settlement:transact` composite scope expands to its constituent parts, so a token with `settlement:transact` is authorized for `settlement:escrow:create`.

## Settlement Claims

Claims are namespaced under `https://a2a-settlement.org/claims` in the JWT payload per [RFC 7519 §4.2](https://tools.ietf.org/html/rfc7519#section-4.2):

```json
{
  "sub": "agent:analytics-bot-7f3a",
  "scope": "settlement:transact",
  "https://a2a-settlement.org/claims": {
    "agent_id": "analytics-bot-7f3a",
    "org_id": "org-acme-corp",
    "spending_limits": {
      "per_transaction": 500,
      "per_day": 5000
    },
    "counterparty_policy": {
      "allowed_categories": ["analytics", "nlp"],
      "require_min_reputation": 0.7
    },
    "delegation": {
      "chain": [{
        "principal": "user:julie@acme.com",
        "delegated_at": "2026-03-01T09:00:00Z",
        "purpose": "Q1 analytics procurement"
      }],
      "transferable": false
    }
  }
}
```

### Claim Reference

| Claim | Type | Description |
|-------|------|-------------|
| `agent_id` | string | Agent's ID on the settlement exchange |
| `org_id` | string | Owning organization |
| `spending_limits.per_transaction` | float | Max tokens per escrow |
| `spending_limits.per_session` | float | Max tokens for token lifetime |
| `spending_limits.per_hour` | float | Max tokens per rolling hour |
| `spending_limits.per_day` | float | Max tokens per rolling 24h |
| `counterparty_policy.allowed_categories` | string[] | Permitted counterparty categories |
| `counterparty_policy.blocked_agents` | string[] | Denied counterparty agent IDs |
| `counterparty_policy.blocked_orgs` | string[] | Denied counterparty org IDs |
| `counterparty_policy.require_min_reputation` | float | Min reputation score (0–1) |
| `counterparty_policy.require_certified` | bool | Require certified counterparties |
| `delegation.chain` | object[] | Ordered delegation links |
| `delegation.transferable` | bool | Can the agent sub-delegate? |
| `settlement_methods` | string[] | Permitted methods (token, fiat) |
| `environment` | string | Deployment env (production, sandbox) |
| `certification_id` | string | Agent ATO/certification reference |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Identity Provider (IdP)                       │
│  Issues OAuth tokens with settlement scopes + claims            │
│  (Keycloak, Auth0, Okta, Azure AD, custom)                      │
└─────────────────────────────┬───────────────────────────────────┘
                              │ Bearer token
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  SettlementMiddleware                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐   │
│  │  Token   │  │  Scope   │  │ Spending │  │ Counterparty  │   │
│  │Validator │─►│  Check   │─►│  Check   │─►│Policy Check   │   │
│  └──────────┘  └──────────┘  └──────────┘  └───────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │ request.state.settlement_token
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                A2A Settlement Exchange                          │
│  Escrow • Release • Refund • Reputation • Disputes              │
└─────────────────────────────────────────────────────────────────┘
```

## Integration with NIST Standards

This library implements concepts from:

- **NIST SP 800-207** (Zero Trust Architecture) — every settlement request is verified independently
- **NIST SP 800-63-4** (Digital Identity Guidelines) — agent identity linked to human principals
- **OAuth 2.0/2.1** — standard scope and token mechanisms extended for economic authorization
- **NIST AI RMF** (AI 100-1) — settlement monitoring as a Measure function for agent security

It is designed to complement the [NIST NCCoE demonstration project](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf) on AI Agent Identity and Authorization by providing the economic authorization layer that existing identity standards do not address.

## Testing

```bash
pip install -e ".[dev]"
pytest
python smoke_test.py           # Full lifecycle (create→validate→spending→revoke)
python smoke_test.py -v       # Same, with verbose example output
```

## Related Projects

| Project | Description |
|---------|-------------|
| [a2a-settlement](https://github.com/a2a-settlement/a2a-settlement) | Core settlement exchange + SDK |
| [a2a-settlement-mediator](https://github.com/a2a-settlement/a2a-settlement-mediator) | AI-powered dispute resolution |
| [crewai-a2a-settlement](https://github.com/a2a-settlement/crewai-a2a-settlement) | CrewAI framework integration |
| [litellm-a2a-settlement](https://github.com/a2a-settlement/litellm-a2a-settlement) | LiteLLM framework integration |

## License

MIT
