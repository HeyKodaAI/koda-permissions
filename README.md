# koda-permissions

Deny-by-default, risk-tiered permission system for AI agent actions.

## What & why

`koda_permissions` is the access-control layer extracted from [Koda AI](https://github.com/HeyKodaAI) — "the AI agent that never lies" — part of the Koda project by Mike Wandzilak / Wandzilak Web Design. In Koda, every action the agent wants to take (send an email, delete a file, run a shell command) passes through this module first. It answers one question: *can the agent do X, and what does the user need to see before or after it happens?*

It is deliberately framework-agnostic: a small Pydantic + SQLite core with an optional FastAPI router. It suits any agent stack that needs risk-tiered action gating — OpenClaw/Clawdbot-style agents, custom orchestrators, or MCP tool servers.

## How it works

Every action has an id of the form `service:action` (or `service.action` — both delimiters are accepted interchangeably) and a risk tier:

| Tier | Default behavior |
|---|---|
| `LOW` | Execute silently |
| `MEDIUM` | Execute, then notify the user |
| `HIGH` | Require explicit approval first |
| `CRITICAL` | Require approval plus a PIN |

A permission check runs in two stages:

1. **Scope gate (allow/deny).** Each action declares required scopes (e.g. `gmail:send_email` requires the `send` scope on `gmail`). A scope that has not been explicitly enabled is denied — there is no implicit grant anywhere.
2. **Tier gate (approval behavior).** If all scopes are enabled, the action's effective risk tier (default, or a user tier override) maps to one of the four approval behaviors above.

## Features

- **Deny by default.** `PermissionStorage.is_scope_enabled()` returns `False` for anything unknown; a missing scope means a denied check.
- **Action registry** with 70+ built-in `ActionDefinition`s (gmail, calendar, slack, github, filesystem, browser, shell, credentials, and Koda's own self-tools), extensible via `register()` / `register_many()` for plugins and skills.
- **Auto-registration of unknown actions.** A check against an unregistered `service:action` id registers it on the fly with a risk tier and required scopes inferred from the action name (`delete`/`remove`/`destroy` → HIGH, `write`/`send`/`create`/`execute`/`control` → MEDIUM, else LOW/read). The auto-registered action is still **denied** until its scopes are explicitly enabled — deny-by-default holds; inference only classifies, it never grants.
- **User tier overrides.** Power users can lower an action's tier, cautious users can raise it; overrides persist and can be reset to defaults.
- **Approval queue.** `request_approval()` / `resolve_approval()` with pending/approved/denied/expired states, PIN enforcement for CRITICAL-tier actions, and queryable history.
- **SQLite persistence** (WAL mode) for scopes, overrides, and approvals — a single file, no server.
- **FastAPI router** exposing the whole system under `/api/v1/permissions/*`.

## Install

Not yet on PyPI. Requires Python 3.11+.

```bash
pip install git+https://github.com/HeyKodaAI/koda-permissions.git
```

Dependencies: `pydantic>=2.0`, `fastapi>=0.110`.

## Quickstart

```python
from koda_permissions.manager import PermissionManager
from koda_permissions.models import RiskTier
from koda_permissions.registry import ActionRegistry
from koda_permissions.storage import PermissionStorage

# ":memory:" for the demo; pass a file path for persistent settings
storage = PermissionStorage(":memory:")
registry = ActionRegistry()
manager = PermissionManager(registry, storage)

# 1. Deny by default: no scope enabled, no action allowed
result = manager.check("gmail:send_email")
print(result.allowed, "-", result.reason)
# False - Missing required scopes: gmail:send

# 2. Enable the scope, and the tier decides the approval behavior
manager.enable_scope("gmail", "send", risk_tier=RiskTier.MEDIUM)
result = manager.check("gmail:send_email")
print(result.allowed, result.risk_tier.value, result.approval_behavior.value)
# True medium notify_after

# 3. HIGH-tier actions go through the approval queue
manager.enable_scope("gmail", "delete")
req_id = manager.request_approval("gmail:delete_email", description="Delete 3 newsletters")
resolved = manager.resolve_approval(req_id, approved=True)
print(resolved["status"])
# approved

# 4. Unknown actions are auto-registered with an inferred tier
#    but stay denied until their scopes are explicitly enabled
result = manager.check("smart_home:control_lights")
print(result.allowed, result.risk_tier.value, "-", result.reason)
# False medium - Missing required scopes: smart_home:write
```

## API overview

- **`koda_permissions.manager.PermissionManager`** — the central authority. `check(action_id) -> PermissionCheckResult`; scope management (`enable_scope`, `disable_scope`, `get_service_scopes`, `get_all_scopes`, `initialize_service_scopes`); tier overrides (`override_tier`, `reset_tier`, `get_overrides`); approvals (`request_approval`, `resolve_approval`, `get_pending_approvals`, `get_approval_history`).
- **`koda_permissions.registry.ActionRegistry`** — catalog of `ActionDefinition`s. `get()` tolerates both `:` and `.` separators; `get_by_service()`, `all_actions()`, `services()`, `register()`, `register_many()`.
- **`koda_permissions.storage.PermissionStorage`** — SQLite backend (scopes, tier overrides, approval requests). Construct with a db path or `":memory:"`.
- **`koda_permissions.models`** — `RiskTier`, `ApprovalBehavior`, `DEFAULT_TIER_BEHAVIORS`, `ServiceScope`, `ServicePermissions`, `ActionDefinition`, `PermissionCheckResult`, `ApprovalRequest`, `ApprovalResponse`, `TierOverride`.
- **`koda_permissions.routes`** — FastAPI `router` (prefix `/api/v1/permissions`) with endpoints for actions, checks, scopes, overrides, and approvals. Call `init_permission_routes(manager)` at startup, then `app.include_router(router)`.

Typical agent loop integration:

```python
result = manager.check(action_id)
if not result.allowed:
    ...  # report denial (result.reason, result.missing_scopes)
elif result.approval_behavior.value in ("require_approval", "require_approval_pin"):
    req_id = manager.request_approval(action_id, description="...")
    ...  # surface to the user, execute only after resolve_approval(req_id, approved=True)
else:
    ...  # execute (and notify afterwards if behavior is notify_after)
```

## Testing

```bash
pip install -e . pytest pytest-asyncio
pytest
```

52 tests covering the manager, registry, and storage layers.

## License

MIT
