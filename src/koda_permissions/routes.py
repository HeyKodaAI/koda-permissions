"""FastAPI routes for the permission system.

Endpoints:
    GET    /api/v1/permissions/actions                  List all registered actions
    GET    /api/v1/permissions/actions/{service}         List actions for a service
    POST   /api/v1/permissions/check                    Check if an action is permitted

    GET    /api/v1/permissions/scopes                   List all scopes
    GET    /api/v1/permissions/scopes/{service}          List scopes for a service
    PUT    /api/v1/permissions/scopes/{service}/{scope}  Enable/disable a scope
    POST   /api/v1/permissions/scopes/initialize         Bulk-initialize scopes for a service

    GET    /api/v1/permissions/overrides                 List all tier overrides
    POST   /api/v1/permissions/overrides                 Create/update a tier override
    DELETE /api/v1/permissions/overrides/{action_id}     Remove a tier override

    GET    /api/v1/permissions/approvals                 List pending approvals
    GET    /api/v1/permissions/approvals/history          Approval history
    POST   /api/v1/permissions/approvals                 Create an approval request
    POST   /api/v1/permissions/approvals/{id}/resolve     Resolve an approval
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from koda_permissions.manager import PermissionManager
from koda_permissions.models import RiskTier

logger = logging.getLogger("koda_permissions.routes")

router = APIRouter(prefix="/api/v1/permissions", tags=["permissions"])

# Module-level reference, initialized by ``init_permission_routes()``.
_manager: PermissionManager | None = None


def init_permission_routes(manager: PermissionManager) -> None:
    """Inject the PermissionManager after app startup."""
    global _manager
    _manager = manager


def _get_manager() -> PermissionManager:
    if _manager is None:
        raise RuntimeError("PermissionManager not initialized")
    return _manager


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class PermissionCheckRequest(BaseModel):
    action_id: str = Field(..., min_length=1)


class ScopeToggleRequest(BaseModel):
    enabled: bool = Field(...)


class ScopeInitRequest(BaseModel):
    service: str = Field(..., min_length=1)
    scopes: list[dict] = Field(
        ...,
        description="List of {scope, risk_tier, description} dicts",
    )


class TierOverrideRequest(BaseModel):
    action_id: str = Field(..., min_length=1)
    new_tier: RiskTier = Field(...)
    reason: str = Field(default="")


class ApprovalCreateRequest(BaseModel):
    action_id: str = Field(..., min_length=1)
    description: str = Field(default="")
    context: dict = Field(default_factory=dict)


class ApprovalResolveRequest(BaseModel):
    approved: bool = Field(...)
    pin: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Action Endpoints
# ---------------------------------------------------------------------------

@router.get("/actions")
async def list_actions() -> dict:
    """List all registered actions with their risk tiers."""
    manager = _get_manager()
    actions = manager._registry.all_actions()
    return {
        "actions": [a.model_dump() for a in actions],
        "count": len(actions),
    }


@router.get("/actions/{service}")
async def list_actions_by_service(service: str) -> dict:
    """List actions for a specific service."""
    manager = _get_manager()
    actions = manager._registry.get_by_service(service)
    return {
        "service": service,
        "actions": [a.model_dump() for a in actions],
        "count": len(actions),
    }


# ---------------------------------------------------------------------------
# Permission Check
# ---------------------------------------------------------------------------

@router.post("/check")
async def check_permission(request: PermissionCheckRequest) -> dict:
    """Check whether the agent is allowed to perform an action."""
    manager = _get_manager()
    result = manager.check(request.action_id)
    return result.model_dump()


# ---------------------------------------------------------------------------
# Scope Endpoints
# ---------------------------------------------------------------------------

@router.get("/scopes")
async def list_all_scopes() -> dict:
    """List all scopes across all services."""
    manager = _get_manager()
    scopes = manager.get_all_scopes()
    return {"scopes": scopes, "count": len(scopes)}


@router.get("/scopes/{service}")
async def list_service_scopes(service: str) -> dict:
    """List scopes for a specific service."""
    manager = _get_manager()
    scopes = manager.get_service_scopes(service)
    return {"service": service, "scopes": scopes, "count": len(scopes)}


@router.put("/scopes/{service}/{scope}")
async def toggle_scope(service: str, scope: str, request: ScopeToggleRequest) -> dict:
    """Enable or disable a scope."""
    manager = _get_manager()
    if request.enabled:
        manager.enable_scope(service, scope)
    else:
        manager.disable_scope(service, scope)
    return {
        "service": service,
        "scope": scope,
        "enabled": request.enabled,
        "message": f"Scope {service}:{scope} {'enabled' if request.enabled else 'disabled'}",
    }


@router.post("/scopes/initialize")
async def initialize_service_scopes(request: ScopeInitRequest) -> dict:
    """Bulk-initialize scopes for a service (all disabled by default)."""
    manager = _get_manager()
    scope_tuples = []
    for s in request.scopes:
        tier = RiskTier(s.get("risk_tier", "high"))
        scope_tuples.append((s["scope"], tier, s.get("description", "")))

    manager.initialize_service_scopes(request.service, scope_tuples)
    return {
        "service": request.service,
        "scopes_initialized": len(scope_tuples),
        "message": "All scopes initialized as disabled (deny-by-default)",
    }


# ---------------------------------------------------------------------------
# Tier Override Endpoints
# ---------------------------------------------------------------------------

@router.get("/overrides")
async def list_overrides() -> dict:
    """List all active tier overrides."""
    manager = _get_manager()
    overrides = manager.get_overrides()
    return {"overrides": overrides, "count": len(overrides)}


@router.post("/overrides")
async def create_override(request: TierOverrideRequest) -> dict:
    """Create or update a tier override for an action."""
    manager = _get_manager()
    override_id = manager.override_tier(
        action_id=request.action_id,
        new_tier=request.new_tier,
        reason=request.reason,
    )
    if override_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown action: {request.action_id}",
        )
    return {
        "id": override_id,
        "action_id": request.action_id,
        "new_tier": request.new_tier.value,
        "message": "Tier override saved",
    }


@router.delete("/overrides/{action_id:path}")
async def delete_override(action_id: str) -> dict:
    """Remove a tier override, reverting to the default."""
    manager = _get_manager()
    success = manager.reset_tier(action_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No override found for {action_id}",
        )
    return {"action_id": action_id, "message": "Override removed, reverted to default tier"}


# ---------------------------------------------------------------------------
# Approval Endpoints
# ---------------------------------------------------------------------------

@router.get("/approvals")
async def list_pending_approvals() -> dict:
    """List all pending approval requests."""
    manager = _get_manager()
    pending = manager.get_pending_approvals()
    return {"pending": pending, "count": len(pending)}


@router.get("/approvals/history")
async def approval_history(limit: int = 50) -> dict:
    """Get approval history."""
    manager = _get_manager()
    history = manager.get_approval_history(limit)
    return {"history": history, "count": len(history)}


@router.post("/approvals")
async def create_approval(request: ApprovalCreateRequest) -> dict:
    """Create an approval request for a high/critical-tier action."""
    manager = _get_manager()
    request_id = manager.request_approval(
        action_id=request.action_id,
        description=request.description,
        context=request.context,
    )
    if request_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action does not require approval or is denied",
        )
    return {"id": request_id, "status": "pending", "message": "Approval requested"}


@router.post("/approvals/{request_id}/resolve")
async def resolve_approval(request_id: str, request: ApprovalResolveRequest) -> dict:
    """Resolve a pending approval request."""
    manager = _get_manager()
    result = manager.resolve_approval(
        request_id=request_id,
        approved=request.approved,
        pin=request.pin,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request {request_id} not found",
        )
    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"],
        )
    return result
