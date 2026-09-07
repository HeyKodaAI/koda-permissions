"""Permission Manager — the central authority for "can the agent do X?"

This is the single function the agent orchestrator will call before executing
any action.  It combines the action registry, user scope settings, tier
overrides, and approval state into a clean allow/deny decision.

Design principles (from spec):
  - Deny by default — if a scope isn't explicitly enabled, it's denied
  - Risk tiers drive approval flow — LOW is silent, CRITICAL needs a PIN
  - Users can override tiers (power users lower them, cautious users raise)
  - Every decision is auditable
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from koda_permissions.models import (
    ApprovalBehavior,
    ApprovalRequest,
    DEFAULT_TIER_BEHAVIORS,
    PermissionCheckResult,
    RiskTier,
)
from koda_permissions.registry import ActionRegistry
from koda_permissions.storage import PermissionStorage

logger = logging.getLogger("koda_permissions.manager")


class PermissionManager:
    """Central permission authority for the agent.

    Usage:
        result = manager.check("gmail:send_email")
        if result.allowed:
            if result.approval_behavior in (ApprovalBehavior.REQUIRE_APPROVAL,
                                             ApprovalBehavior.REQUIRE_APPROVAL_PIN):
                req_id = manager.request_approval("gmail:send_email", ...)
                # ... wait for user response ...
            else:
                # execute the action
        else:
            # report denial to user
    """

    def __init__(
        self,
        registry: ActionRegistry,
        storage: PermissionStorage,
        *,
        pin_verifier: Callable[[str], bool] | None = None,
    ) -> None:
        self._registry = registry
        self._storage = storage
        self._pin_verifier = pin_verifier
        self._storage.normalize_tier_overrides()

    # ------------------------------------------------------------------
    # Core Permission Check
    # ------------------------------------------------------------------

    def check(self, action_id: str) -> PermissionCheckResult:
        """Check whether the agent is allowed to perform an action.

        Returns a ``PermissionCheckResult`` that tells the agent:
        1. Whether the action is allowed at all (scope-level)
        2. What approval behavior applies (tier-level)
        3. What's missing if denied
        """
        action_id = action_id.replace(".", ":", 1) if ":" not in action_id else action_id
        action = self._registry.get(action_id)

        if action is None:
            # Auto-register unknown actions so new tools work without manual
            # registry entries.  Infer service + action from the ID pattern
            # (e.g. "smart_home.list_devices" → service="smart_home", action="list_devices").
            sep = "." if "." in action_id else ":"
            parts = action_id.split(sep, 1)
            if len(parts) == 2:
                service, act = parts
                # Infer risk tier from action name conventions
                if any(k in act for k in ("delete", "remove", "destroy")):
                    tier = RiskTier.HIGH
                elif any(k in act for k in ("write", "send", "create", "execute", "control")):
                    tier = RiskTier.MEDIUM
                else:
                    tier = RiskTier.LOW
                # Infer required scopes from action name
                if any(k in act for k in ("delete", "remove", "destroy")):
                    scopes = ["delete"]
                elif any(k in act for k in ("write", "send", "create", "execute", "control", "trigger")):
                    scopes = ["write"] if "send" not in act else ["send"]
                else:
                    scopes = ["read"]
                from koda_permissions.models import ActionDefinition
                action = ActionDefinition(
                    action_id=action_id,
                    service=service,
                    action=act,
                    risk_tier=tier,
                    required_scopes=scopes,
                    description=f"Auto-registered: {action_id}",
                )
                self._registry.register(action)
                logger.info("Auto-registered permission for action: %s (tier=%s)", action_id, tier.name)
            else:
                logger.warning("Permission check for unknown action: %s", action_id)
                return PermissionCheckResult(
                    allowed=False,
                    action_id=action_id,
                    approval_behavior=ApprovalBehavior.REQUIRE_APPROVAL,
                    reason=f"Unknown action: {action_id}",
                    risk_tier=RiskTier.HIGH,
                )

        # Step 1: Check all required scopes are enabled
        missing_scopes: list[str] = []
        for scope in action.required_scopes:
            if not self._storage.is_scope_enabled(action.service, scope):
                missing_scopes.append(f"{action.service}:{scope}")

        if missing_scopes:
            return PermissionCheckResult(
                allowed=False,
                action_id=action_id,
                approval_behavior=ApprovalBehavior.REQUIRE_APPROVAL,
                reason=f"Missing required scopes: {', '.join(missing_scopes)}",
                missing_scopes=missing_scopes,
                risk_tier=action.risk_tier,
            )

        # Step 2: Determine effective risk tier (check for user overrides)
        effective_tier = self._effective_tier(action_id, action.risk_tier)

        # Step 3: Map tier to approval behavior
        behavior = DEFAULT_TIER_BEHAVIORS.get(
            effective_tier, ApprovalBehavior.REQUIRE_APPROVAL
        )

        return PermissionCheckResult(
            allowed=True,
            action_id=action_id,
            approval_behavior=behavior,
            risk_tier=effective_tier,
        )

    def _effective_tier(self, action_id: str, default_tier: RiskTier) -> RiskTier:
        """Get the effective risk tier, accounting for user overrides."""
        override = self._storage.get_tier_override(action_id)
        if override:
            try:
                return RiskTier(override["override_tier"])
            except ValueError:
                logger.warning(
                    "Invalid tier override '%s' for %s — using default",
                    override["override_tier"],
                    action_id,
                )
        return default_tier

    # ------------------------------------------------------------------
    # Scope Management
    # ------------------------------------------------------------------

    def enable_scope(
        self,
        service: str,
        scope: str,
        risk_tier: RiskTier = RiskTier.HIGH,
        description: str = "",
    ) -> str:
        """Enable a scope for a service. Returns the scope ID."""
        scope_id = self._storage.save_scope(
            service=service,
            scope=scope,
            enabled=True,
            risk_tier=risk_tier.value,
            description=description,
        )
        logger.info("Enabled scope %s:%s (tier: %s)", service, scope, risk_tier.value)
        return scope_id

    def disable_scope(self, service: str, scope: str) -> bool:
        """Disable a scope for a service."""
        result = self._storage.set_scope_enabled(service, scope, enabled=False)
        if result:
            logger.info("Disabled scope %s:%s", service, scope)
        return result

    def get_service_scopes(self, service: str) -> list[dict]:
        """Get all scopes for a service."""
        return self._storage.get_scopes(service)

    def get_all_scopes(self) -> list[dict]:
        """Get all scopes across all services."""
        return self._storage.get_all_scopes()

    # ------------------------------------------------------------------
    # Tier Overrides
    # ------------------------------------------------------------------

    def override_tier(
        self,
        action_id: str,
        new_tier: RiskTier,
        reason: str = "",
    ) -> Optional[str]:
        """Let the user override an action's risk tier.

        Returns the override ID, or None if the action doesn't exist.
        """
        action_id = action_id.replace(".", ":", 1) if ":" not in action_id else action_id
        action = self._registry.get(action_id)
        if action is None:
            return None

        override_id = self._storage.save_tier_override(
            action_id=action_id,
            original_tier=action.risk_tier.value,
            override_tier=new_tier.value,
            reason=reason,
        )
        logger.info(
            "Tier override: %s from %s → %s (reason: %s)",
            action_id,
            action.risk_tier.value,
            new_tier.value,
            reason or "none",
        )
        return override_id

    def reset_tier(self, action_id: str) -> bool:
        """Remove a tier override, reverting to default."""
        action_id = action_id.replace(".", ":", 1) if ":" not in action_id else action_id
        return self._storage.delete_tier_override(action_id)

    def get_overrides(self) -> list[dict]:
        """Get all active tier overrides."""
        return self._storage.get_all_overrides()

    # ------------------------------------------------------------------
    # Approval Requests
    # ------------------------------------------------------------------

    def request_approval(
        self,
        action_id: str,
        description: str = "",
        context: dict | None = None,
    ) -> str | None:
        """Create an approval request for a high/critical action.

        Returns the request ID, or None if the action doesn't need approval.
        """
        action_id = action_id.replace(".", ":", 1) if ":" not in action_id else action_id
        result = self.check(action_id)

        if not result.allowed:
            logger.warning("Cannot request approval for denied action: %s", action_id)
            return None

        if result.approval_behavior in (
            ApprovalBehavior.EXECUTE_SILENT,
            ApprovalBehavior.NOTIFY_AFTER,
        ):
            # No approval needed
            return None

        requires_pin = result.approval_behavior == ApprovalBehavior.REQUIRE_APPROVAL_PIN

        request_id = self._storage.create_approval_request(
            action_id=action_id,
            action_description=description or action_id,
            risk_tier=result.risk_tier.value,
            requires_pin=requires_pin,
            context=context,
        )
        logger.info(
            "Approval requested: %s (id: %s, pin_required: %s)",
            action_id,
            request_id,
            requires_pin,
        )
        return request_id

    def resolve_approval(
        self, request_id: str, approved: bool, pin: str | None = None
    ) -> dict | None:
        """Resolve an approval request.

        For CRITICAL-tier actions, a PIN must be provided.
        Returns the resolved request dict, or None if not found.
        """
        request = self._storage.get_approval_request(request_id)
        if request is None:
            return None

        if request["status"] != "pending":
            logger.warning("Approval %s already resolved: %s", request_id, request["status"])
            return request

        # PIN validation for critical-tier actions
        if approved and request.get("requires_pin") and not pin:
            logger.warning("Approval %s requires PIN but none provided", request_id)
            return {**request, "error": "PIN required for critical-tier actions"}

        if approved and request.get("requires_pin"):
            try:
                valid = self._pin_verifier is not None and self._pin_verifier(pin) is True
            except Exception:
                valid = False
            if not valid:
                return {**request, "error": "PIN verification failed or unavailable"}

        self._storage.resolve_approval(request_id, approved)
        logger.info(
            "Approval %s: %s (action: %s)",
            "granted" if approved else "denied",
            request_id,
            request["action_id"],
        )

        return self._storage.get_approval_request(request_id)

    def get_pending_approvals(self) -> list[dict]:
        """Get all pending approval requests."""
        return self._storage.get_pending_approvals()

    def get_approval_history(self, limit: int = 50) -> list[dict]:
        """Get recent approval history."""
        return self._storage.get_approval_history(limit)

    # ------------------------------------------------------------------
    # Bulk Initialization
    # ------------------------------------------------------------------

    def initialize_service_scopes(
        self,
        service: str,
        scopes: list[tuple[str, RiskTier, str]],
    ) -> None:
        """Register default scopes for a service (all disabled by default).

        Args:
            service: Service identifier
            scopes: List of (scope_name, default_risk_tier, description) tuples
        """
        for scope_name, risk_tier, description in scopes:
            # Only insert if not already present (don't overwrite user settings)
            existing = self._storage.get_scopes(service)
            existing_names = {s["scope"] for s in existing}
            if scope_name not in existing_names:
                self._storage.save_scope(
                    service=service,
                    scope=scope_name,
                    enabled=False,
                    risk_tier=risk_tier.value,
                    description=description,
                )
