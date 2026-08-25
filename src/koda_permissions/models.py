"""Permission system data models.

Implements the deny-by-default, risk-tiered permission model from the design
spec.  Every action the agent can take is classified into a risk tier, and
every service integration has granular scope-level permissions.

Risk Tiers (from spec):
    LOW      → Execute silently (read email, check calendar, summarize doc)
    MEDIUM   → Notify user after (send email, create event, post to Slack)
    HIGH     → Require explicit approval (delete files, bulk ops, purchases)
    CRITICAL → Require approval + PIN (shell access, credential changes)
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Risk Tiers
# ---------------------------------------------------------------------------

class RiskTier(str, enum.Enum):
    """Risk classification for agent actions."""

    LOW = "low"           # Execute silently
    MEDIUM = "medium"     # Notify after execution
    HIGH = "high"         # Require approval before
    CRITICAL = "critical" # Require approval + PIN


class ApprovalBehavior(str, enum.Enum):
    """What the agent should do for a given risk tier."""

    EXECUTE_SILENT = "execute_silent"    # Just do it
    NOTIFY_AFTER = "notify_after"        # Do it, then tell the user
    REQUIRE_APPROVAL = "require_approval"  # Ask first
    REQUIRE_APPROVAL_PIN = "require_approval_pin"  # Ask first + PIN


# Default mapping from risk tier to approval behavior.
DEFAULT_TIER_BEHAVIORS: dict[RiskTier, ApprovalBehavior] = {
    RiskTier.LOW: ApprovalBehavior.EXECUTE_SILENT,
    RiskTier.MEDIUM: ApprovalBehavior.NOTIFY_AFTER,
    RiskTier.HIGH: ApprovalBehavior.REQUIRE_APPROVAL,
    RiskTier.CRITICAL: ApprovalBehavior.REQUIRE_APPROVAL_PIN,
}


# ---------------------------------------------------------------------------
# Service Scopes
# ---------------------------------------------------------------------------

class ServiceScope(BaseModel):
    """A single permission scope for a service integration.

    Example: Gmail → "read" scope, enabled=True, risk_tier=LOW
    """

    service: str = Field(..., min_length=1, description="Service identifier (e.g. 'gmail', 'github')")
    scope: str = Field(..., min_length=1, description="Scope identifier (e.g. 'read', 'send', 'delete')")
    enabled: bool = Field(default=False, description="Whether this scope is allowed (deny-by-default)")
    risk_tier: RiskTier = Field(default=RiskTier.HIGH, description="Risk classification for this scope")
    description: str = Field(default="", description="Human-readable description of what this scope allows")


class ServicePermissions(BaseModel):
    """All permission scopes for a single service.

    Each service starts with all scopes disabled (deny-by-default).
    Users explicitly enable the scopes they want.
    """

    service: str = Field(..., min_length=1)
    display_name: str = Field(default="")
    category: str = Field(default="other", description="Category: communication, productivity, developer, ai, media, smart_home, finance")
    connected: bool = Field(default=False, description="Whether the service is connected/authenticated")
    scopes: list[ServiceScope] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Action Definitions
# ---------------------------------------------------------------------------

class ActionDefinition(BaseModel):
    """Defines a specific action the agent can take, with its risk classification.

    Example: "gmail:send_email" → risk_tier=MEDIUM
    """

    action_id: str = Field(..., description="Unique action identifier (service:action)")
    service: str = Field(..., description="Service this action belongs to")
    action: str = Field(..., description="Action name within the service")
    risk_tier: RiskTier = Field(default=RiskTier.HIGH)
    required_scopes: list[str] = Field(default_factory=list, description="Scopes required for this action")
    description: str = Field(default="")


# ---------------------------------------------------------------------------
# Permission Check Results
# ---------------------------------------------------------------------------

class PermissionCheckResult(BaseModel):
    """Result of checking whether an action is permitted."""

    allowed: bool = Field(...)
    action_id: str = Field(...)
    approval_behavior: ApprovalBehavior = Field(...)
    reason: str = Field(default="", description="Explanation if denied")
    missing_scopes: list[str] = Field(default_factory=list)
    risk_tier: RiskTier = Field(...)


class ApprovalRequest(BaseModel):
    """A request for the user to approve a high/critical-risk action."""

    id: str = Field(..., description="Unique request ID")
    action_id: str = Field(...)
    action_description: str = Field(default="")
    risk_tier: RiskTier = Field(...)
    requires_pin: bool = Field(default=False)
    context: dict = Field(default_factory=dict, description="Action-specific context for the user to review")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = Field(default="pending", description="pending, approved, denied, expired")


class ApprovalResponse(BaseModel):
    """User's response to an approval request."""

    request_id: str = Field(...)
    approved: bool = Field(...)
    pin: Optional[str] = Field(default=None, description="PIN for critical-tier actions")


# ---------------------------------------------------------------------------
# User Permission Overrides
# ---------------------------------------------------------------------------

class TierOverride(BaseModel):
    """User customization of an action's risk tier.

    Power users can lower tiers; cautious users can raise them.
    """

    action_id: str = Field(...)
    original_tier: RiskTier = Field(...)
    override_tier: RiskTier = Field(...)
    reason: str = Field(default="", description="Why the user changed this")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
