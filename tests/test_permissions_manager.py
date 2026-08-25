"""Tests for the PermissionManager — the core permission authority."""

from __future__ import annotations

import pytest

from koda_permissions.manager import PermissionManager
from koda_permissions.models import ApprovalBehavior, RiskTier
from koda_permissions.registry import ActionRegistry
from koda_permissions.storage import PermissionStorage


@pytest.fixture
def storage(tmp_path) -> PermissionStorage:
    return PermissionStorage(str(tmp_path / "permissions.db"))


@pytest.fixture
def registry() -> ActionRegistry:
    return ActionRegistry()


@pytest.fixture
def manager(registry, storage) -> PermissionManager:
    return PermissionManager(registry=registry, storage=storage)


class TestDenyByDefault:
    """The most critical tests: everything is denied unless explicitly allowed."""

    def test_unknown_action_denied(self, manager: PermissionManager) -> None:
        result = manager.check("nonexistent:action")
        assert not result.allowed
        assert "Unknown action" in result.reason

    def test_action_denied_when_scopes_not_enabled(self, manager: PermissionManager) -> None:
        """Gmail send requires the 'send' scope — denied if not enabled."""
        result = manager.check("gmail:send_email")
        assert not result.allowed
        assert "gmail:send" in result.missing_scopes[0]

    def test_all_builtin_actions_denied_without_setup(self, manager: PermissionManager) -> None:
        """Every single built-in action should be denied with a fresh DB."""
        registry = manager._registry
        for action in registry.all_actions():
            if action.required_scopes:  # actions with scopes should be denied
                result = manager.check(action.action_id)
                assert not result.allowed, f"{action.action_id} should be denied"


class TestScopeEnablement:
    """Test enabling scopes and checking permissions."""

    def test_enable_scope_allows_action(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "read", RiskTier.LOW, "Read emails")
        result = manager.check("gmail:read_emails")
        assert result.allowed

    def test_enable_wrong_scope_still_denied(self, manager: PermissionManager) -> None:
        """Enable 'read' but try to send — should be denied."""
        manager.enable_scope("gmail", "read", RiskTier.LOW)
        result = manager.check("gmail:send_email")
        assert not result.allowed
        assert "gmail:send" in result.missing_scopes[0]

    def test_disable_scope_revokes_permission(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "read", RiskTier.LOW)
        assert manager.check("gmail:read_emails").allowed

        manager.disable_scope("gmail", "read")
        assert not manager.check("gmail:read_emails").allowed

    def test_multi_scope_action(self, manager: PermissionManager) -> None:
        """shell:install_package requires both 'execute' and 'network' scopes."""
        manager.enable_scope("shell", "execute", RiskTier.CRITICAL)
        # Still missing 'network'
        result = manager.check("shell:install_package")
        assert not result.allowed

        manager.enable_scope("shell", "network", RiskTier.CRITICAL)
        result = manager.check("shell:install_package")
        assert result.allowed


class TestRiskTierBehavior:
    """Test that risk tiers correctly map to approval behaviors."""

    def test_low_risk_executes_silently(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "read", RiskTier.LOW)
        result = manager.check("gmail:read_emails")
        assert result.allowed
        assert result.approval_behavior == ApprovalBehavior.EXECUTE_SILENT

    def test_medium_risk_notifies_after(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "send", RiskTier.MEDIUM)
        result = manager.check("gmail:send_email")
        assert result.allowed
        assert result.approval_behavior == ApprovalBehavior.NOTIFY_AFTER

    def test_high_risk_requires_approval(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "delete", RiskTier.HIGH)
        result = manager.check("gmail:delete_email")
        assert result.allowed
        assert result.approval_behavior == ApprovalBehavior.REQUIRE_APPROVAL

    def test_critical_risk_requires_pin(self, manager: PermissionManager) -> None:
        manager.enable_scope("shell", "execute", RiskTier.CRITICAL)
        result = manager.check("shell:execute_command")
        assert result.allowed
        assert result.approval_behavior == ApprovalBehavior.REQUIRE_APPROVAL_PIN


class TestTierOverrides:
    """Test user customization of risk tiers."""

    def test_override_lowers_tier(self, manager: PermissionManager) -> None:
        """Power user can lower send_email from MEDIUM to LOW."""
        manager.enable_scope("gmail", "send", RiskTier.MEDIUM)
        manager.override_tier("gmail:send_email", RiskTier.LOW, reason="I send lots of emails")

        result = manager.check("gmail:send_email")
        assert result.allowed
        assert result.risk_tier == RiskTier.LOW
        assert result.approval_behavior == ApprovalBehavior.EXECUTE_SILENT

    def test_override_raises_tier(self, manager: PermissionManager) -> None:
        """Cautious user can raise read_emails from LOW to HIGH."""
        manager.enable_scope("gmail", "read", RiskTier.LOW)
        manager.override_tier("gmail:read_emails", RiskTier.HIGH, reason="Privacy concern")

        result = manager.check("gmail:read_emails")
        assert result.risk_tier == RiskTier.HIGH
        assert result.approval_behavior == ApprovalBehavior.REQUIRE_APPROVAL

    def test_reset_tier_reverts_to_default(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "send", RiskTier.MEDIUM)
        manager.override_tier("gmail:send_email", RiskTier.LOW)

        result = manager.check("gmail:send_email")
        assert result.risk_tier == RiskTier.LOW

        manager.reset_tier("gmail:send_email")
        result = manager.check("gmail:send_email")
        assert result.risk_tier == RiskTier.MEDIUM

    def test_override_nonexistent_action_returns_none(self, manager: PermissionManager) -> None:
        result = manager.override_tier("nonexistent:action", RiskTier.LOW)
        assert result is None


class TestApprovalWorkflow:
    """Test the approval request lifecycle."""

    def test_request_approval_for_high_risk(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "delete", RiskTier.HIGH)
        request_id = manager.request_approval(
            "gmail:delete_email",
            description="Delete spam email",
            context={"email_id": "abc123"},
        )
        assert request_id is not None

        pending = manager.get_pending_approvals()
        assert len(pending) == 1
        assert pending[0]["action_id"] == "gmail:delete_email"

    def test_approve_request(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "delete", RiskTier.HIGH)
        request_id = manager.request_approval("gmail:delete_email")
        assert request_id is not None

        result = manager.resolve_approval(request_id, approved=True)
        assert result is not None
        assert result["status"] == "approved"

        # No more pending
        assert len(manager.get_pending_approvals()) == 0

    def test_deny_request(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "delete", RiskTier.HIGH)
        request_id = manager.request_approval("gmail:delete_email")
        result = manager.resolve_approval(request_id, approved=False)
        assert result["status"] == "denied"

    def test_critical_requires_pin(self, manager: PermissionManager) -> None:
        manager.enable_scope("shell", "execute", RiskTier.CRITICAL)
        request_id = manager.request_approval("shell:execute_command")
        assert request_id is not None

        # Try to approve without PIN
        result = manager.resolve_approval(request_id, approved=True)
        assert "error" in result
        assert "PIN required" in result["error"]

        # Approve with PIN
        result = manager.resolve_approval(request_id, approved=True, pin="1234")
        assert result["status"] == "approved"

    def test_low_risk_returns_none(self, manager: PermissionManager) -> None:
        """LOW risk actions don't need approval."""
        manager.enable_scope("gmail", "read", RiskTier.LOW)
        request_id = manager.request_approval("gmail:read_emails")
        assert request_id is None

    def test_denied_action_cannot_request_approval(self, manager: PermissionManager) -> None:
        """Can't request approval for an action whose scopes aren't enabled."""
        request_id = manager.request_approval("gmail:send_email")
        assert request_id is None

    def test_approval_history(self, manager: PermissionManager) -> None:
        manager.enable_scope("gmail", "delete", RiskTier.HIGH)
        r1 = manager.request_approval("gmail:delete_email", description="first")
        r2 = manager.request_approval("gmail:delete_email", description="second")
        manager.resolve_approval(r1, approved=True)
        manager.resolve_approval(r2, approved=False)

        history = manager.get_approval_history()
        assert len(history) == 2


class TestBulkInitialization:
    """Test initializing scopes for a new service."""

    def test_initialize_creates_disabled_scopes(self, manager: PermissionManager) -> None:
        manager.initialize_service_scopes("notion", [
            ("read", RiskTier.LOW, "Read pages"),
            ("write", RiskTier.MEDIUM, "Create/edit pages"),
            ("delete", RiskTier.HIGH, "Delete pages"),
        ])
        scopes = manager.get_service_scopes("notion")
        assert len(scopes) == 3
        assert all(not s["enabled"] for s in scopes)

    def test_initialize_doesnt_overwrite_existing(self, manager: PermissionManager) -> None:
        """If user already enabled a scope, don't overwrite it."""
        manager.enable_scope("notion", "read", RiskTier.LOW, "Read pages")
        manager.initialize_service_scopes("notion", [
            ("read", RiskTier.LOW, "Read pages"),
            ("write", RiskTier.MEDIUM, "Create/edit pages"),
        ])
        scopes = manager.get_service_scopes("notion")
        read_scope = next(s for s in scopes if s["scope"] == "read")
        assert read_scope["enabled"]  # Should still be enabled
