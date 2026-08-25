"""Tests for the permission storage backend."""

from __future__ import annotations

import pytest

from koda_permissions.storage import PermissionStorage


@pytest.fixture
def storage(tmp_path) -> PermissionStorage:
    return PermissionStorage(str(tmp_path / "permissions.db"))


class TestScopeStorage:
    """Test scope CRUD operations."""

    def test_save_and_get_scope(self, storage: PermissionStorage) -> None:
        storage.save_scope("gmail", "read", enabled=True, risk_tier="low")
        scopes = storage.get_scopes("gmail")
        assert len(scopes) == 1
        assert scopes[0]["scope"] == "read"
        assert scopes[0]["enabled"] == 1

    def test_upsert_scope(self, storage: PermissionStorage) -> None:
        storage.save_scope("gmail", "read", enabled=False)
        storage.save_scope("gmail", "read", enabled=True)
        scopes = storage.get_scopes("gmail")
        assert len(scopes) == 1
        assert scopes[0]["enabled"] == 1

    def test_is_scope_enabled_true(self, storage: PermissionStorage) -> None:
        storage.save_scope("gmail", "read", enabled=True)
        assert storage.is_scope_enabled("gmail", "read") is True

    def test_is_scope_enabled_false(self, storage: PermissionStorage) -> None:
        storage.save_scope("gmail", "read", enabled=False)
        assert storage.is_scope_enabled("gmail", "read") is False

    def test_is_scope_enabled_nonexistent(self, storage: PermissionStorage) -> None:
        """Deny-by-default: nonexistent scope returns False."""
        assert storage.is_scope_enabled("gmail", "read") is False

    def test_toggle_scope(self, storage: PermissionStorage) -> None:
        storage.save_scope("gmail", "read", enabled=True)
        storage.set_scope_enabled("gmail", "read", False)
        assert storage.is_scope_enabled("gmail", "read") is False

    def test_get_all_scopes(self, storage: PermissionStorage) -> None:
        storage.save_scope("gmail", "read", enabled=True)
        storage.save_scope("gmail", "send", enabled=False)
        storage.save_scope("slack", "read", enabled=True)
        all_scopes = storage.get_all_scopes()
        assert len(all_scopes) == 3


class TestTierOverrideStorage:
    """Test tier override persistence."""

    def test_save_and_get_override(self, storage: PermissionStorage) -> None:
        storage.save_tier_override("gmail:send_email", "medium", "low", "Power user")
        override = storage.get_tier_override("gmail:send_email")
        assert override is not None
        assert override["override_tier"] == "low"
        assert override["reason"] == "Power user"

    def test_upsert_override(self, storage: PermissionStorage) -> None:
        storage.save_tier_override("gmail:send_email", "medium", "low")
        storage.save_tier_override("gmail:send_email", "medium", "high")
        override = storage.get_tier_override("gmail:send_email")
        assert override["override_tier"] == "high"

    def test_delete_override(self, storage: PermissionStorage) -> None:
        storage.save_tier_override("gmail:send_email", "medium", "low")
        assert storage.delete_tier_override("gmail:send_email")
        assert storage.get_tier_override("gmail:send_email") is None

    def test_delete_nonexistent(self, storage: PermissionStorage) -> None:
        assert not storage.delete_tier_override("nonexistent")

    def test_get_all_overrides(self, storage: PermissionStorage) -> None:
        storage.save_tier_override("gmail:send_email", "medium", "low")
        storage.save_tier_override("shell:execute_command", "critical", "high")
        overrides = storage.get_all_overrides()
        assert len(overrides) == 2


class TestApprovalStorage:
    """Test approval request persistence."""

    def test_create_and_get_approval(self, storage: PermissionStorage) -> None:
        req_id = storage.create_approval_request(
            action_id="gmail:delete_email",
            action_description="Delete spam email",
            risk_tier="high",
            requires_pin=False,
            context={"email_id": "abc123"},
        )
        request = storage.get_approval_request(req_id)
        assert request is not None
        assert request["action_id"] == "gmail:delete_email"
        assert request["status"] == "pending"
        assert request["context"]["email_id"] == "abc123"

    def test_resolve_approval(self, storage: PermissionStorage) -> None:
        req_id = storage.create_approval_request(
            action_id="test:action",
            action_description="Test",
            risk_tier="high",
            requires_pin=False,
        )
        assert storage.resolve_approval(req_id, approved=True)
        request = storage.get_approval_request(req_id)
        assert request["status"] == "approved"

    def test_resolve_already_resolved(self, storage: PermissionStorage) -> None:
        req_id = storage.create_approval_request(
            action_id="test:action",
            action_description="Test",
            risk_tier="high",
            requires_pin=False,
        )
        storage.resolve_approval(req_id, approved=True)
        # Second resolve should fail (already resolved)
        assert not storage.resolve_approval(req_id, approved=False)

    def test_pending_approvals(self, storage: PermissionStorage) -> None:
        storage.create_approval_request("action:1", "First", "high", False)
        storage.create_approval_request("action:2", "Second", "high", False)
        r3 = storage.create_approval_request("action:3", "Third", "high", False)
        storage.resolve_approval(r3, approved=True)

        pending = storage.get_pending_approvals()
        assert len(pending) == 2

    def test_approval_history(self, storage: PermissionStorage) -> None:
        r1 = storage.create_approval_request("action:1", "First", "high", False)
        r2 = storage.create_approval_request("action:2", "Second", "high", False)
        storage.resolve_approval(r1, approved=True)
        storage.resolve_approval(r2, approved=False)

        history = storage.get_approval_history()
        assert len(history) == 2
        statuses = {h["status"] for h in history}
        assert statuses == {"approved", "denied"}
