import pytest
from koda_permissions.manager import PermissionManager
from koda_permissions.storage import PermissionStorage
from koda_permissions.registry import ActionRegistry
from koda_permissions.models import RiskTier


def critical(verifier=None):
    manager = PermissionManager(ActionRegistry(), PermissionStorage(":memory:"), pin_verifier=verifier)
    manager.enable_scope("shell", "execute")
    return manager, manager.request_approval("shell.execute_command")


@pytest.mark.parametrize("pin", [None, "", "wrong", "1234"])
def test_missing_verifier_never_approves(pin):
    manager, request = critical()
    assert manager.resolve_approval(request, True, pin)["status"] == "pending"


def test_pin_verifier_checks_value_and_denial_needs_no_pin():
    manager, request = critical(lambda value: value == "test-pin")
    assert manager.resolve_approval(request, True, "wrong")["status"] == "pending"
    assert manager.resolve_approval(request, True, "test-pin")["status"] == "approved"
    manager, request = critical()
    assert manager.resolve_approval(request, False)["status"] == "denied"


def test_verifier_exception_fails_closed():
    def broken(value):
        raise RuntimeError("backend unavailable")
    manager, request = critical(broken)
    assert manager.resolve_approval(request, True, "test-pin")["status"] == "pending"


@pytest.mark.parametrize("written,checked", [("gmail:send_email", "gmail.send_email"),
                                            ("gmail.send_email", "gmail:send_email")])
def test_alias_override_and_reset(written, checked):
    manager = PermissionManager(ActionRegistry(), PermissionStorage(":memory:"))
    manager.enable_scope("gmail", "send")
    manager.override_tier(written, RiskTier.CRITICAL)
    assert manager.check(checked).risk_tier == RiskTier.CRITICAL
    request = manager.request_approval(checked)
    assert manager.get_pending_approvals()[0]["action_id"] == "gmail:send_email"
    assert manager.reset_tier(checked)
    assert manager.check(written).risk_tier == RiskTier.MEDIUM


def test_legacy_alias_migration_keeps_stricter_override(tmp_path):
    path = str(tmp_path / "permissions.db")
    storage = PermissionStorage(path)
    storage.save_tier_override("gmail.send_email", "medium", "critical", "strict")
    storage.save_tier_override("gmail:send_email", "medium", "low", "permissive")
    manager = PermissionManager(ActionRegistry(), storage)
    manager.enable_scope("gmail", "send")
    assert manager.check("gmail.send_email").risk_tier == RiskTier.CRITICAL
    assert len(manager.get_overrides()) == 1
    reopened = PermissionManager(ActionRegistry(), PermissionStorage(path))
    assert reopened.check("gmail:send_email").risk_tier == RiskTier.CRITICAL
