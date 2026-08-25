"""Tests for the action registry."""

from __future__ import annotations

import pytest

from koda_permissions.models import RiskTier
from koda_permissions.registry import ActionDefinition, ActionRegistry


class TestRegistryBootstrap:
    """Test that the registry starts with built-in actions."""

    def test_has_builtin_actions(self) -> None:
        registry = ActionRegistry()
        assert registry.count() > 0

    def test_gmail_actions_exist(self) -> None:
        registry = ActionRegistry()
        gmail_actions = registry.get_by_service("gmail")
        assert len(gmail_actions) >= 3  # read, send, send_bulk, delete, manage_labels

    def test_shell_actions_are_critical(self) -> None:
        registry = ActionRegistry()
        shell_actions = registry.get_by_service("shell")
        for action in shell_actions:
            assert action.risk_tier == RiskTier.CRITICAL

    def test_read_actions_are_low_risk(self) -> None:
        registry = ActionRegistry()
        read_action = registry.get("gmail:read_emails")
        assert read_action is not None
        assert read_action.risk_tier == RiskTier.LOW

    def test_all_services_present(self) -> None:
        registry = ActionRegistry()
        services = registry.services()
        expected = {"gmail", "calendar", "slack", "github", "filesystem", "shell", "credentials"}
        assert expected.issubset(set(services))


class TestRegistryMutation:
    """Test registering new actions."""

    def test_register_custom_action(self) -> None:
        registry = ActionRegistry()
        initial_count = registry.count()
        custom = ActionDefinition(
            action_id="spotify:play_song",
            service="spotify",
            action="play_song",
            risk_tier=RiskTier.LOW,
            required_scopes=["playback"],
            description="Play a song",
        )
        registry.register(custom)
        assert registry.count() == initial_count + 1
        assert registry.get("spotify:play_song") is not None

    def test_register_many(self) -> None:
        registry = ActionRegistry()
        initial_count = registry.count()
        actions = [
            ActionDefinition(
                action_id="notion:read_pages",
                service="notion",
                action="read_pages",
                risk_tier=RiskTier.LOW,
                required_scopes=["read"],
            ),
            ActionDefinition(
                action_id="notion:create_page",
                service="notion",
                action="create_page",
                risk_tier=RiskTier.MEDIUM,
                required_scopes=["write"],
            ),
        ]
        registry.register_many(actions)
        assert registry.count() == initial_count + 2

    def test_get_unknown_returns_none(self) -> None:
        registry = ActionRegistry()
        assert registry.get("nonexistent:action") is None


class TestActionDefinitionModel:
    """Test the ActionDefinition model."""

    def test_action_id_required(self) -> None:
        action = ActionDefinition(
            action_id="test:action",
            service="test",
            action="action",
        )
        assert action.action_id == "test:action"
        assert action.risk_tier == RiskTier.HIGH  # default

    def test_required_scopes_default_empty(self) -> None:
        action = ActionDefinition(
            action_id="test:action",
            service="test",
            action="action",
        )
        assert action.required_scopes == []
