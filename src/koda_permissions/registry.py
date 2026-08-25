"""Action registry — defines all known actions and their default risk tiers.

This is the central catalog of everything the agent can do.  Each action
maps to a service, has a default risk tier, and lists the scopes it requires.
The registry is populated at startup and can be extended by skills/plugins.
"""

from __future__ import annotations

from koda_permissions.models import ActionDefinition, RiskTier


# ---------------------------------------------------------------------------
# Built-in Action Definitions
# ---------------------------------------------------------------------------

_BUILTIN_ACTIONS: list[ActionDefinition] = [
    # --- Gmail ---
    ActionDefinition(
        action_id="gmail:read_emails",
        service="gmail",
        action="read_emails",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read and list emails",
    ),
    ActionDefinition(
        action_id="gmail:send_email",
        service="gmail",
        action="send_email",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["send"],
        description="Send an email to a single recipient",
    ),
    ActionDefinition(
        action_id="gmail:send_bulk_email",
        service="gmail",
        action="send_bulk_email",
        risk_tier=RiskTier.HIGH,
        required_scopes=["send"],
        description="Send emails to multiple recipients (>5)",
    ),
    ActionDefinition(
        action_id="gmail:delete_email",
        service="gmail",
        action="delete_email",
        risk_tier=RiskTier.HIGH,
        required_scopes=["delete"],
        description="Permanently delete an email",
    ),
    ActionDefinition(
        action_id="gmail:manage_labels",
        service="gmail",
        action="manage_labels",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["manage_labels"],
        description="Create, edit, or delete email labels/filters",
    ),

    # --- Google Calendar ---
    ActionDefinition(
        action_id="calendar:read_events",
        service="calendar",
        action="read_events",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read calendar events",
    ),
    ActionDefinition(
        action_id="calendar:create_event",
        service="calendar",
        action="create_event",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write"],
        description="Create a new calendar event",
    ),
    ActionDefinition(
        action_id="calendar:delete_event",
        service="calendar",
        action="delete_event",
        risk_tier=RiskTier.HIGH,
        required_scopes=["write"],
        description="Delete a calendar event",
    ),

    # --- Slack ---
    ActionDefinition(
        action_id="slack:read_messages",
        service="slack",
        action="read_messages",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read messages in channels",
    ),
    ActionDefinition(
        action_id="slack:post_message",
        service="slack",
        action="post_message",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["send"],
        description="Post a message to a channel",
    ),
    ActionDefinition(
        action_id="slack:post_dm",
        service="slack",
        action="post_dm",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["send"],
        description="Send a direct message",
    ),

    # --- GitHub ---
    ActionDefinition(
        action_id="github:read_repos",
        service="github",
        action="read_repos",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read repository information, issues, and PRs",
    ),
    ActionDefinition(
        action_id="github:create_issue",
        service="github",
        action="create_issue",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write"],
        description="Create a new issue",
    ),
    ActionDefinition(
        action_id="github:push_code",
        service="github",
        action="push_code",
        risk_tier=RiskTier.HIGH,
        required_scopes=["write"],
        description="Push code to a repository",
    ),

    # --- File System ---
    ActionDefinition(
        action_id="filesystem.read_files",
        service="filesystem",
        action="read_files",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read files in allowed directories",
    ),
    ActionDefinition(
        action_id="filesystem.write_files",
        service="filesystem",
        action="write_files",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write"],
        description="Create or modify files",
    ),
    ActionDefinition(
        action_id="filesystem.delete_files",
        service="filesystem",
        action="delete_files",
        risk_tier=RiskTier.HIGH,
        required_scopes=["delete"],
        description="Delete files or directories",
    ),

    # --- Browser ---
    ActionDefinition(
        action_id="browser:search",
        service="browser",
        action="search",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Search the web for information",
    ),
    ActionDefinition(
        action_id="browser:navigate",
        service="browser",
        action="navigate",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Navigate to a URL and read page content",
    ),
    ActionDefinition(
        action_id="browser:read",
        service="browser",
        action="read",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read content from the current page",
    ),
    ActionDefinition(
        action_id="browser:interact",
        service="browser",
        action="interact",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["read", "interact"],
        description="Click buttons or fill forms on a webpage",
    ),
    ActionDefinition(
        action_id="browser:execute_js",
        service="browser",
        action="execute_js",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["read", "interact"],
        description="Execute JavaScript on the current page",
    ),

    # --- Shell ---
    ActionDefinition(
        action_id="shell:execute_command",
        service="shell",
        action="execute_command",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["execute"],
        description="Execute a shell command",
    ),
    ActionDefinition(
        action_id="shell:install_package",
        service="shell",
        action="install_package",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["execute", "network"],
        description="Install a system or application package",
    ),

    # --- Koda Self-Tools ---
    ActionDefinition(
        action_id="koda.set_personality",
        service="koda",
        action="set_personality",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Switch personality to a preset (professional, casual, warm, etc.)",
    ),
    ActionDefinition(
        action_id="koda.adjust_personality",
        service="koda",
        action="adjust_personality",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Fine-tune personality parameters (formality, verbosity, humor, etc.)",
    ),
    ActionDefinition(
        action_id="koda.change_voice",
        service="koda",
        action="change_voice",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Change speaking voice",
    ),
    ActionDefinition(
        action_id="koda.adjust_voice",
        service="koda",
        action="adjust_voice",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Adjust voice speed, warmth, expressiveness",
    ),
    ActionDefinition(
        action_id="koda.toggle_voice",
        service="koda",
        action="toggle_voice",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Enable/disable voice or change response mode",
    ),
    ActionDefinition(
        action_id="koda.remember",
        service="koda",
        action="remember",
        risk_tier=RiskTier.LOW,
        required_scopes=["memory"],
        description="Store a fact in long-term memory",
    ),
    ActionDefinition(
        action_id="koda.recall",
        service="koda",
        action="recall",
        risk_tier=RiskTier.LOW,
        required_scopes=["memory"],
        description="Search long-term memory",
    ),
    ActionDefinition(
        action_id="koda.forget",
        service="koda",
        action="forget",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["memory"],
        description="Delete information from long-term memory",
    ),
    ActionDefinition(
        action_id="koda.set_name",
        service="koda",
        action="set_name",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Set or change the user's name",
    ),
    ActionDefinition(
        action_id="koda.get_datetime",
        service="koda",
        action="get_datetime",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Get current date and time",
    ),
    ActionDefinition(
        action_id="koda.list_voices",
        service="koda",
        action="list_voices",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="List all available voices",
    ),
    ActionDefinition(
        action_id="koda.voice_diagnostics",
        service="koda",
        action="voice_diagnostics",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Diagnose TTS engine and voice status",
    ),
    ActionDefinition(
        action_id="koda.get_settings",
        service="koda",
        action="get_settings",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Get current personality and voice settings",
    ),
    ActionDefinition(
        action_id="koda.set_accent_color",
        service="koda",
        action="set_accent_color",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Change the UI accent color",
    ),

    # --- Shell Execution ---
    ActionDefinition(
        action_id="shell.execute",
        service="shell",
        action="execute",
        risk_tier=RiskTier.HIGH,
        required_scopes=["execute"],
        description="Execute a shell command (terminal access)",
    ),

    # --- Code Self-Modification ---
    ActionDefinition(
        action_id="code.read",
        service="code",
        action="read",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read Koda's own source code modules",
    ),
    ActionDefinition(
        action_id="code.write",
        service="code",
        action="write",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["write"],
        description="Modify Koda's own source code",
    ),
    ActionDefinition(
        action_id="code.create",
        service="code",
        action="create",
        risk_tier=RiskTier.HIGH,
        required_scopes=["write"],
        description="Create a new tool module in Koda's codebase",
    ),
    ActionDefinition(
        action_id="code.register",
        service="code",
        action="register",
        risk_tier=RiskTier.HIGH,
        required_scopes=["write"],
        description="Register a new tool at runtime (hot-load)",
    ),
    ActionDefinition(
        action_id="code.restart",
        service="code",
        action="restart",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["write"],
        description="Restart Koda to pick up code changes",
    ),

    # --- Frontend Code ---
    ActionDefinition(
        action_id="code.frontend_read",
        service="code",
        action="frontend_read",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Read Koda's frontend source code (Next.js/TypeScript)",
    ),
    ActionDefinition(
        action_id="code.frontend_write",
        service="code",
        action="frontend_write",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["write"],
        description="Modify Koda's frontend source code",
    ),
    ActionDefinition(
        action_id="code.frontend_create",
        service="code",
        action="frontend_create",
        risk_tier=RiskTier.HIGH,
        required_scopes=["write"],
        description="Create a new file in Koda's frontend codebase",
    ),
    ActionDefinition(
        action_id="code.frontend_restart",
        service="code",
        action="frontend_restart",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["write"],
        description="Restart the Next.js dev server (clears .next cache)",
    ),

    # --- Hardware ---
    ActionDefinition(
        action_id="hardware.detect",
        service="hardware",
        action="detect",
        risk_tier=RiskTier.LOW,
        required_scopes=["detect"],
        description="Detect connected hardware devices",
    ),
    ActionDefinition(
        action_id="hardware.install",
        service="hardware",
        action="install",
        risk_tier=RiskTier.HIGH,
        required_scopes=["install"],
        description="Install a Python package via pip",
    ),
    ActionDefinition(
        action_id="hardware.camera",
        service="hardware",
        action="camera",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["camera"],
        description="Capture photo from webcam or list camera devices",
    ),

    # --- YouTube ---
    ActionDefinition(
        action_id="youtube.read",
        service="youtube",
        action="read",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="Fetch YouTube video transcripts, metadata, and search results",
    ),

    # --- Vision / Image Analysis ---
    ActionDefinition(
        action_id="vision.analyze",
        service="vision",
        action="analyze",
        risk_tier=RiskTier.LOW,
        required_scopes=["analyze"],
        description="Analyze images and describe what's in them using vision AI",
    ),
    ActionDefinition(
        action_id="vision.monitor",
        service="vision",
        action="monitor",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["monitor"],
        description="Monitor camera feeds in the background with periodic analysis",
    ),

    # --- Credentials Management ---
    ActionDefinition(
        action_id="credentials:read",
        service="credentials",
        action="read",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="List credential metadata (never exposes values)",
    ),
    ActionDefinition(
        action_id="credentials:create",
        service="credentials",
        action="create",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write"],
        description="Store a new credential",
    ),
    ActionDefinition(
        action_id="credentials:delete",
        service="credentials",
        action="delete",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["delete"],
        description="Delete a stored credential",
    ),
    ActionDefinition(
        action_id="credentials:modify",
        service="credentials",
        action="modify",
        risk_tier=RiskTier.CRITICAL,
        required_scopes=["write"],
        description="Modify credential settings or scopes",
    ),

    # --- Claude Account Management ---
    ActionDefinition(
        action_id="claude:read",
        service="claude",
        action="read",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="List Claude accounts and read responses",
    ),
    ActionDefinition(
        action_id="claude:manage",
        service="claude",
        action="manage",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write"],
        description="Add or remove Claude accounts",
    ),
    ActionDefinition(
        action_id="claude:interact",
        service="claude",
        action="interact",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write", "interact"],
        description="Open Claude tabs, send prompts, broadcast messages",
    ),

    # --- Command Center / Session Management ---
    ActionDefinition(
        action_id="command_center:read",
        service="command_center",
        action="read",
        risk_tier=RiskTier.LOW,
        required_scopes=["read"],
        description="List sessions, get status, view oversight report",
    ),
    ActionDefinition(
        action_id="command_center:manage",
        service="command_center",
        action="manage",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write"],
        description="Create, pause, resume, or end Command Center sessions",
    ),
    ActionDefinition(
        action_id="command_center:interact",
        service="command_center",
        action="interact",
        risk_tier=RiskTier.HIGH,
        required_scopes=["write", "interact"],
        description="Send messages to AI sessions, trigger actions in managed platforms",
    ),
    ActionDefinition(
        action_id="command_center:accounts",
        service="command_center",
        action="accounts",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["write"],
        description="Add, remove, or list platform accounts for sessions",
    ),

    # --- Agent Coordination ---
    ActionDefinition(
        action_id="koda.manage_agent",
        service="koda",
        action="manage_agent",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Manage tasks for Agent 2 (assign, review, status, knowledge)",
    ),

    # --- Git Operations ---
    ActionDefinition(
        action_id="koda.git",
        service="koda",
        action="git",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["settings"],
        description="Git operations (status, commit, push)",
    ),

    # --- Pronunciation ---
    ActionDefinition(
        action_id="koda.fix_pronunciation",
        service="koda",
        action="fix_pronunciation",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Add, remove, or list pronunciation corrections",
    ),

    # --- Singing ---
    ActionDefinition(
        action_id="koda.sing",
        service="koda",
        action="sing",
        risk_tier=RiskTier.LOW,
        required_scopes=["sing"],
        description="Sing a song using DiffSinger voice synthesis",
    ),

    # --- Model Switching ---
    ActionDefinition(
        action_id="koda.switch_model",
        service="koda",
        action="switch_model",
        risk_tier=RiskTier.LOW,
        required_scopes=["settings"],
        description="Switch the AI model (opus/sonnet/haiku)",
    ),

    # --- Document Processing ---
    ActionDefinition(
        action_id="document.convert_pdf",
        service="document",
        action="convert_pdf",
        risk_tier=RiskTier.MEDIUM,
        required_scopes=["read", "write"],
        description="Scan folders and convert PDF files to markdown format",
    ),
]


class ActionRegistry:
    """Central catalog of all known agent actions.

    Initialized with built-in actions and extensible via ``register()``.
    Thread-safe for reads; mutations are expected only at startup / plugin load.
    """

    def __init__(self) -> None:
        self._actions: dict[str, ActionDefinition] = {}
        # Load built-ins — index under both colon and dot variants
        for action in _BUILTIN_ACTIONS:
            self._actions[action.action_id] = action
            # Also store under the alternate delimiter so tools using
            # "filesystem.read_files" match "filesystem:read_files" and vice versa
            alt_id = (
                action.action_id.replace(":", ".", 1)
                if ":" in action.action_id
                else action.action_id.replace(".", ":", 1)
            )
            if alt_id != action.action_id:
                self._actions[alt_id] = action

    # -- Query --

    def get(self, action_id: str) -> ActionDefinition | None:
        """Look up an action by its ID.

        Tolerates both ':' and '.' as service/action separators,
        so 'filesystem.read_files' and 'filesystem:read_files' both match.
        """
        result = self._actions.get(action_id)
        if result is not None:
            return result
        # Try swapping delimiter as fallback
        if "." in action_id:
            return self._actions.get(action_id.replace(".", ":", 1))
        if ":" in action_id:
            return self._actions.get(action_id.replace(":", ".", 1))
        return None

    def get_by_service(self, service: str) -> list[ActionDefinition]:
        """Get all actions for a given service."""
        return [a for a in self._actions.values() if a.service == service]

    def all_actions(self) -> list[ActionDefinition]:
        """Return all registered actions."""
        return list(self._actions.values())

    def services(self) -> list[str]:
        """Return all unique service identifiers."""
        return sorted({a.service for a in self._actions.values()})

    # -- Mutation --

    def register(self, action: ActionDefinition) -> None:
        """Register a new action (e.g. from a skill/plugin)."""
        self._actions[action.action_id] = action

    def register_many(self, actions: list[ActionDefinition]) -> None:
        """Register multiple actions at once."""
        for action in actions:
            self.register(action)

    def count(self) -> int:
        return len(self._actions)
