"""SQLite persistence for the permission system.

Stores:
- Service scope enablements (which scopes the user has turned on)
- Tier overrides (user customizations of action risk tiers)
- Approval requests and their outcomes

Uses the same WAL-mode, lightweight-SQLite pattern as the vault and
personality storage.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("koda_permissions.storage")


class PermissionStorage:
    """SQLite backend for the permission system."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def normalize_tier_overrides(self) -> None:
        """Migrate delimiter aliases atomically; conflicts keep the stricter tier."""
        ranks = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        with self._conn:
            rows = self._conn.execute("SELECT * FROM tier_overrides").fetchall()
            groups = {}
            for row in rows:
                key = row["action_id"]
                key = key.replace(".", ":", 1) if ":" not in key else key
                groups.setdefault(key, []).append(row)
            for canonical, aliases in groups.items():
                winner = max(aliases, key=lambda r: ranks.get(r["override_tier"], 3))
                for row in aliases:
                    self._conn.execute("DELETE FROM tier_overrides WHERE id = ?", (row["id"],))
                self._conn.execute(
                    "INSERT INTO tier_overrides VALUES (?, ?, ?, ?, ?, ?)",
                    (winner["id"], canonical, winner["original_tier"],
                     winner["override_tier"] if winner["override_tier"] in ranks else "critical",
                     winner["reason"], winner["created_at"]),
                )

    def _create_tables(self) -> None:
        """Create tables if they don't exist."""
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS service_scopes (
                id           TEXT PRIMARY KEY,
                service      TEXT NOT NULL,
                scope        TEXT NOT NULL,
                enabled      INTEGER NOT NULL DEFAULT 0,
                risk_tier    TEXT NOT NULL DEFAULT 'high',
                description  TEXT NOT NULL DEFAULT '',
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                UNIQUE(service, scope)
            );

            CREATE TABLE IF NOT EXISTS tier_overrides (
                id              TEXT PRIMARY KEY,
                action_id       TEXT NOT NULL UNIQUE,
                original_tier   TEXT NOT NULL,
                override_tier   TEXT NOT NULL,
                reason          TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_requests (
                id                  TEXT PRIMARY KEY,
                action_id           TEXT NOT NULL,
                action_description  TEXT NOT NULL DEFAULT '',
                risk_tier           TEXT NOT NULL,
                requires_pin        INTEGER NOT NULL DEFAULT 0,
                context_json        TEXT NOT NULL DEFAULT '{}',
                status              TEXT NOT NULL DEFAULT 'pending',
                created_at          TEXT NOT NULL,
                resolved_at         TEXT,
                resolved_by         TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_approval_status
                ON approval_requests(status);
            CREATE INDEX IF NOT EXISTS idx_approval_created
                ON approval_requests(created_at DESC);
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Service Scopes
    # ------------------------------------------------------------------

    def save_scope(
        self,
        service: str,
        scope: str,
        enabled: bool,
        risk_tier: str = "high",
        description: str = "",
    ) -> str:
        """Upsert a service scope setting. Returns the scope ID."""
        now = datetime.now(timezone.utc).isoformat()
        scope_id = str(uuid.uuid4())
        self._conn.execute(
            """
            INSERT INTO service_scopes (id, service, scope, enabled, risk_tier, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(service, scope) DO UPDATE SET
                enabled = excluded.enabled,
                risk_tier = excluded.risk_tier,
                description = excluded.description,
                updated_at = excluded.updated_at
            """,
            (scope_id, service, scope, int(enabled), risk_tier, description, now, now),
        )
        self._conn.commit()
        return scope_id

    def get_scopes(self, service: str) -> list[dict[str, Any]]:
        """Get all scopes for a service."""
        cursor = self._conn.execute(
            "SELECT * FROM service_scopes WHERE service = ? ORDER BY scope",
            (service,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_all_scopes(self) -> list[dict[str, Any]]:
        """Get all scopes across all services."""
        cursor = self._conn.execute(
            "SELECT * FROM service_scopes ORDER BY service, scope"
        )
        return [dict(row) for row in cursor.fetchall()]

    def is_scope_enabled(self, service: str, scope: str) -> bool:
        """Check if a specific scope is enabled. Returns False if not found (deny-by-default)."""
        cursor = self._conn.execute(
            "SELECT enabled FROM service_scopes WHERE service = ? AND scope = ?",
            (service, scope),
        )
        row = cursor.fetchone()
        return bool(row["enabled"]) if row else False

    def set_scope_enabled(self, service: str, scope: str, enabled: bool) -> bool:
        """Toggle a scope on/off. Returns True if the scope exists."""
        cursor = self._conn.execute(
            "UPDATE service_scopes SET enabled = ?, updated_at = ? WHERE service = ? AND scope = ?",
            (int(enabled), datetime.now(timezone.utc).isoformat(), service, scope),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Tier Overrides
    # ------------------------------------------------------------------

    def save_tier_override(
        self,
        action_id: str,
        original_tier: str,
        override_tier: str,
        reason: str = "",
    ) -> str:
        """Save a user's risk-tier override for an action."""
        override_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            INSERT INTO tier_overrides (id, action_id, original_tier, override_tier, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                override_tier = excluded.override_tier,
                reason = excluded.reason,
                created_at = excluded.created_at
            """,
            (override_id, action_id, original_tier, override_tier, reason, now),
        )
        self._conn.commit()
        return override_id

    def get_tier_override(self, action_id: str) -> dict[str, Any] | None:
        """Get the tier override for a specific action, if any."""
        cursor = self._conn.execute(
            "SELECT * FROM tier_overrides WHERE action_id = ?",
            (action_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_all_overrides(self) -> list[dict[str, Any]]:
        """Get all tier overrides."""
        cursor = self._conn.execute("SELECT * FROM tier_overrides ORDER BY action_id")
        return [dict(row) for row in cursor.fetchall()]

    def delete_tier_override(self, action_id: str) -> bool:
        """Remove a tier override, reverting to the default."""
        cursor = self._conn.execute(
            "DELETE FROM tier_overrides WHERE action_id = ?",
            (action_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Approval Requests
    # ------------------------------------------------------------------

    def create_approval_request(
        self,
        action_id: str,
        action_description: str,
        risk_tier: str,
        requires_pin: bool,
        context: dict | None = None,
    ) -> str:
        """Create a new approval request. Returns the request ID."""
        request_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            INSERT INTO approval_requests
                (id, action_id, action_description, risk_tier, requires_pin, context_json, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                request_id,
                action_id,
                action_description,
                risk_tier,
                int(requires_pin),
                json.dumps(context or {}),
                now,
            ),
        )
        self._conn.commit()
        return request_id

    def resolve_approval(
        self, request_id: str, approved: bool, resolved_by: str = "user"
    ) -> bool:
        """Resolve a pending approval request. Returns True if it existed."""
        now = datetime.now(timezone.utc).isoformat()
        status = "approved" if approved else "denied"
        cursor = self._conn.execute(
            """
            UPDATE approval_requests
            SET status = ?, resolved_at = ?, resolved_by = ?
            WHERE id = ? AND status = 'pending'
            """,
            (status, now, resolved_by, request_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def get_pending_approvals(self) -> list[dict[str, Any]]:
        """Get all pending approval requests."""
        cursor = self._conn.execute(
            """
            SELECT * FROM approval_requests
            WHERE status = 'pending'
            ORDER BY created_at DESC
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        for row in rows:
            row["context"] = json.loads(row.pop("context_json", "{}"))
        return rows

    def get_approval_request(self, request_id: str) -> dict[str, Any] | None:
        """Get a specific approval request."""
        cursor = self._conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?",
            (request_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        result = dict(row)
        result["context"] = json.loads(result.pop("context_json", "{}"))
        return result

    def get_approval_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent approval history (all statuses)."""
        cursor = self._conn.execute(
            """
            SELECT * FROM approval_requests
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        for row in rows:
            row["context"] = json.loads(row.pop("context_json", "{}"))
        return rows
