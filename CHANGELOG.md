# Changelog

## 0.1.1 - 2026-09-07

- Critical approvals require an injected `pin_verifier`; missing, incorrect, non-boolean or failing verification leaves the approval pending. Denial never requires a PIN. (Review 1)
- Action ID aliases use the same override and approval identity. Existing dot/colon overrides are migrated atomically; conflicting legacy overrides retain the stricter tier. (Review 2)

### Upgrade

Configure `PermissionManager(registry, storage, pin_verifier=your_pin_verifier)` before allowing critical actions. The synchronous callback must validate the submitted PIN against your authenticated user's configured credential and return exactly `True` on success. The package does not store a PIN, authenticate users or rate-limit attempts; the host must do those things. Do not use a callback that always returns true. Existing integrations without a verifier now fail closed for critical approvals.

### Validation

61 tests pass, including `tests/test_review_regressions.py`; main README quickstart checked. Tests use synthetic data and isolated databases. No live provider calls or service actions were used.
