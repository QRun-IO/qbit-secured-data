# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed: access-log lifecycle
- The access-log worker and JVM shutdown hook hold the logger weakly, so an instance the host drops (tests, reloads) can be collected; its worker stops at the next tick.
- `withRegisterShutdownHook(false)` for hosts that call `SecuredDataRuntime.close()` themselves; `SecuredDataAccessLogger.isWorkerRunning()`.
- Virtual (computed) fields resolve through the table classification instead of throwing (#18).
- Idle access-log ticks open no context, so the worker never validates an unfinished host instance, and a failed tick no longer stops the worker (#18).

### Changed: UI API 1.6.0
- UI API extension secured-data 1.1.0 (requires QQQ 4.1.0-RC.15, UI API 1.6.0): operationIds, standard error responses with BasicErrorResponseV1, extension tags, and retained SecuredDataErrorV1 schema deprecated since 1.1.0.

### Changed — direct core field access and audit protection
- Remove all #1172/#1182 stand-ins and reflective bridges; use core field-access, classified-value token, audit protection, wipe flag and shredded-event APIs directly.
- Register the resolver, key source and audit protector through core supplemental metadata.
- Run core field-access integration and retention proof tests unconditionally.
- Pin QQQ to `4.1.0-RC.7`, which ships field access (#1172) and audit value protection (#1182); all core stand-ins and reflective bridges are removed.

### Changed — RC.6 migration
- Pin QQQ to 4.1.0-RC.6; use released classification, client-channel and table-feature APIs directly.
- Fold UI API code and tests into the main build and remove the profile and reflective registration.
- Remove released-API stand-ins and the local contract assertion facade; retain #1172 field-access stand-ins with RC.7 removal markers.

### Added: phase (f) retention and wipe
- Retention rules, wipe markers, legal holds, wipe runs and a hidden, locked audit-key table, with the `secured_data.retention` permission and a "Retention rules" navigation entry.
- Actions NULL_WITH_MARKER, OVERWRITE_TEXT, KEYED_HASH, DELETE_RECORD and ARCHIVE_THEN_WIPE (host `ArchiveSinkInterface`), with validation and low-entropy refusal.
- Atomic wipe batches (fields, markers, key deletions, audits, access log and run row in one rollback-capable transaction), per-record and per-table legal holds, a Review/Result "Run wipe now" process and a daily scheduled run.
- Per-record-field AES-GCM wrapped DEKs (AAD-bound) for crypto-shredding of audit tokens, `CHANGED_ONLY` audit treatment, and the audit-value protector.
- App-home warning when known backup retention exceeds a rule's `age_days`; `withBackupRetentionDays` and `withArchiveSink` options; README retention section and the backups residual risk.
- Tests: all actions, holds, rollback, Review/Result, schedule, permissions, wrap/unwrap, and the section 15 canary and wipe-proof tests.

### Fixed
- The key source returned a DEK array it then zeroed; it now returns copies, with a regression test.

### Added

- Phase (e) configurable reveal-median, distinct-record and exact-match anomaly detection, with system access-log counters, bounded daily median caching, per-user/day alerts, and flags retained without an alert sink.
- Break-glass start and capped-reveal anomaly flags alongside the existing alerts.
- One Secured Data app home with six live KPIs, six full-width responsive lists, filtered View all links, theme tokens, compact dates, clamped text/tooltips and explicit empty states.
- Transaction-aware, value-free policy/classification change audit rows from post-write customizers and two access-log indexes for anomaly/home queries.
- Boundary, alert, home data, rendering and navigation tests plus a synthetic Next demo harness for coordinator screenshot capture.

- Phase (c) HTTP-independent reveal options, reason validation, UTC daily limits, grants, audit links, cap alerts and assistant refusal.
- Five-second per-user grant cache with immediate invalidation and read-time expiration.
- Start/End break-glass table and record actions, streamed Review/Result summaries, owner/admin authorization, scheduled expiration, alerts and optional admin bell notification.
- Caller status and the versioned `secured-data` UI API extension behind the temporary `uiapi` Maven profile, with committed OpenAPI and contract/HTTP tests.
- Contingent classification field picker support for snake_case and camelCase table selections; unknown-table rejection.
- Memory and real-core coverage for reveal, break-glass, record locks and expiry. Reason columns support 500 characters; existing RDBMS installations must widen the three `reason` columns to VARCHAR(500).

- Phase (b) secured-data classification, policy, reveal-grant, break-glass and insert-only access-log tables, metadata, permissions, pickers and app navigation.
- Versioned classification and policy resolution with channel caps, table features, break-glass expiry and access fingerprints.
- Bounded asynchronous value-free logging, HMAC search fingerprints, rate limits, entropy rules and enumeration alerts.
- RC.5-compatible stand-ins and reflective core adapters; conditional core Query/Get integration coverage.
- PostgreSQL DDL, H2 persistence/constraint coverage, and configuration/deployment documentation.
