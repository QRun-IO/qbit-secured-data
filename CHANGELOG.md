# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
