# AGENTS.md

Guidance for coding agents working in this repository.

## Overview

QBit Secured Data provides FULL/REVEALABLE/MASKED/HIDDEN field tiers by role × DataClassification, reveal grants, break-glass access and an access log. Masking is enforced in QQQ core. This is a scaffold only; domain behavior is not implemented yet.

Design: https://github.com/QRun-IO/qqq/blob/develop/docs/SECURED-DATA.md (§5–§8).

## Build commands

```bash
./mvnw compile
./mvnw test
./mvnw verify  # Checkstyle; JaCoCo: 70% instructions, 90% classes
./mvnw -q -o verify
```

Use the Maven 3.9.11 wrapper (Java 21); Maven 3.10 cannot read the parent POM. On Windows use `./mvnw.cmd`.

## Architecture

Package: `com.kingsrook.qbits.secureddata`. Entry point: `SecuredDataQBitProducer implements QBitMetaDataProducer<SecuredDataQBitConfig>`. It registers QBit metadata and returns it in a `MetaDataProducerMultiOutput`, with no tables yet. Config exposes `tableMetaDataCustomizer` and an initially empty `Map<String, String> defaultTierByClassification`.

Planned tables: `secured_data_classification`, `secured_data_policy`, `secured_data_reveal_grant`, `secured_data_break_glass`, `secured_data_access_log`.

## Invariants and naming

QQQ core owns masking enforcement. Reveal, break-glass and access logging follow the spec; do not imply this scaffold enforces access. Tables use lowercase snake_case with the `secured_data_` prefix; backend names equal table names. Permissions use the full `secured_data` prefix. Processes are table or record actions, not navigation entries.

## Code style

3-space indent, next-line braces, `return (x);`, flower-box Javadoc on classes and methods, fluent `withX()` setters. Follow `checkstyle/` and `CODE_STYLE.md`.

## Dependencies

Parent: `com.kingsrook:qbit-build-parent:2.0.0`. QQQ BOM: `4.1.0-SNAPSHOT`, pending the RC with fieldaccess hooks. Core and Javalin are compile dependencies; memory/RDBMS backends, frontend-next, H2, JUnit and AssertJ support tests. Do not add qbit-alerts yet.

## Release flow

CircleCI uses `kingsrook/qqq-orb@0.6.8`: develop publishes SNAPSHOTs, release/* publishes RCs, and only `vX.Y.Z` GA tags publish releases. Hotfix branches run tests. RC automation uses workflow_dispatch or a merged develop PR labelled `release:rc`. Feature branches start from develop and return by PR. Never publish manually.
