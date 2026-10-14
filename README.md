# QBit Secured Data

Phase (b) of [SECURED-DATA](https://github.com/QRun-IO/qqq/blob/develop/docs/SECURED-DATA.md): classification overrides, policy resolution, enumeration guardrails, and value-free access logging. QQQ core owns masking and query enforcement. Reveal/Start/End operations, home widgets, retention and audit-value protection are later phases.

## Compatibility

Java 21, Maven wrapper 3.9.11, **QQQ 4.1.0-RC.5**. The released dependency pin is unchanged.

RC.5 contains AI exposure metadata, the alerts producer SPI and the tables picker. It does **not** contain field-access enforcement, `DataClassification`, classification properties on AI metadata, client channels, or table-feature permissions. Jar contents and embedded sources were inspected locally (`jar tf`; Git's `unzip` could not run in the Windows sandbox).

Missing APIs live under `com.kingsrook.qbits.secureddata.standin`, with `STAND-IN` removal markers. `CoreFieldAccessBridge` registers a dynamic proxy only when core's `FieldAccessResolverMetaData` exists. It converts decision record components and event enums by name. On RC.5 it logs one INFO that enforcement requires RC.6+; installing this QBit on RC.5 **does not enforce field tiers**.

`CoreMetadataBridge` promotes temporary classifications into core AI metadata when supported, registers the channel wall and table features reflectively, and uses core feature-permission checks when present. A missing API is supported; a present but incompatible API fails startup. The public classification API temporarily returns the stand-in `DataClassification` because the core enum is absent from RC.5. At RC.6, move these imports to core and delete the adapters/stand-ins.

## Install and register

```xml
<dependency>
   <groupId>com.kingsrook.qbits</groupId>
   <artifactId>qbit-secured-data</artifactId>
   <version>1.0.0-SNAPSHOT</version>
</dependency>
```

```java
new SecuredDataQBitProducer()
   .withQBitConfig(new SecuredDataQBitConfig()
      .withBackendName("rdbms")
      .withDefaultTier(DataClassification.PII, FieldAccessTier.MASKED))
   .produce(qInstance);
```

Register the host backend and application tables before producing the QBit. Enable core permissions (`qInstance.withEnforcePermissionsInCoreActions(true)`) at application entry points. Only one secured-data runtime is supported per instance. A namespace labels the QBit identity; table names remain fixed.

The host supplies database connection metadata. Physical table names and field backend names are the same snake_case names as the QQQ metadata; an RDBMS host may set `RDBMSTableBackendDetails.withTableName(table.getName())` through `withTableMetaDataCustomizer(...)`. Apply [the PostgreSQL 15+ DDL](docs/ddl/secured-data-postgres.sql) before serving requests. The same SQL is tested with H2 in PostgreSQL mode.

## Tables, screens and permissions

| Table | Label | User access |
|---|---|---|
| `secured_data_classification` | Classification | Admin management |
| `secured_data_policy` | Policy | Admin management |
| `secured_data_reveal_grant` | Reveal | Admin read; system writes |
| `secured_data_break_glass` | Break-glass session | Admin read; system writes |
| `secured_data_access_log` | Access log | Admin read; system insert only |

Every table has audit rules, explicit record sections and CONFIDENTIAL code classification. The Secured Data app navigates to Classification, Policy, Access log and Break-glass session. Reveal grants are a read-only child list joined by `access_log_id`; no process or home widget appears in navigation. The classification target `(table_name, field_name)` is unique, including the null field used for a table-wide override.

`secured_data.admin` gates configuration editing and activity reads through a standard QQQ custom permission checker. It gives no implicit access to classified fields on application tables. `secured_data.hasAccess` is the catalog base permission; the custom checker requires admin. Activity writes are refused for ordinary users even when they hold admin. Customizers also protect system-only writes, and update/delete capabilities are disabled on the access log, including system calls.

Both table features are registered for **all tables**: `secured_data_full` (Secured data: full) and `secured_data_reveal` (Secured data: reveal). This deliberate catalog choice supports new admin classification rows without a restart. Core's permission-base, READ prerequisite and NOT_PROTECTED semantics are preserved: NOT_PROTECTED application tables grant their features without an explicit permission. Use protected table permission rules when field policies must restrict users. Feature grants have no standard WRITE/admin implication.

The assistant is denied `secured_data_*` through core client-channel metadata. The local custom checker enforces the same wall on RC.5 when the trusted host uses `standin.ClientChannelSession`. On newer core use `QSession.withClientChannel("assistant/t1")`. The normalized channel `assistant` is stored in logs and used for policy caps. A host must set the channel from trusted request context.

ESB integration follows webhooks' host-wiring pattern: `SecuredDataTables.esbTableNames()` lists Classification, Policy, Access log and Break-glass. Connect those names to the host ESB table-event producer. No ESB or qbit-alerts dependency is added.

## Classifying fields

Code metadata establishes defaults. While pinned to RC.5:

```java
import com.kingsrook.qbits.secureddata.standin.AiFieldMetaData;
import com.kingsrook.qbits.secureddata.standin.DataClassification;

email.withSupplementalMetaData(
   new AiFieldMetaData().withClassification(DataClassification.PII));
```

The matching stand-in `AiTableMetaData` sets a table default. These supplemental objects coexist with RC.5's core AI exposure metadata. The producer promotes them into core AI metadata when the newer API is available. After moving to RC.6, use `com.kingsrook.qqq.backend.core.actions.ai.AiFieldMetaData` and core `DataClassification` with the same classification pattern.

Admin rows in Classification can raise **or lower** the default. Effective order:

1. Field-specific classification row.
2. Table-wide row (`field_name` null).
3. Code field classification.
4. Code table classification.
5. Unclassified.

Rows can also set `mask_style` and `low_cardinality`: true/false override entropy detection in either direction; null selects automatic rules. The tables picker reuses core's PVS, and the fields picker uses the selected `table_name`.

Other QBits use `SecuredDataClassifications.effective(table, fieldName)`, `effective(table)`, `highest(table)`, or `highest(table, fieldNames)` under their QContext. An empty field subset returns null. Rows are cached by classification version; startup and successful post-commit insert/update/delete change the version.

## Policy resolution and guardrails

Unclassified/PUBLIC fields and primary keys are FULL. Active, unexpired break-glass grants cover a table or all tables up to their classification ceiling. Full/reveal table features combine with the least restrictive matching non-channel policy tier. A policy matches an active row, the session's `permission_name`, classification and optional table. If no grant row matches, code defaults are CONFIDENTIAL FULL, PII MASKED and PHI MASKED.

A `client_channel` policy row **only caps** the result. Caps also restrict break-glass and feature grants; a channel-only FULL row cannot elevate a default MASKED tier. This makes the channel a ceiling regardless of how access was granted. The admin shortcut applies only to this QBit's own tables.

The four policy guardrail settings combine most restrictively across applicable rows. Positive numeric limits combine by minimum; zero disables a control only when no matching row enables it. `min_entropy_enabled` is enabled if any matching row enables it. When no policy matches, configuration defaults apply.

- `exact_match_per_hour`: 20 searches per user/table/field, including MATCH, NO_MATCH and REFUSED rows. The next request is refused with `Exact-match search limit reached for [field]. Try again later or ask an administrator.`
- `miss_alert_consecutive`: 5 consecutive NO_MATCH outcomes, including across hour boundaries; other outcomes reset the streak.
- `distinct_value_alert`: more than 15 HMAC fingerprints per hour flags the row.
- `min_entropy_enabled`: disables exact match for boolean, PVS/enum, DATE/DATE_TIME, integer year names/labels, state/region/province/zip3 names/labels, and strings with maxLength under 6. Explicit classification-row true/false takes precedence over detection; disabling the control bypasses both.

Database history plus unflushed rows and local in-flight reservations prevent local concurrent overspending. Failed queries/dropped audit rows retain conservative reservations for an hour. Database history is shared, but another node's pending queue/reservations are not: this is not an atomic distributed quota. Hosts requiring that must serialize exact-search preflight across nodes.

Policy/break-glass caches are bounded per instance and keyed by relevant user permissions and policy version; expiry is rechecked at use time. Fingerprints hash user, held permissions mentioned in any policy or either table feature, policy/classification versions, active break-glass ids, and channel. Unrelated records/permissions and reveal grants do not change them. Multi-node hosts must propagate configuration/break-glass changes to `SecuredDataRuntime.invalidatePolicies()` / `invalidateClassifications()` on other nodes; local customizers only invalidate their own instance.

## Logging and lifecycle

`SecuredDataAccessLogger` captures identifiers, counts, normalized channel and outcomes, never field/search values. VIEW includes only configured classifications (PII/PHI by default), at most 50 primary keys encoded as JSON, and one row per table/action. Exact searches produce one row per affected field with MATCH/NO_MATCH/REFUSED; DENIED events become FILTER_DENIED. Break-glass id and refusal reason are recorded when available.

The extra `search_value_fingerprints` TEXT column persists JSON arrays of HMAC-SHA256 fingerprints for distinct-value detection after restarts and across nodes. Use a shared secret key supplier on multi-node deployments; the default is a random per-JVM key, so historical fingerprints from another JVM/key cannot be compared reliably.

One daemon worker drains a bounded queue as a system session. Enqueueing does not wait for persistence. Full queues and failed writes warn without values and increment `getDroppedCount()`. The app can expose this counter later. Explicitly call the instance's `SecuredDataRuntime.close()` at host shutdown; a JVM shutdown hook also drains accepted rows. An abrupt process crash can lose queued rows.

Flagged rows raise the optional alerts producer signal `secured_data.enumeration`, deduplicated by `secured_data.enumeration:<user>:<table>.<field>:<UTC date>`. RC.5 already provides `QAlerts`; without an installed sink it logs the signal. Its catalog validator rejects underscores in type names, so this mandated type is sent through the producer without catalog registration until that core restriction is reconciled. No values or fingerprints are sent to the alert sink.

## Configuration

| Fluent option | Default / purpose |
|---|---|
| `withBackendName(String)` | `memory`; host backend name |
| `withTableMetaDataCustomizer(...)` | Optional host storage/security customization |
| `withDefaultTier(DataClassification, FieldAccessTier)` | CONFIDENTIAL FULL; PII/PHI MASKED |
| `withDefaultTierByClassification(Map<String,String>)` | Compatibility bulk setter; omitted restricted types fail closed |
| `withNameHeuristics(boolean)` | false; opt-in PII for ssn/dob/date_of_birth/email/phone, PHI for diagnosis* |
| `withViewLogClassifications(Set<DataClassification>)` | PII, PHI |
| `withFingerprintKeySupplier(Supplier<byte[]>)` | Random 32-byte JVM key; supplied key must be at least 16 bytes |
| `withAccessLogQueueCapacity(int)` | 4096 rows |
| `withAccessLogFlushIntervalMillis(long)` | 250 ms |
| `withExactMatchPerHour(int)` | 20; zero disables |
| `withMissAlertConsecutive(int)` | 5; zero disables |
| `withDistinctValueAlert(int)` | 15; zero disables |
| `withMinEntropyEnabled(boolean)` | true |
| `withClock(Clock)` | UTC system clock; injectable for deterministic expiry tests |

Configure before producing the QBit; runtime infrastructure and HMAC keys are captured at startup. Classification/policy/break-glass lookups always run as system, with a thread-local recursion guard. No reveal values are cached.

## Build and tests

```powershell
./mvnw.cmd -q -o verify
./mvnw.cmd -q -o -Dqqq.snapshot.version=4.1.0-SECUREDATA-SNAPSHOT verify
```

The direct suite uses memory and H2. `CoreFieldAccessBridgeIT` is included by Surefire and uses JUnit assumptions to skip unless the actual core resolver metadata is present. With the installed core snapshot it exercises Query/Get, policy tiers, masking, exact matches and outcomes, sorting denial, rate/entropy refusal and the assistant wall. Checkstyle and JaCoCo remain 70% instructions / 90% classes; stand-ins are not excluded.

## Remaining phases

RC.6 migration removes temporary types and reflection. Phase (c) adds Reveal and Start/End break-glass operations and expiry scheduling; this phase already reads active grants/sessions. Phase (e) adds the app home and broader anomaly rules. Retention, wipe and audit-value protection remain phases (f)/(g).

## License

[Apache License 2.0](LICENSE). Copyright Kingsrook, LLC.
