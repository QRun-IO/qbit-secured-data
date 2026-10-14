# QBit Secured Data

Phases (b), (c), and (e) of [SECURED-DATA](https://github.com/QRun-IO/qqq/blob/develop/docs/SECURED-DATA.md): classification overrides, policy resolution, enumeration guardrails, and value-free access logging. QQQ core owns masking and query enforcement. Reveal, break-glass, the app home and anomaly alerts are implemented. Retention and audit-value protection remain later phases.

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

## Reveal and break-glass

`new RevealService().options(tableName, fieldName)` describes the reason choices, free-text rules, duration and remaining allowance. `reveal(tableName, primaryKey, fieldName, reason, reasonText)` performs an explicitly permission-enforced Get as the caller before a system read. It returns `value`, core-formatted `displayValue`, `expiresAt`, and `revealId`. Grants and their linked audit rows are system-written; no raw value is copied into the access log.

The effective tier must be REVEALABLE. The chosen granting policy is the row with the highest daily cap (null means unlimited), then the longest duration, then lowest lexical id. Channel-only cap rows never grant reveal settings. A feature/default-based REVEALABLE tier with no granting row uses five minutes and an allowed free-text reason. Limits count grants across all tables for the user in the UTC day. Reason and reason text each have a 500-character limit. A required explanation is accepted alongside a listed reason even if arbitrary free-text reasons are disabled. Capped requests record `REVEAL_DENIED/CAPPED` and raise `secured_data.reveal_capped`; assistant-channel requests record `REVEAL_DENIED/DENIED` and return 403.

Grant lookups cache identifiers and expiration times for at most five seconds per user, check expiration on each use, and invalidate immediately after a new grant. The service serializes cap-check/write and duplicate-session checks within one runtime. Multi-replica deployments must coordinate these operations externally for a globally atomic cap and single active session; the in-process lock is not a distributed lock.

`secured_data_break_glass_start` is a table action, labeled **Start break-glass**, requiring `secured_data_break_glass_start.hasAccess`. Its reason must contain 20-500 characters; duration defaults to 60 minutes and accepts 1-480. Table scope is optional and classification ceiling defaults to PHI. `secured_data_break_glass_end` is a record action with the standard streamed ETL Review/Result screens; ownership/admin authorization is checked at review and again at execution. Neither action is a navigation entry. The current admin-only activity table permissions remain in place; an owner can invoke End using the session id returned by status without obtaining admin access to activity tables.

Start raises `secured_data.break_glass` at core's `HIGH` mapping (`AlertSeverity.ERROR`). End and expiry resolve the same per-session alert. Bell delivery targets holders of `secured_data.admin` through core's optional notification SPI #1125. RC.5 and the installed secure-data snapshot lack that SPI: a clear warning is logged. TODO: switch to a direct notification call when #1125 ships and verify against a notification-capable core.

Configure `.withSchedulerName("yourScheduler")` to register the hidden `secured_data_break_glass_expire` process every minute. Without a scheduler, the host must invoke that process itself. Tier resolution checks expiration independently, so delayed maintenance cannot prolong access. `new StatusService().status()` returns the caller's active session or null, grants used today, and the allowance for each readable REVEALABLE field.

## UI API extension

The `secured-data` extension is version **1.0.0**:

- `POST /qqq/v1/qbit/secured-data/reveal`
- `GET /qqq/v1/qbit/secured-data/reveal/options?tableName=&fieldName=`
- `GET /qqq/v1/qbit/secured-data/status`

Build with `-Duiapi=true` and a compatible core to compile `src/main/java-uiapi` and `src/test/java-uiapi`. The producer registers the extension only when both its classes and core's extension metadata exist. The committed contract is [secured-data.yaml](src/main/resources/openapi/qqq-v1/secured-data.yaml); regenerate intentionally with `-Dqqq.uiApi.regenerate=true`. The supplied core exposes `UiApiContract.check`, so a local test-only `UiApiContractAssertions` adapter supplies the documented assertion facade. All UI API roots and adapters are `STAND-IN(core=QRun-IO/qqq#1128, removeBy=RC.6)` and fold into the normal roots at RC.6. The core OpenAPI model cannot mark object properties required; the request schema documents required properties and the handler validates them.

The classification field picker uses CUSTOM possible values, reading `table_name` or `tableName` from the form's other values. It returns only the selected readable table's labeled fields, returns none without a selection, and rejects an unknown table. TODO: add `dependsOn("table_name")` when the core metadata API supports it.

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
| `withSchedulerName(String)` | Host scheduler for the 60-second break-glass expiry job; null means host-managed invocation |
| `withClock(Clock)` | UTC system clock; injectable for deterministic expiry tests |

Configure before producing the QBit; runtime infrastructure and HMAC keys are captured at startup. Classification/policy/break-glass lookups always run as system, with a thread-local recursion guard. No reveal values are cached.

## Build and tests

```powershell
./mvnw.cmd -q -o clean verify
./mvnw.cmd -q -o clean verify -Dqqq.snapshot.version=4.1.0-SECUREDATA-SNAPSHOT -Duiapi=true
```

The direct suite uses memory and H2. `CoreFieldAccessBridgeIT` is included by Surefire and uses JUnit assumptions to skip unless the actual core resolver metadata is present. With the installed core snapshot it exercises Query/Get, policy tiers, masking, exact matches and outcomes, sorting denial, rate/entropy refusal and the assistant wall. Checkstyle and JaCoCo remain 70% instructions / 90% classes; stand-ins are not excluded.

## Anomaly monitoring (phase e)

Application REVEAL and queued EXACT_MATCH_FILTER audit writes evaluate persisted access-log counters as system, counting the current row once. Successful reveals flag above three times the user's median across the previous 30 complete UTC days (including zero days), with at least ten reveals today. More than 20 distinct `(table, record)` pairs within the last hour also flag. More than 50 exact-match attempts on one restricted field within the last hour flag independently of enumeration controls. The default rate limit of 20 usually refuses searches first; refused attempts still count.

Break-glass starts and capped reveal refusals also flag. Each raises `secured_data.anomaly` with dedup key `secured_data.anomaly:<user>:<UTC day>` through the optional alerts SPI. Existing enumeration, break-glass and cap alerts remain intact. No qbit-alerts dependency is required; flags remain visible without a sink. The sink owns deduplication. End and expiry events remain in the break-glass activity list rather than representing new session anomalies.

Thresholds are positive integers:

| Config method | Default |
| --- | ---: |
| `withAnomalyDailyMedianMultiplier` | 3 |
| `withAnomalyMinimumDailyReveals` | 10 |
| `withAnomalyDistinctRecordsPerHour` | 20 |
| `withAnomalyExactMatchesPerHour` | 50 |

Medians use 30 scalar indexed counts on first qualifying use per user/day, cached for at most 2,048 users per instance and cleared at UTC day rollover. Today's and hourly counts read persisted history; distinct-record queries return at most the threshold plus one grouped rows. Counter evaluation and insertion serialize within an instance; other nodes become visible through persisted rows. This monitors activity rather than providing a distributed enforcement lock. Historical backfills after caching take effect next UTC day or after runtime restart. Existing deployments should apply the two new access-log indexes in `docs/ddl/secured-data-postgres.sql`.

## Secured Data home

The single Secured Data app owns one full-width HTML home widget, following qbit-webhooks' data/view/renderer pattern. It reads as the viewer with normal permissions and record security:

- Six KPIs: reveals today, unexpired grants, active and unexpired break-glass sessions, anomaly flags and denied filters over seven days, and this runtime's access-log queue drops since startup. Denied filters include refused exact-match attempts.
- Six full-width lists: recent reveals (10), top revealers and reasons (30-day backend aggregates, top 10), recent break-glass starts/ends/expiries (10), policy/classification changes (10), and seven-day anomaly flags (10).
- Each list has a filtered access-log `View all` link without the widget's ten-row limit. Configure the host table route with `withTablePathPrefix("/app")`.

Lists order newest first with id tie-breaking; rankings order by count descending then group alphabetically. Narrow screens use wrapping labelled card rows. Dates stay compact on one line, text is ellipsized with full tooltips, and colors inherit the host with `--qqq-grid-border` for borders. There are no inner scrollers. Empty lists explicitly say there is no activity.

Navigation contains Classification, Policy, Access log and Break-glass sessions. Reveal grants remain a child list; retention is not implemented. Successful policy/classification inserts, updates and deletes produce value-free change rows with actor, record id and action in the source transaction. No configuration values are copied into these rows.

### Local screenshot harness

`SecuredDataDemoServer` is a test-only memory-backed Next demo adapted from qbit-webhooks. It seeds synthetic activity for all six lists, including long reasons, sessions and anomaly flags. It uses a demo administrator and must only be run locally. After a test run, launch in PowerShell:

```powershell
[xml]$report = Get-Content target/surefire-reports/TEST-com.kingsrook.qbits.secureddata.SecuredDataHomeTest.xml
$demoClasspath = ($report.testsuite.properties.property | Where-Object name -eq 'java.class.path').value
java -cp $demoClasspath com.kingsrook.qbits.secureddata.SecuredDataDemoServer
```

Open `http://localhost:8098/app/secured_data`. Stop the demo before `clean` on Windows. Capture light and dark at 390, 768, 1024, 1440, 1920 and 3200 px under `target/screenshots/`. This session started the server, but screenshot capture was blocked by Chromium `spawn EPERM` in the sandbox and two connected-browser timeouts. The coordinator still needs to capture and inspect the twelve images through Next.

## Remaining phases

RC.6 migration removes temporary types and reflection. Retention, wipe and audit-value protection remain phases (f)/(g).

## License

[Apache License 2.0](LICENSE). Copyright Kingsrook, LLC.
