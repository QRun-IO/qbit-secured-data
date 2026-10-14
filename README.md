# QBit Secured Data

Field access for QQQ applications: FULL, REVEALABLE, MASKED and HIDDEN tiers by role × DataClassification, with masking enforced in QQQ core, explicit reveal grants, break-glass access and an access log. This repository currently contains only the compiling scaffold; enforcement and domain features are not implemented here yet. See the [secured-data spec](https://github.com/QRun-IO/qqq/blob/develop/docs/SECURED-DATA.md), especially §5–§8.

## Requirements

Java 21 and QQQ 4.1.0-RC.5 (RC.6 for the fieldaccess hooks). The Maven wrapper pins Maven 3.9.11.

## Install

```xml
<dependency>
   <groupId>com.kingsrook.qbits</groupId>
   <artifactId>qbit-secured-data</artifactId>
   <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Tables and permissions

Planned tables (none are produced yet):

- `secured_data_classification`
- `secured_data_policy`
- `secured_data_reveal_grant`
- `secured_data_break_glass`
- `secured_data_access_log`

Backend names match table names. Permissions use the `secured_data` prefix; role × DataClassification policies determine field tiers. Reveal and break-glass semantics follow the spec.

## Configuration

`SecuredDataQBitConfig` exposes an optional `tableMetaDataCustomizer` and an initially empty `Map<String, String> defaultTierByClassification`. These settings reserve the configuration surface; the scaffold does not apply policies or customize tables yet.

## Adopting in another app

```java
new SecuredDataQBitProducer()
   .withQBitConfig(new SecuredDataQBitConfig())
   .produce(qInstance);
```

Import both classes from `com.kingsrook.qbits.secureddata`. Production registers the QBit identity and config in the QInstance; no tables are added yet.

## Build

```bash
./mvnw compile
./mvnw test
./mvnw verify
./mvnw -q -o verify  # when dependencies are cached locally
```

Verification includes Checkstyle and JaCoCo gates of 70% instructions and 90% classes. On Windows, use `./mvnw.cmd`.

## License

[Apache License 2.0](LICENSE). Copyright Kingsrook, LLC.
