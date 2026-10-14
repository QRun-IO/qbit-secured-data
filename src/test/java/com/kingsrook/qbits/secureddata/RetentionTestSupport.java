/*
 * QQQ - Low-code Application Framework for Engineers.
 * Copyright (C) 2021-2025.  Kingsrook, LLC
 * 651 N Broad St Ste 205 # 6917 | Middletown DE 19709 | United States
 * contact@kingsrook.com
 * https://github.com/Kingsrook/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kingsrook.qbits.secureddata;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.ai.AiFieldMetaData;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.instances.QInstanceValidator;
import com.kingsrook.qqq.backend.core.model.audits.AuditsMetaDataProvider;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSTableBackendDetails;

final class RetentionTestSupport
{
   static String BACKEND = "retention_rdbms";
   static final String KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
   static final Instant OLD = SecuredDataTestSupport.NOW.minusSeconds(60L * 86400);
   static QInstance setup() throws Exception
   {
      SecuredDataTestSupport.close();
      System.setProperty("QQQ_SECURED_DATA_KEK", KEY);
      System.setProperty("QQQ_AUDIT_HMAC_KEY", KEY);
      SecuredDataTestSupport.CLOCK.now = SecuredDataTestSupport.NOW;
      String db = "retention_" + UUID.randomUUID().toString().replace("-", "");
      BACKEND = db;  // pools are cached by backend name, so each instance needs its own
      String url = "jdbc:h2:mem:" + db + ";MODE=PostgreSQL;DATABASE_TO_UPPER=FALSE;DB_CLOSE_DELAY=-1";
      RDBMSBackendMetaData backend = new RDBMSBackendMetaData().withName(BACKEND).withVendor("h2").withHostName("mem").withDatabaseName(db).withUsername("sa");
      backend.setJdbcUrl(url);
      QInstance instance = SecuredDataTestSupport.base();
      instance.addBackend(backend);
      QTableMetaData table = new QTableMetaData().withName("reading").withLabel("Reading").withBackendName(BACKEND).withPrimaryKeyField("id")
         .withBackendDetails(new RDBMSTableBackendDetails().withTableName("reading"))
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.READ_WRITE_PERMISSIONS))
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.FIELD))
         .withField(new QFieldMetaData("id", QFieldType.INTEGER))
         .withField(new QFieldMetaData("reading_time", QFieldType.DATE_TIME))
         .withField(new QFieldMetaData("reading_date", QFieldType.DATE))
         .withField(new QFieldMetaData("systolic", QFieldType.INTEGER).withSupplementalMetaData(new AiFieldMetaData().withClassification(DataClassification.PHI)))
         .withField(new QFieldMetaData("secret", QFieldType.STRING).withMaxLength(255).withBehavior(com.kingsrook.qqq.backend.core.model.metadata.fields.ValueTooLongBehavior.ERROR).withSupplementalMetaData(new AiFieldMetaData().withClassification(DataClassification.PHI)))
         .withField(new QFieldMetaData("notes", QFieldType.TEXT).withSupplementalMetaData(new AiFieldMetaData().withClassification(DataClassification.PII)));
      table.getFields().values().forEach(f -> f.setBackendName(f.getName()));
      instance.addTable(table);
      new AuditsMetaDataProvider().defineAll(instance, BACKEND, t -> t.withBackendDetails(new RDBMSTableBackendDetails().withTableName(t.getName())));
      try(Connection connection = DriverManager.getConnection(url, "sa", ""))
      {
         for(QTableMetaData t : instance.getTables().values())
         {
            StringBuilder sql = new StringBuilder("CREATE TABLE ").append(t.getName()).append(" (");
            for(QFieldMetaData field : t.getFields().values())
            {
               field.setBackendName(field.getName());
               sql.append(field.getName()).append(" ");
               if(field.getName().equals(t.getPrimaryKeyField()))
               {
                  sql.append("INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY");
               }
               else
               {
                  sql.append(switch(field.getType())
                  {
                     case INTEGER -> "INTEGER";
                     case LONG -> "BIGINT";
                     case DATE_TIME -> "TIMESTAMP WITH TIME ZONE";
                     case DATE -> "DATE";
                     case BOOLEAN -> "BOOLEAN";
                     case DECIMAL -> "DECIMAL";
                     default -> "TEXT";
                  });
               }
               sql.append(",");
            }
            sql.setLength(sql.length() - 1);
            connection.createStatement().execute(sql.append(")").toString());
         }
         for(String sql : Files.readString(Path.of("docs/ddl/secured-data-postgres.sql")).split(";"))
         {
            if(!sql.isBlank()) connection.createStatement().execute(sql);
         }
      }
      new SecuredDataQBitProducer().withQBitConfig(new SecuredDataQBitConfig().withBackendName(BACKEND).withClock(SecuredDataTestSupport.CLOCK)
         .withBackupRetentionDays(35).withAccessLogFlushIntervalMillis(60000)
         .withTableMetaDataCustomizer((i,t) -> t.withBackendDetails(new RDBMSTableBackendDetails().withTableName(t.getName())))).produce(instance);
      QContext.init(instance, SecuredDataTestSupport.user("admin", "secured_data.admin", "secured_data.retention", "reading.read", "reading.write"));
      SecuredDataTestSupport.RUNTIMES.add(SecuredDataRuntime.current());
      new QInstanceValidator().validate(instance);
      return instance;
   }
   static QRecord rule(String action, String fields) throws Exception
   {
      return SystemWrites.insertOne(SecuredDataTables.RETENTION_RULE, new QRecord().withValue("name", "30-day policy").withValue("table_name", "reading")
         .withValue("field_names", fields).withValue("age_field_name", "reading_time").withValue("age_days", 30).withValue("action", action)
         .withValue("archive_storage_name", "archive"));
   }
   static QRecord reading(Object value) throws Exception
   {
      return SystemWrites.insertOne("reading", new QRecord().withValue("systolic", (java.io.Serializable)value).withValue("secret", "test-secret")
         .withValue("notes", "test-notes").withValue("reading_time", OLD).withValue("reading_date", OLD.atZone(java.time.ZoneOffset.UTC).toLocalDate()));
   }
   static List<QRecord> rows(String table)
   {
      return SystemWrites.query(table, new QQueryFilter());
   }
   static void close()
   {
      SecuredDataTestSupport.close();
      System.clearProperty("QQQ_SECURED_DATA_KEK");
      System.clearProperty("QQQ_AUDIT_HMAC_KEY");
      System.clearProperty("QQQ_AUDIT_HMAC_KEY_ID");
   }
}
