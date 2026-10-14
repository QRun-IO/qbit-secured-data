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


import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.standin.ClientChannelSession;
import com.kingsrook.qbits.secureddata.standin.DataClassification;
import com.kingsrook.qbits.secureddata.support.CoreMetadataBridge;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.tables.DeleteAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.instances.QInstanceValidator;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;

/*******************************************************************************
 ** Memory-backed, permission-enforced fixtures shared by direct and bridge tests.
 *******************************************************************************/
final class SecuredDataTestSupport
{
   static final Instant NOW = Instant.parse("2026-10-13T12:00:00Z");
   static final MutableClock CLOCK = new MutableClock();
   static final List<SecuredDataRuntime> RUNTIMES = new ArrayList<>();



   /*******************************************************************************
    ** Setup.
    *******************************************************************************/
   static QInstance setup() throws QException
   {
      return (setup(config ->
      {
      }));
   }



   /*******************************************************************************
    ** Setup.
    *******************************************************************************/
   static QInstance setup(Consumer<SecuredDataQBitConfig> tweak) throws QException
   {
      close();
      MemoryRecordStore.fullReset();
      CLOCK.now = NOW;
      QInstance instance = base();
      instance.addBackend(new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));
      instance.addTable(person("memory"));
      SecuredDataQBitConfig config = new SecuredDataQBitConfig().withClock(CLOCK).withAccessLogFlushIntervalMillis(60000);
      tweak.accept(config);
      new SecuredDataQBitProducer().withQBitConfig(config).produce(instance);
      QContext.init(instance, user("u1", "cs_admin"));
      RUNTIMES.add(SecuredDataRuntime.current());
      new QInstanceValidator().validate(instance);
      return (instance);
   }



   /*******************************************************************************
    ** Base.
    *******************************************************************************/
   static QInstance base()
   {
      return (new QInstance().withEnforcePermissionsInCoreActions(true)
         .withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("anonymous").withType(QAuthenticationType.FULLY_ANONYMOUS)));
   }



   /*******************************************************************************
    ** Person.
    *******************************************************************************/
   static QTableMetaData person(String backend)
   {
      QTableMetaData table = new QTableMetaData().withName("person").withBackendName(backend).withPrimaryKeyField("id")
         .withLabel("Person").withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.READ_WRITE_PERMISSIONS))
         .withField(new QFieldMetaData("id", QFieldType.INTEGER))
         .withField(new QFieldMetaData("email", QFieldType.STRING).withMaxLength(255))
         .withField(new QFieldMetaData("ssn", QFieldType.STRING).withMaxLength(255))
         .withField(new QFieldMetaData("notes", QFieldType.TEXT));
      CoreMetadataBridge.classifyField(table.getField("email"), DataClassification.PII);
      CoreMetadataBridge.classifyField(table.getField("ssn"), DataClassification.PHI);
      table.getFields().values().forEach(field -> field.setBackendName(field.getName()));
      return (table);
   }



   /*******************************************************************************
    ** User.
    *******************************************************************************/
   static QSession user(String id, String... permissions)
   {
      List<String> grants = new ArrayList<>(Arrays.asList(permissions));
      grants.add("person.read");
      return (new QSession().withUser(new QUser().withIdReference(id).withFullName(id)).withPermissions(grants));
   }



   /*******************************************************************************
    ** Channel user.
    *******************************************************************************/
   static QSession channelUser(String channel, String... permissions) throws Exception
   {
      QSession session;
      try
      {
         session = new QSession();
         QSession.class.getMethod("withClientChannel", String.class).invoke(session, channel);
      }
      catch(NoSuchMethodException expected)
      {
         session = new ClientChannelSession().withClientChannel(channel);
      }
      List<String> grants = new ArrayList<>(Arrays.asList(permissions));
      grants.add("person.read");
      return (session.withUser(new QUser().withIdReference("u1").withFullName("User One")).withPermissions(grants));
   }



   /*******************************************************************************
    ** Policy.
    *******************************************************************************/
   static QRecord policy(String permission, String classification, String tier) throws QException
   {
      return (insert(SecuredDataTables.POLICY, policyRow(permission, classification, tier)));
   }



   /*******************************************************************************
    ** Policy row.
    *******************************************************************************/
   static QRecord policyRow(String permission, String classification, String tier)
   {
      return (new QRecord().withValue("name", permission + " " + classification).withValue("permission_name", permission)
         .withValue("classification", classification).withValue("tier", tier).withValue("is_active", true));
   }



   /*******************************************************************************
    ** Classification.
    *******************************************************************************/
   static QRecord classification(String field, String classification) throws QException
   {
      return (insert(SecuredDataTables.CLASSIFICATION, new QRecord().withValue("table_name", "person")
         .withValue("field_name", field).withValue("classification", classification)));
   }



   /*******************************************************************************
    ** Insert.
    *******************************************************************************/
   static QRecord insert(String table, QRecord row) throws QException
   {
      return (SystemWrites.insertOne(table, row));
   }



   /*******************************************************************************
    ** Update.
    *******************************************************************************/
   static void update(String table, QRecord row) throws QException
   {
      List<QRecord> records = SystemWrites.call(() -> new UpdateAction().execute(new UpdateInput(table).withRecord(row)).getRecords());
      org.assertj.core.api.Assertions.assertThat(records.getFirst().getErrors()).isNullOrEmpty();
   }



   /*******************************************************************************
    ** Delete.
    *******************************************************************************/
   static void delete(String table, QRecord row) throws QException
   {
      SystemWrites.call(() -> new DeleteAction().execute(new DeleteInput(table).withPrimaryKeys(List.of(row.getValue("id")))));
   }



   /*******************************************************************************
    ** Logs.
    *******************************************************************************/
   static List<QRecord> logs()
   {
      return (SystemWrites.query(SecuredDataTables.ACCESS_LOG, new QQueryFilter()));
   }



   /*******************************************************************************
    ** Close.
    *******************************************************************************/
   static void close()
   {
      RUNTIMES.forEach(SecuredDataRuntime::close);
      RUNTIMES.clear();
      QContext.clear();
   }



   /*******************************************************************************
    ** Mutable clock.
    *******************************************************************************/
   static class MutableClock extends Clock
   {
      Instant now = NOW;



      /*******************************************************************************
       ** Get zone.
       *******************************************************************************/
      public ZoneId getZone()
      {
         return (ZoneOffset.UTC);
      }



      /*******************************************************************************
       ** With zone.
       *******************************************************************************/
      public Clock withZone(ZoneId zone)
      {
         return (this);
      }



      /*******************************************************************************
       ** Instant.
       *******************************************************************************/
      public Instant instant()
      {
         return (now);
      }
   }
}
