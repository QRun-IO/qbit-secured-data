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


import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.metadata.FieldsOfTablePossibleValueSource;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataEnums;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.SecuredDataMetadata;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessTier;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.values.SearchPossibleValueSourceInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.ClientChannelsMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermissionsMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.NOW;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.RUNTIMES;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.base;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.channelUser;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.classification;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.close;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.delete;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.insert;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.logs;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.person;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.policyRow;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.setup;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.update;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.user;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;



/*******************************************************************************
 ** Secured data qbit producer test.
 *******************************************************************************/
class SecuredDataQBitProducerTest
{



   /*******************************************************************************
    ** Cleanup.
    *******************************************************************************/
   @AfterEach
   void cleanup()
   {
      close();
   }

   /*******************************************************************************
    ** Produces complete metadata.
    *******************************************************************************/
   @Test
   void producesCompleteMetadata() throws Exception
   {
      QInstance instance = setup();
      assertThat(instance.getTables().keySet()).containsAll(SecuredDataTables.ALL);
      assertThat(instance.getQBits().get("com.kingsrook.qbits:qbit-secured-data").getVersion()).isEqualTo("1.0.0");
      for(String name : SecuredDataTables.ALL)
      {
         QTableMetaData table = instance.getTable(name);
         assertThat(table.getAuditRules().getAuditLevel()).isEqualTo(name.equals(SecuredDataTables.AUDIT_KEY) ? AuditLevel.NONE : AuditLevel.FIELD);
         assertThat(table.getSections()).isNotEmpty();
         assertThat(SecuredDataMetadata.classification(table, null)).isEqualTo(DataClassification.CONFIDENTIAL);
         table.getFields().values().forEach(field -> assertThat(field.getBackendName()).isEqualTo(field.getName()));
      }
      assertThat(SecuredDataTables.esbTableNames()).containsExactlyElementsOf(SecuredDataTables.MAIN);
      assertThat(SecuredDataEnums.sources()).hasSize(6);
      assertThat(ClientChannelsMetaData.ofOrWithNew(instance).getDeniedPatterns().get("assistant")).contains("secured_data_*");
      assertThat(TableFeaturePermissionsMetaData.ofOrWithNew(instance).getPermissions()).extracting("suffix").contains("secured_data_full", "secured_data_reveal");
      assertThat(instance.getTable(SecuredDataTables.ACCESS_LOG).getDisabledCapabilities()).contains(Capability.TABLE_UPDATE, Capability.TABLE_DELETE);
      assertThat(instance.getJoin(SecuredDataTables.REVEALS_JOIN)).isNotNull();
      assertThat(instance.getWidget(SecuredDataTables.REVEALS_WIDGET)).isNotNull();
      assertThat(instance.getApp("secured_data").getChildren()).hasSize(5);
   }

   /*******************************************************************************
    ** Config and producer contract.
    *******************************************************************************/
   @Test
   void configAndProducerContract() throws Exception
   {
      SecuredDataQBitConfig config = new SecuredDataQBitConfig().withBackendName("memory")
         .withDefaultTier(DataClassification.PHI, FieldAccessTier.HIDDEN).withDefaultTierByClassification(Map.of("PHI", "FULL"))
         .withNameHeuristics(true).withTableMetaDataCustomizer((instance, table) -> table);
      assertThat(config.defaultTier(DataClassification.PHI)).isEqualTo(FieldAccessTier.FULL);
      assertThat(config.defaultTier(DataClassification.PII)).isEqualTo(FieldAccessTier.MASKED);
      SecuredDataQBitProducer producer = new SecuredDataQBitProducer().withQBitConfig(config).withNamespace("test");
      assertThat(producer.getNamespace()).isEqualTo("test");
      assertThat(producer.getQBitConfig()).isSameAs(config);
      assertThat(producer.isEnabled()).isTrue();
      assertThat(new SecuredDataQBitProducer().isEnabled()).isFalse();
      assertThatThrownBy(() -> new SecuredDataQBitConfig().withAccessLogQueueCapacity(0).validate()).isInstanceOf(IllegalArgumentException.class);
      setup();
      assertThatThrownBy(() -> new SecuredDataQBitProducer().withQBitConfig(config).produce(QContext.getQInstance())).isInstanceOf(IllegalStateException.class);
   }

   /*******************************************************************************
    ** Admin can read but cannot forge activity and assistant cannot read.
    *******************************************************************************/
   @Test
   void adminCanReadButCannotForgeActivityAndAssistantCannotRead() throws Exception
   {
      QInstance instance = setup();
      QContext.setQSession(user("admin", "secured_data.admin"));
      assertThat(new QueryAction().execute(new QueryInput(SecuredDataTables.POLICY)).getRecords()).isEmpty();
      for(String table : SecuredDataTables.SYSTEM_WRITTEN)
      {
         assertThatThrownBy(() -> new InsertAction().execute(new InsertInput(table).withRecord(new QRecord()))).hasMessageContaining("Permission denied");
      }
      QContext.setQSession(channelUser("assistant/t1", "secured_data.admin"));
      for(String table : SecuredDataTables.ALL)
      {
         assertThatThrownBy(() -> new QueryAction().execute(new QueryInput(table))).hasMessageContaining("Permission denied");
      }
      QContext.setQSession(user("ordinary"));
      assertThatThrownBy(() -> new QueryAction().execute(new QueryInput(SecuredDataTables.CLASSIFICATION))).hasMessageContaining("Permission denied");
   }

   /*******************************************************************************
    ** Fields picker and classification uniqueness.
    *******************************************************************************/
   @Test
   void fieldsPickerAndClassificationUniqueness() throws Exception
   {
      setup();
      FieldsOfTablePossibleValueSource picker = new FieldsOfTablePossibleValueSource();
      assertThat(picker.search(new SearchPossibleValueSourceInput().withOtherValues(Map.of("table_name", "person")))).hasSize(4);
      assertThat(picker.search(new SearchPossibleValueSourceInput())).isEmpty();
      assertThat(picker.getPossibleValue("email").getId()).isEqualTo("email");
      assertThat(picker.getPossibleValue(null)).isNull();
      classification(null, "CONFIDENTIAL");
      assertThatThrownBy(() -> classification(null, "PHI")).hasMessageContaining("system insert failed");
      assertThatThrownBy(() -> classification("no_such_field", "PHI")).hasMessageContaining("system insert failed");
      assertThatThrownBy(() -> insert(SecuredDataTables.POLICY, policyRow("x", "PII", "FULL").withValue("reveal_minutes", 61))).hasMessageContaining("system insert failed");
   }

   /*******************************************************************************
    ** System cannot update or delete an access log.
    *******************************************************************************/
   @Test
   void systemCannotUpdateOrDeleteAnAccessLog() throws Exception
   {
      setup();
      QRecord row = insert(SecuredDataTables.ACCESS_LOG, new QRecord().withValue("event_type", "VIEW").withValue("table_name", "person").withValue("created_at", NOW));
      assertThatThrownBy(() -> update(SecuredDataTables.ACCESS_LOG, new QRecord().withValue("id", row.getValue("id")).withValue("outcome", "DENIED"))).isInstanceOf(Exception.class);
      assertThatThrownBy(() -> delete(SecuredDataTables.ACCESS_LOG, row)).isInstanceOf(Exception.class);
      assertThat(logs()).hasSize(1);
   }

   /*******************************************************************************
    ** Versions invalidate after commit and never for rollback.
    *******************************************************************************/
   @Test
   void versionsInvalidateAfterCommitAndNeverForRollback() throws Exception
   {
      setup();
      var runtime = SecuredDataRuntime.current();
      var customizer = new com.kingsrook.qbits.secureddata.metadata.SecuredDataTableCustomizers();
      var transaction = new com.kingsrook.qqq.backend.core.actions.QBackendTransaction();
      var input = new InsertInput(SecuredDataTables.CLASSIFICATION).withTransaction(transaction);
      long before = runtime.classificationVersion();
      customizer.postInsert(input, List.of(new QRecord().withValue("id", 42)));
      assertThat(runtime.classificationVersion()).isEqualTo(before);
      transaction.rollback();
      assertThat(runtime.classificationVersion()).isEqualTo(before);
      customizer.postInsert(input, List.of(new QRecord().withValue("id", 43)));
      transaction.commit();
      assertThat(runtime.classificationVersion()).isGreaterThan(before);
   }

   /*******************************************************************************
    ** Code heuristics are opt in and preserve explicit classifications.
    *******************************************************************************/
   @Test
   void codeHeuristicsAreOptInAndPreserveExplicitClassifications() throws Exception
   {
      QInstance instance = base();
      instance.addBackend(new com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData().withName("memory")
         .withBackendType(com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule.class));
      QTableMetaData table = person("memory");
      table.withField(new com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData("diagnosis_code", com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType.STRING));
      instance.addTable(table);
      new SecuredDataQBitProducer().withQBitConfig(new SecuredDataQBitConfig().withNameHeuristics(true)).produce(instance);
      QContext.init(instance, user("u1"));
      RUNTIMES.add(SecuredDataRuntime.current());
      assertThat(SecuredDataClassifications.effective(table, "diagnosis_code")).isEqualTo(DataClassification.PHI);
      assertThat(SecuredDataClassifications.effective(table, "email")).isEqualTo(DataClassification.PII);
   }

}
