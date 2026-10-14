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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Base64;
import java.util.Set;
import java.nio.charset.StandardCharsets;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.retention.RetentionRules;
import com.kingsrook.qbits.secureddata.retention.RetentionWidgets;
import com.kingsrook.qbits.secureddata.retention.WipeService;
import com.kingsrook.qbits.secureddata.retention.WipeProcesses;
import com.kingsrook.qbits.secureddata.standin.DMLType;
import com.kingsrook.qbits.secureddata.standin.ClassifiedValueTokens;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.customizers.TableCustomizerInterface;
import com.kingsrook.qqq.backend.core.actions.customizers.TableCustomizers;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.AbstractActionInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static com.kingsrook.qbits.secureddata.RetentionTestSupport.*;
import static org.assertj.core.api.Assertions.*;

class RetentionWipeTest
{
   @AfterEach void cleanup() { close(); }

   @ParameterizedTest
   @ValueSource(strings={"NULL_WITH_MARKER", "OVERWRITE_TEXT", "KEYED_HASH", "DELETE_RECORD", "ARCHIVE_THEN_WIPE"})
   void eachActionIsTransactionalAndValueFree(String action) throws Exception
   {
      var instance = setup();
      List<String> archiveJson = new ArrayList<>();
      SecuredDataRuntime.current().config().withArchiveSink((store, key, bytes) -> {
         assertThat(store).isEqualTo("archive");
         assertThat(new String(bytes, StandardCharsets.UTF_8)).doesNotContain("test-secret");
         archiveJson.add(new String(SecuredDataKeySource.decrypt(bytes, key), StandardCharsets.UTF_8));
      });
      QRecord rule = rule(action, "secret");
      QRecord record = reading(120);
      var keys = SecuredDataRuntime.current().keys();
      keys.keyForRecordField("reading", "secret", record.getValue("id"), true);
      assertThat(rows(SecuredDataTables.AUDIT_KEY)).isNotEmpty();
      QRecord run = new WipeService().batch(rule.getValue("id"), List.of(record.getValue("id")));
      assertThat(run.getValueInteger("wiped_count")).isEqualTo(1);
      assertThat(rows(SecuredDataTables.AUDIT_KEY)).isEmpty();
      assertThat(keys.keyForRecordField("reading", "secret", record.getValue("id"), false)).isEmpty();
      if(action.equals("DELETE_RECORD")) assertThat(rows("reading")).isEmpty();
      else {
         QRecord remaining = rows("reading").getFirst();
         if(action.equals("OVERWRITE_TEXT")) assertThat(remaining.getValue("secret")).isEqualTo("[wiped per policy]");
         else if(action.equals("KEYED_HASH")) {
            assertThat(remaining.getValueString("secret")).startsWith("hmac:v1:");
            assertThat(ClassifiedValueTokens.verifyRecordField(instance.getTable("reading"), instance.getTable("reading").getField("secret"), record.getValue("id"), "test-secret", remaining.getValueString("secret"))).isTrue();
         }
         else assertThat(remaining.getValue("secret")).isNull();
      }
      if(action.equals("ARCHIVE_THEN_WIPE")) assertThat(archiveJson).containsExactly("{\"secret\":\"test-secret\"}");
      else assertThat(archiveJson).isEmpty();
      assertThat(rows(SecuredDataTables.WIPE_MARKER)).isNotEmpty();
      assertThat(rows(SecuredDataTables.ACCESS_LOG).stream().filter(r -> "WIPE".equals(r.getValueString("event_type"))).toList()).isNotEmpty()
         .allSatisfy(r -> { assertThat(r.getValueString("record_id")).isEqualTo(record.getValueString("id")); assertThat(r.getValueInteger("record_count")).isEqualTo(1); });
      assertThat(rows("auditDetail")).anySatisfy(r -> assertThat(r.getValueString("newValue")).isEqualTo("shredded:v1:" + rule.getValueString("id")));
   }

   @Test void recordAndTableLegalHoldsAndAgeAreRechecked() throws Exception
   {
      setup();
      QRecord rule = rule("NULL_WITH_MARKER", "systolic");
      QRecord one = reading(120), two = reading(130);
      QRecord hold = SystemWrites.insertOne(SecuredDataTables.LEGAL_HOLD, new QRecord().withValue("table_name", "reading").withValue("record_id", one.getValueString("id")).withValue("reason", "Preservation"));
      QRecord run = new WipeService().batch(rule.getValue("id"), List.of(one.getValue("id"), two.getValue("id")));
      assertThat(run.getValueInteger("held_count")).isEqualTo(1);
      assertThat(run.getValueInteger("wiped_count")).isEqualTo(1);
      SecuredDataTestSupport.update(SecuredDataTables.LEGAL_HOLD, new QRecord().withValue("id", hold.getValue("id")).withValue("record_id", null));
      assertThat(new WipeService().batch(rule.getValue("id"), List.of(one.getValue("id"))).getValueInteger("held_count")).isEqualTo(1);
      SecuredDataTestSupport.update(SecuredDataTables.LEGAL_HOLD, new QRecord().withValue("id", hold.getValue("id")).withValue("status", "RELEASED"));
      assertThat(new WipeService().batch(rule.getValue("id"), List.of(one.getValue("id"))).getValueInteger("wiped_count")).isEqualTo(1);
      QRecord young = reading(140);
      SecuredDataTestSupport.update("reading", new QRecord().withValue("id", young.getValue("id")).withValue("reading_time", SecuredDataTestSupport.NOW));
      assertThat(new WipeService().batch(rule.getValue("id"), List.of(young.getValue("id"))).getValueInteger("eligible_count")).isZero();
   }

   @Test void failureAfterFirstRecordRollsBackUpdatesKeysMarkersAuditsAndRun() throws Exception
   {
      var instance = setup();
      QRecord rule = rule("NULL_WITH_MARKER", "secret");
      QRecord first = reading(120), second = reading(130);
      for(QRecord row : List.of(first, second)) SecuredDataRuntime.current().keys().keyForRecordField("reading", "secret", row.getValue("id"), true);
      int audits = rows("auditDetail").size();
      FailSecond.id = second.getValue("id");
      instance.getTable("reading").withCustomizer(TableCustomizers.PRE_UPDATE_RECORD, new QCodeReference(FailSecond.class));
      assertThatThrownBy(() -> new WipeService().batch(rule.getValue("id"), List.of(first.getValue("id"), second.getValue("id")))).hasMessageContaining("rolled back");
      assertThat(rows("reading")).allSatisfy(r -> assertThat(r.getValue("secret")).isEqualTo("test-secret"));
      assertThat(rows(SecuredDataTables.AUDIT_KEY)).hasSize(2);
      assertThat(rows(SecuredDataTables.WIPE_MARKER)).isEmpty();
      assertThat(rows(SecuredDataTables.WIPE_RUN)).isEmpty();
      assertThat(rows("auditDetail")).hasSize(audits);
   }

   public static class FailSecond implements TableCustomizerInterface
   {
      static java.io.Serializable id;
      @Override public List<QRecord> preInsertOrUpdate(AbstractActionInput input, List<QRecord> records, boolean preview, Optional<List<QRecord>> old) throws QException
      {
         if(records.stream().anyMatch(r -> id.equals(r.getValue("id")))) throw new QException("Injected failure");
         return records;
      }
   }

   @Test void reviewResultAndDailySchedule() throws Exception
   {
      setup();
      QRecord rule = rule("NULL_WITH_MARKER", "systolic");
      reading(120);
      QRecord held = reading(130);
      SystemWrites.insertOne(SecuredDataTables.LEGAL_HOLD, new QRecord().withValue("table_name", "reading").withValue("record_id", held.getValueString("id")).withValue("reason", "Preserve"));
      var lines = ProcessRunner.run(WipeProcesses.WIPE, rule.getValue("id"));
      assertThat(lines.review()).anyMatch(s -> s.contains("to wipe")).anyMatch(s -> s.contains("held"));
      assertThat(lines.result()).anyMatch(s -> s.contains("wiped")).anyMatch(s -> s.contains("held"));
      reading(150);
      assertThatThrownBy(() -> new WipeProcesses.Daily().run(new RunBackendStepInput(), new RunBackendStepOutput())).hasMessageContaining("system session");
      QContext.setQSession(new QSystemUserSession(QContext.getQInstance()));
      var output = new RunBackendStepOutput();
      new WipeProcesses.Daily().run(new RunBackendStepInput(), output);
      assertThat(output.getRecords()).anySatisfy(r -> assertThat(r.getValueInteger("wiped_count")).isEqualTo(1));
      var scheduled = WipeProcesses.processes(new SecuredDataQBitConfig().withSchedulerName("test")).getLast();
      assertThat(scheduled.getSchedule().getRepeatSeconds()).isEqualTo(86400);
   }

   @Test void permissionsKeyLockAndBackupsPanels() throws Exception
   {
      var instance = setup();
      QRecord rule = rule("NULL_WITH_MARKER", "secret"), record = reading(120);
      SecuredDataRuntime.current().keys().keyForRecordField("reading", "secret", record.getValue("id"), true);
      var keyTable = instance.getTable(SecuredDataTables.AUDIT_KEY);
      assertThat(keyTable.getField("wrapped_key").getFieldSecurityLock().getOverrideValues()).containsExactly(com.kingsrook.qbits.secureddata.metadata.RetentionTables.KEY_LOCK_NEVER_GRANTED);
      assertThat(keyTable.getDisabledCapabilities()).contains(com.kingsrook.qqq.backend.core.model.metadata.tables.Capability.TABLE_EXPORT);
      assertThat(SecuredDataTables.MAIN).doesNotContain(SecuredDataTables.AUDIT_KEY);
      assertThat(new QueryAction().execute(new QueryInput(SecuredDataTables.AUDIT_KEY)).getRecords()).allSatisfy(r -> assertThat(r.getValue("wrapped_key")).isNull());
      assertThat(RetentionRules.backupWarning(rule)).contains("35 days", "30 days", "recoverable");
      assertThat(com.kingsrook.qbits.secureddata.app.SecuredDataHomeView.render(com.kingsrook.qbits.secureddata.app.SecuredDataHomeData.load())).contains("Backups keep data for 35 days");
      RenderWidgetInput input = new RenderWidgetInput().withWidgetMetaData(RetentionWidgets.backups());
      input.getQueryParams().put("id", rule.getValueString("id"));
      assertThat(new RetentionWidgets.Backups().render(input)).isNotNull();
      new WipeService().batch(rule.getValue("id"), List.of(record.getValue("id")));
      var widget = RetentionWidgets.wipedFields(instance.getTable("reading"));
      input = new RenderWidgetInput().withWidgetMetaData(widget); input.getQueryParams().put("id", record.getValueString("id"));
      assertThat(new RetentionWidgets.WipedFields().render(input)).isNotNull();
      QContext.setQSession(SecuredDataTestSupport.user("ordinary"));
      assertThatThrownBy(() -> new WipeService().batch(rule.getValue("id"), List.of(record.getValue("id")))).hasMessageContaining("secured_data.retention");
   }

   @Test void changedOnlyAndWrapUnwrap() throws Exception
   {
      var instance = setup();
      QRecord rule = rule("NULL_WITH_MARKER", "secret");
      SecuredDataTestSupport.update(SecuredDataTables.RETENTION_RULE, new QRecord().withValue("id", rule.getValue("id")).withValue("audit_treatment", "CHANGED_ONLY"));
      var table = instance.getTable("reading");
      var protectedValues = new SecuredDataAuditProtector().protect(table, table.getField("secret"), 1, "old", "new", DMLType.UPDATE);
      assertThat(protectedValues.oldToken()).isEqualTo("changed:v1"); assertThat(protectedValues.newToken()).isEqualTo("changed:v1");
      assertThat(rows(SecuredDataTables.AUDIT_KEY)).isEmpty();
      byte[] plain = Base64.getDecoder().decode(KEY);
      byte[] encrypted = SecuredDataKeySource.encrypt(plain, "binding");
      assertThat(SecuredDataKeySource.decrypt(encrypted, "binding")).isEqualTo(plain);
      assertThatThrownBy(() -> SecuredDataKeySource.decrypt(encrypted, "wrong-binding")).isInstanceOf(IllegalStateException.class);
      encrypted[15] ^= 1;
      assertThatThrownBy(() -> SecuredDataKeySource.decrypt(encrypted, "binding")).isInstanceOf(IllegalStateException.class);
      System.setProperty("QQQ_SECURED_DATA_KEK", "bad");
      assertThatThrownBy(() -> SecuredDataKeySource.encrypt(plain, "binding")).hasMessageContaining("QQQ_SECURED_DATA_KEK");
   }

   @Test void validatesPolicyAndRefusesMissingArchive() throws Exception
   {
      setup();
      assertThatThrownBy(() -> rule("KEYED_HASH", "systolic")).hasMessageContaining("insert failed");
      assertThatThrownBy(() -> rule("NULL_WITH_MARKER", "missing")).hasMessageContaining("insert failed");
      assertThatThrownBy(() -> rule("NULL_WITH_MARKER", "secret,secret")).hasMessageContaining("insert failed");
      var rule = rule("ARCHIVE_THEN_WIPE", "secret"); var record = reading(120);
      assertThatThrownBy(() -> new WipeService().batch(rule.getValue("id"), List.of(record.getValue("id")))).hasMessageContaining("ArchiveSinkInterface");
      assertThat(rows("reading").getFirst().getValue("secret")).isEqualTo("test-secret");
      assertThatThrownBy(() -> new SecuredDataQBitConfig().withBackupRetentionDays(-1)).isInstanceOf(IllegalArgumentException.class);
   }

   @Test void wrongKekCannotUnwrapAndKeyReturnedIsNeverZeroed() throws Exception
   {
      setup();
      rule("NULL_WITH_MARKER", "secret");
      QRecord record = reading(120);
      var keys = SecuredDataRuntime.current().keys();
      Object pk = record.getValue("id");
      String binding = "readingsecret" + pk;

      // Regression: the source once returned the array it then zeroed in finally.
      byte[] created = keys.keyForRecordField("reading", "secret", (java.io.Serializable) pk, true).orElseThrow().key();
      assertThat(created).hasSize(32).isNotEqualTo(new byte[32]);
      QRecord stored = SystemWrites.call(() -> new QueryAction().execute(new QueryInput(SecuredDataTables.AUDIT_KEY)
         .withFilter(SecuredDataKeySource.recordField("reading", "secret", (java.io.Serializable) pk)).withShouldOmitHiddenFields(false)).getRecords()).getFirst();
      byte[] wrapped = Base64.getDecoder().decode(stored.getValueString("wrapped_key"));
      assertThat(created).isEqualTo(SecuredDataKeySource.decrypt(wrapped, binding));

      // Lookups (uncached then cached) agree with the unwrapped DEK, and callers zeroing their copy cannot poison the cache.
      byte[] looked = keys.keyForRecordField("reading", "secret", (java.io.Serializable) pk, false).orElseThrow().key();
      assertThat(looked).isNotEqualTo(new byte[32]).isEqualTo(created);
      java.util.Arrays.fill(looked, (byte) 0);
      byte[] cached = keys.keyForRecordField("reading", "secret", (java.io.Serializable) pk, false).orElseThrow().key();
      assertThat(cached).isEqualTo(created).isNotEqualTo(new byte[32]);

      // A different KEK, or a different binding, cannot unwrap.
      System.setProperty("QQQ_SECURED_DATA_KEK", "/v79vLu6ubi3trW0s7KxsK+uraypqKempaSjoqGgn56dnJuamZiXlpU=");
      assertThatThrownBy(() -> SecuredDataKeySource.decrypt(wrapped, binding)).isInstanceOf(IllegalStateException.class);
      System.setProperty("QQQ_SECURED_DATA_KEK", KEY);
      assertThatThrownBy(() -> SecuredDataKeySource.decrypt(wrapped, binding + "x")).isInstanceOf(IllegalStateException.class);
      assertThat(SecuredDataKeySource.decrypt(wrapped, binding)).isEqualTo(created);
   }

   @Test void keyedHashIsRefusedOnLowEntropyFields() throws Exception
   {
      setup();
      assertThat(rule("KEYED_HASH", "secret").getValue("id")).isNotNull();
      SystemWrites.insertOne(SecuredDataTables.CLASSIFICATION, new QRecord().withValue("table_name", "reading").withValue("field_name", "secret")
         .withValue("classification", "PHI").withValue("low_cardinality", true));
      assertThatThrownBy(() -> rule("KEYED_HASH", "secret")).hasMessageContaining("insert failed");
      assertThatThrownBy(() -> RetentionRules.validate(new QRecord().withValue("table_name", "reading").withValue("field_names", "secret")
         .withValue("age_field_name", "reading_time").withValue("age_days", 30).withValue("batch_size", 10).withValue("action", "KEYED_HASH")
         .withValue("audit_treatment", "SHREDDABLE"))).hasMessageContaining("low-entropy");
      assertThat(rule("OVERWRITE_TEXT", "secret").getValue("id")).isNotNull();
   }
}
