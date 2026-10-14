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


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.retention.WipeService;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.ClassifiedValueKeySource.KeyAndId;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.ClassifiedValueTokens;
import com.kingsrook.qqq.backend.core.actions.reporting.ExportAction;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.actions.reporting.ExportInput;
import com.kingsrook.qqq.backend.core.model.actions.reporting.ReportDestination;
import com.kingsrook.qqq.backend.core.model.actions.reporting.ReportFormat;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.secureddata.RetentionTestSupport.rows;
import static com.kingsrook.qbits.secureddata.RetentionTestSupport.rule;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** SECURED-DATA section 15 proofs: a planted canary never leaves the host table,
 ** and shredded audit tokens cannot be brute-forced once the data key is gone.
 *******************************************************************************/
class RetentionProofTest
{
   private static final SecureRandom RANDOM = new SecureRandom();
   private static final String OTHER_KEY = "/v79vLu6ubi3trW0s7KxsK+uraypqKempaSjoqGgn56dnJuamZiXlpU=";



   /*******************************************************************************
    ** Cleanup.
    *******************************************************************************/
   @AfterEach
   void cleanup()
   {
      RetentionTestSupport.close();
   }



   /*******************************************************************************
    ** Letters g-v only, so a marker can never coincide with hex digests or tokens.
    *******************************************************************************/
   private static String canary()
   {
      StringBuilder marker = new StringBuilder("CANARY-PHI-");
      for(int i = 0; i < 16; i++)
      {
         marker.append((char) ('g' + RANDOM.nextInt(16)));
      }
      return (marker.toString());
   }



   /*******************************************************************************
    ** The marker, or any substring of it longer than four characters.
    *******************************************************************************/
   private static List<String> leaks(String haystack, String... markers)
   {
      List<String> found = new ArrayList<>();
      for(String marker : markers)
      {
         for(int length = 5; length <= marker.length(); length++)
         {
            for(int start = 0; start + length <= marker.length(); start++)
            {
               if(haystack.contains(marker.substring(start, start + length)))
               {
                  found.add("length " + length + " at " + start);
               }
            }
         }
      }
      return (found);
   }



   /*******************************************************************************
    ** Canary through CRUD, a failing validation, a wipe run, a masked export and
    ** the access log: it may appear only in the host table itself.
    *******************************************************************************/
   @Test
   void canaryNeverLeavesTheHostTable() throws Exception
   {
      String first = canary();
      String second = canary();
      String rejected = canary();
      try(LogCapture logs = new LogCapture())
      {
         QInstance instance = RetentionTestSupport.setup();
         QLogger.getLogger(RetentionProofTest.class).info("log-capture-sentinel");
         assertThat(logs.lines()).anyMatch(line -> line.contains("log-capture-sentinel"));
         SecuredDataTestSupport.policy("viewer", "PHI", "MASKED");
         SecuredDataTestSupport.policy("viewer", "PII", "MASKED");
         SecuredDataTestSupport.policy("secured_data.admin", "PHI", "FULL");
         SecuredDataTestSupport.policy("secured_data.admin", "PII", "FULL");
         QRecord rule = rule("NULL_WITH_MARKER", "secret,notes");

         // CRUD with audits.
         List<String> errors = new ArrayList<>();
         QRecord inserted = new InsertAction().execute(new InsertInput("reading").withRecord(new QRecord().withValue("secret", first).withValue("notes", first)
            .withValue("systolic", 120).withValue("reading_time", RetentionTestSupport.OLD))).getRecords().getFirst();
         assertThat(inserted.getErrors()).isNullOrEmpty();
         Serializable id = inserted.getValue("id");
         QRecord updated = new UpdateAction().execute(new UpdateInput("reading").withRecord(new QRecord().withValue("id", id).withValue("secret", second)
            .withValue("notes", second))).getRecords().getFirst();
         assertThat(updated.getErrors()).isNullOrEmpty();

         // A failing validation: the secret value is over the field's maximum length.
         QRecord invalid = new InsertAction().execute(new InsertInput("reading").withRecord(new QRecord().withValue("secret", rejected + "x".repeat(300))
            .withValue("notes", rejected).withValue("reading_time", RetentionTestSupport.OLD))).getRecords().getFirst();
         assertThat(invalid.getErrors()).as("the invalid insert must be reported as an error").isNotEmpty();
         invalid.getErrors().forEach(error -> errors.add(String.valueOf(error.getMessage())));

         // A masked user reads and exports; the access log records the views.
         QContext.setQSession(SecuredDataTestSupport.user("viewer", "viewer", "reading.read"));
         assertThat(new QueryAction().execute(new QueryInput("reading")).getRecords()).hasSize(1);
         ByteArrayOutputStream export = new ByteArrayOutputStream();
         ExportInput exportInput = new ExportInput();
         exportInput.setTableName("reading");
         new ExportAction().execute(exportInput.withReportDestination(new ReportDestination().withReportFormat(ReportFormat.CSV).withReportOutputStream(export)));
         String exported = export.toString(StandardCharsets.UTF_8);
         assertThat(exported).isNotBlank();
         SecuredDataRuntime.current().logger().flush();

         // Positive control: the scan does detect the planted value where it legitimately lives.
         assertThat(leaks(JsonUtils.toJson(rows("reading")), second)).isNotEmpty();

         // The wipe run, as the retention administrator.
         QContext.setQSession(SecuredDataTestSupport.user("admin", "secured_data.admin", "secured_data.retention", "reading.read", "reading.write"));
         QRecord run = new WipeService().batch(rule.getValue("id"), List.of(id));
         assertThat(run.getValueInteger("wiped_count")).isEqualTo(1);
         assertThat(rows("reading").getFirst().getValue("secret")).isNull();
         assertThat(leaks(JsonUtils.toJson(rows("reading")), first, second)).as("the wiped host table").isEmpty();

         List<String> places = new ArrayList<>();
         Map<String, String> haystacks = new LinkedHashMap<>();
         haystacks.put("export", exported);
         haystacks.put("errors", String.join(" ", errors));
         haystacks.put("logs", String.join("\n", logs.lines()));
         for(String table : List.of("audit", "auditDetail", SecuredDataTables.ACCESS_LOG, SecuredDataTables.WIPE_RUN, SecuredDataTables.WIPE_MARKER,
            SecuredDataTables.AUDIT_KEY, SecuredDataTables.RETENTION_RULE, SecuredDataTables.LEGAL_HOLD, SecuredDataTables.POLICY, SecuredDataTables.CLASSIFICATION))
         {
            haystacks.put(table, JsonUtils.toJson(rows(table)));
            assertThat(instance.getTable(table)).isNotNull();
         }
         haystacks.forEach((name, text) ->
         {
            if(!leaks(text, first, second, rejected).isEmpty())
            {
               places.add(name);
            }
         });
         assertThat(places).as("places where the canary or a long fragment of it appeared").isEmpty();
         assertThat(haystacks.get("audit")).isNotBlank();
         assertThat(rows("auditDetail")).isNotEmpty();
         assertThat(rows(SecuredDataTables.ACCESS_LOG)).isNotEmpty();
      }
   }



   /*******************************************************************************
    ** HMAC-SHA256 over the agreed record binding, exactly as the token format does.
    *******************************************************************************/
   private static String digest(byte[] key, QTableMetaData table, String field, Serializable pk, int value) throws Exception
   {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      byte[] out = mac.doFinal((String.join("\u001F", table.getName(), field, String.valueOf(pk)) + "\u001F" + value).getBytes(StandardCharsets.UTF_8));
      return (Base64.getUrlEncoder().withoutPadding().encodeToString(out));
   }



   /*******************************************************************************
    ** After the wipe nothing can recover a systolic reading from its audit tokens,
    ** not even with every key still reachable, while before the wipe the same
    ** procedure does find the value (so the search genuinely detects a match).
    *******************************************************************************/
   @Test
   void shreddedAuditTokensCannotBeBruteForcedAfterTheWipe() throws Exception
   {
      QInstance instance = RetentionTestSupport.setup();
      System.setProperty("QQQ_AUDIT_HMAC_KEY", OTHER_KEY);
      QTableMetaData table = instance.getTable("reading");
      SecuredDataTestSupport.policy("secured_data.admin", "PHI", "FULL");
      SecuredDataTestSupport.policy("secured_data.admin", "PII", "FULL");
      QRecord rule = rule("NULL_WITH_MARKER", "systolic");

      List<QRecord> toInsert = new ArrayList<>();
      for(int systolic = 60; systolic <= 250; systolic++)
      {
         toInsert.add(new QRecord().withValue("systolic", systolic).withValue("secret", "s").withValue("reading_time", RetentionTestSupport.OLD));
      }
      List<QRecord> inserted = new InsertAction().execute(new InsertInput("reading").withRecords(toInsert)).getRecords();
      assertThat(inserted).hasSize(191).allSatisfy(r -> assertThat(r.getErrors()).isNullOrEmpty());
      Map<Serializable, Integer> truth = new LinkedHashMap<>();
      inserted.forEach(r -> truth.put(r.getValue("id"), r.getValueInteger("systolic")));

      // A control record the wipe will not touch: its data key stays reachable.
      QRecord control = new InsertAction().execute(new InsertInput("reading").withRecord(new QRecord().withValue("systolic", 111)
         .withValue("reading_time", SecuredDataTestSupport.NOW))).getRecords().getFirst();

      Map<Serializable, List<String>> tokens = auditTokens(truth.keySet());
      assertThat(tokens).hasSize(191).allSatisfy((id, list) -> assertThat(list).isNotEmpty().allMatch(t -> t.startsWith("shred:v1:")));

      // Before the wipe, the DEK verifies the true value and no other value.
      var keys = SecuredDataRuntime.current().keys();
      for(var entry : truth.entrySet())
      {
         Optional<KeyAndId> dek = keys.keyForRecordField("reading", "systolic", entry.getKey(), false);
         assertThat(dek).isPresent();
         for(String token : tokens.get(entry.getKey()))
         {
            assertThat(ClassifiedValueTokens.verifyRecordField(table, table.getField("systolic"), entry.getKey(), entry.getValue(), token)).isTrue();
            assertThat(ClassifiedValueTokens.verifyRecordField(table, table.getField("systolic"), entry.getKey(), entry.getValue() + 1, token)).isFalse();
            assertThat(token).endsWith(digest(dek.get().key(), table, "systolic", entry.getKey(), entry.getValue()));
         }
      }
      assertThat(rows(SecuredDataTables.AUDIT_KEY)).hasSize(192);

      // Wipe the old readings in policy-sized batches.
      List<Serializable> ids = new ArrayList<>(truth.keySet());
      for(int offset = 0; offset < ids.size(); offset += 100)
      {
         new WipeService().batch(rule.getValue("id"), ids.subList(offset, Math.min(offset + 100, ids.size())));
      }
      assertThat(rows("reading").stream().filter(r -> truth.containsKey(r.getValue("id")))).allSatisfy(r -> assertThat(r.getValue("systolic")).isNull());
      assertThat(rows(SecuredDataTables.AUDIT_KEY)).hasSize(1);
      assertThat(rows(SecuredDataTables.AUDIT_KEY).getFirst().getValueString("record_id")).isEqualTo(String.valueOf(control.getValue("id")));

      // Every key the test can still reach.
      List<byte[]> reachable = new ArrayList<>();
      reachable.add(Base64.getDecoder().decode(OTHER_KEY));
      reachable.add(Base64.getDecoder().decode(RetentionTestSupport.KEY));
      reachable.add(keys.keyForRecordField("reading", "systolic", control.getValue("id"), false).orElseThrow().key());
      reachable.add(new byte[32]);
      assertThat(reachable.get(2)).isNotEqualTo(new byte[32]);

      Map<Serializable, List<String>> after = auditTokens(truth.keySet());
      int matches = 0;
      for(var entry : truth.entrySet())
      {
         assertThat(after.get(entry.getKey())).containsAll(tokens.get(entry.getKey()));
         for(String token : after.get(entry.getKey()))
         {
            String tail = token.substring(token.lastIndexOf(':') + 1);
            for(int guess = 60; guess <= 250; guess++)
            {
               if(ClassifiedValueTokens.verifyRecordField(table, table.getField("systolic"), entry.getKey(), guess, token))
               {
                  matches++;
               }
               for(byte[] key : reachable)
               {
                  if(digest(key, table, "systolic", entry.getKey(), guess).equals(tail))
                  {
                     matches++;
                  }
               }
            }
         }
      }
      assertThat(matches).as("brute-force matches after the wipe").isZero();
      assertThat(rows("auditDetail")).anySatisfy(row -> assertThat(row.getValueString("newValue")).startsWith("shredded:v1:"));
   }



   /*******************************************************************************
    ** Every systolic audit-detail value for the given records, by record id.
    *******************************************************************************/
   private static Map<Serializable, List<String>> auditTokens(Iterable<Serializable> ids)
   {
      Map<Serializable, String> recordByAudit = new LinkedHashMap<>();
      for(QRecord audit : SystemWrites.query("audit", new QQueryFilter()))
      {
         recordByAudit.put(audit.getValue("id"), audit.getValueString("recordId"));
      }
      Map<Serializable, List<String>> result = new LinkedHashMap<>();
      for(Serializable id : ids)
      {
         result.put(id, new ArrayList<>());
      }
      for(QRecord detail : SystemWrites.query("auditDetail", new QQueryFilter()))
      {
         if(!"systolic".equals(detail.getValueString("fieldName")))
         {
            continue;
         }
         String record = recordByAudit.get(detail.getValue("auditId"));
         for(Serializable id : ids)
         {
            if(String.valueOf(id).equals(record))
            {
               for(String value : new String[] {detail.getValueString("oldValue"), detail.getValueString("newValue")})
               {
                  if(value != null && !value.isBlank())
                  {
                     result.get(id).add(value);
                  }
               }
            }
         }
      }
      return (result);
   }
}
