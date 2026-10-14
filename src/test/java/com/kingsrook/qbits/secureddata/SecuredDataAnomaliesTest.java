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

import java.time.temporal.ChronoUnit;
import java.util.List;
import com.kingsrook.qbits.secureddata.breakglass.BreakGlassService;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.reveal.RevealService;
import com.kingsrook.qbits.secureddata.support.ActivityLog;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessEventType;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessOutcome;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.alerts.AlertsInstanceMetaData;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.*;
import static org.assertj.core.api.Assertions.*;

class SecuredDataAnomaliesTest
{
   @AfterEach void cleanup() { close(); }

   void init(java.util.function.Consumer<SecuredDataQBitConfig> config) throws Exception
   {
      var instance = setup(config);
      SecuredDataAccessLoggerTest.AlertsSink.signals.clear();
      AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(SecuredDataAccessLoggerTest.AlertsSink.class));
   }

   QRecord reveal(int record) throws Exception
   {
      return insert(SecuredDataTables.ACCESS_LOG, ActivityLog.row("REVEAL", "person", "ALLOWED")
         .withValue("record_id", String.valueOf(record)).withValue("field_name", "email"));
   }

   static void seed(QRecord row) throws Exception
   {
      SystemWrites.call(() -> new InsertAction().execute(new InsertInput(SecuredDataTables.ACCESS_LOG).withRecord(row)));
   }

   void alertCount(int count)
   {
      assertThat(SecuredDataAccessLoggerTest.AlertsSink.signals).filteredOn(s -> "secured_data.anomaly".equals(s.getAlertTypeName())).hasSize(count)
         .allSatisfy(s -> assertThat(s.getDedupKey()).isEqualTo("secured_data.anomaly:u1:2026-10-13"));
   }

   @Test void minimumTenAndZeroDaysMedian() throws Exception
   {
      init(c -> {});
      for(int i = 0; i < 9; i++) assertThat(reveal(1).getValueBoolean("anomaly_flag")).isFalse();
      alertCount(0);
      assertThat(reveal(1).getValueBoolean("anomaly_flag")).isTrue();
      alertCount(1);
   }

   @Test void strictlyAboveThreeTimesMedianAndDailyCacheRollover() throws Exception
   {
      init(c -> {});
      for(int day = 1; day <= 30; day++)
         for(int i = 0; i < 4; i++) seed(ActivityLog.row("REVEAL", "person", "ALLOWED").withValue("record_id", "1")
            .withValue("created_at", NOW.truncatedTo(ChronoUnit.DAYS).minus(day, ChronoUnit.DAYS).plusSeconds(i)));
      for(int i = 0; i < 12; i++) assertThat(reveal(1).getValueBoolean("anomaly_flag")).isFalse();
      alertCount(0);
      assertThat(reveal(1).getValueBoolean("anomaly_flag")).isTrue();
      alertCount(1);
      CLOCK.now = NOW.plus(1, ChronoUnit.DAYS);
      assertThat(reveal(1).getValueBoolean("anomaly_flag")).isFalse();
   }

   @Test void distinctRecordBoundaryDuplicatesOtherUsersAndExpiredRows() throws Exception
   {
      init(c -> c.withAnomalyMinimumDailyReveals(1000));
      for(int i = 0; i < 20; i++) assertThat(reveal(i).getValueBoolean("anomaly_flag")).isFalse();
      assertThat(reveal(0).getValueBoolean("anomaly_flag")).isFalse();
      seed(ActivityLog.row("REVEAL", "person", "ALLOWED").withValue("user_id", "other").withValue("record_id", "999"));
      seed(ActivityLog.row("REVEAL", "person", "ALLOWED").withValue("record_id", "998").withValue("created_at", NOW.minusSeconds(3600)));
      alertCount(0);
      assertThat(reveal(20).getValueBoolean("anomaly_flag")).isTrue();
      alertCount(1);
      CLOCK.now = NOW.plusSeconds(3601);
      assertThat(reveal(21).getValueBoolean("anomaly_flag")).isFalse();
   }

   @Test void exactMatchFiftyFirstQueuedSearchFlagsWithoutEnumerationAlert() throws Exception
   {
      init(c -> c.withExactMatchPerHour(0).withMissAlertConsecutive(0).withDistinctValueAlert(0));
      var logger = SecuredDataRuntime.current().logger();
      for(int i = 0; i < 50; i++) logger.onAccess(SecuredDataAccessLoggerTest.event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.MATCH, "hash"));
      logger.flush();
      assertThat(logs()).allSatisfy(row -> assertThat(row.getValueBoolean("anomaly_flag")).isFalse());
      alertCount(0);
      logger.onAccess(SecuredDataAccessLoggerTest.event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.MATCH, "hash"));
      logger.flush();
      assertThat(logs().getLast().getValueBoolean("anomaly_flag")).isTrue();
      alertCount(1);
   }

   @Test void configurableThresholdsAndMissingAlertSink() throws Exception
   {
      setup(c -> c.withAnomalyDailyMedianMultiplier(2).withAnomalyMinimumDailyReveals(3).withAnomalyDistinctRecordsPerHour(2).withAnomalyExactMatchesPerHour(2));
      assertThat(reveal(1).getValueBoolean("anomaly_flag")).isFalse();
      assertThat(reveal(2).getValueBoolean("anomaly_flag")).isFalse();
      assertThat(reveal(3).getValueBoolean("anomaly_flag")).isTrue();
      QContext.setQSession(user("u2"));
      for(int i = 0; i < 3; i++)
      {
         var row = insert(SecuredDataTables.ACCESS_LOG, ActivityLog.row("EXACT_MATCH_FILTER", "person", "MATCH").withValue("field_name", "email"));
         assertThat(row.getValueBoolean("anomaly_flag")).isEqualTo(i == 2);
      }
   }

   @Test void actualRevealServiceBreakGlassAndCapFlagAndAlert() throws Exception
   {
      init(c -> c.withAnomalyMinimumDailyReveals(1));
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE").withValue("daily_reveal_cap", 1));
      var pk = insert("person", new QRecord().withValue("email", "private@example.invalid")).getValue("id");
      new RevealService().reveal("person", pk, "email", "Support", null);
      assertThat(logs()).filteredOn(r -> "REVEAL".equals(r.getValueString("event_type"))).singleElement()
         .satisfies(r -> assertThat(r.getValueBoolean("anomaly_flag")).isTrue());
      alertCount(1);
      assertThatThrownBy(() -> new RevealService().reveal("person", pk, "email", "Support", null)).isInstanceOf(com.kingsrook.qbits.secureddata.reveal.RevealCappedException.class);
      alertCount(2);
      QContext.setQSession(user("u1", BreakGlassService.START + ".hasAccess"));
      new BreakGlassService().start("Investigating urgent customer incident", 5, null, null);
      alertCount(3);
      assertThat(logs()).filteredOn(r -> "BREAK_GLASS_START".equals(r.getValueString("event_type"))).singleElement()
         .satisfies(r -> assertThat(r.getValueBoolean("anomaly_flag")).isTrue());
   }

   @Test void invalidThresholdsRejected() throws Exception
   {
      for(var config : List.of(new SecuredDataQBitConfig().withAnomalyDailyMedianMultiplier(0), new SecuredDataQBitConfig().withAnomalyMinimumDailyReveals(0),
         new SecuredDataQBitConfig().withAnomalyDistinctRecordsPerHour(0), new SecuredDataQBitConfig().withAnomalyExactMatchesPerHour(0)))
         assertThatThrownBy(config::validate).isInstanceOf(IllegalArgumentException.class);
   }
   @Test void exactMatchCounterIsScopedToFieldTableUserAndHour() throws Exception
   {
      init(c -> c.withAnomalyExactMatchesPerHour(2));
      seed(ActivityLog.row("EXACT_MATCH_FILTER", "person", "MATCH").withValue("field_name", "email").withValue("created_at", NOW.minusSeconds(3600)));
      seed(ActivityLog.row("EXACT_MATCH_FILTER", "person", "MATCH").withValue("field_name", "ssn"));
      seed(ActivityLog.row("EXACT_MATCH_FILTER", "person", "MATCH").withValue("field_name", "email").withValue("user_id", "u2"));
      for(int i = 0; i < 3; i++)
      {
         QRecord row = insert(SecuredDataTables.ACCESS_LOG, ActivityLog.row("EXACT_MATCH_FILTER", "person", "MATCH").withValue("field_name", "email"));
         assertThat(row.getValueBoolean("anomaly_flag")).isEqualTo(i == 2);
      }
      alertCount(1);
   }

   @Test void configurableMedianMultiplierUsesHistoricalCounts() throws Exception
   {
      init(c -> c.withAnomalyDailyMedianMultiplier(2).withAnomalyMinimumDailyReveals(3));
      for(int day = 1; day <= 30; day++)
         for(int i = 0; i < 2; i++) seed(ActivityLog.row("REVEAL", "person", "ALLOWED").withValue("record_id", "1")
            .withValue("created_at", NOW.minus(day, ChronoUnit.DAYS)));
      for(int i = 0; i < 4; i++) assertThat(reveal(1).getValueBoolean("anomaly_flag")).isFalse();
      alertCount(0);
      assertThat(reveal(1).getValueBoolean("anomaly_flag")).isTrue();
      alertCount(1);
   }

}
