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


import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessEvent;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessEventType;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessOutcome;
import com.kingsrook.qqq.backend.core.alerts.AlertResolution;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.AlertSinkInterface;
import com.kingsrook.qqq.backend.core.alerts.AlertsInstanceMetaData;
import com.kingsrook.qqq.backend.core.context.CapturedContext;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.CLOCK;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.NOW;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.channelUser;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.classification;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.close;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.insert;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.logs;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.person;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.policy;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.policyRow;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.setup;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.user;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;



/*******************************************************************************
 ** Secured data access logger test.
 *******************************************************************************/
class SecuredDataAccessLoggerTest
{



   /*******************************************************************************
    ** Cleanup.
    *******************************************************************************/
   @AfterEach
   void cleanup()
   {
      close();
   }

   static FieldAccessEvent event(FieldAccessEventType type, FieldAccessOutcome outcome, String fingerprint)
   {
      return (new FieldAccessEvent().withType(type).withOutcome(outcome).withTableName("person").withFieldNames(List.of("email"))
         .withActionName("query").withRecordCount(outcome == FieldAccessOutcome.MATCH ? 1 : 0)
         .withSearchValueFingerprints(fingerprint == null ? null : List.of(fingerprint)));
   }

   /*******************************************************************************
    ** Twenty first search refused including unflushed rows and persisted history.
    *******************************************************************************/
   @Test
   void twentyFirstSearchRefusedIncludingUnflushedRowsAndPersistedHistory() throws Exception
   {
      setup();
      policy("cs_admin", "PII", "REVEALABLE");
      var resolver = SecuredDataRuntime.current().resolver();
      var logger = SecuredDataRuntime.current().logger();
      for(int i = 0; i < 20; i++)
      {
         var event = event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.MATCH, resolver.fingerprintSearchValue("known"));
         resolver.checkExactMatch(event);
         resolver.onAccess(event);
         if(i == 9)
         {
            logger.flush();
         }
      }
      var refused = event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.REFUSED, resolver.fingerprintSearchValue("sentinel"));
      assertThatThrownBy(() -> resolver.checkExactMatch(refused)).isInstanceOf(QPermissionDeniedException.class)
         .hasMessage("Exact-match search limit reached for [email]. Try again later or ask an administrator.");
      resolver.onAccess(refused);
      logger.flush();
      assertThat(logs()).filteredOn(row -> "EXACT_MATCH_FILTER".equals(row.getValueString("event_type"))).hasSize(21);
      assertThat(logs().stream().filter(row -> "REFUSED".equals(row.getValueString("outcome")))).hasSize(1);
      assertThat(JsonUtils.toJson(logs())).doesNotContain("sentinel").doesNotContain("known");
      CLOCK.now = NOW.plusSeconds(3601);
      resolver.checkExactMatch(event(FieldAccessEventType.EXACT_MATCH_FILTER, null, null));
   }

   /*******************************************************************************
    ** Misses and distinct values flag and raise through real alerts spi.
    *******************************************************************************/
   @Test
   void missesAndDistinctValuesFlagAndRaiseThroughRealAlertsSpi() throws Exception
   {
      QInstance instance = setup();
      AlertsSink.signals.clear();
      AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(AlertsSink.class));
      var resolver = SecuredDataRuntime.current().resolver();
      for(int i = 0; i < 5; i++)
      {
         resolver.onAccess(event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.NO_MATCH, resolver.fingerprintSearchValue("same")));
      }
      SecuredDataRuntime.current().logger().flush();
      assertThat(logs().stream().filter(row -> Boolean.TRUE.equals(row.getValueBoolean("anomaly_flag")))) .hasSize(1);
      assertThat(AlertsSink.signals).hasSize(1);
      assertThat(AlertsSink.signals.getFirst().getDedupKey()).isEqualTo("secured_data.enumeration:u1:person.email:2026-10-13");
      assertThat(AlertsSink.signals.getFirst().getAlertTypeName()).isEqualTo("secured_data.enumeration");
      QContext.setQSession(user("different", "cs_admin"));
      for(int i = 0; i < 16; i++)
      {
         resolver.onAccess(event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.MATCH, resolver.fingerprintSearchValue("value-" + i)));
      }
      SecuredDataRuntime.current().logger().flush();
      assertThat(logs().stream().filter(row -> Boolean.TRUE.equals(row.getValueBoolean("anomaly_flag")))).hasSize(2);
      assertThat(AlertsSink.signals).hasSize(2);
   }

   /*******************************************************************************
    ** Match resets miss streak and policy can disable all controls.
    *******************************************************************************/
   @Test
   void matchResetsMissStreakAndPolicyCanDisableAllControls() throws Exception
   {
      setup();
      var resolver = SecuredDataRuntime.current().resolver();
      for(int i = 0; i < 4; i++)
      {
         resolver.onAccess(event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.NO_MATCH, "hash"));
      }
      resolver.onAccess(event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.MATCH, "hash"));
      resolver.onAccess(event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.NO_MATCH, "hash"));
      SecuredDataRuntime.current().logger().flush();
      assertThat(logs()).allMatch(row -> !row.getValueBoolean("anomaly_flag"));
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE").withValue("exact_match_per_hour", 0)
         .withValue("miss_alert_consecutive", 0).withValue("distinct_value_alert", 0).withValue("min_entropy_enabled", false));
      for(int i = 0; i < 25; i++)
      {
         var event = event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.NO_MATCH, resolver.fingerprintSearchValue(i));
         resolver.checkExactMatch(event);
         resolver.onAccess(event);
      }
      SecuredDataRuntime.current().logger().flush();
      assertThat(logs()).allMatch(row -> !row.getValueBoolean("anomaly_flag"));
   }

   /*******************************************************************************
    ** Views only log configured classifications with fifty ids and channel.
    *******************************************************************************/
   @Test
   void viewsOnlyLogConfiguredClassificationsWithFiftyIdsAndChannel() throws Exception
   {
      setup();
      QContext.setQSession(channelUser("assistant/t1", "cs_admin"));
      var logger = SecuredDataRuntime.current().logger();
      logger.onAccess(event(FieldAccessEventType.VIEW, null, null).withFieldNames(List.of("notes")));
      List<Serializable> ids = IntStream.rangeClosed(1, 80).mapToObj(i -> (Serializable) i).toList();
      logger.onAccess(event(FieldAccessEventType.VIEW, null, null).withFieldNames(List.of("notes", "email", "ssn")).withPrimaryKeys(ids).withRecordCount(80));
      logger.onAccess(event(FieldAccessEventType.DENIED, null, null));
      logger.flush();
      assertThat(logs()).hasSize(2);
      QRecord view = logs().stream().filter(row -> "VIEW".equals(row.getValueString("event_type"))).findFirst().orElseThrow();
      assertThat(view.getValueString("field_name")).isEqualTo("email,ssn");
      assertThat(view.getValueString("client_channel")).isEqualTo("assistant");
      assertThat(JsonUtils.toObject(view.getValueString("record_id"), Integer[].class)).hasSize(50);
      assertThat(logs().stream().anyMatch(row -> "FILTER_DENIED".equals(row.getValueString("event_type")))) .isTrue();
      SecuredDataRuntime.current().config().withViewLogClassifications(Set.of(DataClassification.CONFIDENTIAL));
      classification("notes", "CONFIDENTIAL");
      logger.onAccess(event(FieldAccessEventType.VIEW, null, null).withFieldNames(List.of("notes", "email")));
      logger.flush();
      assertThat(logs()).filteredOn(row -> !"CLASSIFICATION_CHANGE".equals(row.getValueString("event_type"))).hasSize(3);
   }

   /*******************************************************************************
    ** Queue overflow and shutdown are observable without failing access.
    *******************************************************************************/
   @Test
   void queueOverflowAndShutdownAreObservableWithoutFailingAccess() throws Exception
   {
      setup(config -> config.withAccessLogQueueCapacity(1));
      var logger = SecuredDataRuntime.current().logger();
      logger.onAccess(event(FieldAccessEventType.VIEW, null, null));
      logger.onAccess(event(FieldAccessEventType.VIEW, null, null));
      assertThat(logger.getDroppedCount()).isEqualTo(1);
      logger.close();
      assertThat(logs()).hasSize(1);
      logger.onAccess(event(FieldAccessEventType.VIEW, null, null));
      assertThat(logger.getDroppedCount()).isEqualTo(2);
   }

   /*******************************************************************************
    ** Asynchronous worker drains in system context.
    *******************************************************************************/
   @Test
   void asynchronousWorkerDrainsInSystemContext() throws Exception
   {
      setup(config -> config.withAccessLogFlushIntervalMillis(10));
      SecuredDataRuntime.current().logger().onAccess(event(FieldAccessEventType.VIEW, null, null));
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while(logs().isEmpty() && System.nanoTime() < deadline)
      {
         Thread.sleep(10);
      }
      assertThat(logs()).hasSize(1);
      assertThat(QContext.getQSession().getUser().getIdReference()).isEqualTo("u1");
   }

   /*******************************************************************************
    ** Concurrent preflight cannot spend the same last slot.
    *******************************************************************************/
   @Test
   void concurrentPreflightCannotSpendTheSameLastSlot() throws Exception
   {
      QInstance instance = setup();
      var resolver = SecuredDataRuntime.current().resolver();
      for(int i = 0; i < 19; i++)
      {
         resolver.checkExactMatch(event(FieldAccessEventType.EXACT_MATCH_FILTER, null, null));
      }
      AtomicInteger accepted = new AtomicInteger();
      CountDownLatch start = new CountDownLatch(1);
      try(var pool = Executors.newFixedThreadPool(8))
      {
         List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
         for(int i = 0; i < 8; i++)
         {
            futures.add(pool.submit(() ->
            {
               QContext.withTemporaryContext(new CapturedContext(instance, user("u1", "cs_admin")), () ->
               {
                  start.await();
                  try
                  {
                     resolver.checkExactMatch(event(FieldAccessEventType.EXACT_MATCH_FILTER, null, null));
                     accepted.incrementAndGet();
                  }
                  catch(QPermissionDeniedException expected)
                  {
                  }
               });
               return (null);
            }));
         }
         start.countDown();
         for(var future : futures)
         {
            future.get(5, TimeUnit.SECONDS);
         }
      }
      assertThat(accepted).hasValue(1);
   }


   /*******************************************************************************
    ** Consecutive misses span an hour but distinct values do not.
    *******************************************************************************/
   @Test
   void consecutiveMissesSpanAnHourButDistinctValuesDoNot() throws Exception
   {
      QInstance instance = setup();
      AlertsSink.signals.clear();
      AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(AlertsSink.class));
      var resolver = SecuredDataRuntime.current().resolver();
      for(int i = 0; i < 4; i++)
      {
         resolver.onAccess(event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.NO_MATCH, resolver.fingerprintSearchValue("same")));
      }
      SecuredDataRuntime.current().logger().flush();
      CLOCK.now = NOW.plusSeconds(3601);
      resolver.onAccess(event(FieldAccessEventType.EXACT_MATCH_FILTER, FieldAccessOutcome.NO_MATCH, resolver.fingerprintSearchValue("same")));
      SecuredDataRuntime.current().logger().flush();
      assertThat(AlertsSink.signals).hasSize(1);
      assertThat(logs().stream().filter(row -> Boolean.TRUE.equals(row.getValueBoolean("anomaly_flag")))) .hasSize(1);
   }

   /*******************************************************************************
    ** Break glass identity is captured before worker switches to system.
    *******************************************************************************/
   @Test
   void breakGlassIdentityIsCapturedBeforeWorkerSwitchesToSystem() throws Exception
   {
      setup();
      QRecord grant = insert(SecuredDataTables.BREAK_GLASS, new QRecord().withValue("user_id", "u1").withValue("status", "ACTIVE")
         .withValue("classification_ceiling", "PHI").withValue("started_at", NOW).withValue("expires_at", NOW.plusSeconds(60)));
      SecuredDataRuntime.current().logger().onAccess(event(FieldAccessEventType.VIEW, null, null));
      SecuredDataRuntime.current().logger().flush();
      assertThat(logs().getFirst().getValue("break_glass_id")).isEqualTo(grant.getValue("id"));
   }



   /*******************************************************************************
    ** Alerts sink.
    *******************************************************************************/
   public static class AlertsSink implements AlertSinkInterface
   {
      static final List<AlertSignal> signals = new ArrayList<>();



      /*******************************************************************************
       ** Raise.
       *******************************************************************************/
      public void raise(AlertSignal signal)
      {
         signals.add(signal);
      }



      /*******************************************************************************
       ** Resolve.
       *******************************************************************************/
      public void resolve(AlertResolution resolution)
      {
      }



      /*******************************************************************************
       ** Heartbeat.
       *******************************************************************************/
      public void heartbeat(String key, Instant at)
      {
      }
   }


   /*******************************************************************************
    ** The worker starts while the host is still building its instance. An idle
    ** tick opens no context, so it never validates (or enriches) an unfinished
    ** instance on the worker thread, and a failing tick is logged instead of
    ** cancelling every later tick.
    *******************************************************************************/
   @Test
   void idleTicksNeverValidateAnUnfinishedInstance() throws Exception
   {
      setup();
      SecuredDataRuntime runtime = SecuredDataRuntime.current();
      QInstance unfinished = SecuredDataTestSupport.base();
      unfinished.addTable(new QTableMetaData().withName("unfinished").withBackendName("not_registered_yet"));
      SecuredDataAccessLogger idle = new SecuredDataAccessLogger(unfinished, runtime);
      try
      {
         idle.flush();
         idle.scheduledFlush();
         assertThat(unfinished.getHasBeenValidated()).isFalse();
      }
      finally
      {
         idle.close();
      }
   }
}
