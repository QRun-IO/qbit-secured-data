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


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.standin.FieldAccessEvent;
import com.kingsrook.qbits.secureddata.standin.FieldAccessEventType;
import com.kingsrook.qbits.secureddata.standin.FieldAccessOutcome;
import com.kingsrook.qbits.secureddata.support.CoreMetadataBridge;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.QAlerts;
import com.kingsrook.qqq.backend.core.context.CapturedContext;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;


/*******************************************************************************
 ** Bounded asynchronous value-free audit, with persisted and local enumeration accounting.
 *******************************************************************************/
public class SecuredDataAccessLogger implements AutoCloseable
{
   private static final QLogger LOG = QLogger.getLogger(SecuredDataAccessLogger.class);
   private final QInstance instance;
   private final SecuredDataRuntime runtime;
   private final ArrayBlockingQueue<PendingLog> queue;
   private final ScheduledExecutorService worker;
   private final Thread shutdownHook;
   private final AtomicLong dropped = new AtomicLong();
   private final Object flushLock = new Object();
   private final Object lifecycleLock = new Object();
   private final ThreadLocal<String> refusalReason = new ThreadLocal<>();
   private final Map<String, ArrayDeque<Instant>> reservations = new HashMap<>();
   private volatile boolean closed;



   /*******************************************************************************
    ** Settings are captured for the acting user, before the worker becomes system.
    *******************************************************************************/
   private record PendingLog(QRecord row, SecuredDataResolver.Guardrails guardrails)
   {
   }



   /*******************************************************************************
    ** One daemon drains this instance's queue; the JVM hook flushes on shutdown.
    *******************************************************************************/
   public SecuredDataAccessLogger(QInstance instance, SecuredDataRuntime runtime)
   {
      this.instance = instance;
      this.runtime = runtime;
      this.queue = new ArrayBlockingQueue<>(runtime.config().getAccessLogQueueCapacity());
      this.worker = Executors.newSingleThreadScheduledExecutor(task ->
      {
         Thread thread = new Thread(task, "secured-data-access-log");
         thread.setDaemon(true);
         return (thread);
      });
      long interval = runtime.config().getAccessLogFlushIntervalMillis();
      worker.scheduleWithFixedDelay(this::flush, interval, interval, TimeUnit.MILLISECONDS);
      shutdownHook = new Thread(this::close, "secured-data-access-log-shutdown");
      Runtime.getRuntime().addShutdownHook(shutdownHook);
   }



   /*******************************************************************************
    ** Drop count for operational monitoring and the future app home.
    *******************************************************************************/
   public long getDroppedCount()
   {
      return (dropped.get());
   }



   /*******************************************************************************
    ** Snapshot identifiers only. A failed/full logger must never fail the read.
    *******************************************************************************/
   public void onAccess(FieldAccessEvent event)
   {
      if(SystemWrites.active())
      {
         return;
      }
      try
      {
         QTableMetaData table = instance.getTable(event.getTableName());
         if(table == null || SecuredDataTables.ALL.contains(table.getName()))
         {
            return;
         }
         List<String> fields = event.getFieldNames() == null ? List.of() : event.getFieldNames();
         if(event.getType() == FieldAccessEventType.VIEW)
         {
            fields = fields.stream().filter(field -> runtime.config().getViewLogClassifications().contains(SecuredDataClassifications.effective(table, field))).toList();
            if(fields.isEmpty())
            {
               return;
            }
         }
         if(event.getType() == FieldAccessEventType.EXACT_MATCH_FILTER)
         {
            for(String field : fields.stream().distinct().toList())
            {
               offer(row(event, List.of(field)), runtime.resolver().guardrails(table, field));
            }
         }
         else
         {
            offer(row(event, fields), null);
         }
      }
      catch(Exception e)
      {
         drop("Unable to queue secured-data access log");
      }
   }



   /*******************************************************************************
    ** Build a row without copying record values, arbitrary reasons or filter objects.
    *******************************************************************************/
   private QRecord row(FieldAccessEvent event, List<String> fields)
   {
      QSession session = QContext.getQSession();
      String type = event.getType() == FieldAccessEventType.DENIED ? "FILTER_DENIED" : event.getType().name();
      String outcome = event.getOutcome() == null ? (event.getType() == FieldAccessEventType.DENIED ? "DENIED" : "ALLOWED") : event.getOutcome().name();
      QRecord row = new QRecord().withValue("event_type", type).withValue("user_id", SecuredDataResolver.userId())
         .withValue("user_name", session == null || session.getUser() == null ? null : session.getUser().getFullName())
         .withValue("table_name", event.getTableName()).withValue("field_name", String.join(",", fields))
         .withValue("record_count", event.getRecordCount()).withValue("action_name", event.getActionName())
         .withValue("client_channel", CoreMetadataBridge.channel(session)).withValue("outcome", outcome)
         .withValue("anomaly_flag", false).withValue("created_at", runtime.config().getClock().instant());
      if(event.getPrimaryKeys() != null)
      {
         row.setValue("record_id", JsonUtils.toJson(event.getPrimaryKeys().stream().limit(50).toList()));
      }
      if(event.getSearchValueFingerprints() != null)
      {
         row.setValue("search_value_fingerprints", JsonUtils.toJson(event.getSearchValueFingerprints()));
      }
      if(event.getOutcome() == FieldAccessOutcome.REFUSED)
      {
         row.setValue("reason", Objects.requireNonNullElse(refusalReason.get(), "Exact-match search refused by access policy or enumeration guardrail."));
         refusalReason.remove();
      }
      QTableMetaData table = instance.getTable(event.getTableName());
      QRecord breakGlass = runtime.resolver().activeBreakGlass(table.getName(), SecuredDataClassifications.highest(table, fields));
      if(breakGlass != null)
      {
         row.setValue("break_glass_id", breakGlass.getValue("id"));
      }
      return (row);
   }



   /*******************************************************************************
    ** A full queue drops without waiting, warning only with value-free text.
    *******************************************************************************/
   private void offer(QRecord row, SecuredDataResolver.Guardrails guardrails)
   {
      synchronized(lifecycleLock)
      {
         if(closed || !queue.offer(new PendingLog(row, guardrails)))
         {
            drop("Secured-data access-log queue is full or closed; dropped one row");
         }
      }
   }



   /*******************************************************************************
    ** Keep failed persistence observable without dumping sensitive record objects.
    *******************************************************************************/
   private void drop(String message)
   {
      dropped.incrementAndGet();
      LOG.warn(message);
   }



   /*******************************************************************************
    ** Authoritative persisted count plus queued rows and uncompleted local searches.
    ** Serializes preflight and drain accounting, never ordinary VIEW enqueues.
    *******************************************************************************/
   public void checkExactMatch(FieldAccessEvent event) throws QPermissionDeniedException
   {
      synchronized(flushLock)
      {
         refusalReason.remove();
         String user = SecuredDataResolver.userId();
         QTableMetaData table = instance.getTable(event.getTableName());
         Instant now = runtime.config().getClock().instant();
         Instant since = now.minus(1, ChronoUnit.HOURS);
         expireReservations(since);
         List<String> fields = event.getFieldNames().stream().distinct().toList();
         for(String field : fields)
         {
            if(!runtime.resolver().resolve(table, table.getField(field)).exactMatchAllowed())
            {
               refusalReason.set("Exact-match search is disabled for this low-cardinality field.");
               throw (new QPermissionDeniedException("Permission denied."));
            }
            int limit = runtime.resolver().guardrails(table, field).exactMatchPerHour();
            if(limit == 0)
            {
               continue;
            }
            List<QRecord> persisted = history(user, table.getName(), field, since);
            long pending = queue.stream().filter(item -> matches(item.row(), user, table.getName(), field, since)).count();
            long reserved = reservations.getOrDefault(key(user, table.getName(), field), new ArrayDeque<>()).size();
            // Accepted outcomes in the queue still have their reservation until flush.
            long completedReserved = queue.stream().filter(item -> matches(item.row(), user, table.getName(), field, since))
               .filter(item -> !"REFUSED".equals(item.row().getValueString("outcome"))).count();
            if(persisted.size() + pending + Math.max(0, reserved - completedReserved) >= limit)
            {
               String reason = "Exact-match search limit reached for [" + field + "]. Try again later or ask an administrator.";
               refusalReason.set(reason);
               throw (new QPermissionDeniedException(reason));
            }
         }
         for(String field : fields)
         {
            if(runtime.resolver().guardrails(table, field).exactMatchPerHour() > 0)
            {
               reservations.computeIfAbsent(key(user, table.getName(), field), ignored -> new ArrayDeque<>()).addLast(now);
            }
         }
      }
   }



   /*******************************************************************************
    ** Retire conservative reservations left behind by failed queries or dropped logs.
    *******************************************************************************/
   private void expireReservations(Instant since)
   {
      reservations.values().forEach(times -> times.removeIf(time -> !time.isAfter(since)));
      reservations.values().removeIf(ArrayDeque::isEmpty);
   }



   /*******************************************************************************
    ** Identifier-safe composite key.
    *******************************************************************************/
   private static String key(String user, String table, String field)
   {
      return (JsonUtils.toJson(List.of(user, table, field)));
   }



   /*******************************************************************************
    ** The queue contains one exact-match row per field, matching the indexed query.
    *******************************************************************************/
   private static boolean matches(QRecord row, String user, String table, String field, Instant since)
   {
      return ("EXACT_MATCH_FILTER".equals(row.getValueString("event_type")) && Objects.equals(user, row.getValueString("user_id"))
         && Objects.equals(table, row.getValueString("table_name")) && Objects.equals(field, row.getValueString("field_name"))
         && row.getValueInstant("created_at").isAfter(since));
   }



   /*******************************************************************************
    ** Indexed history lookup, always under a system session.
    *******************************************************************************/
   private List<QRecord> history(String user, String table, String field, Instant since)
   {
      return (SystemWrites.query(SecuredDataTables.ACCESS_LOG, new QQueryFilter()
         .withCriteria(new QFilterCriteria("user_id", QCriteriaOperator.EQUALS, user))
         .withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, table))
         .withCriteria(new QFilterCriteria("field_name", QCriteriaOperator.EQUALS, field))
         .withCriteria(new QFilterCriteria("event_type", QCriteriaOperator.EQUALS, "EXACT_MATCH_FILTER"))
         .withCriteria(new QFilterCriteria("created_at", QCriteriaOperator.GREATER_THAN, since))
         .withOrderBy(new QFilterOrderBy("created_at", false)).withOrderBy(new QFilterOrderBy("id", false))));
   }



   /*******************************************************************************
    ** Drain safely both from the worker and explicit test/host shutdown calls.
    *******************************************************************************/
   public void flush()
   {
      synchronized(flushLock)
      {
         QContext.withTemporaryContext(new CapturedContext(instance, new QSystemUserSession(instance)), () ->
         {
            PendingLog pending;
            while((pending = queue.peek()) != null)
            {
               QRecord row = pending.row();
               try
               {
                  boolean anomaly = isAnomaly(pending);
                  row.setValue("anomaly_flag", anomaly);
                  SystemWrites.insertOne(SecuredDataTables.ACCESS_LOG, row);
                  if(anomaly)
                  {
                     raiseAlert(row);
                  }
                  completeReservation(row);
               }
               catch(Exception e)
               {
                  drop("Unable to persist secured-data access log; dropped one row");
               }
               finally
               {
                  queue.poll();
               }
            }
         });
      }
   }



   /*******************************************************************************
    ** Only persisted successful searches release their in-flight reservation.
    *******************************************************************************/
   private void completeReservation(QRecord row)
   {
      if(!"EXACT_MATCH_FILTER".equals(row.getValueString("event_type")) || "REFUSED".equals(row.getValueString("outcome")))
      {
         return;
      }
      ArrayDeque<Instant> times = reservations.get(key(row.getValueString("user_id"), row.getValueString("table_name"), row.getValueString("field_name")));
      if(times != null)
      {
         times.pollFirst();
      }
   }



   /*******************************************************************************
    ** Evaluate each row in drain order against already persisted predecessors.
    *******************************************************************************/
   private boolean isAnomaly(PendingLog pending) throws java.io.IOException
   {
      SecuredDataResolver.Guardrails settings = pending.guardrails();
      if(settings == null)
      {
         return (false);
      }
      QRecord row = pending.row();
      List<QRecord> history = history(row.getValueString("user_id"), row.getValueString("table_name"), row.getValueString("field_name"),
         row.getValueInstant("created_at").minus(1, ChronoUnit.HOURS));
      int misses = "NO_MATCH".equals(row.getValueString("outcome")) ? 1 : 0;
      if(misses > 0 && settings.missAlertConsecutive() > 0)
      {
         List<QRecord> recent = SystemWrites.query(SecuredDataTables.ACCESS_LOG, new QQueryFilter()
            .withCriteria(new QFilterCriteria("user_id", QCriteriaOperator.EQUALS, row.getValueString("user_id")))
            .withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, row.getValueString("table_name")))
            .withCriteria(new QFilterCriteria("field_name", QCriteriaOperator.EQUALS, row.getValueString("field_name")))
            .withCriteria(new QFilterCriteria("event_type", QCriteriaOperator.EQUALS, "EXACT_MATCH_FILTER"))
            .withOrderBy(new QFilterOrderBy("created_at", false)).withOrderBy(new QFilterOrderBy("id", false))
            .withLimit(Math.max(1, settings.missAlertConsecutive())));
         for(QRecord previous : recent)
         {
            if(!"NO_MATCH".equals(previous.getValueString("outcome")))
            {
               break;
            }
            misses++;
         }
      }
      Set<String> distinct = new HashSet<>();
      List<QRecord> combined = new ArrayList<>(history);
      combined.add(row);
      for(QRecord item : combined)
      {
         String fingerprints = item.getValueString("search_value_fingerprints");
         if(fingerprints != null)
         {
            distinct.addAll(Arrays.asList(JsonUtils.toObject(fingerprints, String[].class)));
         }
      }
      return ((settings.missAlertConsecutive() > 0 && misses >= settings.missAlertConsecutive())
         || (settings.distinctValueAlert() > 0 && distinct.size() > settings.distinctValueAlert()));
   }



   /*******************************************************************************
    ** Core #1090 is released in RC.5; its optional sink is supplied by qbit-alerts.
    *******************************************************************************/
   private static void raiseAlert(QRecord row)
   {
      String dedup = "secured_data.enumeration:" + row.getValueString("user_id") + ":" + row.getValueString("table_name") + "."
         + row.getValueString("field_name") + ":" + row.getValueInstant("created_at").atOffset(java.time.ZoneOffset.UTC).toLocalDate();
      QAlerts.raise(new AlertSignal("secured_data.enumeration").withDedupKey(dedup)
         .withTitle("Repeated exact-match searches on secured data").withSummary("Review the secured-data access log for enumeration activity."));
   }



   /*******************************************************************************
    ** Idempotent shutdown; stops scheduling and drains accepted rows.
    *******************************************************************************/
   @Override
   public void close()
   {
      synchronized(lifecycleLock)
      {
         closed = true;
      }
      worker.shutdown();
      flush();
      if(Thread.currentThread() != shutdownHook)
      {
         try
         {
            Runtime.getRuntime().removeShutdownHook(shutdownHook);
         }
         catch(IllegalStateException expected)
         {
            // JVM shutdown has already begun.
         }
      }
   }
}
