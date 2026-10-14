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

package com.kingsrook.qbits.secureddata.retention;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import com.kingsrook.qbits.secureddata.SecuredDataKeySource;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.ActivityLog;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.actions.audits.AuditShreddedEvent;
import com.kingsrook.qqq.backend.core.actions.tables.DeleteAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.tables.WipeAuditFlag;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;

/*******************************************************************************
 ** ID-only extraction and atomic, system-owned batches. No host values are placed
 ** in process records, run messages, access logs or exceptions.
 *******************************************************************************/
public final class WipeService
{
   /*******************************************************************************
    ** Checked-exception-aware streaming boundary.
    *******************************************************************************/
   @FunctionalInterface
   public interface PageConsumer
   {
      /*******************************************************************************
       ** Consume one bounded page.
       *******************************************************************************/
      void accept(List<QRecord> records) throws QException;
   }

   public static final String PERMISSION = "secured_data.retention";

   /*******************************************************************************
    ** Enforce at every callable boundary, including process resumption.
    *******************************************************************************/
   public static void checkPermission() throws QPermissionDeniedException
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession)
         && (QContext.getQSession() == null || !QContext.getQSession().hasPermission(PERMISSION) || "assistant".equals(QContext.getQSession().getClientChannelName())))
      {
         throw (new QPermissionDeniedException("Permission denied: secured_data.retention is required."));
      }
   }

   /*******************************************************************************
    ** Reload the rule instead of trusting process-state configuration.
    *******************************************************************************/
   public static QRecord rule(Serializable id) throws QException
   {
      List<QRecord> rows = SystemWrites.query(SecuredDataTables.RETENTION_RULE, new QQueryFilter().withCriteria(new QFilterCriteria("id", QCriteriaOperator.EQUALS, id)));
      if(rows.isEmpty())
      {
         throw (new QException("Retention rule no longer exists."));
      }
      QRecord rule = rows.getFirst();
      RetentionRules.validate(rule);
      return (rule);
   }

   /*******************************************************************************
    ** A bounded keyset scan. Per-field predicates return IDs only, even for PHI.
    ** Packets carry IDs, field names and a hold indicator, never stored values.
    *******************************************************************************/
   public void extract(QRecord rule, PageConsumer consumer) throws QException
   {
      checkPermission();
      RetentionRules.validate(rule);
      if(!Boolean.TRUE.equals(rule.getValueBoolean("is_active")))
      {
         return;
      }
      String tableName = rule.getValueString("table_name");
      QTableMetaData table = QContext.getQInstance().getTable(tableName);
      String pkName = table.getPrimaryKeyField();
      Serializable after = null;
      while(true)
      {
         QQueryFilter filter = eligible(rule, null).withOrderBy(new QFilterOrderBy(pkName)).withLimit(rule.getValueInteger("batch_size"));
         if(after != null)
         {
            filter.withCriteria(new QFilterCriteria(pkName, QCriteriaOperator.GREATER_THAN, after));
         }
         List<QRecord> ids = query(tableName, filter, Set.of(pkName));
         if(ids.isEmpty())
         {
            return;
         }
         List<QRecord> packets = new ArrayList<>();
         for(QRecord id : ids)
         {
            Serializable pk = id.getValue(pkName);
            packets.add(new QRecord().withValue("id", pk).withValue("rule_id", rule.getValue("id"))
               .withValue("held", held(tableName, pk)));
         }
         consumer.accept(packets);
         after = ids.getLast().getValue(pkName);
      }
   }

   /*******************************************************************************
    ** Candidate fields are tested in SQL, not fetched.
    *******************************************************************************/
   private static QQueryFilter eligible(QRecord rule, String field)
   {
      QTableMetaData table = QContext.getQInstance().getTable(rule.getValueString("table_name"));
      Instant cutoff = SecuredDataRuntime.current().config().getClock().instant().minus(rule.getValueInteger("age_days"), ChronoUnit.DAYS);
      Serializable age = table.getField(rule.getValueString("age_field_name")).getType() == QFieldType.DATE ? cutoff.atZone(ZoneOffset.UTC).toLocalDate() : cutoff;
      QQueryFilter filter = new QQueryFilter().withCriteria(new QFilterCriteria(rule.getValueString("age_field_name"), QCriteriaOperator.LESS_THAN, age));
      QQueryFilter nonnull = new QQueryFilter().withBooleanOperator(QQueryFilter.BooleanOperator.OR);
      for(String name : field == null ? RetentionRules.fields(rule) : List.of(field))
      {
         nonnull.withCriteria(new QFilterCriteria(name, QCriteriaOperator.IS_NOT_BLANK));
      }
      return (filter.withSubFilter(nonnull));
   }

   /*******************************************************************************
    ** Active record and whole-table holds pause all policies.
    *******************************************************************************/
   public static boolean held(String table, Serializable pk)
   {
      return (!SystemWrites.query(SecuredDataTables.LEGAL_HOLD, new QQueryFilter()
         .withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, table))
         .withCriteria(new QFilterCriteria("status", QCriteriaOperator.EQUALS, "ACTIVE"))
         .withSubFilter(new QQueryFilter().withBooleanOperator(QQueryFilter.BooleanOperator.OR)
            .withCriteria(new QFilterCriteria("record_id", QCriteriaOperator.IS_BLANK))
            .withCriteria(new QFilterCriteria("record_id", QCriteriaOperator.EQUALS, String.valueOf(pk))))).isEmpty());
   }

   /*******************************************************************************
    ** Explicit projection and transaction for every host read.
    *******************************************************************************/
   private static List<QRecord> query(String table, QQueryFilter filter, Set<String> fields) throws QException
   {
      return (SystemWrites.call(() -> new QueryAction().execute(new QueryInput(table).withFilter(filter).withFieldNamesToInclude(fields)
         .withShouldFetchHeavyFields(true).withTransaction(QContext.getQBackendTransaction())).getRecords()));
   }

   /*******************************************************************************
    ** Revalidate eligibility and holds inside the batch, then commit all effects.
    ** Cross-backend and nontransactional deployments are refused before any writes.
    *******************************************************************************/
   public QRecord batch(Serializable ruleId, List<Serializable> ids) throws QException
   {
      checkPermission();
      QRecord rule = rule(ruleId);
      QTableMetaData table = QContext.getQInstance().getTable(rule.getValueString("table_name"));
      if(ids.size() > rule.getValueInteger("batch_size"))
      {
         throw (new QException("Wipe batch exceeds the policy batch size."));
      }
      if(QContext.getQBackendTransaction() != null)
      {
         throw (new QException("Wipe batches must own their transaction."));
      }
      for(String name : List.of(SecuredDataTables.RETENTION_RULE, SecuredDataTables.WIPE_MARKER, SecuredDataTables.LEGAL_HOLD,
         SecuredDataTables.WIPE_RUN, SecuredDataTables.AUDIT_KEY, SecuredDataTables.ACCESS_LOG, "audit", "auditDetail"))
      {
         QTableMetaData metadata = QContext.getQInstance().getTable(name);
         if(metadata != null && !Objects.equals(metadata.getBackendName(), table.getBackendName()))
         {
            throw (new QException("Wipe, audit and secured-data tables must share one transactional backend."));
         }
      }
      if("ARCHIVE_THEN_WIPE".equals(rule.getValueString("action")) && SecuredDataRuntime.current().config().getArchiveSink() == null)
      {
         throw (new QException("ARCHIVE_THEN_WIPE requires a host ArchiveSinkInterface backed by object storage."));
      }
      try(QBackendTransaction transaction = QBackendTransaction.openFor(new UpdateInput(table.getName())))
      {
         if(transaction == null || transaction.getClass() == QBackendTransaction.class)
         {
            throw (new QException("Wipe requires a backend with rollback-capable write transactions."));
         }
         QContext.setTransaction(transaction);
         try
         {
            QRecord result = SystemWrites.call(() -> apply(rule, table, ids, transaction));
            transaction.commit();
            return (result);
         }
         catch(Exception e)
         {
            transaction.rollback();
            throw (new QException("Wipe batch failed and was rolled back; no values are included in this message."));
         }
         finally
         {
            SecuredDataRuntime.current().keys().close();
            QContext.clearTransaction();
         }
      }
   }

   /*******************************************************************************
    ** Batch body. Markers, key deletion, audit, access log and run row share tx.
    *******************************************************************************/
   private QRecord apply(QRecord initialRule, QTableMetaData table, List<Serializable> ids, QBackendTransaction transaction) throws QException
   {
      QRecord rule = rule(initialRule.getValue("id"));
      Instant started = SecuredDataRuntime.current().config().getClock().instant();
      List<Serializable> wiped = new ArrayList<>();
      int held = 0;
      Map<Serializable, List<String>> fieldsById = new LinkedHashMap<>();
      if(Boolean.TRUE.equals(rule.getValueBoolean("is_active")))
      {
         for(String field : RetentionRules.fields(rule))
         {
            QQueryFilter filter = eligible(rule, field).withCriteria(new QFilterCriteria(table.getPrimaryKeyField(), QCriteriaOperator.IN, ids));
            for(QRecord row : query(table.getName(), filter, Set.of(table.getPrimaryKeyField())))
            {
               fieldsById.computeIfAbsent(row.getValue(table.getPrimaryKeyField()), ignored -> new ArrayList<>()).add(field);
            }
         }
      }
      List<QRecord> markers = new ArrayList<>();
      Map<String, List<Serializable>> logged = new LinkedHashMap<>();
      for(var entry : fieldsById.entrySet())
      {
         Serializable pk = entry.getKey();
         if(held(table.getName(), pk))
         {
            held++;
            continue;
         }
         List<String> fields = entry.getValue();
         String action = rule.getValueString("action");
         if("DELETE_RECORD".equals(action))
         {
            fields = new ArrayList<>(table.getFields().keySet());
            fields.remove(table.getPrimaryKeyField());
         }
         change(rule, table, pk, fields, transaction);
         for(String field : fields)
         {
            List<QRecord> keys = query(SecuredDataTables.AUDIT_KEY, SecuredDataKeySource.recordField(table.getName(), field, pk), Set.of("id"));
            for(QRecord key : keys)
            {
               var deleted = new DeleteAction().execute(new DeleteInput(SecuredDataTables.AUDIT_KEY).withPrimaryKeys(List.of(key.getValue("id"))).withTransaction(transaction));
               if(deleted.getDeletedRecordCount() != 1)
               {
                  throw (new QException("Audit key deletion failed."));
               }
               AuditShreddedEvent.shreddedDetail(table, pk, table.getField(field), rule.getValueString("id"), transaction);
            }
            markers.add(new QRecord().withValue("table_name", table.getName()).withValue("record_id", String.valueOf(pk)).withValue("field_name", field)
               .withValue("rule_id", rule.getValue("id")).withValue("action", action).withValue("wiped_at", started));
            logged.computeIfAbsent(field, ignored -> new ArrayList<>()).add(pk);
         }
         wiped.add(pk);
      }
      QRecord run = SystemWrites.insertOne(SecuredDataTables.WIPE_RUN, new QRecord().withValue("rule_id", rule.getValue("id"))
         .withValue("started_at", started).withValue("finished_at", SecuredDataRuntime.current().config().getClock().instant())
         .withValue("status", "COMPLETE").withValue("eligible_count", fieldsById.size()).withValue("held_count", held)
         .withValue("wiped_count", wiped.size()).withValue("error_count", 0).withValue("record_ids", boundedIds(wiped))
         .withValue("message", "Policy batch completed."), transaction);
      for(QRecord marker : markers)
      {
         marker.setValue("run_id", run.getValue("id"));
         List<QRecord> previous = SystemWrites.query(SecuredDataTables.WIPE_MARKER, SecuredDataKeySource.recordField(marker.getValueString("table_name"), marker.getValueString("field_name"), marker.getValue("record_id")));
         if(previous.isEmpty())
         {
            SystemWrites.insertOne(SecuredDataTables.WIPE_MARKER, marker, transaction);
         }
         else
         {
            marker.setValue("id", previous.getFirst().getValue("id"));
            update(SecuredDataTables.WIPE_MARKER, marker, transaction);
         }
      }
      for(var entry : logged.entrySet())
      {
         for(int offset = 0; offset < entry.getValue().size(); offset += 50)
         {
            List<Serializable> chunk = entry.getValue().subList(offset, Math.min(offset + 50, entry.getValue().size()));
            SystemWrites.insertOne(SecuredDataTables.ACCESS_LOG, ActivityLog.row("WIPE", table.getName(), "ALLOWED")
               .withValue("rule_id", rule.getValue("id")).withValue("field_name", entry.getKey()).withValue("record_id", boundedIds(chunk))
               .withValue("record_count", chunk.size()).withValue("action_name", rule.getValue("action")), transaction);
         }
      }
      update(SecuredDataTables.RETENTION_RULE, new QRecord().withValue("id", rule.getValue("id")).withValue("last_run_at", started).withValue("last_run_count", wiped.size()), transaction);
      return (run);
   }

   /*******************************************************************************
    ** The two value transformations read only the fields they transform; all
    ** other operations work entirely by ID. Archive receives encrypted JSON only.
    *******************************************************************************/
   private static void change(QRecord rule, QTableMetaData table, Serializable pk, List<String> fields, QBackendTransaction transaction) throws QException
   {
      String action = rule.getValueString("action");
      if("DELETE_RECORD".equals(action))
      {
         if(new DeleteAction().execute(new DeleteInput(table.getName()).withPrimaryKeys(List.of(pk)).withTransaction(transaction)).getDeletedRecordCount() != 1)
         {
            throw (new QException("Record deletion failed."));
         }
         return;
      }
      QRecord stored = null;
      if(Set.of("KEYED_HASH", "ARCHIVE_THEN_WIPE").contains(action))
      {
         stored = query(table.getName(), new QQueryFilter().withCriteria(new QFilterCriteria(table.getPrimaryKeyField(), QCriteriaOperator.EQUALS, pk)), new LinkedHashSet<>(fields)).getFirst();
      }
      if("ARCHIVE_THEN_WIPE".equals(action))
      {
         String objectKey = "secured-data/" + UUID.randomUUID() + ".aesgcm";
         Map<String, Serializable> values = new LinkedHashMap<>();
         for(String field : fields)
         {
            values.put(field, stored.getValue(field));
         }
         byte[] json = JsonUtils.toJson(values).getBytes(StandardCharsets.UTF_8);
         try
         {
            byte[] encrypted = SecuredDataKeySource.encrypt(json, objectKey);
            SecuredDataRuntime.current().config().getArchiveSink().put(rule.getValueString("archive_storage_name"), objectKey, encrypted);
         }
         finally
         {
            Arrays.fill(json, (byte) 0);
            values.clear();
         }
      }
      QRecord patch = new QRecord().withValue(table.getPrimaryKeyField(), pk);
      for(String field : fields)
      {
         Serializable value = switch(action)
         {
            case "OVERWRITE_TEXT" -> rule.getValue("overwrite_text");
            case "KEYED_HASH" -> SecuredDataRuntime.current().keys().instanceToken(table, table.getField(field), pk, stored.getValue(field));
            default -> null;
         };
         patch.setValue(field, value);
      }
      UpdateInput input = new UpdateInput(table.getName()).withRecord(patch).withTransaction(transaction);
      input.setFlags(Set.of(new WipeAuditFlag(rule.getValueString("id"))));
      check(new UpdateAction().execute(input).getRecords());

   }

   /*******************************************************************************
    ** Check record-level backend failures, which need not throw exceptions.
    *******************************************************************************/
   private static void check(List<QRecord> records) throws QException
   {
      if(records.isEmpty() || records.stream().anyMatch(row -> row.getErrors() != null && !row.getErrors().isEmpty()))
      {
         throw (new QException("Wipe write failed."));
      }
   }

   /*******************************************************************************
    ** System metadata updates still validate in the transaction.
    *******************************************************************************/
   private static void update(String table, QRecord row, QBackendTransaction transaction) throws QException
   {
      check(new UpdateAction().execute(new UpdateInput(table).withRecord(row).withTransaction(transaction)).getRecords());
   }

   /*******************************************************************************
    ** Bounded identifiers, never values. Full record evidence is in audit rows.
    *******************************************************************************/
   private static String boundedIds(List<Serializable> ids)
   {
      String joined = ids.stream().limit(50).map(String::valueOf).collect(Collectors.joining(","));
      return (joined.length() > 4000 ? joined.substring(0, 4000) : joined);
   }
}
