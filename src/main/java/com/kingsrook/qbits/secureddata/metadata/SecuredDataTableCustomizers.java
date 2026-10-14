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

package com.kingsrook.qbits.secureddata.metadata;


import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import com.kingsrook.qbits.secureddata.SecuredDataResolver;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.actions.customizers.TableCustomizerInterface;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.AbstractActionInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.model.statusmessages.BadInputStatusMessage;


/*******************************************************************************
 ** Validation, activity-table write protection and post-commit cache invalidation.
 *******************************************************************************/
public class SecuredDataTableCustomizers implements TableCustomizerInterface
{
   /*******************************************************************************
    ** Defend system-only activity writes even when a caller skips permission checks.
    *******************************************************************************/
   @Override
   public List<QRecord> preInsertOrUpdate(AbstractActionInput input, List<QRecord> records, boolean preview, Optional<List<QRecord>> oldRecords) throws QException
   {
      String table = input instanceof InsertInput insert ? insert.getTableName() : ((UpdateInput) input).getTableName();
      assertWrite(table, input instanceof UpdateInput);
      if(!SecuredDataTables.SYSTEM_WRITTEN.contains(table))
      {
         for(QRecord record : records)
         {
            QRecord old = oldRecords.orElse(List.of()).stream().filter(row -> Objects.equals(row.getValue("id"), record.getValue("id"))).findFirst().orElse(null);
            QRecord effective = old == null ? new QRecord() : new QRecord(old);
            record.getValues().forEach(effective::setValue);
            validate(table, record, effective);
            Instant now = SecuredDataRuntime.current().config().getClock().instant();
            if(old == null)
            {
               record.setValue("create_date", now);
            }
            record.setValue("modify_date", now);
            record.setValue("modified_by", SecuredDataResolver.userId());
         }
      }
      return (records);
   }



   /*******************************************************************************
    ** Access logs are append-only even for the system.
    *******************************************************************************/
   private static void assertWrite(String table, boolean mutation) throws QPermissionDeniedException
   {
      if((mutation && SecuredDataTables.ACCESS_LOG.equals(table))
         || (SecuredDataTables.SYSTEM_WRITTEN.contains(table) && !SystemWrites.active() && !(QContext.getQSession() instanceof QSystemUserSession)))
      {
         throw (new QPermissionDeniedException("Secured-data activity is system-written; access logs are insert-only."));
      }
   }



   /*******************************************************************************
    ** Validate target names, unique table-wide classifications and guardrail ranges.
    *******************************************************************************/
   private static void validate(String table, QRecord record, QRecord effective)
   {
      String target = effective.getValueString("table_name");
      QTableMetaData metadata = target == null ? null : QContext.getQInstance().getTable(target);
      if(target != null && metadata == null)
      {
         record.addError(new BadInputStatusMessage("Select an existing table."));
      }
      if(SecuredDataTables.CLASSIFICATION.equals(table))
      {
         String field = effective.getValueString("field_name");
         if(field != null && field.isBlank())
         {
            field = null;
            record.setValue("field_name", null);
         }
         if(field != null && (metadata == null || !metadata.getFields().containsKey(field)))
         {
            record.addError(new BadInputStatusMessage("Select a field of the selected table."));
         }
         if(target != null)
         {
            for(QRecord row : SystemWrites.query(table, new QQueryFilter().withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, target))))
            {
               if(Objects.equals(field, row.getValueString("field_name")) && !Objects.equals(row.getValue("id"), effective.getValue("id")))
               {
                  record.addError(new BadInputStatusMessage("A classification for this table and field already exists."));
               }
            }
         }
      }
      else
      {
         Integer minutes = effective.getValueInteger("reveal_minutes");
         if(minutes != null && (minutes < 1 || minutes > 60))
         {
            record.addError(new BadInputStatusMessage("Reveal duration must be 1 to 60 minutes."));
         }
         for(String name : List.of("exact_match_per_hour", "miss_alert_consecutive", "distinct_value_alert", "daily_reveal_cap"))
         {
            Integer value = effective.getValueInteger(name);
            if(value != null && value < 0)
            {
               record.addError(new BadInputStatusMessage("Guardrail limits cannot be negative."));
            }
         }
      }
   }



   /*******************************************************************************
    ** User deletes of activity are forbidden; the log is immutable for everyone.
    *******************************************************************************/
   @Override
   public List<QRecord> preDelete(DeleteInput input, List<QRecord> records, boolean preview) throws QException
   {
      assertWrite(input.getTableName(), true);
      return (records);
   }



   /*******************************************************************************
    ** Only successful mutations invalidate; transactions invalidate after commit.
    *******************************************************************************/
   @Override
   public List<QRecord> postInsertOrUpdate(AbstractActionInput input, List<QRecord> records, Optional<List<QRecord>> oldRecords) throws QException
   {
      if(input instanceof InsertInput insert)
      {
         changed(insert.getTableName(), records, insert.getTransaction());
         audit(insert.getTableName(), records, "INSERT", insert.getTransaction());
      }
      else if(input instanceof UpdateInput update)
      {
         changed(update.getTableName(), records, update.getTransaction());
         audit(update.getTableName(), records, "UPDATE", update.getTransaction());
      }
      return (records);
   }



   /*******************************************************************************
    ** Deletions change the same versions as inserts and updates.
    *******************************************************************************/
   @Override
   public List<QRecord> postDelete(DeleteInput input, List<QRecord> records) throws QException
   {
      changed(input.getTableName(), records, input.getTransaction());
      audit(input.getTableName(), records, "DELETE", input.getTransaction());
      return (records);
   }



   /*******************************************************************************
    ** Capture the instance service; callbacks need no current user context.
    *******************************************************************************/
   private static void changed(String table, List<QRecord> records, QBackendTransaction transaction)
   {
      if(records.stream().noneMatch(row -> row.getErrors() == null || row.getErrors().isEmpty()))
      {
         return;
      }
      SecuredDataRuntime runtime = SecuredDataRuntime.current();
      Runnable invalidate = SecuredDataTables.CLASSIFICATION.equals(table) ? runtime::invalidateClassifications
         : SecuredDataTables.POLICY.equals(table) || SecuredDataTables.BREAK_GLASS.equals(table) ? runtime::invalidatePolicies : null;
      if(invalidate != null)
      {
         QBackendTransaction active = transaction == null ? QContext.getQBackendTransaction() : transaction;
         if(active == null)
         {
            invalidate.run();
         }
         else
         {
            active.addAfterCommitCallback(invalidate);
         }
      }
   }

   /*******************************************************************************
    ** Value-free mutation audit in the same transaction as the changed metadata.
    *******************************************************************************/
   private static void audit(String table, List<QRecord> records, String action, QBackendTransaction transaction) throws QException
   {
      if(!List.of(SecuredDataTables.POLICY, SecuredDataTables.CLASSIFICATION).contains(table))
      {
         return;
      }
      for(QRecord record : records)
      {
         if(record.getErrors() == null || record.getErrors().isEmpty())
         {
            SystemWrites.insertOne(SecuredDataTables.ACCESS_LOG, com.kingsrook.qbits.secureddata.support.ActivityLog.row(
               SecuredDataTables.POLICY.equals(table) ? "POLICY_CHANGE" : "CLASSIFICATION_CHANGE", table, "ALLOWED")
               .withValue("record_id", record.getValueString("id")).withValue("action_name", action),
               transaction == null ? QContext.getQBackendTransaction() : transaction);
         }
      }
   }
}
