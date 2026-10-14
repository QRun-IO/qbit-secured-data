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

package com.kingsrook.qbits.secureddata.reveal;

import java.io.Serializable;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import com.kingsrook.qbits.secureddata.SecuredDataResolver;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.standin.FieldAccessTier;
import com.kingsrook.qbits.secureddata.support.ActivityLog;
import com.kingsrook.qbits.secureddata.support.SecuredDataMetadata;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.permissions.CorePermissionEnforcer;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionEnforcement;
import com.kingsrook.qqq.backend.core.actions.permissions.TablePermissionSubType;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.QAlerts;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QBadRequestException;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QNotFoundException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** Reveal authorization and grant creation independent of any HTTP transport.
 *******************************************************************************/
public class RevealService
{
   /*******************************************************************************
    ** Use the current instance runtime, including its injectable clock.
    *******************************************************************************/
   public RevealOptions options(String tableName, String fieldName) throws QException
   {
      requireActor();
      QRecord policy = policy(tableName, fieldName);
      String reasons = policy.getValueString("reason_options");
      Integer cap = policy.getValueInteger("daily_reveal_cap");
      return (new RevealOptions(reasons == null ? List.of() : Arrays.stream(reasons.split("\\R")).map(String::trim).filter(s -> !s.isEmpty()).toList(),
         !Boolean.FALSE.equals(policy.getValueBoolean("allow_free_text_reason")), Boolean.TRUE.equals(policy.getValueBoolean("require_free_text")),
         Objects.requireNonNullElse(policy.getValueInteger("reveal_minutes"), 5), cap == null ? null : Math.max(0, cap - usedToday())));
   }

   /*******************************************************************************
    ** A single coherent policy: unlimited/highest cap, then longest duration, then id.
    *******************************************************************************/
   private QRecord policy(String tableName, String fieldName) throws QException
   {
      requireTarget(tableName, fieldName);
      if("assistant".equals(SecuredDataMetadata.channel(QContext.getQSession())))
      {
         throw (new QPermissionDeniedException("Reveal is unavailable on the assistant channel."));
      }
      QTableMetaData table = QContext.getQInstance().getTable(tableName);
      if(table == null || !table.getFields().containsKey(fieldName))
      {
         throw (new QNotFoundException("Table or field not found."));
      }
      GetInput input = new GetInput(tableName);
      input.setPermissionEnforcement(PermissionEnforcement.ENFORCE);
      CorePermissionEnforcer.checkTablePermissions(input, TablePermissionSubType.READ);
      if(SecuredDataRuntime.current().resolver().resolve(table, table.getField(fieldName)).tier() != FieldAccessTier.REVEALABLE)
      {
         throw (new QPermissionDeniedException("Field is not revealable."));
      }
      return (SecuredDataRuntime.current().resolver().revealPolicies(table, fieldName).stream()
         .max(Comparator.comparingInt((QRecord row) -> Objects.requireNonNullElse(row.getValueInteger("daily_reveal_cap"), Integer.MAX_VALUE))
            .thenComparingInt(row -> Objects.requireNonNullElse(row.getValueInteger("reveal_minutes"), 5))
            .thenComparing(row -> row.getValueString("id"), Comparator.reverseOrder()))
         .orElse(new QRecord().withValue("reveal_minutes", 5).withValue("allow_free_text_reason", true)));
   }

   /*******************************************************************************
    ** UTC daily count across all tables, including expired grants.
    *******************************************************************************/
   public int usedToday()
   {
      Instant start = SecuredDataRuntime.current().config().getClock().instant().atOffset(ZoneOffset.UTC).toLocalDate().atStartOfDay().toInstant(ZoneOffset.UTC);
      return (SystemWrites.query(SecuredDataTables.REVEAL_GRANT, new QQueryFilter()
         .withCriteria(new QFilterCriteria("user_id", QCriteriaOperator.EQUALS, SecuredDataResolver.userId()))
         .withCriteria(new QFilterCriteria("granted_at", QCriteriaOperator.GREATER_THAN_OR_EQUALS, start))).size());
   }

   /*******************************************************************************
    ** Serialize the cap check and write within this runtime; first fetch always as caller.
    *******************************************************************************/
   public RevealResult reveal(String tableName, Serializable primaryKey, String fieldName, String reason, String reasonText) throws QException
   {
      requireActor();
      SecuredDataRuntime runtime = SecuredDataRuntime.current();
      synchronized(runtime)
      {
         if("assistant".equals(SecuredDataMetadata.channel(QContext.getQSession())))
         {
            denied(tableName, primaryKey, fieldName, "DENIED");
            throw (new QPermissionDeniedException("Reveal is unavailable on the assistant channel."));
         }
         if(primaryKey == null)
         {
            throw (new QBadRequestException("primaryKey is required."));
         }
         requireTarget(tableName, fieldName);
         GetInput input = new GetInput(tableName).withPrimaryKey(primaryKey).withShouldFetchHeavyFields(true);
         input.setPermissionEnforcement(PermissionEnforcement.ENFORCE);
         if(new GetAction().execute(input).getRecord() == null)
         {
            throw (new QNotFoundException("No record was found"));
         }
         RevealOptions options = options(tableName, fieldName);
         validateReason(options, reason, reasonText);
         if(options.remainingDailyAllowance() != null && options.remainingDailyAllowance() == 0)
         {
            denied(tableName, primaryKey, fieldName, "CAPPED");
            QAlerts.raise(new AlertSignal("secured_data.reveal_capped").withDedupKey("secured_data.reveal_capped:" + SecuredDataResolver.userId())
               .withTitle("Daily reveal allowance exhausted").withSummary("Review the secured-data access log."));
            throw (new RevealCappedException());
         }
         QRecord raw = SystemWrites.call(() -> new GetAction().execute(new GetInput(tableName).withPrimaryKey(primaryKey)
            .withShouldFetchHeavyFields(true).withShouldTranslatePossibleValues(true)).getRecord());
         if(raw == null)
         {
            throw (new QNotFoundException("No record was found"));
         }
         com.kingsrook.qqq.backend.core.actions.values.QValueFormatter.setDisplayValuesInRecords(QContext.getQInstance().getTable(tableName), List.of(raw));
         Instant now = runtime.config().getClock().instant();
         Instant expiry = now.plusSeconds(options.revealMinutes() * 60L);
         QRecord audit = SystemWrites.insertOne(SecuredDataTables.ACCESS_LOG, ActivityLog.row("REVEAL", tableName, "ALLOWED")
            .withValue("record_id", String.valueOf(primaryKey)).withValue("field_name", fieldName).withValue("reason", reason).withValue("reason_text", reasonText));
         QRecord grant = SystemWrites.insertOne(SecuredDataTables.REVEAL_GRANT, new QRecord()
            .withValue("user_id", SecuredDataResolver.userId()).withValue("user_name", QContext.getQSession().getUser().getFullName())
            .withValue("table_name", tableName).withValue("field_name", fieldName).withValue("record_id", String.valueOf(primaryKey))
            .withValue("reason", reason).withValue("reason_text", reasonText).withValue("granted_at", now).withValue("expires_at", expiry)
            .withValue("access_log_id", audit.getValue("id")));
         runtime.resolver().invalidateReveals();
         return (new RevealResult(raw.getValue(fieldName), raw.getDisplayValue(fieldName), expiry, grant.getValue("id")));
      }
   }

   /*******************************************************************************
    ** Grants require a stable authenticated user identity across sessions.
    *******************************************************************************/
   private void requireActor() throws QPermissionDeniedException
   {
      if("anonymous".equals(SecuredDataResolver.userId()) || SecuredDataResolver.userId().isBlank())
      {
         throw (new QPermissionDeniedException("Reveal requires an authenticated user."));
      }
   }

   /*******************************************************************************
    ** Missing target identifiers are malformed input, not an internal lookup error.
    *******************************************************************************/
   private void requireTarget(String table, String field) throws QBadRequestException
   {
      if(table == null || table.isBlank() || field == null || field.isBlank())
      {
         throw (new QBadRequestException("tableName and fieldName are required."));
      }
   }

   /*******************************************************************************
    ** Persist refusals without user supplied text or protected values.
    *******************************************************************************/
   private void denied(String table, Serializable pk, String field, String outcome) throws QException
   {
      SystemWrites.insertOne(SecuredDataTables.ACCESS_LOG, ActivityLog.row("REVEAL_DENIED", table, outcome)
         .withValue("record_id", String.valueOf(pk)).withValue("field_name", field));
   }

   /*******************************************************************************
    ** Reasons are a listed option or allowed free text; both inputs are bounded.
    *******************************************************************************/
   private void validateReason(RevealOptions options, String reason, String text) throws QBadRequestException
   {
      boolean hasText = text != null && !text.isBlank();
      boolean listed = reason != null && options.reasonOptions().contains(reason);
      if((reason != null && reason.length() > 500) || (text != null && text.length() > 500)
         || (options.requireFreeText() && !hasText)
         || (!options.allowFreeTextReason() && hasText && !options.requireFreeText())
         || (!listed && !(options.allowFreeTextReason() && (hasText || (reason != null && !reason.isBlank())))))
      {
         throw (new QBadRequestException("Supply an allowed reason and required explanation, each at most 500 characters."));
      }
   }
}
