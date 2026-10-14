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

package com.kingsrook.qbits.secureddata.breakglass;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import com.kingsrook.qbits.secureddata.SecuredDataResolver;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.permissions.SecuredDataPermissions;
import com.kingsrook.qbits.secureddata.standin.DataClassification;
import com.kingsrook.qbits.secureddata.support.ActivityLog;
import com.kingsrook.qbits.secureddata.support.CoreMetadataBridge;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.alerts.AlertSeverity;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.QAlerts;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QBadRequestException;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QNotFoundException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;

/*******************************************************************************
 ** Explicit, audited emergency access. No implicit admin access to user data.
 *******************************************************************************/
public class BreakGlassService
{
   public static final String START = "secured_data_break_glass_start";
   public static final String END = "secured_data_break_glass_end";
   public static final String EXPIRE = "secured_data_break_glass_expire";
   private static final QLogger LOG = QLogger.getLogger(BreakGlassService.class);

   /*******************************************************************************
    ** Validate first, then create a system-owned session and publish its policy version.
    *******************************************************************************/
   public QRecord start(String reason, Integer minutes, String table, DataClassification ceiling) throws QException
   {
      checkChannel();
      if(!QContext.getQSession().hasPermission(START + ".hasAccess"))
      {
         throw (new QPermissionDeniedException("Permission denied."));
      }
      int duration = minutes == null ? 60 : minutes;
      if(reason == null || reason.trim().length() < 20 || reason.length() > 500 || duration < 1 || duration > 480)
      {
         throw (new QBadRequestException("Reason must contain 20-500 characters; duration must be 1-480 minutes."));
      }
      if(table != null && table.isBlank())
      {
         table = null;
      }
      if(table != null && QContext.getQInstance().getTable(table) == null)
      {
         throw (new QBadRequestException("Unknown table scope."));
      }
      SecuredDataRuntime runtime = SecuredDataRuntime.current();
      synchronized(runtime)
      {
         if(!runtime.resolver().activeBreakGlass().isEmpty())
         {
            throw (new QBadRequestException("An active break-glass session already exists."));
         }
         Instant now = runtime.config().getClock().instant();
         QRecord row = SystemWrites.insertOne(SecuredDataTables.BREAK_GLASS, new QRecord()
            .withValue("user_id", SecuredDataResolver.userId()).withValue("user_name", QContext.getQSession().getUser().getFullName())
            .withValue("reason", reason).withValue("table_name", table).withValue("classification_ceiling", Objects.requireNonNullElse(ceiling, DataClassification.PHI).name())
            .withValue("started_at", now).withValue("expires_at", now.plusSeconds(duration * 60L)).withValue("status", "ACTIVE"));
         runtime.invalidatePolicies();
         log(row, "BREAK_GLASS_START");
         QAlerts.raise(new AlertSignal("secured_data.break_glass").withSeverity(AlertSeverity.fromLabel("HIGH", AlertSeverity.ERROR)).withDedupKey(dedup(row))
            .withTitle("Break-glass access started").withSummary("Review the secured-data break-glass session.").withOccurredAt(now));
         notifyAdmins(row);
         return (row);
      }
   }

   /*******************************************************************************
    ** Owner or admin may end an active session, never an assistant channel.
    *******************************************************************************/
   public QRecord end(Serializable id) throws QException
   {
      checkChannel();
      synchronized(SecuredDataRuntime.current())
      {
         QRecord row = find(id);
         checkOwner(row);
         if(!"ACTIVE".equals(row.getValueString("status")))
         {
            throw (new QBadRequestException("Session is already finished."));
         }
         return (finish(row, "ENDED", "BREAK_GLASS_END"));
      }
   }

   /*******************************************************************************
    ** Review uses the same ownership check; load rechecks against persisted state.
    *******************************************************************************/
   public void checkOwner(QRecord row) throws QPermissionDeniedException
   {
      checkChannel();
      if(!Objects.equals(SecuredDataResolver.userId(), row.getValueString("user_id"))
         && !QContext.getQSession().hasPermission(SecuredDataPermissions.ADMIN))
      {
         throw (new QPermissionDeniedException("Only the owner or a secured-data administrator can end this session."));
      }
   }

   /*******************************************************************************
    ** All rows are looked up as system; authorization remains the caller responsibility.
    *******************************************************************************/
   public QRecord find(Serializable id) throws QNotFoundException
   {
      List<QRecord> rows = SystemWrites.query(SecuredDataTables.BREAK_GLASS, new QQueryFilter(new QFilterCriteria("id", QCriteriaOperator.EQUALS, id)));
      if(rows.isEmpty())
      {
         throw (new QNotFoundException("No record was found"));
      }
      return (rows.getFirst());
   }

   /*******************************************************************************
    ** Scheduled maintenance always performs its lookups and changes as system.
    *******************************************************************************/
   public int expire() throws QException
   {
      synchronized(SecuredDataRuntime.current())
      {
         return (SystemWrites.call(() ->
         {
            List<QRecord> rows = SystemWrites.query(SecuredDataTables.BREAK_GLASS, new QQueryFilter()
               .withCriteria(new QFilterCriteria("status", QCriteriaOperator.EQUALS, "ACTIVE"))
               .withCriteria(new QFilterCriteria("expires_at", QCriteriaOperator.LESS_THAN_OR_EQUALS, SecuredDataRuntime.current().config().getClock().instant())));
            for(QRecord row : rows)
            {
               finish(row, "EXPIRED", "BREAK_GLASS_EXPIRED");
            }
            return (rows.size());
         }));
      }
   }

   /*******************************************************************************
    ** Update, audit and resolve using one stable per-session alert key.
    *******************************************************************************/
   private QRecord finish(QRecord row, String status, String event) throws QException
   {
      QRecord update = new QRecord().withValue("id", row.getValue("id")).withValue("status", status)
         .withValue("ended_at", SecuredDataRuntime.current().config().getClock().instant()).withValue("ended_by", SecuredDataResolver.userId());
      QRecord result = SystemWrites.call(() -> new UpdateAction().execute(new UpdateInput(SecuredDataTables.BREAK_GLASS).withRecord(update)).getRecords().getFirst());
      if(result.getErrors() != null && !result.getErrors().isEmpty())
      {
         throw (new QException("Unable to finish break-glass session."));
      }
      SecuredDataRuntime.current().invalidatePolicies();
      log(row, event);
      QAlerts.resolve("secured_data.break_glass", dedup(row), status);
      return (result);
   }

   /*******************************************************************************
    ** Audit the actor and affected session without copying protected field values.
    *******************************************************************************/
   private void log(QRecord row, String event) throws QException
   {
      SystemWrites.insertOne(SecuredDataTables.ACCESS_LOG, ActivityLog.row(event, SecuredDataTables.BREAK_GLASS, "ALLOWED")
         .withValue("break_glass_id", row.getValue("id")).withValue("record_id", row.getValueString("id")).withValue("reason", row.getValue("reason")));
   }

   /*******************************************************************************
    ** Stable alert identity.
    *******************************************************************************/
   private String dedup(QRecord row)
   {
      return ("secured_data.break_glass:" + row.getValueString("id"));
   }

   /*******************************************************************************
    ** RC.5 lacks #1125; use the notify SPI when installed without a qbit-alerts dependency.
    *******************************************************************************/
   private void notifyAdmins(QRecord row)
   {
      try
      {
         Class<?> signalClass = Class.forName("com.kingsrook.qqq.backend.core.alerts.NotificationSignal");
         Class<?> audienceClass = Class.forName("com.kingsrook.qqq.backend.core.alerts.NotificationAudience");
         Object signal = signalClass.getConstructor(String.class).newInstance("Break-glass access started");
         signalClass.getMethod("withAudience", audienceClass).invoke(signal, audienceClass.getMethod("permission", String.class).invoke(null, SecuredDataPermissions.ADMIN));
         signalClass.getMethod("withSourceName", String.class).invoke(signal, "secured_data");
         signalClass.getMethod("withSourceKey", String.class).invoke(signal, dedup(row));
         QAlerts.class.getMethod("notify", signalClass).invoke(null, signal);
      }
      catch(ClassNotFoundException | NoSuchMethodException expected)
      {
         // TODO(core #1125): remove reflection at RC.6 and use the notification SPI directly.
         LOG.warn("Break-glass admin bell notification unavailable: core notification SPI #1125 is not installed.");
      }
      catch(ReflectiveOperationException e)
      {
         LOG.warn("Unable to deliver break-glass admin bell notification.");
      }
   }

   /*******************************************************************************
    ** Deny unauthenticated and assistant invocations in direct service calls too.
    *******************************************************************************/
   private void checkChannel() throws QPermissionDeniedException
   {
      if(QContext.getQSession() == null || QContext.getQSession().getUser() == null
         || "anonymous".equals(SecuredDataResolver.userId()) || SecuredDataResolver.userId().isBlank()
         || "assistant".equals(CoreMetadataBridge.channel(QContext.getQSession())))
      {
         throw (new QPermissionDeniedException("Permission denied."));
      }
   }
}
