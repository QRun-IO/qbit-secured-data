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

package com.kingsrook.qbits.secureddata.support;


import java.util.List;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.actions.permissions.CorePermissionEnforcer;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;


/*******************************************************************************
 ** System-session lookups and writes; restoring the caller even after a failure.
 *******************************************************************************/
public final class SystemWrites
{
   private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);



   /*******************************************************************************
    ** Work inside a system session.
    *******************************************************************************/
   @FunctionalInterface
   public interface Work<T>
   {
      /*******************************************************************************
       ** Execute.
       *******************************************************************************/
      T run() throws QException;
   }



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SystemWrites()
   {
   }



   /*******************************************************************************
    ** Preserve the transaction and instance, replacing only the session.
    *******************************************************************************/
   public static <T> T call(Work<T> work) throws QException
   {
      QSession previous = QContext.getQSession();
      DEPTH.set(DEPTH.get() + 1);
      QContext.setQSession(new QSystemUserSession(QContext.getQInstance()));
      try(CorePermissionEnforcer.AuthorizedScope ignored = CorePermissionEnforcer.openAuthorizedScope())
      {
         return (work.run());
      }
      finally
      {
         QContext.setQSession(previous);
         DEPTH.set(DEPTH.get() - 1);
      }
   }



   /*******************************************************************************
    ** Reentrancy guard used by the resolver.
    *******************************************************************************/
   public static boolean active()
   {
      return (DEPTH.get() > 0);
   }



   /*******************************************************************************
    ** Query without user locks or field access recursion.
    *******************************************************************************/
   public static List<QRecord> query(String table, QQueryFilter filter)
   {
      try
      {
         return (call(() -> new QueryAction().execute(new QueryInput(table).withFilter(filter)).getRecords()));
      }
      catch(QException e)
      {
         throw (new IllegalStateException("Unable to read secured-data state", e));
      }
   }



   /*******************************************************************************
    ** Insert and reject backend record errors.
    *******************************************************************************/
   public static QRecord insertOne(String table, QRecord record) throws QException
   {
      return (insertOne(table, record, QContext.getQBackendTransaction()));
   }

   /*******************************************************************************
    ** Explicit transaction for post-write customizers; audit rolls back with its source.
    *******************************************************************************/
   public static QRecord insertOne(String table, QRecord record, QBackendTransaction transaction) throws QException
   {
      if(com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.ACCESS_LOG.equals(table))
      {
         synchronized(com.kingsrook.qbits.secureddata.SecuredDataRuntime.current().anomalies())
         {
            return (insertAndAlert(table, record, transaction));
         }
      }
      return (insertAndAlert(table, record, transaction));
   }

   /*******************************************************************************
    ** Serialize same-node counter evaluation and insertion. Preserve enumeration flags.
    *******************************************************************************/
   private static QRecord insertAndAlert(String table, QRecord record, QBackendTransaction transaction) throws QException
   {
      boolean anomaly = com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.ACCESS_LOG.equals(table)
         && com.kingsrook.qbits.secureddata.SecuredDataRuntime.current().anomalies().evaluate(record);
      if(anomaly)
      {
         record.setValue("anomaly_flag", true);
      }
      QRecord inserted = call(() -> new InsertAction().execute(new InsertInput(table).withRecord(record).withTransaction(transaction)).getRecords().getFirst());
      if(inserted.getErrors() != null && !inserted.getErrors().isEmpty())
      {
         throw (new QException("Secured-data system insert failed"));
      }
      if(anomaly)
      {
         if(transaction == null)
         {
            com.kingsrook.qbits.secureddata.SecuredDataAnomalies.raise(inserted);
         }
         else
         {
            var context = new com.kingsrook.qqq.backend.core.context.CapturedContext(QContext.getQInstance(), QContext.getQSession());
            transaction.addAfterCommitCallback(() -> QContext.withTemporaryContext(context,
               () -> com.kingsrook.qbits.secureddata.SecuredDataAnomalies.raise(inserted)));
         }
      }
      return (inserted);
   }
}
