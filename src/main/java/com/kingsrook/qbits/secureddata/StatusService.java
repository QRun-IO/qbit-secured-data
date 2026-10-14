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
import com.kingsrook.qbits.secureddata.reveal.RevealOptions;
import com.kingsrook.qbits.secureddata.reveal.RevealService;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** Caller-only banner and per-field reveal allowance summary.
 *******************************************************************************/
public class StatusService
{
   /*******************************************************************************
    ** Active session projection.
    *******************************************************************************/
   public record BreakGlassStatus(Serializable id, String reason, Instant expiresAt, String scope, String ceiling)
   {
   }

   /*******************************************************************************
    ** Allowances differ by granting policy; null remaining means unlimited.
    *******************************************************************************/
   public record Allowance(String tableName, String fieldName, Integer remainingDailyAllowance)
   {
   }

   /*******************************************************************************
    ** Status response.
    *******************************************************************************/
   public record Status(BreakGlassStatus breakGlass, int revealsUsedToday, List<Allowance> revealAllowances)
   {
   }

   /*******************************************************************************
    ** Only readable revealable fields are included, without any record values.
    *******************************************************************************/
   public Status status() throws QException
   {
      List<QRecord> active = SecuredDataRuntime.current().resolver().activeBreakGlass();
      QRecord row = active.isEmpty() ? null : active.getFirst();
      BreakGlassStatus session = row == null ? null : new BreakGlassStatus(row.getValue("id"), row.getValueString("reason"), row.getValueInstant("expires_at"),
         row.getValueString("table_name"), row.getValueString("classification_ceiling"));
      RevealService service = new RevealService();
      List<Allowance> allowances = new ArrayList<>();
      for(QTableMetaData table : QContext.getQInstance().getTables().values())
      {
         for(QFieldMetaData field : table.getFields().values())
         {
            try
            {
               RevealOptions options = service.options(table.getName(), field.getName());
               allowances.add(new Allowance(table.getName(), field.getName(), options.remainingDailyAllowance()));
            }
            catch(QPermissionDeniedException expected)
            {
               // This field offers no reveal operation to the caller.
            }
         }
      }
      return (new Status(session, service.usedToday(), List.copyOf(allowances)));
   }
}
