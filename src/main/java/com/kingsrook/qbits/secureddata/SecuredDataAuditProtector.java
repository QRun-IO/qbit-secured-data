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
import com.kingsrook.qbits.secureddata.retention.RetentionRules;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.actions.audits.AuditValueProtectorInterface;
import com.kingsrook.qqq.backend.core.actions.audits.DMLAuditAction.DMLType;
import com.kingsrook.qqq.backend.core.actions.audits.ProtectedAuditValues;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.ClassifiedValueTokens;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** Classifications and policy determine whether audits retain a keyed derivative.
 *******************************************************************************/
public final class SecuredDataAuditProtector implements AuditValueProtectorInterface
{
   /*******************************************************************************
    ** Core also uses this source for runtime classification overrides.
    *******************************************************************************/
   @Override
   public DataClassification classificationOf(QTableMetaData table, QFieldMetaData field)
   {
      DataClassification classification = SecuredDataClassifications.effective(table, field.getName());
      if(com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.ALL.contains(table.getName()))
      {
         return (classification);
      }
      return (RetentionRules.active(table.getName(), field.getName()).isEmpty() ? classification : DataClassification.max(classification, DataClassification.PII));
   }

   /*******************************************************************************
    ** Null stays absent; CHANGED_ONLY never creates a DEK.
    *******************************************************************************/
   @Override
   public ProtectedAuditValues protect(QTableMetaData table, QFieldMetaData field, Serializable pk, Serializable oldValue, Serializable newValue, DMLType dmlType)
   {
      boolean changed = RetentionRules.changedOnly(table.getName(), field.getName());
      String message = (oldValue == null ? "Set " : newValue == null ? "Removed " : "Changed ") + field.getLabel();
      return (new ProtectedAuditValues(oldValue == null ? null : changed ? "changed:v1" : ClassifiedValueTokens.forRecordField(table, field, pk, oldValue),
         newValue == null ? null : changed ? "changed:v1" : ClassifiedValueTokens.forRecordField(table, field, pk, newValue), message));
   }
}
