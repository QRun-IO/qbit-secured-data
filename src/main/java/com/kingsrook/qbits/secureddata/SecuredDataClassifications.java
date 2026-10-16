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


import java.util.Collection;
import java.util.Objects;
import com.kingsrook.qbits.secureddata.support.SecuredDataMetadata;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Public classification API shared by QBits, with runtime rows overriding code metadata.
 *******************************************************************************/
public final class SecuredDataClassifications
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataClassifications()
   {
   }



   /*******************************************************************************
    ** Field row, table row, code field, code table, then unclassified.
    *******************************************************************************/
   public static DataClassification effective(QTableMetaData table, String fieldName)
   {
      QRecord row = row(table, fieldName);
      if(row != null)
      {
         return (DataClassification.valueOf(row.getValueString("classification")));
      }
      ////////////////////////////////////////////////////////////////////
      // getFields, not getField: a virtual field is not in the map and  //
      // getField throws, while it still takes the table classification //
      ////////////////////////////////////////////////////////////////////
      QFieldMetaData field = table.getFields() == null || fieldName == null ? null : table.getFields().get(fieldName);
      DataClassification classification = field == null ? null : SecuredDataMetadata.classification(table, field);
      return (classification == null ? SecuredDataMetadata.classification(table, null) : classification);
   }



   /*******************************************************************************
    ** Table-level override or code-level table classification.
    *******************************************************************************/
   public static DataClassification effective(QTableMetaData table)
   {
      QRecord row = row(table, null);
      return (row == null ? SecuredDataMetadata.classification(table, null) : DataClassification.valueOf(row.getValueString("classification")));
   }



   /*******************************************************************************
    ** Most sensitive effective field, including an empty table's classification.
    *******************************************************************************/
   public static DataClassification highest(QTableMetaData table)
   {
      return (table.getFields().isEmpty() ? effective(table) : highest(table, table.getFields().keySet()));
   }



   /*******************************************************************************
    ** Most sensitive among the requested fields only; an empty subset is null.
    *******************************************************************************/
   public static DataClassification highest(QTableMetaData table, Collection<String> fieldNames)
   {
      DataClassification highest = null;
      for(String fieldName : fieldNames)
      {
         highest = DataClassification.max(highest, effective(table, fieldName));
      }
      return (highest);
   }



   /*******************************************************************************
    ** Effective classification row also owns mask and low-cardinality overrides.
    *******************************************************************************/
   static QRecord row(QTableMetaData table, String fieldName)
   {
      SecuredDataRuntime runtime = SecuredDataRuntime.current();
      if(runtime == null)
      {
         return (null);
      }
      QRecord tableRow = null;
      for(QRecord row : runtime.classificationRows())
      {
         if(!Objects.equals(table.getName(), row.getValueString("table_name")))
         {
            continue;
         }
         String field = row.getValueString("field_name");
         if(Objects.equals(fieldName, field))
         {
            return (row);
         }
         if(field == null || field.isBlank())
         {
            tableRow = row;
         }
      }
      return (tableRow);
   }

   /*******************************************************************************
    ** Shared phase-b entropy guardrail, including runtime overrides.
    *******************************************************************************/
   public static boolean lowEntropy(QTableMetaData table, String field)
   {
      return (SecuredDataResolver.lowCardinality(table.getField(field), row(table, field)));
   }
}
