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

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.secureddata.SecuredDataClassifications;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** Shared validation and effective audit treatment; no record values are queried.
 *******************************************************************************/
public final class RetentionRules
{
   public static final Set<String> ACTIONS = Set.of("NULL_WITH_MARKER", "OVERWRITE_TEXT", "KEYED_HASH", "DELETE_RECORD", "ARCHIVE_THEN_WIPE");

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private RetentionRules()
   {
   }

   /*******************************************************************************
    ** Validated comma selection; preserve order and reject duplicates.
    *******************************************************************************/
   public static List<String> fields(QRecord rule)
   {
      String names = rule.getValueString("field_names");
      return (names == null ? List.of() : Arrays.stream(names.split(",", -1)).map(String::trim).toList());
   }

   /*******************************************************************************
    ** Fresh rules in the current transaction; edits take effect without a stale cache.
    *******************************************************************************/
   public static List<QRecord> active(String table, String field)
   {
      return (SystemWrites.query(SecuredDataTables.RETENTION_RULE, new QQueryFilter()
         .withCriteria(new QFilterCriteria("is_active", QCriteriaOperator.EQUALS, true))
         .withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, table)))
         .stream().filter(rule -> fields(rule).contains(field)).toList());
   }

   /*******************************************************************************
    ** A changed-only policy takes precedence over derivatives.
    *******************************************************************************/
   public static boolean changedOnly(String table, String field)
   {
      return (active(table, field).stream().anyMatch(rule -> "CHANGED_ONLY".equals(rule.getValueString("audit_treatment"))));
   }

   /*******************************************************************************
    ** Validate both edits and persisted policies before any execution.
    *******************************************************************************/
   public static void validate(QRecord rule)
   {
      QTableMetaData table = QContext.getQInstance().getTable(rule.getValueString("table_name"));
      if(table == null || SecuredDataTables.ALL.contains(table.getName()))
      {
         throw (new IllegalArgumentException("Select a host table for retention."));
      }
      List<String> fields = fields(rule);
      if(fields.isEmpty() || fields.size() != Set.copyOf(fields).size() || fields.stream().anyMatch(f -> table.getField(f) == null || f.equals(table.getPrimaryKeyField())))
      {
         throw (new IllegalArgumentException("Select unique, non-key fields of the selected table."));
      }
      var age = table.getField(rule.getValueString("age_field_name"));
      if(age == null || !Set.of(QFieldType.DATE, QFieldType.DATE_TIME).contains(age.getType()))
      {
         throw (new IllegalArgumentException("Age must use a date or date-time field of the selected table."));
      }
      if(rule.getValueInteger("age_days") == null || rule.getValueInteger("age_days") < 1 || rule.getValueInteger("batch_size") == null || rule.getValueInteger("batch_size") < 1)
      {
         throw (new IllegalArgumentException("Age days and batch size must be positive."));
      }
      String action = rule.getValueString("action");
      if(!ACTIONS.contains(action) || !Set.of("SHREDDABLE", "CHANGED_ONLY").contains(rule.getValueString("audit_treatment")))
      {
         throw (new IllegalArgumentException("Select a supported action and audit treatment."));
      }
      for(String name : fields)
      {
         var field = table.getField(name);
         if(Set.of("OVERWRITE_TEXT", "KEYED_HASH").contains(action) && !Set.of(QFieldType.STRING, QFieldType.TEXT).contains(field.getType()))
         {
            throw (new IllegalArgumentException("Overwrite and keyed hash require STRING or TEXT fields."));
         }
         if("KEYED_HASH".equals(action) && SecuredDataClassifications.lowEntropy(table, name))
         {
            throw (new IllegalArgumentException("Keyed hash is forbidden for low-entropy fields."));
         }
         if("KEYED_HASH".equals(action) && field.getMaxLength() != null && field.getMaxLength() < 200)
         {
            throw (new IllegalArgumentException("Keyed hash requires capacity for a 200-character token."));
         }
         if(Set.of("NULL_WITH_MARKER", "ARCHIVE_THEN_WIPE").contains(action) && field.getIsRequired())
         {
            throw (new IllegalArgumentException("Null wipe requires nullable fields."));
         }
         String overwrite = rule.getValueString("overwrite_text");
         if("OVERWRITE_TEXT".equals(action) && (overwrite == null || field.getMaxLength() != null && overwrite.length() > field.getMaxLength()))
         {
            throw (new IllegalArgumentException("Overwrite text must fit every target field."));
         }
      }
      if("ARCHIVE_THEN_WIPE".equals(action) && (rule.getValueString("archive_storage_name") == null || rule.getValueString("archive_storage_name").isBlank()))
      {
         throw (new IllegalArgumentException("Archive then wipe requires an archive storage name."));
      }
   }

   /*******************************************************************************
    ** Known backup window; unknown is explicit rather than assumed safe.
    *******************************************************************************/
   public static String backupWarning(QRecord rule)
   {
      Integer days = SecuredDataRuntime.current().config().getBackupRetentionDays();
      Integer age = rule.getValueInteger("age_days");
      return (days != null && age != null && days > age ? "Backups keep data for " + days + " days, longer than this rule's " + age
         + " days. Wiped values remain recoverable from backups until they expire." : null);
   }
}
