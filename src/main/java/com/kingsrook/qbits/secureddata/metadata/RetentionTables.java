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

import java.util.List;
import com.kingsrook.qbits.secureddata.SecuredDataQBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.security.FieldSecurityLock;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.SectionFactory;
import com.kingsrook.qqq.backend.core.model.metadata.tables.UniqueKey;
import static com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.AUDIT_KEY;
import static com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.LEGAL_HOLD;
import static com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.RETENTION_RULE;
import static com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.WIPE_MARKER;
import static com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.WIPE_RUN;
import static com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.base;
import static com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.field;

/*******************************************************************************
 ** Retention policies, value-free history, legal holds and mutable audit keys.
 *******************************************************************************/
public final class RetentionTables
{
   public static final String KEY_LOCK = "secured_data_internal_key";

   /** A key value no session is ever given, so the lock denies every user (validator requires a non-empty override list). */
   public static final String KEY_LOCK_NEVER_GRANTED = "secured_data_never_granted";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private RetentionTables()
   {
   }

   /*******************************************************************************
    ** No backup or WORM registration is made for the key table.
    *******************************************************************************/
   public static List<QTableMetaData> tables(SecuredDataQBitConfig config)
   {
      QTableMetaData rule = base(config, RETENTION_RULE, "Retention rules")
         .withField(field("name", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("tables"))
         .withField(field("field_names", QFieldType.TEXT).withIsRequired(true))
         .withField(field("age_field_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("secured_data_fields"))
         .withField(field("age_days", QFieldType.INTEGER).withIsRequired(true))
         .withField(field("action", QFieldType.STRING).withMaxLength(40).withDefaultValue("NULL_WITH_MARKER"))
         .withField(field("overwrite_text", QFieldType.TEXT).withDefaultValue("[wiped per policy]"))
         .withField(field("audit_treatment", QFieldType.STRING).withMaxLength(30).withDefaultValue("SHREDDABLE"))
         .withField(field("archive_storage_name", QFieldType.STRING).withMaxLength(255))
         .withField(field("batch_size", QFieldType.INTEGER).withDefaultValue(500))
         .withField(field("is_active", QFieldType.BOOLEAN).withDefaultValue(true))
         .withField(field("last_run_at", QFieldType.DATE_TIME).withIsEditable(false))
         .withField(field("last_run_count", QFieldType.INTEGER).withIsEditable(false))
         .withField(field("create_date", QFieldType.DATE_TIME))
         .withField(field("modify_date", QFieldType.DATE_TIME))
         .withField(field("modified_by", QFieldType.STRING).withMaxLength(255));
      rule.withSection(SectionFactory.defaultT1("id", "name", "table_name", "field_names"));
      rule.withSection(SectionFactory.defaultT2("age_field_name", "age_days", "action", "overwrite_text", "audit_treatment", "archive_storage_name", "batch_size", "is_active"));
      rule.withSection(SectionFactory.defaultT3("last_run_at", "last_run_count", "create_date", "modify_date", "modified_by"));
      rule.withSection(SectionFactory.customT2("backups", new com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon("backup"))
         .withLabel("Backups").withWidgetName(com.kingsrook.qbits.secureddata.retention.RetentionWidgets.BACKUPS));
      rule.withSection(SectionFactory.customT2("markers", new com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon("delete"))
         .withLabel("Wipe markers").withWidgetName(com.kingsrook.qbits.secureddata.retention.RetentionWidgets.MARKERS));
      QTableMetaData marker = base(config, WIPE_MARKER, "Wipe marker")
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("record_id", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("field_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("rule_id", QFieldType.INTEGER).withIsRequired(true))
         .withField(field("action", QFieldType.STRING).withMaxLength(40).withIsRequired(true))
         .withField(field("wiped_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("run_id", QFieldType.INTEGER).withIsRequired(true))
         .withUniqueKey(new UniqueKey().withFieldNames(List.of("table_name", "record_id", "field_name")));
      marker.withSection(SectionFactory.defaultT1("id", "table_name", "record_id", "field_name", "rule_id", "action", "wiped_at", "run_id"));
      QTableMetaData hold = base(config, LEGAL_HOLD, "Legal hold")
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("tables"))
         .withField(field("record_id", QFieldType.STRING).withMaxLength(255))
         .withField(field("reason", QFieldType.TEXT).withIsRequired(true))
         .withField(field("placed_by", QFieldType.STRING).withMaxLength(255))
         .withField(field("placed_at", QFieldType.DATE_TIME))
         .withField(field("released_by", QFieldType.STRING).withMaxLength(255))
         .withField(field("released_at", QFieldType.DATE_TIME))
         .withField(field("status", QFieldType.STRING).withMaxLength(20).withDefaultValue("ACTIVE"));
      hold.withSection(SectionFactory.defaultT1("id", "table_name", "record_id", "reason", "status"));
      hold.withSection(SectionFactory.defaultT3("placed_by", "placed_at", "released_by", "released_at"));
      QTableMetaData run = base(config, WIPE_RUN, "Wipe run")
         .withField(field("rule_id", QFieldType.INTEGER).withIsRequired(true))
         .withField(field("started_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("finished_at", QFieldType.DATE_TIME))
         .withField(field("status", QFieldType.STRING).withMaxLength(30))
         .withField(field("eligible_count", QFieldType.INTEGER))
         .withField(field("held_count", QFieldType.INTEGER))
         .withField(field("wiped_count", QFieldType.INTEGER))
         .withField(field("error_count", QFieldType.INTEGER))
         .withField(field("record_ids", QFieldType.STRING).withMaxLength(4000))
         .withField(field("message", QFieldType.STRING).withMaxLength(500));
      run.withSection(SectionFactory.defaultT1("id", "rule_id", "status", "eligible_count", "held_count", "wiped_count", "error_count"));
      run.withSection(SectionFactory.defaultT3("started_at", "finished_at", "record_ids", "message"));
      QTableMetaData key = base(config, AUDIT_KEY, "Audit key")
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.NONE))
         .withoutCapabilities(Capability.TABLE_EXPORT)
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("record_id", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("field_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("wrapped_key", QFieldType.TEXT).withIsRequired(true).withIsSensitive(true).withIsHidden(true)
            .withFieldSecurityLock(new FieldSecurityLock().withSecurityKeyType(KEY_LOCK).withDefaultBehavior(FieldSecurityLock.Behavior.DENY).withOverrideValues(List.of(KEY_LOCK_NEVER_GRANTED))))
         .withField(field("created_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withUniqueKey(new UniqueKey().withFieldNames(List.of("table_name", "record_id", "field_name")));
      key.withSection(SectionFactory.defaultT1("id", "table_name", "record_id", "field_name", "created_at"));
      return (List.of(rule, marker, hold, run, key));
   }
}
