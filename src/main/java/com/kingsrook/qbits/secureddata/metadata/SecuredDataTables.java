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


import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.secureddata.SecuredDataQBitConfig;
import com.kingsrook.qbits.secureddata.permissions.SecuredDataPermissions;
import com.kingsrook.qbits.secureddata.support.CoreMetadataBridge;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.ChildRecordListRenderer;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.joins.JoinOn;
import com.kingsrook.qqq.backend.core.model.metadata.joins.JoinType;
import com.kingsrook.qqq.backend.core.model.metadata.joins.QJoinMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.PVSValueFormatAndFields;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSource;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSourceType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.SectionFactory;
import com.kingsrook.qqq.backend.core.model.metadata.tables.TablesPossibleValueSourceMetaDataProvider;
import com.kingsrook.qqq.backend.core.model.metadata.tables.UniqueKey;


/*******************************************************************************
 ** The five audited tables, record sections, possible values and reveal child list.
 *******************************************************************************/
public final class SecuredDataTables
{
   public static final String CLASSIFICATION = "secured_data_classification";
   public static final String POLICY = "secured_data_policy";
   public static final String REVEAL_GRANT = "secured_data_reveal_grant";
   public static final String BREAK_GLASS = "secured_data_break_glass";
   public static final String ACCESS_LOG = "secured_data_access_log";
   public static final List<String> ALL = List.of(CLASSIFICATION, POLICY, REVEAL_GRANT, BREAK_GLASS, ACCESS_LOG);
   public static final List<String> MAIN = List.of(CLASSIFICATION, POLICY, ACCESS_LOG, BREAK_GLASS);
   public static final List<String> SYSTEM_WRITTEN = List.of(REVEAL_GRANT, BREAK_GLASS, ACCESS_LOG);
   public static final String REVEALS_JOIN = "secured_data_access_log_reveals";
   public static final String REVEALS_WIDGET = "securedDataReveals";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataTables()
   {
   }



   /*******************************************************************************
    ** Main table events for the host ESB wiring, following WebhooksIntegrations.
    *******************************************************************************/
   public static List<String> esbTableNames()
   {
      return (MAIN);
   }



   /*******************************************************************************
    ** Complete table metadata.
    *******************************************************************************/
   public static List<QTableMetaData> tables(SecuredDataQBitConfig config)
   {
      return (List.of(classification(config), policy(config), revealGrant(config), breakGlass(config), accessLog(config)));
   }



   /*******************************************************************************
    ** Common identity, audit and administration rules.
    *******************************************************************************/
   private static QTableMetaData base(SecuredDataQBitConfig config, String name, String label)
   {
      QTableMetaData table = new QTableMetaData().withName(name).withLabel(label).withBackendName(config.getBackendName())
         .withPrimaryKeyField("id").withField(new QFieldMetaData("id", QFieldType.INTEGER).withBackendName("id").withIsEditable(false))
         .withPermissionRules(SecuredDataPermissions.rules()).withIcon(new QIcon("shield"))
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.FIELD));
      CoreMetadataBridge.classifyTable(table);
      if(ACCESS_LOG.equals(name))
      {
         table.withoutCapabilities(Capability.TABLE_UPDATE, Capability.TABLE_DELETE);
      }
      return (table);
   }



   /*******************************************************************************
    ** Every database column has an explicit snake_case name.
    *******************************************************************************/
   private static QFieldMetaData field(String name, QFieldType type)
   {
      QFieldMetaData field = new QFieldMetaData(name, type).withBackendName(name).withLabel(name.replace('_', ' '));
      // TODO(contingent): dependsOn("table_name") once the core RC has it
      return (field);
   }



   /*******************************************************************************
    ** Define Classification.
    *******************************************************************************/
   private static QTableMetaData classification(SecuredDataQBitConfig config)
   {
      QTableMetaData table = base(config, CLASSIFICATION, "Classification")
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("tables"))
         .withField(field("field_name", QFieldType.STRING).withMaxLength(255).withPossibleValueSourceName("secured_data_fields"))
         .withField(field("classification", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("secured_data_classification"))
         .withField(field("mask_style", QFieldType.STRING).withMaxLength(255).withPossibleValueSourceName("secured_data_mask_style"))
         .withField(field("low_cardinality", QFieldType.BOOLEAN))
         .withField(field("notes", QFieldType.TEXT))
         .withField(field("create_date", QFieldType.DATE_TIME))
         .withField(field("modify_date", QFieldType.DATE_TIME))
         .withField(field("modified_by", QFieldType.STRING).withMaxLength(255));
      table.withSection(SectionFactory.defaultT1("id", "table_name", "field_name", "classification"));
      table.withSection(SectionFactory.defaultT2("mask_style", "low_cardinality", "notes"));
      table.withSection(SectionFactory.defaultT3("create_date", "modify_date", "modified_by"));
      table.withUniqueKey(new UniqueKey().withFieldNames(List.of("table_name", "field_name")));
      return (table);
   }



   /*******************************************************************************
    ** Define Policy.
    *******************************************************************************/
   private static QTableMetaData policy(SecuredDataQBitConfig config)
   {
      QTableMetaData table = base(config, POLICY, "Policy")
         .withField(field("name", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("permission_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("classification", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("secured_data_classification"))
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withPossibleValueSourceName("tables"))
         .withField(field("tier", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("secured_data_tier"))
         .withField(field("reveal_minutes", QFieldType.INTEGER).withDefaultValue(5))
         .withField(field("daily_reveal_cap", QFieldType.INTEGER))
         .withField(field("reason_options", QFieldType.TEXT))
         .withField(field("allow_free_text_reason", QFieldType.BOOLEAN).withDefaultValue(true))
         .withField(field("require_free_text", QFieldType.BOOLEAN).withDefaultValue(false))
         .withField(field("client_channel", QFieldType.STRING).withMaxLength(255))
         .withField(field("exact_match_per_hour", QFieldType.INTEGER).withDefaultValue(20))
         .withField(field("miss_alert_consecutive", QFieldType.INTEGER).withDefaultValue(5))
         .withField(field("distinct_value_alert", QFieldType.INTEGER).withDefaultValue(15))
         .withField(field("min_entropy_enabled", QFieldType.BOOLEAN).withDefaultValue(true))
         .withField(field("is_active", QFieldType.BOOLEAN).withDefaultValue(true))
         .withField(field("create_date", QFieldType.DATE_TIME))
         .withField(field("modify_date", QFieldType.DATE_TIME))
         .withField(field("modified_by", QFieldType.STRING).withMaxLength(255));
      table.withSection(SectionFactory.defaultT1("id", "name", "permission_name", "classification"));
      table.withSection(SectionFactory.defaultT2("table_name", "tier", "reveal_minutes", "daily_reveal_cap", "reason_options", "allow_free_text_reason", "require_free_text", "client_channel", "exact_match_per_hour", "miss_alert_consecutive", "distinct_value_alert", "min_entropy_enabled", "is_active"));
      table.withSection(SectionFactory.defaultT3("create_date", "modify_date", "modified_by"));
      return (table);
   }



   /*******************************************************************************
    ** Define Reveal.
    *******************************************************************************/
   private static QTableMetaData revealGrant(SecuredDataQBitConfig config)
   {
      QTableMetaData table = base(config, REVEAL_GRANT, "Reveal")
         .withField(field("user_id", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("user_name", QFieldType.STRING).withMaxLength(255))
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("tables"))
         .withField(field("record_id", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("field_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("secured_data_fields"))
         .withField(field("reason", QFieldType.STRING).withMaxLength(500))
         .withField(field("reason_text", QFieldType.TEXT))
         .withField(field("granted_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("expires_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("access_log_id", QFieldType.INTEGER).withIsRequired(true));
      table.withSection(SectionFactory.defaultT1("id", "user_id", "user_name", "table_name"));
      table.withSection(SectionFactory.defaultT2("record_id", "field_name", "reason", "reason_text", "access_log_id"));
      table.withSection(SectionFactory.defaultT3("granted_at", "expires_at"));
      return (table);
   }



   /*******************************************************************************
    ** Define Break-glass session.
    *******************************************************************************/
   private static QTableMetaData breakGlass(SecuredDataQBitConfig config)
   {
      QTableMetaData table = base(config, BREAK_GLASS, "Break-glass session")
         .withField(field("user_id", QFieldType.STRING).withMaxLength(255).withIsRequired(true))
         .withField(field("user_name", QFieldType.STRING).withMaxLength(255))
         .withField(field("reason", QFieldType.STRING).withMaxLength(500))
         .withField(field("reason_text", QFieldType.TEXT))
         .withField(field("classification_ceiling", QFieldType.STRING).withMaxLength(255).withDefaultValue("PHI").withPossibleValueSourceName("secured_data_classification"))
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withPossibleValueSourceName("tables"))
         .withField(field("started_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("expires_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("ended_at", QFieldType.DATE_TIME))
         .withField(field("ended_by", QFieldType.STRING).withMaxLength(255))
         .withField(field("status", QFieldType.STRING).withMaxLength(255).withDefaultValue("ACTIVE").withPossibleValueSourceName("secured_data_break_glass_status"));
      table.withSection(SectionFactory.defaultT1("id", "user_id", "user_name", "reason"));
      table.withSection(SectionFactory.defaultT2("reason_text", "classification_ceiling", "table_name", "ended_by", "status"));
      table.withSection(SectionFactory.defaultT3("started_at", "expires_at", "ended_at"));
      return (table);
   }



   /*******************************************************************************
    ** Define Access log.
    *******************************************************************************/
   private static QTableMetaData accessLog(SecuredDataQBitConfig config)
   {
      QTableMetaData table = base(config, ACCESS_LOG, "Access log")
         .withField(field("event_type", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("secured_data_event_type"))
         .withField(field("user_id", QFieldType.STRING).withMaxLength(255))
         .withField(field("user_name", QFieldType.STRING).withMaxLength(255))
         .withField(field("table_name", QFieldType.STRING).withMaxLength(255).withIsRequired(true).withPossibleValueSourceName("tables"))
         .withField(field("record_id", QFieldType.TEXT))
         .withField(field("field_name", QFieldType.TEXT))
         .withField(field("record_count", QFieldType.INTEGER))
         .withField(field("action_name", QFieldType.STRING).withMaxLength(255))
         .withField(field("reason", QFieldType.STRING).withMaxLength(500))
         .withField(field("reason_text", QFieldType.TEXT))
         .withField(field("client_channel", QFieldType.STRING).withMaxLength(255))
         .withField(field("outcome", QFieldType.STRING).withMaxLength(255).withPossibleValueSourceName("secured_data_outcome"))
         .withField(field("anomaly_flag", QFieldType.BOOLEAN).withDefaultValue(false))
         .withField(field("break_glass_id", QFieldType.INTEGER))
         .withField(field("created_at", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("search_value_fingerprints", QFieldType.TEXT));
      table.withSection(SectionFactory.defaultT1("id", "event_type", "user_id", "user_name"));
      table.withSection(SectionFactory.defaultT2("table_name", "record_id", "field_name", "record_count", "action_name", "reason", "reason_text", "client_channel", "outcome", "anomaly_flag", "break_glass_id", "search_value_fingerprints"));
      table.withSection(SectionFactory.defaultT3("created_at"));
      table.withSection(SectionFactory.customT2("reveals", new QIcon("visibility")).withLabel("Reveals").withWidgetName(REVEALS_WIDGET));
      return (table);
   }



   /*******************************************************************************
    ** Core table picker plus a dependent field picker.
    *******************************************************************************/
   public static List<QPossibleValueSource> possibleValueSources(QInstance instance)
   {
      List<QPossibleValueSource> sources = new ArrayList<>(SecuredDataEnums.sources());
      if(instance.getPossibleValueSource("tables") == null)
      {
         sources.add(TablesPossibleValueSourceMetaDataProvider.defineTablesPossibleValueSource(instance));
      }
      sources.add(new QPossibleValueSource().withName("secured_data_fields").withType(QPossibleValueSourceType.CUSTOM)
         .withIdType(QFieldType.STRING).withValueFormatAndFields(PVSValueFormatAndFields.LABEL_ONLY)
         .withCustomCodeReference(new QCodeReference(FieldsOfTablePossibleValueSource.class)));
      return (sources);
   }



   /*******************************************************************************
    ** Reveals belong to the access-log record that authorized them.
    *******************************************************************************/
   public static QJoinMetaData revealsJoin()
   {
      return (new QJoinMetaData().withName(REVEALS_JOIN).withType(JoinType.ONE_TO_MANY)
         .withLeftTable(ACCESS_LOG).withRightTable(REVEAL_GRANT).withJoinOn(new JoinOn("id", "access_log_id")));
   }



   /*******************************************************************************
    ** Read-only child list, never a navigation entry.
    *******************************************************************************/
   public static QWidgetMetaData revealsWidget()
   {
      return (ChildRecordListRenderer.widgetMetaDataBuilder(revealsJoin()).withName(REVEALS_WIDGET).withLabel("Reveals")
         .withCanAddChildRecord(false).withMaxRows(50).getWidgetMetaData().withGridColumns(12)
         .withPermissionRules(SecuredDataPermissions.rules()));
   }
}
