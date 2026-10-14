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

import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.permissions.SecuredDataPermissions;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.ChildRecordListRenderer;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.WidgetType;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.joins.JoinOn;
import com.kingsrook.qqq.backend.core.model.metadata.joins.JoinType;
import com.kingsrook.qqq.backend.core.model.metadata.joins.QJoinMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** Value-free policy panels and host-opt-in record marker lists.
 *******************************************************************************/
public final class RetentionWidgets
{
   public static final String BACKUPS = "securedDataBackups";
   public static final String MARKERS = "securedDataRuleMarkers";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private RetentionWidgets()
   {
   }

   /*******************************************************************************
    ** Markers belong to retention rules and are never editable in child lists.
    *******************************************************************************/
   public static QJoinMetaData markersJoin()
   {
      return (new QJoinMetaData().withName("secured_data_rule_markers").withType(JoinType.ONE_TO_MANY)
         .withLeftTable(SecuredDataTables.RETENTION_RULE).withRightTable(SecuredDataTables.WIPE_MARKER).withJoinOn(new JoinOn("id", "rule_id")));
   }

   /*******************************************************************************
    ** Standard rule child list.
    *******************************************************************************/
   public static QWidgetMetaData markers()
   {
      return (ChildRecordListRenderer.widgetMetaDataBuilder(markersJoin()).withName(MARKERS).withLabel("Wipe markers")
         .withCanAddChildRecord(false).withMaxRows(50).getWidgetMetaData().withPermissionRules(SecuredDataPermissions.rules()));
   }

   /*******************************************************************************
    ** Known physical backup retention and its residual recovery risk.
    *******************************************************************************/
   public static QWidgetMetaData backups()
   {
      return (new QWidgetMetaData().withName(BACKUPS).withLabel("Backups").withType(WidgetType.HTML.getType()).withGridColumns(12)
         .withCodeReference(new QCodeReference(Backups.class)).withPermissionRules(SecuredDataPermissions.rules()));
   }

   /*******************************************************************************
    ** Host adds this metadata and a section referencing its name on its own table.
    ** The immutable widget configuration selects the table, not request parameters.
    *******************************************************************************/
   public static QWidgetMetaData wipedFields(QTableMetaData table)
   {
      return (new QWidgetMetaData().withName("securedDataWipedFields_" + table.getName()).withLabel("Wiped fields").withType(WidgetType.HTML.getType())
         .withGridColumns(12).withDefaultValue("hostTable", table.getName()).withCodeReference(new QCodeReference(WipedFields.class)));
   }

   /*******************************************************************************
    ** Render the rule through normal user permissions.
    *******************************************************************************/
   public static class Backups extends AbstractWidgetRenderer
   {
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         List<QRecord> rules = new QueryAction().execute(new QueryInput(SecuredDataTables.RETENTION_RULE)
            .withFilter(new QQueryFilter().withCriteria(new QFilterCriteria("id", QCriteriaOperator.EQUALS, input.getQueryParams().get("id"))))).getRecords();
         StringBuilder html = new StringBuilder("<div>");
         Integer days = SecuredDataRuntime.current().config().getBackupRetentionDays();
         html.append("<p>Physical backup retention: ").append(days == null ? "unknown" : days + " days").append(".</p>");
         for(QRecord rule : rules)
         {
            String warning = RetentionRules.backupWarning(rule);
            if(warning != null)
            {
               html.append("<p role='alert'>").append(escape(warning)).append("</p>");
            }
         }
         html.append("<p>CNPG physical backups and WAL cannot exclude audit keys. A backup and the KEK can recover wiped data until that backup expires.</p></div>");
         return (new RenderWidgetOutput(new RawHTML(null, html.toString())));
      }
   }

   /*******************************************************************************
    ** Authorize the host record with an ID-only query before looking up markers.
    *******************************************************************************/
   public static class WipedFields extends AbstractWidgetRenderer
   {
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         String tableName = (String) input.getWidgetMetaData().getDefaultValues().get("hostTable");
         var table = com.kingsrook.qqq.backend.core.context.QContext.getQInstance().getTable(tableName);
         String id = input.getQueryParams().get("id");
         List<QRecord> visible = new QueryAction().execute(new QueryInput(tableName).withFieldNamesToInclude(Set.of(table.getPrimaryKeyField()))
            .withFilter(new QQueryFilter().withCriteria(new QFilterCriteria(table.getPrimaryKeyField(), QCriteriaOperator.EQUALS, id)))).getRecords();
         StringBuilder html = new StringBuilder("<ul aria-label='Wiped fields'>");
         if(!visible.isEmpty())
         {
            for(QRecord marker : SystemWrites.query(SecuredDataTables.WIPE_MARKER, new QQueryFilter()
               .withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, tableName))
               .withCriteria(new QFilterCriteria("record_id", QCriteriaOperator.EQUALS, id))))
            {
               List<QRecord> rules = SystemWrites.query(SecuredDataTables.RETENTION_RULE, new QQueryFilter().withCriteria(new QFilterCriteria("id", QCriteriaOperator.EQUALS, marker.getValue("rule_id"))));
               String age = rules.isEmpty() ? "unknown" : rules.getFirst().getValueString("age_days");
               html.append("<li>").append(escape(marker.getValueString("field_name"))).append(": Wiped per policy (").append(escape(age)).append(" days)</li>");
            }
         }
         return (new RenderWidgetOutput(new RawHTML(null, html.append("</ul>").toString())));
      }
   }

   /*******************************************************************************
    ** Escape user-managed names and all text before HTML rendering.
    *******************************************************************************/
   private static String escape(String text)
   {
      return (text == null ? "" : text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"));
   }
}
