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

package com.kingsrook.qbits.secureddata.app;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qqq.backend.core.actions.tables.AggregateAction;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.Aggregate;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.AggregateInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.AggregateOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.GroupBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.QFilterOrderByAggregate;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.QFilterOrderByGroupBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;

/*******************************************************************************
 ** Real home data, read as the viewer. Counts and rankings aggregate in the backend.
 *******************************************************************************/
public class SecuredDataHomeData
{
   private final Map<String, Long> kpis = new LinkedHashMap<>();
   private final List<Section> sections = new ArrayList<>();

   /*******************************************************************************
    ** A full-width table and the exact filter behind its View all link.
    *******************************************************************************/
   public record Section(String title, String empty, List<String> fields, List<String> labels, List<QRecord> rows, String href)
   {
   }

   /*******************************************************************************
    ** Six KPIs and six lists; no samples or hidden truncation of aggregate counts.
    *******************************************************************************/
   public static SecuredDataHomeData load() throws QException
   {
      SecuredDataHomeData data = new SecuredDataHomeData();
      Instant now = SecuredDataRuntime.current().config().getClock().instant();
      Instant week = now.minus(7, ChronoUnit.DAYS);
      Instant month = now.minus(30, ChronoUnit.DAYS);
      data.kpis.put("Reveals today", count(SecuredDataTables.ACCESS_LOG, events(now.truncatedTo(ChronoUnit.DAYS), now, "REVEAL")));
      data.kpis.put("Active reveal grants", count(SecuredDataTables.REVEAL_GRANT, new QQueryFilter()
         .withCriteria(new QFilterCriteria("expires_at", QCriteriaOperator.GREATER_THAN, now))));
      data.kpis.put("Active break-glass sessions", count(SecuredDataTables.BREAK_GLASS, new QQueryFilter()
         .withCriteria(new QFilterCriteria("status", QCriteriaOperator.EQUALS, "ACTIVE"))
         .withCriteria(new QFilterCriteria("expires_at", QCriteriaOperator.GREATER_THAN, now))));
      QQueryFilter anomalies = window(week, now).withCriteria(new QFilterCriteria("anomaly_flag", QCriteriaOperator.EQUALS, true));
      data.kpis.put("Anomaly flags (7 days)", count(SecuredDataTables.ACCESS_LOG, anomalies));
      QQueryFilter denied = window(week, now).withSubFilter(new QQueryFilter().withBooleanOperator(QQueryFilter.BooleanOperator.OR)
         .withCriteria(new QFilterCriteria("event_type", QCriteriaOperator.EQUALS, "FILTER_DENIED"))
         .withSubFilter(new QQueryFilter().withCriteria(new QFilterCriteria("event_type", QCriteriaOperator.EQUALS, "EXACT_MATCH_FILTER"))
            .withCriteria(new QFilterCriteria("outcome", QCriteriaOperator.EQUALS, "REFUSED"))));
      data.kpis.put("Denied filters (7 days)", count(SecuredDataTables.ACCESS_LOG, denied));
      data.kpis.put("Access-log queue drops", SecuredDataRuntime.current().logger().getDroppedCount());
      data.recent("Recent reveals", "No reveals yet", events(null, now, "REVEAL"),
         List.of("user_name", "table_name", "record_id", "field_name", "reason", "created_at", "client_channel"),
         List.of("User", "Table", "Record", "Field", "Reason", "When", "Channel"));
      data.top("Top revealers (30 days)", "No reveals in the last 30 days", "user_id", "User", events(month, now, "REVEAL"));
      data.top("Top reasons (30 days)", "No reveal reasons in the last 30 days", "reason", "Reason", events(month, now, "REVEAL"));
      data.recent("Break-glass events", "No break-glass events yet", events(null, now, "BREAK_GLASS_START", "BREAK_GLASS_END", "BREAK_GLASS_EXPIRED"),
         List.of("user_name", "event_type", "reason", "created_at"), List.of("User", "Event", "Reason", "When"));
      data.recent("Policy and classification changes", "No policy or classification changes yet", events(null, now, "POLICY_CHANGE", "CLASSIFICATION_CHANGE"),
         List.of("user_name", "table_name", "record_id", "action_name", "created_at"), List.of("User", "Table", "Record", "Action", "When"));
      data.recent("Anomaly flags", "No anomaly flags in the last 7 days", anomalies,
         List.of("user_name", "event_type", "table_name", "field_name", "created_at"), List.of("User", "Event", "Table", "Field", "When"));
      for(QRecord rule : new QueryAction().execute(new QueryInput(SecuredDataTables.RETENTION_RULE)).getRecords())
      {
         String warning = com.kingsrook.qbits.secureddata.retention.RetentionRules.backupWarning(rule);
         if(warning != null)
         {
            data.backupWarnings.add(rule.getValueString("name") + ": " + warning);
         }
      }
      return (data);
   }

   /*******************************************************************************
    ** Scalar counts preserve viewer permissions.
    *******************************************************************************/
   private static long count(String table, QQueryFilter filter) throws QException
   {
      return (new CountAction().execute(new CountInput(table).withFilter(filter)).getCount());
   }

   /*******************************************************************************
    ** Newest ten, with deterministic id ordering for equal timestamps.
    *******************************************************************************/
   private void recent(String title, String empty, QQueryFilter filter, List<String> fields, List<String> labels) throws QException
   {
      filter.withOrderBy(new QFilterOrderBy("created_at", false)).withOrderBy(new QFilterOrderBy("id", false));
      String href = link(filter);
      List<QRecord> rows = new QueryAction().execute(new QueryInput(SecuredDataTables.ACCESS_LOG).withFilter(filter.withLimit(10))).getRecords();
      sections.add(new Section(title, empty, fields, labels, rows, href));
   }

   /*******************************************************************************
    ** Top ten complete counts, with stable alphabetical tie ordering.
    *******************************************************************************/
   private void top(String title, String empty, String field, String label, QQueryFilter filter) throws QException
   {
      String href = link(filter);
      GroupBy group = new GroupBy(QFieldType.STRING, field);
      Aggregate count = new Aggregate("id", AggregateOperator.COUNT);
      filter.withOrderBy(new QFilterOrderByAggregate(count, false)).withOrderBy(new QFilterOrderByGroupBy(group));
      var results = new AggregateAction().execute(new AggregateInput(SecuredDataTables.ACCESS_LOG).withFilter(filter)
         .withGroupBy(group).withAggregate(count).withLimit(10)).getResults();
      List<QRecord> rows = results.stream().map(result -> new QRecord().withValue(field, result.getGroupByValue(group))
         .withValue("count", result.getAggregateValue(count))).toList();
      sections.add(new Section(title, empty, List.of(field, "count"), List.of(label, "Reveals"), rows, href));
   }

   /*******************************************************************************
    ** Next's table filter wire format, URL encoded; no widget row limit in the link.
    *******************************************************************************/
   private static String link(QQueryFilter filter)
   {
      return (SecuredDataRuntime.current().config().getTablePathPrefix() + "/" + SecuredDataTables.ACCESS_LOG
         + "?filter=" + URLEncoder.encode(JsonUtils.toJson(filter), StandardCharsets.UTF_8));
   }

   /*******************************************************************************
    ** Event filter scoped to a time window.
    *******************************************************************************/
   private static QQueryFilter events(Instant from, Instant now, String... events)
   {
      return (window(from, now).withCriteria(new QFilterCriteria("event_type", QCriteriaOperator.IN, java.util.Arrays.asList(events))));
   }

   /*******************************************************************************
    ** Exclude future timestamps from all home activity windows.
    *******************************************************************************/
   private static QQueryFilter window(Instant from, Instant now)
   {
      QQueryFilter filter = new QQueryFilter().withCriteria(new QFilterCriteria("created_at", QCriteriaOperator.LESS_THAN_OR_EQUALS, now));
      if(from != null)
      {
         filter.withCriteria(new QFilterCriteria("created_at", QCriteriaOperator.GREATER_THAN_OR_EQUALS, from));
      }
      return (filter);
   }

   /*******************************************************************************
    ** KPI row.
    *******************************************************************************/
   public Map<String, Long> getKpis()
   {
      return (kpis);
   }

   /*******************************************************************************
    ** Full-width lists in display order.
    *******************************************************************************/
   public List<Section> getSections()
   {
      return (sections);
   }

   private final List<String> backupWarnings = new ArrayList<>();

   /*******************************************************************************
    ** One warning for each policy outlived by known physical backups.
    *******************************************************************************/
   public List<String> getBackupWarnings()
   {
      return (backupWarnings);
   }
}
