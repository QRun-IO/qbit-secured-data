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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.tables.AggregateAction;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.QAlerts;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.Aggregate;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.AggregateInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.AggregateOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.aggregate.GroupBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;

/*******************************************************************************
 ** System-only access-log counters. No protected values or unbounded row reads.
 *******************************************************************************/
public class SecuredDataAnomalies
{
   private final SecuredDataQBitConfig config;
   private final Map<String, Double> medians = new LinkedHashMap<>();
   private Instant medianDay;

   /*******************************************************************************
    ** Instance-scoped bounded daily cache.
    *******************************************************************************/
   public SecuredDataAnomalies(SecuredDataQBitConfig config)
   {
      this.config = config;
   }

   /*******************************************************************************
    ** Evaluate before insertion, including this row exactly once.
    *******************************************************************************/
   public synchronized boolean evaluate(QRecord row) throws QException
   {
      String event = row.getValueString("event_type");
      if("BREAK_GLASS_START".equals(event) || ("REVEAL_DENIED".equals(event) && "CAPPED".equals(row.getValueString("outcome"))))
      {
         return (true);
      }
      Instant now = row.getValueInstant("created_at");
      if(!List.of("REVEAL", "EXACT_MATCH_FILTER").contains(event) || now == null)
      {
         return (false);
      }
      String user = row.getValueString("user_id");
      QQueryFilter hour = filter(user, event, now.minus(1, ChronoUnit.HOURS), now, QCriteriaOperator.LESS_THAN_OR_EQUALS);
      hour.getCriteria().stream().filter(criteria -> "created_at".equals(criteria.getFieldName())
         && criteria.getOperator() == QCriteriaOperator.GREATER_THAN_OR_EQUALS).forEach(criteria -> criteria.setOperator(QCriteriaOperator.GREATER_THAN));
      if("EXACT_MATCH_FILTER".equals(event))
      {
         hour.withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, row.getValueString("table_name")))
            .withCriteria(new QFilterCriteria("field_name", QCriteriaOperator.EQUALS, row.getValueString("field_name")));
         return (count(hour) >= config.getAnomalyExactMatchesPerHour());
      }
      Instant day = now.truncatedTo(ChronoUnit.DAYS);
      int today = count(filter(user, event, day, now, QCriteriaOperator.LESS_THAN_OR_EQUALS)) + 1;
      if(today >= config.getAnomalyMinimumDailyReveals() && today > config.getAnomalyDailyMedianMultiplier() * median(user, day))
      {
         return (true);
      }
      GroupBy table = new GroupBy(QFieldType.STRING, "table_name");
      GroupBy record = new GroupBy(QFieldType.STRING, "record_id");
      var groups = SystemWrites.call(() -> new AggregateAction().execute(new AggregateInput(SecuredDataTables.ACCESS_LOG)
         .withFilter(hour).withGroupBy(table).withGroupBy(record).withAggregate(new Aggregate("id", AggregateOperator.COUNT))
         .withLimit(config.getAnomalyDistinctRecordsPerHour() + 1)).getResults());
      long distinct = groups.size();
      boolean alreadySeen = groups.stream().anyMatch(group -> java.util.Objects.equals(group.getGroupByValue(table), row.getValue("table_name"))
         && java.util.Objects.equals(group.getGroupByValue(record), row.getValue("record_id")));
      return (distinct + (alreadySeen ? 0 : 1) > config.getAnomalyDistinctRecordsPerHour());
   }

   /*******************************************************************************
    ** Previous thirty complete UTC days, including zeros; even median averages middle days.
    ** Thirty scalar counts once per user/day; at most 2048 cached users.
    *******************************************************************************/
   private double median(String user, Instant day) throws QException
   {
      if(!day.equals(medianDay))
      {
         medians.clear();
         medianDay = day;
      }
      if(!medians.containsKey(user))
      {
         int[] counts = new int[30];
         for(int i = 0; i < counts.length; i++)
         {
            counts[i] = count(filter(user, "REVEAL", day.minus(i + 1, ChronoUnit.DAYS), day.minus(i, ChronoUnit.DAYS), QCriteriaOperator.LESS_THAN));
         }
         Arrays.sort(counts);
         if(medians.size() >= 2048)
         {
            medians.remove(medians.keySet().iterator().next());
         }
         medians.put(user, (counts[14] + (double) counts[15]) / 2);
      }
      return (medians.get(user));
   }

   /*******************************************************************************
    ** Scalar database count, always as system.
    *******************************************************************************/
   private static int count(QQueryFilter filter) throws QException
   {
      return (SystemWrites.call(() -> new CountAction().execute(new CountInput(SecuredDataTables.ACCESS_LOG).withFilter(filter)).getCount()));
   }

   /*******************************************************************************
    ** Bounded time window and user, compatible with indexed access-log lookups.
    *******************************************************************************/
   private static QQueryFilter filter(String user, String event, Instant from, Instant until, QCriteriaOperator endOperator)
   {
      return (new QQueryFilter().withCriteria(new QFilterCriteria("user_id", QCriteriaOperator.EQUALS, user))
         .withCriteria(new QFilterCriteria("event_type", QCriteriaOperator.EQUALS, event))
         .withCriteria(new QFilterCriteria("created_at", QCriteriaOperator.GREATER_THAN_OR_EQUALS, from))
         .withCriteria(new QFilterCriteria("created_at", endOperator, until)));
   }

   /*******************************************************************************
    ** Optional SPI: flags remain useful without a sink. Deduplication belongs to the sink.
    *******************************************************************************/
   public static void raise(QRecord row)
   {
      QAlerts.raise(new AlertSignal("secured_data.anomaly")
         .withDedupKey("secured_data.anomaly:" + row.getValueString("user_id") + ":" + row.getValueInstant("created_at").toString().substring(0, 10))
         .withOccurredAt(row.getValueInstant("created_at")).withTitle("Unusual secured-data access")
         .withSummary("Review the flagged secured-data access-log row."));
   }
}
