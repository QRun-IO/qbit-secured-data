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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.SecuredDataQBitConfig;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.permissions.CustomPermissionChecker;
import com.kingsrook.qqq.backend.core.actions.processes.BackendStep;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.AbstractActionInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLineInterface;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.processes.Status;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.MetaDataWithPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QBackendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.QScheduleMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractLoadStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractTransformStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ExtractViaQueryStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ProcessSummaryProviderInterface;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;

/*******************************************************************************
 ** Standard Review/Result action and a daily system scheduler entry point.
 *******************************************************************************/
public final class WipeProcesses
{
   public static final String WIPE = "secured_data_wipe";
   public static final String DAILY = "secured_data_wipe_daily";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private WipeProcesses()
   {
   }

   /*******************************************************************************
    ** Processes are table actions or hidden schedules, never navigation entries.
    *******************************************************************************/
   public static List<QProcessMetaData> processes(SecuredDataQBitConfig config)
   {
      Map<String, Serializable> values = new LinkedHashMap<>();
      values.put(StreamedETLWithFrontendProcess.FIELD_SOURCE_TABLE, SecuredDataTables.RETENTION_RULE);
      values.put(StreamedETLWithFrontendProcess.FIELD_DESTINATION_TABLE, SecuredDataTables.WIPE_RUN);
      values.put(StreamedETLWithFrontendProcess.FIELD_SUPPORTS_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_DO_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_PREVIEW_MESSAGE, "Eligible records will be wiped; active legal holds are preserved.");
      QPermissionRules permissions = new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION)
         .withPermissionBaseName("secured_data").withCustomPermissionChecker(new QCodeReference(Permission.class));
      QProcessMetaData wipe = StreamedETLWithFrontendProcess.defineProcessMetaData(Extract.class, Review.class, Load.class, values)
         .withName(WIPE).withLabel("Run wipe now").withTableName(SecuredDataTables.RETENTION_RULE).withMinInputRecords(1).withPermissionRules(permissions);
      QProcessMetaData daily = new QProcessMetaData().withName(DAILY).withLabel("Daily retention wipe").withIsHidden(true).withPermissionRules(permissions)
         .withStep(new QBackendStepMetaData().withName("wipe").withCode(new QCodeReference(Daily.class)));
      if(config.getSchedulerName() != null)
      {
         daily.withSchedule(new QScheduleMetaData().withSchedulerName(config.getSchedulerName()).withRepeatSeconds(config.getWipeIntervalSeconds()).withInitialDelaySeconds(30));
      }
      return (List.of(wipe, daily));
   }

   /*******************************************************************************
    ** Explicit retention permission is independent of classified-value access.
    *******************************************************************************/
   public static class Permission implements CustomPermissionChecker
   {
      @Override
      public void checkPermissionsThrowing(AbstractActionInput input, MetaDataWithPermissionRules metadata) throws QPermissionDeniedException
      {
         WipeService.checkPermission();
      }
   }

   /*******************************************************************************
    ** Select policies using the standard table-selection filter, then stream IDs.
    *******************************************************************************/
   public static class Extract extends ExtractViaQueryStep
   {
      @Override
      public Integer doCount(RunBackendStepInput input)
      {
         return (null);
      }

      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         WipeService.checkPermission();
         for(QRecord rule : SystemWrites.query(SecuredDataTables.RETENTION_RULE, getQueryFilter(input)))
         {
            new WipeService().extract(rule, packets ->
            {
               for(QRecord packet : packets)
               {
                  getRecordPipe().addRecord(packet);
               }
            });
         }
      }
   }

   /*******************************************************************************
    ** Counts per policy and hold status; no record or field values in summaries.
    *******************************************************************************/
   public static class Review extends AbstractTransformStep implements ProcessSummaryProviderInterface
   {
      private final Map<String, ProcessSummaryLine> lines = new LinkedHashMap<>();

      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         WipeService.checkPermission();
         for(QRecord packet : input.getRecords())
         {
            String id = packet.getValueString("rule_id");
            boolean held = Boolean.TRUE.equals(packet.getValueBoolean("held"));
            String label = held ? "held" : "to wipe";
            lines.computeIfAbsent(id + label, key -> line(id, held, false)).incrementCountAndAddPrimaryKey(null);
            output.getRecords().add(packet);
         }
      }

      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean result)
      {
         return (new ArrayList<>(lines.values()));
      }
   }

   /*******************************************************************************
    ** Group only the current ETL page, splitting again by each policy's batch size.
    *******************************************************************************/
   public static class Load extends AbstractLoadStep implements ProcessSummaryProviderInterface
   {
      private final Map<String, ProcessSummaryLine> lines = new LinkedHashMap<>();

      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         WipeService.checkPermission();
         Map<Serializable, List<Serializable>> rules = new LinkedHashMap<>();
         for(QRecord packet : input.getRecords())
         {
            rules.computeIfAbsent(packet.getValue("rule_id"), ignored -> new ArrayList<>()).add(packet.getValue("id"));
         }
         for(var entry : rules.entrySet())
         {
            int size = WipeService.rule(entry.getKey()).getValueInteger("batch_size");
            for(int offset = 0; offset < entry.getValue().size(); offset += size)
            {
               QRecord run = new WipeService().batch(entry.getKey(), entry.getValue().subList(offset, Math.min(offset + size, entry.getValue().size())));
               output.getRecords().add(run);
               for(boolean held : List.of(false, true))
               {
                  String id = String.valueOf(entry.getKey());
                  ProcessSummaryLine line = lines.computeIfAbsent(id + held, ignored -> line(id, held, true));
                  for(int n = 0; n < run.getValueInteger(held ? "held_count" : "wiped_count"); n++)
                  {
                     line.incrementCountAndAddPrimaryKey(null);
                  }
               }
            }
         }
      }

      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean result)
      {
         return (new ArrayList<>(lines.values()));
      }
   }

   /*******************************************************************************
    ** Scheduler identity must already be system; never elevate a user invocation.
    *******************************************************************************/
   public static class Daily implements BackendStep
   {
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         if(!(QContext.getQSession() instanceof QSystemUserSession))
         {
            throw (new QPermissionDeniedException("Daily retention requires the system session."));
         }
         for(QRecord rule : SystemWrites.query(SecuredDataTables.RETENTION_RULE, new QQueryFilter().withCriteria(new QFilterCriteria("is_active", QCriteriaOperator.EQUALS, true))))
         {
            List<QException> errors = new ArrayList<>();
            new WipeService().extract(rule, packets ->
            {
               try
               {
                  output.getRecords().add(new WipeService().batch(rule.getValue("id"), packets.stream().map(row -> row.getValue("id")).toList()));
               }
               catch(QException e)
               {
                  errors.add(e);
               }
            });
            if(!errors.isEmpty())
            {
               throw (new QException("Daily retention had rolled-back batches."));
            }
         }
      }
   }

   /*******************************************************************************
    ** Standard future/past summary text.
    *******************************************************************************/
   private static ProcessSummaryLine line(String id, boolean held, boolean result)
   {
      ProcessSummaryLine line = new ProcessSummaryLine(held ? Status.INFO : Status.OK, 0, null);
      String future = "eligible records for rule " + id + (held ? " held by legal hold" : " to wipe");
      String past = "records for rule " + id + (held ? " held by legal hold" : " wiped");
      line.setSingularFutureMessage(future);
      line.setPluralFutureMessage(future);
      line.setSingularPastMessage(past);
      line.setPluralPastMessage(past);
      return (line);
   }
}
