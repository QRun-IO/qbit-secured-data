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

package com.kingsrook.qbits.secureddata.processes;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.SecuredDataQBitConfig;
import com.kingsrook.qbits.secureddata.breakglass.BreakGlassService;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.actions.processes.BackendStep;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLineInterface;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.processes.Status;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QBackendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QComponentType;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QFrontendComponentMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QFrontendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.QScheduleMetaData;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractLoadStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractTransformStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ExtractViaQueryStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ProcessSummaryProviderInterface;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;

/*******************************************************************************
 ** Table/record actions and the expiry schedule. Never added to navigation.
 *******************************************************************************/
public final class BreakGlassProcesses
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private BreakGlassProcesses()
   {
   }

   /*******************************************************************************
    ** A start form, a streamed Review/Result end action, and a hidden scheduled job.
    *******************************************************************************/
   public static List<QProcessMetaData> processes(SecuredDataQBitConfig config)
   {
      QProcessMetaData start = new QProcessMetaData().withName(BreakGlassService.START).withLabel("Start break-glass")
         .withTableName(SecuredDataTables.BREAK_GLASS).withMinInputRecords(0).withMaxInputRecords(0)
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION))
         .withStep(new QFrontendStepMetaData().withName("input").withLabel("Start break-glass")
            .withComponent(new QFrontendComponentMetaData().withType(QComponentType.EDIT_FORM))
            .withFormField(new QFieldMetaData("reason", QFieldType.STRING).withLabel("Reason").withIsRequired(true).withMaxLength(500))
            .withFormField(new QFieldMetaData("duration_minutes", QFieldType.INTEGER).withLabel("Duration minutes").withDefaultValue(60))
            .withFormField(new QFieldMetaData("table_name", QFieldType.STRING).withLabel("Table scope").withPossibleValueSourceName("tables"))
            .withFormField(new QFieldMetaData("classification_ceiling", QFieldType.STRING).withLabel("Classification ceiling")
               .withDefaultValue("PHI").withPossibleValueSourceName("secured_data_classification")))
         .withStep(new QBackendStepMetaData().withName("start").withCode(new QCodeReference(Start.class)))
         .withStep(new QFrontendStepMetaData().withName("result").withLabel("Result")
            .withComponent(new QFrontendComponentMetaData().withType(QComponentType.VIEW_FORM))
            .withViewField(new QFieldMetaData("message", QFieldType.STRING)));
      Map<String, Serializable> values = new HashMap<>();
      values.put(StreamedETLWithFrontendProcess.FIELD_SOURCE_TABLE, SecuredDataTables.BREAK_GLASS);
      values.put(StreamedETLWithFrontendProcess.FIELD_DESTINATION_TABLE, SecuredDataTables.BREAK_GLASS);
      values.put(StreamedETLWithFrontendProcess.FIELD_SUPPORTS_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_DO_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_PREVIEW_MESSAGE, "The selected break-glass sessions will be ended.");
      QProcessMetaData end = StreamedETLWithFrontendProcess.defineProcessMetaData(EndExtract.class, EndReview.class, EndLoad.class, values)
         .withName(BreakGlassService.END).withLabel("End break-glass").withTableName(SecuredDataTables.BREAK_GLASS).withMinInputRecords(1)
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.NOT_PROTECTED));
      QProcessMetaData expire = new QProcessMetaData().withName(BreakGlassService.EXPIRE).withLabel("Expire break-glass sessions").withIsHidden(true)
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION))
         .withStep(new QBackendStepMetaData().withName("expire").withCode(new QCodeReference(Expire.class)));
      if(config.getSchedulerName() != null)
      {
         expire.withSchedule(new QScheduleMetaData().withSchedulerName(config.getSchedulerName()).withRepeatSeconds(60).withInitialDelaySeconds(30));
      }
      return (List.of(start, end, expire));
   }

   /*******************************************************************************
    ** Start after the form is submitted.
    *******************************************************************************/
   public static class Start implements BackendStep
   {
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         String ceiling = input.getValueString("classification_ceiling");
         DataClassification classification;
         try
         {
            classification = ceiling == null ? null : DataClassification.valueOf(ceiling);
         }
         catch(IllegalArgumentException e)
         {
            throw (new com.kingsrook.qqq.backend.core.exceptions.QBadRequestException("Unknown classification ceiling."));
         }
         new BreakGlassService().start(input.getValueString("reason"), input.getValueInteger("duration_minutes"), input.getValueString("table_name"), classification);
         output.addValue("message", "Break-glass access is active.");
      }
   }

   /*******************************************************************************
    ** Extract with system visibility; ownership is checked before any row enters the pipe.
    *******************************************************************************/
   public static class EndExtract extends ExtractViaQueryStep
   {
      @Override
      public Integer doCount(RunBackendStepInput input)
      {
         return (null);
      }

      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         for(QRecord row : SystemWrites.query(SecuredDataTables.BREAK_GLASS, getQueryFilter(input)))
         {
            new BreakGlassService().checkOwner(row);
            getRecordPipe().addRecord(row);
         }
      }
   }

   /*******************************************************************************
    ** Review validates ownership and reports the change in future and past tense.
    *******************************************************************************/
   public static class EndReview extends AbstractTransformStep implements ProcessSummaryProviderInterface
   {
      private final ProcessSummaryLine line = summary();

      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         for(QRecord row : input.getRecords())
         {
            new BreakGlassService().checkOwner(row);
            if("ACTIVE".equals(row.getValueString("status")))
            {
               line.incrementCountAndAddPrimaryKey(row.getValue("id"));
               output.getRecords().add(row);
            }
         }
      }

      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         ArrayList<ProcessSummaryLineInterface> lines = new ArrayList<>();
         line.addSelfToListIfAnyCount(lines);
         return (lines);
      }
   }

   /*******************************************************************************
    ** Apply the reviewed operation, rechecking persisted ownership at execution time.
    *******************************************************************************/
   public static class EndLoad extends AbstractLoadStep implements ProcessSummaryProviderInterface
   {
      private final ProcessSummaryLine line = summary();

      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         for(QRecord row : input.getRecords())
         {
            output.getRecords().add(new BreakGlassService().end(row.getValue("id")));
            line.incrementCountAndAddPrimaryKey(row.getValue("id"));
         }
      }

      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         ArrayList<ProcessSummaryLineInterface> lines = new ArrayList<>();
         line.addSelfToListIfAnyCount(lines);
         return (lines);
      }
   }

   /*******************************************************************************
    ** Standard ETL summary wording.
    *******************************************************************************/
   private static ProcessSummaryLine summary()
   {
      ProcessSummaryLine line = new ProcessSummaryLine(Status.OK, 0, null);
      line.setSingularFutureMessage("session will be ended");
      line.setPluralFutureMessage("sessions will be ended");
      line.setSingularPastMessage("session was ended");
      line.setPluralPastMessage("sessions were ended");
      return (line);
   }

   /*******************************************************************************
    ** Expiry job; system context and writes are established by the service.
    *******************************************************************************/
   public static class Expire implements BackendStep
   {
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         output.addValue("expired", new BreakGlassService().expire());
      }
   }
}
