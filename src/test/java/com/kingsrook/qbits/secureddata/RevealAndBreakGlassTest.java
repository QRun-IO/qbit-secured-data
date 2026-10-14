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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.breakglass.BreakGlassService;
import com.kingsrook.qbits.secureddata.metadata.FieldsOfTablePossibleValueSource;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.processes.BreakGlassProcesses;
import com.kingsrook.qbits.secureddata.reveal.RevealCappedException;
import com.kingsrook.qbits.secureddata.reveal.RevealService;
import com.kingsrook.qbits.secureddata.standin.DataClassification;
import com.kingsrook.qbits.secureddata.standin.FieldAccessTier;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.alerts.AlertResolution;
import com.kingsrook.qqq.backend.core.alerts.AlertSeverity;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.AlertSinkInterface;
import com.kingsrook.qqq.backend.core.alerts.AlertsInstanceMetaData;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QBadRequestException;
import com.kingsrook.qqq.backend.core.exceptions.QNotFoundException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.values.SearchPossibleValueSourceInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.*;
import static org.assertj.core.api.Assertions.*;

class RevealAndBreakGlassTest
{
   RevealService reveals = new RevealService();
   BreakGlassService breaks = new BreakGlassService();
   Serializable pk;
   QRecord policy;

   @BeforeEach
   void init() throws Exception
   {
      var instance = setup();
      policy = insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE")
         .withValue("reason_options", "Support\nInvestigation").withValue("daily_reveal_cap", 2).withValue("allow_free_text_reason", false));
      pk = insert("person", new QRecord().withValue("email", "secret@example.invalid").withValue("ssn", "123456789")).getValue("id");
      Sink.signals.clear(); Sink.resolutions.clear();
      AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(Sink.class));
   }

   @AfterEach
   void cleanup() { close(); }

   @Test
   void revealValueAuditLinkCacheAndExactExpiry() throws Exception
   {
      var resolver = SecuredDataRuntime.current().resolver();
      assertThat(resolver.isRevealActive("person", "email", pk)).isFalse();
      var result = reveals.reveal("person", pk, "email", "Support", null);
      assertThat(result.value()).isEqualTo("secret@example.invalid");
      assertThat(result.displayValue()).isEqualTo("secret@example.invalid");
      assertThat(result.expiresAt()).isEqualTo(NOW.plusSeconds(300));
      assertThat(resolver.isRevealActive("person", "email", pk)).isTrue();
      assertThat(resolver.isRevealActive("person", "ssn", pk)).isFalse();
      assertThat(resolver.isRevealActive("person", "email", 999)).isFalse();
      QRecord grant = SystemWrites.query(SecuredDataTables.REVEAL_GRANT, new QQueryFilter()).getFirst();
      QRecord log = logs().stream().filter(r -> "REVEAL".equals(r.getValueString("event_type"))).findFirst().orElseThrow();
      assertThat(grant.getValue("access_log_id")).isEqualTo(log.getValue("id"));
      assertThat(log.getValueString("reason")).isEqualTo("Support");
      QContext.setQSession(user("u2", "cs_admin"));
      assertThat(resolver.isRevealActive("person", "email", pk)).isFalse();
      QContext.setQSession(user("u1", "cs_admin"));
      assertThat(resolver.isRevealActive("person", "email", pk)).isTrue();
      CLOCK.now = NOW.plusSeconds(300);
      assertThat(resolver.isRevealActive("person", "email", pk)).isFalse();
   }

   @Test
   void optionsSelectOneMostPermissiveGrantingPolicy() throws Exception
   {
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE").withValue("daily_reveal_cap", 10)
         .withValue("reveal_minutes", 15).withValue("reason_options", "Other policy").withValue("require_free_text", true));
      var options = reveals.options("person", "email");
      assertThat(options.remainingDailyAllowance()).isEqualTo(10);
      assertThat(options.revealMinutes()).isEqualTo(15);
      assertThat(options.reasonOptions()).containsExactly("Other policy");
      assertThat(options.requireFreeText()).isTrue();
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE").withValue("client_channel", "web").withValue("reveal_minutes", 60));
      QContext.setQSession(channelUser("web", "cs_admin"));
      assertThat(reveals.options("person", "email").revealMinutes()).isEqualTo(15);
   }

   @Test
   void wrongTierAndReadPermissionAreRefused() throws Exception
   {
      assertThatThrownBy(() -> reveals.reveal("person", pk, "ssn", "Support", null)).isInstanceOf(QPermissionDeniedException.class);
      QContext.setQSession(new QSession().withUser(user("u1").getUser()).withPermissions(List.of("cs_admin")));
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", "Support", null)).isInstanceOf(QPermissionDeniedException.class);
      assertThat(SystemWrites.query(SecuredDataTables.REVEAL_GRANT, new QQueryFilter())).isEmpty();
   }

   @Test
   void missingRecordAndFieldAreNotFound() throws Exception
   {
      assertThatThrownBy(() -> reveals.reveal("person", 999, "email", "Support", null)).isInstanceOf(QNotFoundException.class);
      assertThatThrownBy(() -> reveals.options("person", "bogus")).isInstanceOf(QNotFoundException.class);
      assertThatThrownBy(() -> reveals.reveal("person", null, "email", "Support", null)).isInstanceOf(QBadRequestException.class);
   }

   @Test
   void invalidReasonsAndLengthAreRejected() throws Exception
   {
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", "Bogus", null)).isInstanceOf(QBadRequestException.class);
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", "Support", "x".repeat(501))).isInstanceOf(QBadRequestException.class);
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", "x".repeat(501), null)).isInstanceOf(QBadRequestException.class);
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", null, null)).isInstanceOf(QBadRequestException.class);
   }

   @Test
   void freeTextRequiredAndFiveHundredCharactersAccepted() throws Exception
   {
      update(SecuredDataTables.POLICY, new QRecord().withValue("id", policy.getValue("id")).withValue("allow_free_text_reason", true).withValue("require_free_text", true));
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", "Support", null)).isInstanceOf(QBadRequestException.class);
      assertThat(reveals.reveal("person", pk, "email", null, "x".repeat(500)).value()).isEqualTo("secret@example.invalid");
   }

   @Test
   void dailyCapAcrossTablesAlertsAndResetsAtUtcMidnight() throws Exception
   {
      reveals.reveal("person", pk, "email", "Support", null);
      QContext.getQInstance().addTable(person("memory").withName("customer"));
      QContext.setQSession(user("u1", "cs_admin", "customer.read"));
      Serializable other = insert("customer", new QRecord().withValue("email", "second@example.invalid")).getValue("id");
      reveals.reveal("customer", other, "email", "Support", null);
      assertThat(reveals.options("person", "email").remainingDailyAllowance()).isZero();
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", "Support", null)).isInstanceOf(RevealCappedException.class);
      assertThat(logs()).anyMatch(r -> "CAPPED".equals(r.getValueString("outcome")) && "REVEAL_DENIED".equals(r.getValueString("event_type")));
      assertThat(Sink.signals).anyMatch(s -> "secured_data.reveal_capped".equals(s.getAlertTypeName()));
      CLOCK.now = NOW.plusSeconds(86400);
      assertThat(reveals.options("person", "email").remainingDailyAllowance()).isEqualTo(2);
   }

   @Test
   void assistantRefusedAndLogged() throws Exception
   {
      QContext.setQSession(channelUser("assistant/thread", "cs_admin"));
      assertThatThrownBy(() -> reveals.reveal("person", pk, "email", "Support", null)).isInstanceOf(QPermissionDeniedException.class);
      assertThat(logs()).anyMatch(r -> "REVEAL_DENIED".equals(r.getValueString("event_type")) && "assistant".equals(r.getValueString("client_channel")));
   }

   void enableStart() { QContext.setQSession(user("u1", "cs_admin", BreakGlassService.START + ".hasAccess")); }

   @Test
   void breakGlassStartsImmediatelyAlertsAndReportsStatus() throws Exception
   {
      enableStart();
      String fingerprint = SecuredDataRuntime.current().resolver().getAccessFingerprint();
      QRecord row = breaks.start("Investigating urgent incident", null, null, null);
      assertThat(tier("email")).isEqualTo(FieldAccessTier.FULL);
      assertThat(tier("ssn")).isEqualTo(FieldAccessTier.FULL);
      assertThat(SecuredDataRuntime.current().resolver().getAccessFingerprint()).isNotEqualTo(fingerprint);
      assertThat(Sink.signals).filteredOn(s -> "secured_data.break_glass".equals(s.getAlertTypeName())).singleElement().satisfies(s -> { assertThat(s.getSeverity()).isEqualTo(AlertSeverity.ERROR); assertThat(s.getAlertTypeName()).isEqualTo("secured_data.break_glass"); });
      var status = new StatusService().status();
      assertThat(status.breakGlass().id()).isEqualTo(row.getValue("id"));
      assertThat(status.breakGlass().expiresAt()).isEqualTo(NOW.plusSeconds(3600));
      assertThat(status.breakGlass().ceiling()).isEqualTo("PHI");
      assertThatThrownBy(() -> breaks.start("Another urgent investigation", 60, null, null)).isInstanceOf(QBadRequestException.class);
   }

   FieldAccessTier tier(String field) { var table = QContext.getQInstance().getTable("person"); return SecuredDataRuntime.current().resolver().resolve(table, table.getField(field)).tier(); }

   @Test
   void ceilingScopeAndReadTimeExpiry() throws Exception
   {
      enableStart();
      breaks.start("Investigating urgent incident", 1, "person", DataClassification.PII);
      assertThat(tier("email")).isEqualTo(FieldAccessTier.FULL);
      assertThat(tier("ssn")).isEqualTo(FieldAccessTier.MASKED);
      CLOCK.now = NOW.plusSeconds(60);
      assertThat(tier("email")).isEqualTo(FieldAccessTier.REVEALABLE);
      assertThat(new StatusService().status().breakGlass()).isNull();
      breaks.start("Investigating another incident", 1, SecuredDataTables.POLICY, null);
      assertThat(tier("email")).isEqualTo(FieldAccessTier.REVEALABLE);
   }

   @Test
   void ownerAndAdminEndButOthersCannot() throws Exception
   {
      enableStart(); QRecord row = breaks.start("Investigating urgent incident", 60, null, null);
      Serializable firstId = row.getValue("id");
      QContext.setQSession(user("u2"));
      assertThatThrownBy(() -> breaks.end(firstId)).isInstanceOf(QPermissionDeniedException.class);
      QContext.setQSession(user("u2", "secured_data.admin"));
      breaks.end(row.getValue("id"));
      assertThat(breaks.find(row.getValue("id")).getValueString("ended_by")).isEqualTo("u2");
      assertThat(Sink.resolutions).hasSize(1);
      enableStart(); row = breaks.start("Investigating urgent incident", 60, null, null);
      breaks.end(row.getValue("id"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.REVEALABLE);
      assertThat(logs()).anyMatch(r -> "BREAK_GLASS_END".equals(r.getValueString("event_type")));
   }

   @Test
   void expiryJobIsIdempotentAndResolvesAlert() throws Exception
   {
      enableStart(); QRecord row = breaks.start("Investigating urgent incident", 1, null, null);
      CLOCK.now = NOW.plusSeconds(60);
      var output = new RunBackendStepOutput();
      new BreakGlassProcesses.Expire().run(new RunBackendStepInput(), output);
      assertThat(breaks.find(row.getValue("id")).getValueString("status")).isEqualTo("EXPIRED");
      assertThat(breaks.expire()).isZero();
      assertThat(Sink.resolutions).hasSize(1);
      assertThat(logs()).anyMatch(r -> "BREAK_GLASS_EXPIRED".equals(r.getValueString("event_type")));
   }

   @Test
   void breakGlassValidationAndPermission() throws Exception
   {
      assertThatThrownBy(() -> breaks.start("Investigating urgent incident", 60, null, null)).isInstanceOf(QPermissionDeniedException.class);
      enableStart();
      assertThatThrownBy(() -> breaks.start("short", 60, null, null)).isInstanceOf(QBadRequestException.class);
      assertThatThrownBy(() -> breaks.start("Investigating urgent incident", 481, null, null)).isInstanceOf(QBadRequestException.class);
      assertThatThrownBy(() -> breaks.start("Investigating urgent incident", 0, null, null)).isInstanceOf(QBadRequestException.class);
      assertThatThrownBy(() -> breaks.start("Investigating urgent incident", 60, "missing", null)).isInstanceOf(QBadRequestException.class);
      QContext.setQSession(channelUser("assistant", BreakGlassService.START + ".hasAccess"));
      assertThatThrownBy(() -> breaks.start("Investigating urgent incident", 60, null, null)).isInstanceOf(QPermissionDeniedException.class);
   }

   @Test
   void statusAllowanceAndPicker() throws Exception
   {
      var status = new StatusService().status();
      assertThat(status.breakGlass()).isNull();
      assertThat(status.revealAllowances()).singleElement().satisfies(a -> { assertThat(a.tableName()).isEqualTo("person"); assertThat(a.fieldName()).isEqualTo("email"); assertThat(a.remainingDailyAllowance()).isEqualTo(2); });
      var provider = new FieldsOfTablePossibleValueSource();
      assertThat(provider.search(new SearchPossibleValueSourceInput())).isEmpty();
      assertThat(provider.search(new SearchPossibleValueSourceInput().withOtherValues(Map.of("table_name", "")))).isEmpty();
      var fields = provider.search(new SearchPossibleValueSourceInput().withOtherValues(Map.of("table_name", "person")));
      assertThat(fields).extracting(v -> v.getId()).containsExactlyInAnyOrder("id", "email", "ssn", "notes");
      assertThat(fields).allMatch(v -> v.getLabel() != null);
      assertThat(provider.search(new SearchPossibleValueSourceInput().withOtherValues(Map.of("tableName", "person")))).hasSize(4);
      assertThatThrownBy(() -> provider.search(new SearchPossibleValueSourceInput().withOtherValues(Map.of("tableName", "unknown")))).hasMessageContaining("Unknown table");
   }

   @Test
   void endReviewAndResultRecheckOwnership() throws Exception
   {
      enableStart(); QRecord row = breaks.start("Investigating urgent incident", 60, null, null);
      var input = new RunBackendStepInput(); input.setRecords(List.of(row));
      var output = new RunBackendStepOutput();
      var review = new BreakGlassProcesses.EndReview(); review.runOnePage(input, output);
      assertThat(review.getProcessSummary(output, false)).hasSize(1);
      var load = new BreakGlassProcesses.EndLoad(); load.runOnePage(input, new RunBackendStepOutput());
      assertThat(load.getProcessSummary(output, true)).hasSize(1);
      assertThat(breaks.find(row.getValue("id")).getValueString("status")).isEqualTo("ENDED");
   }

   @Test
   void startAndEndThroughProcessEngine() throws Exception
   {
      enableStart();
      var input = new RunBackendStepInput();
      input.addValue("reason", "Investigating urgent incident");
      input.addValue("duration_minutes", 60);
      new BreakGlassProcesses.Start().run(input, new RunBackendStepOutput());
      QRecord row = SecuredDataRuntime.current().resolver().activeBreakGlass().getFirst();
      var lines = ProcessRunner.run(BreakGlassService.END, row.getValue("id"));
      assertThat(lines.review()).anyMatch(line -> line.contains("will be ended"));
      assertThat(lines.result()).anyMatch(line -> line.contains("was ended"));
      assertThat(breaks.find(row.getValue("id")).getValueString("status")).isEqualTo("ENDED");
   }

   @Test
   void expiryScheduleUsesHostSchedulerAndSixtySeconds()
   {
      var config = new SecuredDataQBitConfig().withSchedulerName("host");
      var process = BreakGlassProcesses.processes(config).getLast();
      assertThat(process.getSchedule().getRepeatSeconds()).isEqualTo(60);
      assertThat(process.getSchedule().getSchedulerName()).isEqualTo("host");
      assertThat(process.getIsHidden()).isTrue();
   }

   public static class Sink implements AlertSinkInterface
   {
      static final List<AlertSignal> signals = new ArrayList<>();
      static final List<AlertResolution> resolutions = new ArrayList<>();
      public void raise(AlertSignal signal) { signals.add(signal); }
      public void resolve(AlertResolution resolution) { resolutions.add(resolution); }
      public void heartbeat(String key, Instant at) { }
   }
}
