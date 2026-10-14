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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import com.kingsrook.qbits.secureddata.app.SecuredDataApp;
import com.kingsrook.qbits.secureddata.app.SecuredDataHomeData;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.ActivityLog;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.*;
import static org.assertj.core.api.Assertions.*;

class SecuredDataHomeTest
{
   @AfterEach void cleanup() { close(); }

   String home() throws Exception
   {
      return ((RawHTML) new SecuredDataApp.HomeRenderer().render(new RenderWidgetInput()).getWidgetData()).getHtml();
   }

   @Test void emptyStateAndNav() throws Exception
   {
      var instance = setup();
      QContext.setQSession(user("admin", "secured_data.admin"));
      var data = SecuredDataHomeData.load();
      assertThat(data.getKpis().values()).containsOnly(0L);
      assertThat(data.getSections()).hasSize(6).allSatisfy(s -> assertThat(s.rows()).isEmpty());
      assertThat(home()).contains("No reveals yet", "No reveals in the last 30 days", "No reveal reasons in the last 30 days",
         "No break-glass events yet", "No policy or classification changes yet", "No anomaly flags in the last 7 days");
      var app = instance.getApp("secured_data");
      assertThat(app.getWidgets()).containsExactly(SecuredDataApp.HOME_WIDGET);
      assertThat(app.getChildren()).extracting(c -> c.getName()).containsExactly(SecuredDataTables.CLASSIFICATION, SecuredDataTables.POLICY,
         SecuredDataTables.ACCESS_LOG, SecuredDataTables.BREAK_GLASS, SecuredDataTables.RETENTION_RULE);
      assertThat(instance.getTable(SecuredDataTables.ACCESS_LOG).getSections()).anyMatch(s -> SecuredDataTables.REVEALS_WIDGET.equals(s.getWidgetName()));
   }

   @Test void seededKpisOrderingLimitsLinksAndEveryWidget() throws Exception
   {
      setup(c -> c.withTablePathPrefix("/admin/data").withAccessLogQueueCapacity(1));
      QContext.setQSession(user("admin", "secured_data.admin"));
      for(int i = 0; i < 15; i++)
         SecuredDataAnomaliesTest.seed(ActivityLog.row("REVEAL", "person", "ALLOWED").withValue("user_id", i < 12 ? "alice" : "bob")
            .withValue("user_name", i < 12 ? "Alice <b>" : "Bob").withValue("reason", i < 11 ? "Customer support" : "Case review")
            .withValue("record_id", String.valueOf(i)).withValue("field_name", "email").withValue("client_channel", "web")
            .withValue("created_at", NOW.minusSeconds(i)).withValue("anomaly_flag", i == 0));
      SecuredDataAnomaliesTest.seed(ActivityLog.row("REVEAL", "person", "ALLOWED").withValue("created_at", NOW.minusSeconds(31 * 86400L)));
      SecuredDataAnomaliesTest.seed(ActivityLog.row("REVEAL", "person", "ALLOWED").withValue("created_at", NOW.plusSeconds(60)));
      for(String type : List.of("BREAK_GLASS_START", "BREAK_GLASS_END", "BREAK_GLASS_EXPIRED", "FILTER_DENIED"))
         SecuredDataAnomaliesTest.seed(ActivityLog.row(type, "person", "ALLOWED"));
      SecuredDataAnomaliesTest.seed(ActivityLog.row("EXACT_MATCH_FILTER", "person", "REFUSED"));
      SecuredDataAnomaliesTest.seed(ActivityLog.row("FILTER_DENIED", "person", "DENIED").withValue("created_at", NOW.minusSeconds(8 * 86400L)));
      for(int i = 0; i < 2; i++)
         insert(SecuredDataTables.REVEAL_GRANT, new QRecord().withValue("user_id", "alice").withValue("table_name", "person")
            .withValue("record_id", "1").withValue("field_name", "email").withValue("granted_at", NOW.minusSeconds(60))
            .withValue("expires_at", NOW.plusSeconds(i == 0 ? 60 : 0)).withValue("access_log_id", 1));
      for(int i = 0; i < 3; i++)
         insert(SecuredDataTables.BREAK_GLASS, new QRecord().withValue("user_id", "alice").withValue("started_at", NOW.minusSeconds(60))
            .withValue("expires_at", NOW.plusSeconds(i == 0 ? 60 : 0)).withValue("status", i == 2 ? "ENDED" : "ACTIVE"));
      var policy = policy("role", "PII", "MASKED");
      update(SecuredDataTables.POLICY, new QRecord().withValue("id", policy.getValue("id")).withValue("name", "Changed"));
      delete(SecuredDataTables.POLICY, policy);
      classification("email", "PII");
      var logger = SecuredDataRuntime.current().logger();
      logger.onAccess(SecuredDataAccessLoggerTest.event(com.kingsrook.qbits.secureddata.standin.FieldAccessEventType.VIEW, null, null));
      logger.onAccess(SecuredDataAccessLoggerTest.event(com.kingsrook.qbits.secureddata.standin.FieldAccessEventType.VIEW, null, null));
      var data = SecuredDataHomeData.load();
      assertThat(data.getKpis()).containsEntry("Reveals today", 15L).containsEntry("Active reveal grants", 1L)
         .containsEntry("Active break-glass sessions", 1L).containsEntry("Anomaly flags (7 days)", 1L)
         .containsEntry("Denied filters (7 days)", 2L).containsEntry("Access-log queue drops", 1L);
      assertThat(data.getSections().get(0).rows()).hasSize(10).extracting(r -> r.getValueString("record_id"))
         .containsExactly("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
      assertThat(data.getSections().get(1).rows()).extracting(r -> r.getValueString("user_id")).containsExactly("alice", "bob");
      assertThat(data.getSections().get(1).rows().getFirst().getValueInteger("count")).isEqualTo(12);
      assertThat(data.getSections().get(2).rows().getFirst().getValueString("reason")).isEqualTo("Customer support");
      assertThat(data.getSections().get(3).rows()).hasSize(3);
      assertThat(data.getSections().get(4).rows()).hasSize(4).extracting(r -> r.getValueString("action_name")).containsExactly("INSERT", "DELETE", "UPDATE", "INSERT");
      assertThat(data.getSections().get(5).rows()).hasSize(1);
      for(var section : data.getSections())
      {
         assertThat(section.href()).startsWith("/admin/data/secured_data_access_log?filter=");
         String filter = URLDecoder.decode(section.href().split("filter=")[1], StandardCharsets.UTF_8);
         assertThat(filter).contains("created_at").doesNotContain("\"limit\":10");
      }
      String html = home();
      assertThat(html).contains("Recent reveals", "Top revealers (30 days)", "Top reasons (30 days)", "Break-glass events", "Policy and classification changes", "Anomaly flags")
         .contains("Alice &lt;b&gt;", "Customer support", "BREAK_GLASS_EXPIRED", "CLASSIFICATION_CHANGE", "View all", "UTC", "title=", "text-overflow:ellipsis", "white-space:nowrap", "minmax(min(100%", "var(--qqq-grid-border")
         .doesNotContain("Alice <b>", "overflow:auto", "overflow-x", "<style", "#ffffff", "rgba(");
      assertThat(html.split("<section ", -1)).hasSize(7);
   }

   @Test void viewerWithoutAdminCannotReadHome() throws Exception
   {
      setup();
      assertThatThrownBy(SecuredDataHomeData::load).isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException.class);
   }

   @Test void classificationMutationsAreValueFreeAndAttributed() throws Exception
   {
      setup();
      QContext.setQSession(user("admin", "secured_data.admin"));
      var input = new com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput(SecuredDataTables.CLASSIFICATION)
         .withRecord(new QRecord().withValue("table_name", "person").withValue("field_name", "email").withValue("classification", "PII"));
      var row = new com.kingsrook.qqq.backend.core.actions.tables.InsertAction().execute(input).getRecords().getFirst();
      new com.kingsrook.qqq.backend.core.actions.tables.UpdateAction().execute(new com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput(SecuredDataTables.CLASSIFICATION)
         .withRecord(new QRecord().withValue("id", row.getValue("id")).withValue("classification", "PHI")));
      new com.kingsrook.qqq.backend.core.actions.tables.DeleteAction().execute(new com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput(SecuredDataTables.CLASSIFICATION)
         .withPrimaryKeys(List.of(row.getValue("id"))));
      assertThat(logs()).hasSize(3).allSatisfy(r -> {
         assertThat(r.getValueString("user_id")).isEqualTo("admin");
         assertThat(r.getValueString("record_id")).isEqualTo(row.getValueString("id"));
         assertThat(r.getValueString("event_type")).isEqualTo("CLASSIFICATION_CHANGE");
         assertThat(r.getValue("reason")).isNull();
      });
      assertThat(logs()).extracting(r -> r.getValueString("action_name")).containsExactly("INSERT", "UPDATE", "DELETE");
   }
}
