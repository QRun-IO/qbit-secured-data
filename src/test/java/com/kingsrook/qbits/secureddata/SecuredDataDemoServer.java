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

import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.ActivityLog;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.instances.AbstractQQQApplication;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.core.modules.authentication.QAuthenticationModuleCustomizerInterface;
import com.kingsrook.qqq.middleware.javalin.QApplicationJavalinServer;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.*;

/*******************************************************************************
 ** Test-only local Next demo, following WebhooksDemoServer. Synthetic identifiers
 ** and reasons only; never shipped. Run on port 8098 after test compilation.
 *******************************************************************************/
public class SecuredDataDemoServer
{
   /*******************************************************************************
    ** Local demo administrator; not an application authentication implementation.
    *******************************************************************************/
   public static class Sessions implements QAuthenticationModuleCustomizerInterface
   {
      /*******************************************************************************
       ** Give the local demo access to its home and tables.
       *******************************************************************************/
      public void customizeSession(QInstance instance, QSession session, Map<String, Object> context)
      {
         session.setUser(new QUser().withIdReference("demo-admin").withFullName("Demo Administrator"));
         session.setPermissions(Set.of("secured_data.admin", "secured_data.hasAccess", "person.read"));
      }
   }

   /*******************************************************************************
    ** Seed every home section with realistic synthetic rows.
    *******************************************************************************/
   public static void seedDemo() throws Exception
   {
      String[] names = {"Avery Morgan", "Jordan Patel", "Sam Rivera", "Taylor Chen"};
      String[] reasons = {"Customer identity verification", "Support case follow-up", "Account recovery investigation", "Review of an escalated access request with the customer support team"};
      for(int i = 0; i < 48; i++)
      {
         SecuredDataAnomaliesTest.seed(ActivityLog.row("REVEAL", "person", "ALLOWED")
            .withValue("user_id", "operator-" + i % 4).withValue("user_name", names[i % 4])
            .withValue("record_id", String.valueOf(4200 + i)).withValue("field_name", i % 2 == 0 ? "email" : "ssn")
            .withValue("reason", reasons[i % 4]).withValue("client_channel", i % 3 == 0 ? "api" : "web")
            .withValue("created_at", NOW.minusSeconds(i < 15 ? i * 180L : i * 36000L)).withValue("anomaly_flag", i < 2));
      }
      for(int i = 0; i < 3; i++)
      {
         String event = new String[] {"BREAK_GLASS_START", "BREAK_GLASS_END", "BREAK_GLASS_EXPIRED"}[i];
         SecuredDataAnomaliesTest.seed(ActivityLog.row(event, SecuredDataTables.BREAK_GLASS, "ALLOWED")
            .withValue("user_name", names[i]).withValue("reason", "Urgent investigation of customer support incident SD-2026-1042")
            .withValue("created_at", NOW.minusSeconds(i * 1200L)).withValue("anomaly_flag", i == 0));
      }
      for(int i = 0; i < 4; i++)
      {
         insert(SecuredDataTables.REVEAL_GRANT, new QRecord().withValue("user_id", "operator-" + i).withValue("user_name", names[i])
            .withValue("table_name", "person").withValue("record_id", "4200").withValue("field_name", "email")
            .withValue("granted_at", NOW.minusSeconds(60)).withValue("expires_at", NOW.plusSeconds(240)).withValue("access_log_id", i + 1));
      }
      insert(SecuredDataTables.BREAK_GLASS, new QRecord().withValue("user_id", "operator-0").withValue("user_name", names[0])
         .withValue("started_at", NOW.minusSeconds(300)).withValue("expires_at", NOW.plusSeconds(3300)).withValue("status", "ACTIVE"));
      for(int i = 0; i < 6; i++)
         SecuredDataAnomaliesTest.seed(ActivityLog.row("FILTER_DENIED", "person", "DENIED").withValue("user_name", names[i % 4]));
      policy("support_specialist", "PII", "REVEALABLE");
      classification("email", "PII");
   }

   /*******************************************************************************
    ** Run the real bundled Next frontend and middleware against memory data.
    *******************************************************************************/
   public static void main(String[] args) throws Exception
   {
      QInstance instance = setup();
      instance.getAuthentication().setCustomizer(new QCodeReference(Sessions.class));
      QContext.setQSession(user("demo-admin", "secured_data.admin"));
      seedDemo();
      new QApplicationJavalinServer(new AbstractQQQApplication()
      {
         public QInstance defineQInstance()
         {
            return (instance);
         }
      }).withPort(args.length == 0 ? 8098 : Integer.parseInt(args[0])).withServeFrontendNext(true).start();
      System.out.println("Secured Data demo: http://localhost:8098/app/secured_data");
   }
}
