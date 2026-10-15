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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.breakglass.BreakGlassService;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qqq.backend.core.alerts.AlertResolution;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.AlertSinkInterface;
import com.kingsrook.qqq.backend.core.alerts.AlertsInstanceMetaData;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.instances.AbstractQQQApplication;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.modules.authentication.QAuthenticationModuleCustomizerInterface;
import com.kingsrook.qqq.middleware.javalin.QApplicationJavalinServer;
import com.kingsrook.qqq.middleware.javalin.QJavalinImplementation;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.*;
import static org.assertj.core.api.Assertions.*;

class SecuredDataHttpTest
{
   QApplicationJavalinServer server;
   int port;

   @AfterEach
   void cleanup()
   {
      if(server != null) server.stop();
      QJavalinImplementation.setSessionCookieHttpOnly(false);
      close();
   }

   public static class Sessions implements QAuthenticationModuleCustomizerInterface
   {
      public void customizeSession(QInstance instance, QSession session, Map<String, Object> context)
      {
         session.setPermissions(java.util.Set.of("person.read", "cs_admin"));
      }
   }

   void start() throws Exception
   {
      QInstance instance = setup();
      instance.getAuthentication().setType(QAuthenticationType.MOCK);
      instance.getAuthentication().setCustomizer(new QCodeReference(Sessions.class));
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE").withValue("daily_reveal_cap", 1));
      insert("person", new QRecord().withValue("id", 1).withValue("email", "HTTP-CANARY@example.invalid"));
      server = new QApplicationJavalinServer(new AbstractQQQApplication()
      {
         public QInstance defineQInstance() { return instance; }
      }).withPort(0).withServeFrontendNext(false).withServeFrontendMaterialDashboard(false).withServeLegacyUnversionedMiddlewareAPI(false).withStrictUiApiRoutes(true);
      server.start();
      var serviceField = QApplicationJavalinServer.class.getDeclaredField("service");
      serviceField.setAccessible(true);
      port = ((io.javalin.Javalin) serviceField.get(server)).port();
   }

   HttpResponse<String> request(String path, String body, boolean assistant) throws Exception
   {
      var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/qqq/v1" + path)).header("Cookie", "sessionUUID=phase-c-user");
      if(assistant) builder.header("X-QQQ-Client", "assistant");
      if(body != null) builder.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
      return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
   }

   @Test
   void optionsRevealStatusAndCapThroughRealMiddleware() throws Exception
   {
      start();
      var options = request("/qbit/secured-data/reveal/options?tableName=person&fieldName=email", null, false);
      assertThat(options.statusCode()).as(options.body()).isEqualTo(200);
      assertThat(new JSONObject(options.body()).getInt("remainingDailyAllowance")).isEqualTo(1);
      String body = "{\"tableName\":\"person\",\"primaryKey\":1,\"fieldName\":\"email\",\"reason\":\"Investigation\"}";
      var reveal = request("/qbit/secured-data/reveal", body, false);
      assertThat(reveal.statusCode()).as(reveal.body()).isEqualTo(200);
      assertThat(new JSONObject(reveal.body()).getString("value")).isEqualTo("HTTP-CANARY@example.invalid");
      var status = request("/qbit/secured-data/status", null, false);
      assertThat(status.statusCode()).as(status.body()).isEqualTo(200);
      assertThat(new JSONObject(status.body()).getInt("revealsUsedToday")).isEqualTo(1);
      assertErrorResponse(request("/qbit/secured-data/reveal", body, false), 429);
      assertErrorResponse(request("/qbit/secured-data/reveal", body, true), 403);
      assertErrorResponse(request("/qbit/secured-data/reveal", "{}", false), 400);
      assertErrorResponse(request("/qbit/secured-data/reveal", "{\"primaryKey\":1}", false), 400);
      assertErrorResponse(request("/qbit/secured-data/reveal/options?tableName=person&fieldName=missing", null, false), 404);
   }

   /*******************************************************************************
    ** Verify standard error bodies without changing endpoint status semantics.
    *******************************************************************************/
   private void assertErrorResponse(HttpResponse<String> response, int status)
   {
      assertThat(response.statusCode()).as(response.body()).isEqualTo(status);
      JSONObject body = new JSONObject(response.body());
      assertThat(body.keySet()).contains("error", "code", "message", "traceId");
      assertThat(body.getString("error")).isNotBlank();
      assertThat(body.getString("code")).isNotBlank();
      assertThat(body.getString("message")).isNotBlank();
      assertThat(body.getString("traceId")).isNotBlank();
   }

   @Test
   void notificationTargetsOnlySecuredDataAdmins() throws Exception
   {
      Class<?> signalType;
      try { signalType = Class.forName("com.kingsrook.qqq.backend.core.alerts.NotificationSignal"); }
      catch(ClassNotFoundException expected) { org.junit.jupiter.api.Assumptions.assumeTrue(false, "Installed core lacks notification SPI #1125"); return; }
      var instance = setup();
      Bell.signal = null;
      AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(Bell.class));
      var metadata = AlertsInstanceMetaData.ofOrWithNew(instance);
      var setter = metadata.getClass().getDeclaredMethod("setLoadedSink", AlertSinkInterface.class);
      setter.setAccessible(true);
      setter.invoke(metadata, java.lang.reflect.Proxy.newProxyInstance(AlertSinkInterface.class.getClassLoader(), new Class<?>[] {AlertSinkInterface.class},
         (proxy, method, args) -> { if(method.getName().equals("notify")) Bell.signal = args[0]; return null; }));
      QContext.setQSession(user("u1", BreakGlassService.START + ".hasAccess"));
      new BreakGlassService().start("Urgent incident investigation", 60, null, null);
      assertThat(Bell.signal).isNotNull();
      Object audience = signalType.getMethod("getAudience").invoke(Bell.signal);
      assertThat((List<?>) audience.getClass().getMethod("getValues").invoke(audience)).isEqualTo(List.of("secured_data.admin"));
   }

   public static class Bell implements AlertSinkInterface
   {
      static Object signal;
      public void raise(AlertSignal ignored) { }
      public void resolve(AlertResolution ignored) { }
      public void heartbeat(String key, Instant at) { }
   }
}
