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


import java.util.List;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.channelUser;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.classification;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.close;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.insert;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.logs;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.person;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.policy;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.setup;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.update;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.user;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;



/*******************************************************************************
 ** Core field access bridge it.
 *******************************************************************************/
class CoreFieldAccessBridgeIT
{
   static final String EMAIL = "CANARY-EMAIL-918273@example.invalid";
   static final String SSN = "CANARY-PHI-192837465";

   /*******************************************************************************
    ** Require core.
    *******************************************************************************/
   @BeforeEach
   void requireCore()
   {
      boolean available;
      try
      {
         Class.forName("com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessResolverMetaData");
         available = true;
      }
      catch(ClassNotFoundException expected)
      {
         available = false;
      }
      Assumptions.assumeTrue(available, "QQQ RC.6 field-access core is not on this classpath");
   }



   /*******************************************************************************
    ** Cleanup.
    *******************************************************************************/
   @AfterEach
   void cleanup()
   {
      close();
   }

   /*******************************************************************************
    ** End to end query get exact match and denial matrix.
    *******************************************************************************/
   @Test
   void endToEndQueryGetExactMatchAndDenialMatrix() throws Exception
   {
      QInstance instance = setup();
      for(String classification : List.of("PII", "PHI"))
      {
         policy("cs_rep", classification, "MASKED");
         policy("cs_admin", classification, "REVEALABLE");
         policy("admin", classification, "FULL");
      }
      QRecord person = insert("person", new QRecord().withValue("email", EMAIL).withValue("ssn", SSN).withValue("notes", "ordinary"));
      for(String role : List.of("cs_rep", "cs_admin", "admin"))
      {
         QContext.setQSession(user(role, role));
         QRecord query = new QueryAction().execute(new QueryInput("person")).getRecords().getFirst();
         QRecord get = new GetAction().execute(new GetInput("person").withPrimaryKey(person.getValue("id"))).getRecord();
         for(QRecord row : List.of(query, get))
         {
            assertThat(row.getValueString("notes")).isEqualTo("ordinary");
            if(role.equals("admin"))
            {
               assertThat(row.getValueString("email")).isEqualTo(EMAIL);
               assertThat(row.getValueString("ssn")).isEqualTo(SSN);
            }
            else
            {
               assertThat(row.getValueString("email")).isNotNull().isNotEqualTo(EMAIL);
               assertThat(row.getValueString("ssn")).isNotNull().isNotEqualTo(SSN);
            }
         }
      }
      QContext.setQSession(user("cs_admin", "cs_admin"));
      assertThat(search(EMAIL)).hasSize(1).allMatch(row -> !EMAIL.equals(row.getValueString("email")));
      assertThat(search("NOT-IN-TABLE")).isEmpty();
      assertThatThrownBy(() -> new QueryAction().execute(new QueryInput("person").withFilter(new QQueryFilter().withOrderBy(new QFilterOrderBy("email"))))).hasMessageContaining("Permission denied");
      QContext.setQSession(user("cs_rep", "cs_rep"));
      assertThatThrownBy(() -> search(EMAIL)).hasMessageContaining("Permission denied");
      QContext.setQSession(user("admin", "admin"));
      assertThat(search(EMAIL)).hasSize(1).allMatch(row -> EMAIL.equals(row.getValueString("email")));
      SecuredDataRuntime.current().logger().flush();
      assertThat(logs().stream().filter(row -> "EXACT_MATCH_FILTER".equals(row.getValueString("event_type"))).map(row -> row.getValueString("outcome"))).contains("MATCH", "NO_MATCH");
      assertThat(logs().stream().filter(row -> "FILTER_DENIED".equals(row.getValueString("event_type")))).isNotEmpty();
      assertThat(com.kingsrook.qqq.backend.core.utils.JsonUtils.toJson(logs())).doesNotContain(EMAIL, SSN, "NOT-IN-TABLE");
      QContext.setQSession(channelUser("assistant/t1", "secured_data.admin"));
      assertThatThrownBy(() -> new QueryAction().execute(new QueryInput(SecuredDataTables.ACCESS_LOG))).hasMessageContaining("Permission denied");
   }

   /*******************************************************************************
    ** Core preflight reports exactly one refused log and honors entropy.
    *******************************************************************************/
   @Test
   void corePreflightReportsExactlyOneRefusedLogAndHonorsEntropy() throws Exception
   {
      setup();
      policy("cs_admin", "PII", "REVEALABLE");
      for(int i = 0; i < 20; i++)
      {
         assertThat(search("known" + i)).isEmpty();
      }
      assertThatThrownBy(() -> search("known21")).hasMessageContaining("Exact-match search limit reached for [email]");
      SecuredDataRuntime.current().logger().flush();
      assertThat(logs().stream().filter(row -> "EXACT_MATCH_FILTER".equals(row.getValueString("event_type")))) .hasSize(21);
      assertThat(logs().stream().filter(row -> "REFUSED".equals(row.getValueString("outcome")))) .hasSize(1);
      classification("email", "PII");
      QRecord row = com.kingsrook.qbits.secureddata.support.SystemWrites.query(SecuredDataTables.CLASSIFICATION, new QQueryFilter()).getFirst();
      update(SecuredDataTables.CLASSIFICATION, new QRecord().withValue("id", row.getValue("id")).withValue("low_cardinality", true));
      assertThatThrownBy(() -> search("known")).hasMessageContaining("Permission denied");
   }



   @Test
   void revealUnmasksOnlyGrantedRecordAndExpiresInCoreGet() throws Exception
   {
      setup();
      policy("cs_admin", "PII", "REVEALABLE");
      QRecord row = insert("person", new QRecord().withValue("email", EMAIL));
      QRecord other = insert("person", new QRecord().withValue("email", "OTHER-CANARY"));
      GetInput get = new GetInput("person").withPrimaryKey(row.getValue("id"));
      assertThat(new GetAction().execute(get).getRecord().getValueString("email")).isNotEqualTo(EMAIL);
      var reveal = new com.kingsrook.qbits.secureddata.reveal.RevealService().reveal("person", row.getValue("id"), "email", "Investigating", null);
      assertThat(reveal.value()).isEqualTo(EMAIL);
      assertThat(new GetAction().execute(get).getRecord().getValueString("email")).isEqualTo(EMAIL);
      assertThat(new GetAction().execute(new GetInput("person").withPrimaryKey(other.getValue("id"))).getRecord().getValueString("email")).isNotEqualTo("OTHER-CANARY");
      SecuredDataTestSupport.CLOCK.now = SecuredDataTestSupport.NOW.plusSeconds(300);
      assertThat(new GetAction().execute(get).getRecord().getValueString("email")).isNotEqualTo(EMAIL);
   }

   @Test
   void revealPreservesCoreRecordLockDenial() throws Exception
   {
      QInstance instance = setup();
      policy("cs_admin", "PII", "REVEALABLE");
      QRecord row = insert("person", new QRecord().withValue("email", EMAIL).withValue("notes", "tenant-a"));
      instance.addSecurityKeyType(new com.kingsrook.qqq.backend.core.model.metadata.security.QSecurityKeyType().withName("tenant"));
      instance.getTable("person").withRecordSecurityLock(new com.kingsrook.qqq.backend.core.model.metadata.security.RecordSecurityLock().withSecurityKeyType("tenant").withFieldName("notes"));
      QContext.getQSession().withSecurityKeyValue("tenant", "tenant-b");
      assertThat(new GetAction().execute(new GetInput("person").withPrimaryKey(row.getValue("id"))).getRecord()).isNull();
      assertThatThrownBy(() -> new com.kingsrook.qbits.secureddata.reveal.RevealService().reveal("person", row.getValue("id"), "email", "Investigating", null))
         .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QNotFoundException.class);
      assertThat(com.kingsrook.qbits.secureddata.support.SystemWrites.query(SecuredDataTables.REVEAL_GRANT, new QQueryFilter())).isEmpty();
   }

   /*******************************************************************************
    ** Search.
    *******************************************************************************/
   private List<QRecord> search(String email) throws Exception
   {
      return (new QueryAction().execute(new QueryInput("person").withFilter(new QQueryFilter()
         .withCriteria(new QFilterCriteria("email", QCriteriaOperator.EQUALS, email)))).getRecords());
   }
}
