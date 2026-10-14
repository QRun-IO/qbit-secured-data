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
import com.kingsrook.qbits.secureddata.standin.AiTableMetaData;
import com.kingsrook.qbits.secureddata.standin.DataClassification;
import com.kingsrook.qbits.secureddata.standin.FieldAccessTier;
import com.kingsrook.qbits.secureddata.standin.FieldMaskStyle;
import com.kingsrook.qbits.secureddata.support.CoreMetadataBridge;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.CLOCK;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.NOW;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.channelUser;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.classification;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.close;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.delete;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.insert;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.person;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.policy;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.policyRow;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.setup;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.update;
import static com.kingsrook.qbits.secureddata.SecuredDataTestSupport.user;
import static org.assertj.core.api.Assertions.assertThat;



/*******************************************************************************
 ** Secured data resolver test.
 *******************************************************************************/
class SecuredDataResolverTest
{
   QTableMetaData person;
   SecuredDataResolver resolver;



   /*******************************************************************************
    ** Init.
    *******************************************************************************/
   @BeforeEach
   void init() throws Exception
   {
      person = setup().getTable("person");
      resolver = SecuredDataRuntime.current().resolver();
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
    ** Tier.
    *******************************************************************************/
   FieldAccessTier tier(String field)
   {
      return (resolver.resolve(person, person.getField(field)).tier());
   }

   /*******************************************************************************
    ** Classification order and highest.
    *******************************************************************************/
   @Test
   void classificationOrderAndHighest() throws Exception
   {
      assertThat(SecuredDataClassifications.effective(person)).isNull();
      assertThat(SecuredDataClassifications.effective(person, "email")).isEqualTo(DataClassification.PII);
      person.withSupplementalMetaData(new AiTableMetaData().withClassification(DataClassification.CONFIDENTIAL));
      assertThat(SecuredDataClassifications.effective(person, "notes")).isEqualTo(DataClassification.CONFIDENTIAL);
      assertThat(SecuredDataClassifications.effective(person, "email")).isEqualTo(DataClassification.PII);
      QRecord tableRow = classification(null, "PHI");
      assertThat(SecuredDataClassifications.effective(person, "email")).isEqualTo(DataClassification.PHI);
      assertThat(SecuredDataClassifications.effective(person)).isEqualTo(DataClassification.PHI);
      QRecord fieldRow = classification("email", "PUBLIC");
      assertThat(SecuredDataClassifications.effective(person, "email")).isEqualTo(DataClassification.PUBLIC);
      assertThat(SecuredDataClassifications.highest(person)).isEqualTo(DataClassification.PHI);
      assertThat(SecuredDataClassifications.highest(person, List.of("email"))).isEqualTo(DataClassification.PUBLIC);
      assertThat(SecuredDataClassifications.highest(person, List.of())).isNull();
      delete(SecuredDataTables.CLASSIFICATION, fieldRow);
      delete(SecuredDataTables.CLASSIFICATION, tableRow);
      assertThat(SecuredDataClassifications.effective(person, "email")).isEqualTo(DataClassification.PII);
   }

   /*******************************************************************************
    ** Defaults public primary key and admin separation.
    *******************************************************************************/
   @Test
   void defaultsPublicPrimaryKeyAndAdminSeparation() throws Exception
   {
      assertThat(tier("id")).isEqualTo(FieldAccessTier.FULL);
      assertThat(tier("notes")).isEqualTo(FieldAccessTier.FULL);
      assertThat(tier("email")).isEqualTo(FieldAccessTier.MASKED);
      assertThat(tier("ssn")).isEqualTo(FieldAccessTier.MASKED);
      classification("notes", "CONFIDENTIAL");
      assertThat(tier("notes")).isEqualTo(FieldAccessTier.FULL);
      QContext.setQSession(user("admin", "secured_data.admin"));
      assertThat(tier("ssn")).isEqualTo(FieldAccessTier.MASKED);
      QTableMetaData own = QContext.getQInstance().getTable(SecuredDataTables.POLICY);
      assertThat(resolver.resolve(own, own.getField("name")).tier()).isEqualTo(FieldAccessTier.FULL);
      assertThat(SystemWrites.call(() -> tier("ssn"))).isEqualTo(FieldAccessTier.FULL);
      assertThat(tier("ssn")).isEqualTo(FieldAccessTier.MASKED);
   }

   /*******************************************************************************
    ** Least restrictive active matching policy and table scope.
    *******************************************************************************/
   @Test
   void leastRestrictiveActiveMatchingPolicyAndTableScope() throws Exception
   {
      policy("cs_admin", "PII", "REVEALABLE");
      policy("other_role", "PII", "FULL");
      assertThat(tier("email")).isEqualTo(FieldAccessTier.REVEALABLE);
      QRecord full = policy("cs_admin", "PII", "FULL");
      assertThat(tier("email")).isEqualTo(FieldAccessTier.FULL);
      update(SecuredDataTables.POLICY, new QRecord().withValue("id", full.getValue("id")).withValue("is_active", false));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.REVEALABLE);
      QTableMetaData another = new QTableMetaData().withName("another").withBackendName("memory").withPrimaryKeyField("id")
         .withField(new QFieldMetaData("id", QFieldType.INTEGER));
      QContext.getQInstance().addTable(another);
      update(SecuredDataTables.POLICY, new QRecord().withValue("id", full.getValue("id")).withValue("is_active", true).withValue("table_name", "another"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.REVEALABLE);
   }

   /*******************************************************************************
    ** Channel rows only cap including features and break glass.
    *******************************************************************************/
   @Test
   void channelRowsOnlyCapIncludingFeaturesAndBreakGlass() throws Exception
   {
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "FULL").withValue("client_channel", "assistant"));
      QContext.setQSession(channelUser("assistant/t1", "cs_admin"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.MASKED);
      policy("cs_admin", "PII", "FULL");
      QRecord cap = insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "HIDDEN").withValue("client_channel", "assistant"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.HIDDEN);
      QContext.setQSession(user("u1", "cs_admin"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.FULL);
      QContext.setQSession(channelUser("assistant/t2", "cs_admin", "person.secured_data_full"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.HIDDEN);
      breakGlass("PHI", null);
      assertThat(tier("email")).isEqualTo(FieldAccessTier.HIDDEN);
   }

   /*******************************************************************************
    ** Feature grants have no admin shortcut.
    *******************************************************************************/
   @Test
   void featureGrantsHaveNoAdminShortcut() throws Exception
   {
      policy("cs_admin", "PII", "HIDDEN");
      assertThat(tier("email")).isEqualTo(FieldAccessTier.HIDDEN);
      QContext.setQSession(user("u1", "cs_admin", "person.secured_data_reveal"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.REVEALABLE);
      QContext.setQSession(user("u1", "person.secured_data_full"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.FULL);
   }



   /*******************************************************************************
    ** Break glass.
    *******************************************************************************/
   QRecord breakGlass(String ceiling, String scope) throws Exception
   {
      return (insert(SecuredDataTables.BREAK_GLASS, new QRecord().withValue("user_id", "u1").withValue("classification_ceiling", ceiling)
         .withValue("table_name", scope).withValue("status", "ACTIVE").withValue("started_at", NOW).withValue("expires_at", NOW.plusSeconds(60))));
   }

   /*******************************************************************************
    ** Break glass ceiling user and exact expiry.
    *******************************************************************************/
   @Test
   void breakGlassCeilingUserAndExactExpiry() throws Exception
   {
      QRecord grant = breakGlass("PII", "person");
      assertThat(tier("email")).isEqualTo(FieldAccessTier.FULL);
      assertThat(tier("ssn")).isEqualTo(FieldAccessTier.MASKED);
      QContext.setQSession(user("other"));
      assertThat(tier("email")).isEqualTo(FieldAccessTier.MASKED);
      QContext.setQSession(user("u1"));
      String before = resolver.getAccessFingerprint();
      CLOCK.now = NOW.plusSeconds(60);
      assertThat(tier("email")).isEqualTo(FieldAccessTier.MASKED);
      assertThat(resolver.getAccessFingerprint()).isNotEqualTo(before);
   }

   /*******************************************************************************
    ** Fingerprint tracks only relevant state.
    *******************************************************************************/
   @Test
   void fingerprintTracksOnlyRelevantState() throws Exception
   {
      String initial = resolver.getAccessFingerprint();
      assertThat(resolver.getAccessFingerprint()).isEqualTo(initial);
      QContext.setQSession(user("u1", "cs_admin", "unrelated.permission"));
      assertThat(resolver.getAccessFingerprint()).isEqualTo(initial);
      insert("person", new QRecord().withValue("notes", "unrelated"));
      assertThat(resolver.getAccessFingerprint()).isEqualTo(initial);
      QRecord policy = policy("cs_admin", "PII", "REVEALABLE");
      String afterPolicy = resolver.getAccessFingerprint();
      assertThat(afterPolicy).isNotEqualTo(initial);
      QRecord classification = classification("email", "PHI");
      String afterClassification = resolver.getAccessFingerprint();
      assertThat(afterClassification).isNotEqualTo(afterPolicy);
      update(SecuredDataTables.CLASSIFICATION, new QRecord().withValue("id", classification.getValue("id")).withValue("classification", "PII"));
      assertThat(resolver.getAccessFingerprint()).isNotEqualTo(afterClassification);
      String beforeBreak = resolver.getAccessFingerprint();
      QRecord grant = breakGlass("PHI", null);
      assertThat(resolver.getAccessFingerprint()).isNotEqualTo(beforeBreak);
      update(SecuredDataTables.BREAK_GLASS, new QRecord().withValue("id", grant.getValue("id")).withValue("status", "ENDED"));
      String ended = resolver.getAccessFingerprint();
      delete(SecuredDataTables.BREAK_GLASS, grant);
      assertThat(resolver.getAccessFingerprint()).isNotEqualTo(ended);
      String beforeDelete = resolver.getAccessFingerprint();
      delete(SecuredDataTables.POLICY, policy);
      assertThat(resolver.getAccessFingerprint()).isNotEqualTo(beforeDelete);
      String beforeChannel = resolver.getAccessFingerprint();
      QContext.setQSession(channelUser("assistant/t1", "cs_admin"));
      assertThat(resolver.getAccessFingerprint()).isNotEqualTo(beforeChannel);
   }



   /*******************************************************************************
    ** Entropy auto and both overrides.
    *******************************************************************************/
   @ParameterizedTest
   @CsvSource({"BOOLEAN, flag", "DATE, dob", "DATE_TIME, timestamp", "INTEGER, birthYear", "STRING, state", "STRING, region", "STRING, province", "STRING, zip3"})
   void entropyAutoAndBothOverrides(String type, String name) throws Exception
   {
      QFieldMetaData field = new QFieldMetaData(name, QFieldType.valueOf(type)).withMaxLength(255);
      person.addField(field);
      CoreMetadataBridge.classifyField(field, DataClassification.PII);
      assertThat(resolver.resolve(person, field).exactMatchAllowed()).isFalse();
      QRecord row = insert(SecuredDataTables.CLASSIFICATION, new QRecord().withValue("table_name", "person").withValue("field_name", name)
         .withValue("classification", "PII").withValue("low_cardinality", false).withValue("mask_style", "FULL"));
      assertThat(resolver.resolve(person, field).exactMatchAllowed()).isTrue();
      assertThat(resolver.resolve(person, field).maskStyle()).isEqualTo(FieldMaskStyle.FULL);
      update(SecuredDataTables.CLASSIFICATION, new QRecord().withValue("id", row.getValue("id")).withValue("low_cardinality", true));
      assertThat(resolver.resolve(person, field).exactMatchAllowed()).isFalse();
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE").withValue("min_entropy_enabled", false));
      assertThat(resolver.resolve(person, field).exactMatchAllowed()).isTrue();
   }

   /*******************************************************************************
    ** Enum short string and year label auto rules.
    *******************************************************************************/
   @Test
   void enumShortStringAndYearLabelAutoRules()
   {
      assertThat(SecuredDataResolver.lowCardinality(new QFieldMetaData("kind", QFieldType.STRING).withPossibleValueSourceName("enum"), null)).isTrue();
      assertThat(SecuredDataResolver.lowCardinality(new QFieldMetaData("code", QFieldType.STRING).withMaxLength(5), null)).isTrue();
      assertThat(SecuredDataResolver.lowCardinality(new QFieldMetaData("y", QFieldType.INTEGER).withLabel("Birth year"), null)).isTrue();
      assertThat(SecuredDataResolver.lowCardinality(new QFieldMetaData("code", QFieldType.STRING).withMaxLength(6), null)).isFalse();
   }

   /*******************************************************************************
    ** Most restrictive guardrails and hmac.
    *******************************************************************************/
   @Test
   void mostRestrictiveGuardrailsAndHmac() throws Exception
   {
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "FULL").withValue("exact_match_per_hour", 0).withValue("min_entropy_enabled", false));
      insert(SecuredDataTables.POLICY, policyRow("cs_admin", "PII", "REVEALABLE").withValue("exact_match_per_hour", 7).withValue("miss_alert_consecutive", 3));
      var guardrails = resolver.guardrails(person, "email");
      assertThat(guardrails.exactMatchPerHour()).isEqualTo(7);
      assertThat(guardrails.missAlertConsecutive()).isEqualTo(3);
      assertThat(guardrails.minEntropyEnabled()).isTrue();
      String hash = resolver.fingerprintSearchValue("CANARY-SEARCH");
      assertThat(hash).isEqualTo(resolver.fingerprintSearchValue("CANARY-SEARCH")).doesNotContain("CANARY");
      assertThat(hash).isNotEqualTo(resolver.fingerprintSearchValue("different"));
   }

   /*******************************************************************************
    ** Reveal grant scope and expiration.
    *******************************************************************************/
   @Test
   void revealGrantScopeAndExpiration() throws Exception
   {
      insert(SecuredDataTables.REVEAL_GRANT, new QRecord().withValue("user_id", "u1").withValue("table_name", "person")
         .withValue("record_id", "7").withValue("field_name", "email").withValue("granted_at", NOW).withValue("expires_at", NOW.plusSeconds(10))
         .withValue("access_log_id", 1));
      assertThat(resolver.isRevealActive("person", "email", 7)).isTrue();
      assertThat(resolver.isRevealActive("person", "ssn", 7)).isFalse();
      assertThat(resolver.isRevealActive("person", "email", 8)).isFalse();
      CLOCK.now = NOW.plusSeconds(10);
      assertThat(resolver.isRevealActive("person", "email", 7)).isFalse();
   }
}
