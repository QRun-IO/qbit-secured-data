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


import java.security.SecureRandom;
import java.time.Clock;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import com.kingsrook.qbits.secureddata.standin.DataClassification;
import com.kingsrook.qbits.secureddata.standin.FieldAccessTier;
import com.kingsrook.qqq.backend.core.model.metadata.producers.MetaDataCustomizerInterface;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Configuration for policy resolution and bounded asynchronous access logging.
 *******************************************************************************/
public class SecuredDataQBitConfig implements QBitConfig
{
   private static final byte[] JVM_KEY = new SecureRandom().generateSeed(32);
   private Map<String, String> defaultTierByClassification = new HashMap<>(Map.of("CONFIDENTIAL", "FULL", "PII", "MASKED", "PHI", "MASKED"));
   private String backendName = "memory";
   private Clock clock = Clock.systemUTC();
   private int accessLogQueueCapacity = 4096;
   private long accessLogFlushIntervalMillis = 250;
   private int exactMatchPerHour = 20;
   private int missAlertConsecutive = 5;
   private int distinctValueAlert = 15;
   private boolean minEntropyEnabled = true;
   private boolean nameHeuristics = false;
   private Set<DataClassification> viewLogClassifications = EnumSet.of(DataClassification.PII, DataClassification.PHI);
   private Supplier<byte[]> fingerprintKeySupplier = () -> JVM_KEY.clone();
   private MetaDataCustomizerInterface<QTableMetaData> tableMetaDataCustomizer = null;



   /*******************************************************************************
    ** Get backendName.
    *******************************************************************************/
   public String getBackendName()
   {
      return (backendName);
   }



   /*******************************************************************************
    ** Configure backendName.
    *******************************************************************************/
   public SecuredDataQBitConfig withBackendName(String backendName)
   {
      this.backendName = backendName;
      return (this);
   }



   /*******************************************************************************
    ** Get clock.
    *******************************************************************************/
   public Clock getClock()
   {
      return (clock);
   }



   /*******************************************************************************
    ** Configure clock.
    *******************************************************************************/
   public SecuredDataQBitConfig withClock(Clock clock)
   {
      this.clock = clock;
      return (this);
   }



   /*******************************************************************************
    ** Get accessLogQueueCapacity.
    *******************************************************************************/
   public int getAccessLogQueueCapacity()
   {
      return (accessLogQueueCapacity);
   }



   /*******************************************************************************
    ** Configure accessLogQueueCapacity.
    *******************************************************************************/
   public SecuredDataQBitConfig withAccessLogQueueCapacity(int accessLogQueueCapacity)
   {
      this.accessLogQueueCapacity = accessLogQueueCapacity;
      return (this);
   }



   /*******************************************************************************
    ** Get accessLogFlushIntervalMillis.
    *******************************************************************************/
   public long getAccessLogFlushIntervalMillis()
   {
      return (accessLogFlushIntervalMillis);
   }



   /*******************************************************************************
    ** Configure accessLogFlushIntervalMillis.
    *******************************************************************************/
   public SecuredDataQBitConfig withAccessLogFlushIntervalMillis(long accessLogFlushIntervalMillis)
   {
      this.accessLogFlushIntervalMillis = accessLogFlushIntervalMillis;
      return (this);
   }



   /*******************************************************************************
    ** Get exactMatchPerHour.
    *******************************************************************************/
   public int getExactMatchPerHour()
   {
      return (exactMatchPerHour);
   }



   /*******************************************************************************
    ** Configure exactMatchPerHour.
    *******************************************************************************/
   public SecuredDataQBitConfig withExactMatchPerHour(int exactMatchPerHour)
   {
      this.exactMatchPerHour = exactMatchPerHour;
      return (this);
   }



   /*******************************************************************************
    ** Get missAlertConsecutive.
    *******************************************************************************/
   public int getMissAlertConsecutive()
   {
      return (missAlertConsecutive);
   }



   /*******************************************************************************
    ** Configure missAlertConsecutive.
    *******************************************************************************/
   public SecuredDataQBitConfig withMissAlertConsecutive(int missAlertConsecutive)
   {
      this.missAlertConsecutive = missAlertConsecutive;
      return (this);
   }



   /*******************************************************************************
    ** Get distinctValueAlert.
    *******************************************************************************/
   public int getDistinctValueAlert()
   {
      return (distinctValueAlert);
   }



   /*******************************************************************************
    ** Configure distinctValueAlert.
    *******************************************************************************/
   public SecuredDataQBitConfig withDistinctValueAlert(int distinctValueAlert)
   {
      this.distinctValueAlert = distinctValueAlert;
      return (this);
   }



   /*******************************************************************************
    ** Get minEntropyEnabled.
    *******************************************************************************/
   public boolean getMinEntropyEnabled()
   {
      return (minEntropyEnabled);
   }



   /*******************************************************************************
    ** Configure minEntropyEnabled.
    *******************************************************************************/
   public SecuredDataQBitConfig withMinEntropyEnabled(boolean minEntropyEnabled)
   {
      this.minEntropyEnabled = minEntropyEnabled;
      return (this);
   }



   /*******************************************************************************
    ** Get nameHeuristics.
    *******************************************************************************/
   public boolean getNameHeuristics()
   {
      return (nameHeuristics);
   }



   /*******************************************************************************
    ** Configure nameHeuristics.
    *******************************************************************************/
   public SecuredDataQBitConfig withNameHeuristics(boolean nameHeuristics)
   {
      this.nameHeuristics = nameHeuristics;
      return (this);
   }



   /*******************************************************************************
    ** Get viewLogClassifications.
    *******************************************************************************/
   public Set<DataClassification> getViewLogClassifications()
   {
      return (viewLogClassifications);
   }



   /*******************************************************************************
    ** Configure viewLogClassifications.
    *******************************************************************************/
   public SecuredDataQBitConfig withViewLogClassifications(Set<DataClassification> viewLogClassifications)
   {
      this.viewLogClassifications = viewLogClassifications;
      return (this);
   }



   /*******************************************************************************
    ** Get fingerprintKeySupplier.
    *******************************************************************************/
   public Supplier<byte[]> getFingerprintKeySupplier()
   {
      return (fingerprintKeySupplier);
   }



   /*******************************************************************************
    ** Configure fingerprintKeySupplier.
    *******************************************************************************/
   public SecuredDataQBitConfig withFingerprintKeySupplier(Supplier<byte[]> fingerprintKeySupplier)
   {
      this.fingerprintKeySupplier = fingerprintKeySupplier;
      return (this);
   }



   /*******************************************************************************
    ** Get tableMetaDataCustomizer.
    *******************************************************************************/
   @Override
   public MetaDataCustomizerInterface<QTableMetaData> getTableMetaDataCustomizer()
   {
      return (tableMetaDataCustomizer);
   }



   /*******************************************************************************
    ** Configure tableMetaDataCustomizer.
    *******************************************************************************/
   public SecuredDataQBitConfig withTableMetaDataCustomizer(MetaDataCustomizerInterface<QTableMetaData> tableMetaDataCustomizer)
   {
      this.tableMetaDataCustomizer = tableMetaDataCustomizer;
      return (this);
   }



   /*******************************************************************************
    ** Default tier for a classification.
    *******************************************************************************/
   public SecuredDataQBitConfig withDefaultTier(DataClassification classification, FieldAccessTier tier)
   {
      defaultTierByClassification.put(classification.name(), tier.name());
      return (this);
   }



   /*******************************************************************************
    ** Compatibility getter for scaffold configuration.
    *******************************************************************************/
   public Map<String, String> getDefaultTierByClassification()
   {
      return (Map.copyOf(defaultTierByClassification));
   }



   /*******************************************************************************
    ** Replace configured defaults; missing restricted classifications fail closed.
    *******************************************************************************/
   public SecuredDataQBitConfig withDefaultTierByClassification(Map<String, String> tiers)
   {
      tiers.forEach((classification, tier) ->
      {
         DataClassification.valueOf(classification);
         FieldAccessTier.valueOf(tier);
      });
      defaultTierByClassification = new HashMap<>(tiers);
      return (this);
   }



   /*******************************************************************************
    ** Resolve the configured default.
    *******************************************************************************/
   public FieldAccessTier defaultTier(DataClassification classification)
   {
      return (FieldAccessTier.valueOf(defaultTierByClassification.getOrDefault(classification.name(), "MASKED")));
   }



   /*******************************************************************************
    ** Reject invalid infrastructure and guardrail settings at startup.
    *******************************************************************************/
   public void validate()
   {
      if(backendName == null || backendName.isBlank() || accessLogQueueCapacity < 1 || accessLogFlushIntervalMillis < 1
         || exactMatchPerHour < 0 || missAlertConsecutive < 0 || distinctValueAlert < 0)
      {
         throw (new IllegalArgumentException("Invalid secured-data configuration"));
      }
      Objects.requireNonNull(clock);
      Objects.requireNonNull(viewLogClassifications);
      Objects.requireNonNull(fingerprintKeySupplier);
   }
}
