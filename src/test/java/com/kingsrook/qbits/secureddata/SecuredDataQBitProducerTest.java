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
import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.producers.MetaDataCustomizerInterface;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Verify the scaffold's registration and configuration contract.
 *******************************************************************************/
class SecuredDataQBitProducerTest
{
   /*******************************************************************************
    ** Produce the identity and exact config into an otherwise empty instance.
    *******************************************************************************/
   @Test
   void producesQBitWithoutTables()
   {
      QInstance instance = new QInstance();
      SecuredDataQBitConfig config = new SecuredDataQBitConfig();
      SecuredDataQBitProducer producer = new SecuredDataQBitProducer().withQBitConfig(config);
      MetaDataProducerMultiOutput output = producer.produce(instance);
      QBitMetaData qBit = instance.getQBits().get("com.kingsrook.qbits:qbit-secured-data");

      assertThat(qBit).isNotNull();
      assertThat(qBit.getGroupId()).isEqualTo("com.kingsrook.qbits");
      assertThat(qBit.getArtifactId()).isEqualTo("qbit-secured-data");
      assertThat(qBit.getVersion()).isEqualTo("1.0.0");
      assertThat(qBit.getConfig()).isSameAs(config);
      assertThat(producer.getQBitConfig()).isSameAs(config);
      assertThat(producer.isEnabled()).isTrue();
      assertThat(producer.getNamespace()).isNull();
      assertThat(output.getEach(QBitMetaData.class)).containsExactly(qBit);
      assertThat(output.getEach(QTableMetaData.class)).isEmpty();
      assertThat(instance.getTables()).isEmpty();
      assertThat(config.getDefaultTierByClassification()).isEmpty();
      assertThat(config.getTableMetaDataCustomizer()).isNull();
   }



   /*******************************************************************************
    ** Configured instances may be namespaced; unconfigured scanning is disabled.
    *******************************************************************************/
   @Test
   void supportsNamespacedConfiguration()
   {
      assertThat(new SecuredDataQBitProducer().isEnabled()).isFalse();
      MetaDataCustomizerInterface<QTableMetaData> customizer = (instance, table) -> table;
      Map<String, String> tiers = Map.of("CONFIDENTIAL", "MASKED");
      SecuredDataQBitConfig config = new SecuredDataQBitConfig()
         .withTableMetaDataCustomizer(customizer)
         .withDefaultTierByClassification(tiers);
      SecuredDataQBitProducer producer = new SecuredDataQBitProducer()
         .withQBitConfig(config)
         .withNamespace("test");
      QInstance instance = new QInstance();
      producer.produce(instance);

      assertThat(producer.getNamespace()).isEqualTo("test");
      assertThat(instance.getQBits().get("com.kingsrook.qbits:qbit-secured-data:test").getConfig()).isSameAs(config);
      assertThat(config.getTableMetaDataCustomizer()).isSameAs(customizer);
      assertThat(config.getDefaultTierByClassification()).containsExactlyEntriesOf(tiers);
      assertThat(new SecuredDataQBitConfig().getDefaultTierByClassification()).isEmpty();
      assertThat(instance.getTables()).isEmpty();
   }
}
