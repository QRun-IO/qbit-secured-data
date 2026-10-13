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


import java.util.HashMap;
import java.util.Map;
import com.kingsrook.qqq.backend.core.model.metadata.producers.MetaDataCustomizerInterface;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Configuration for the secured-data qbit.
 *******************************************************************************/
public class SecuredDataQBitConfig implements QBitConfig
{
   private MetaDataCustomizerInterface<QTableMetaData> tableMetaDataCustomizer;
   private Map<String, String> defaultTierByClassification = new HashMap<>();



   /*******************************************************************************
    ** Getter for the optional table customizer.
    *******************************************************************************/
   @Override
   public MetaDataCustomizerInterface<QTableMetaData> getTableMetaDataCustomizer()
   {
      return (tableMetaDataCustomizer);
   }



   /*******************************************************************************
    ** Fluent setter for the optional table customizer.
    *******************************************************************************/
   public SecuredDataQBitConfig withTableMetaDataCustomizer(MetaDataCustomizerInterface<QTableMetaData> tableMetaDataCustomizer)
   {
      this.tableMetaDataCustomizer = tableMetaDataCustomizer;
      return (this);
   }



   /*******************************************************************************
    ** Getter for the default tiers by classification (initially empty).
    *******************************************************************************/
   public Map<String, String> getDefaultTierByClassification()
   {
      return (defaultTierByClassification);
   }



   /*******************************************************************************
    ** Fluent setter for the default tiers by classification.
    *******************************************************************************/
   public SecuredDataQBitConfig withDefaultTierByClassification(Map<String, String> defaultTierByClassification)
   {
      this.defaultTierByClassification = defaultTierByClassification;
      return (this);
   }
}
