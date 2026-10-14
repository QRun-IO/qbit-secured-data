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

package com.kingsrook.qbits.secureddata.standin;


import java.util.LinkedHashMap;
import java.util.Map;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.QSupplementalInstanceMetaData;


/*******************************************************************************
 ** Temporary registry for the subset needed by this QBit.
 *******************************************************************************/
// STAND-IN(core=QRun-IO/qqq#1142, removeBy=RC.6): copy of com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermissionsMetaData registration subset; delete when the pin moves to RC.6.
public class TableFeaturePermissionsMetaData implements QSupplementalInstanceMetaData
{
   private final Map<String, String> entries = new LinkedHashMap<>();



   /*******************************************************************************
    ** Registry name, distinct from the future core registry.
    *******************************************************************************/
   @Override
   public String getName()
   {
      return ("securedDataTableFeatures");
   }



   /*******************************************************************************
    ** Instance registry.
    *******************************************************************************/
   public static TableFeaturePermissionsMetaData ofOrWithNew(QInstance instance)
   {
      return (QSupplementalInstanceMetaData.ofOrWithNew(instance, "securedDataTableFeatures", TableFeaturePermissionsMetaData::new));
   }



   /*******************************************************************************
    ** Register the QBit's entry.
    *******************************************************************************/
   public TableFeaturePermissionsMetaData withPermission(String key, String value)
   {
      entries.put(key, value);
      return (this);
   }



   /*******************************************************************************
    ** Read-only registration view.
    *******************************************************************************/
   public Map<String, String> getEntries()
   {
      return (Map.copyOf(entries));
   }
}
