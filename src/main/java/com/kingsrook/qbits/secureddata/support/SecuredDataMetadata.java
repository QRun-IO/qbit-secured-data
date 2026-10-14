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

package com.kingsrook.qbits.secureddata.support;

import com.kingsrook.qqq.backend.core.actions.ai.AiExposure;
import com.kingsrook.qqq.backend.core.actions.ai.AiFieldMetaData;
import com.kingsrook.qqq.backend.core.actions.ai.AiTableMetaData;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.ClientChannelsMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermission;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermissionsMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;

/*******************************************************************************
 ** Secured-data defaults and registration using the released core metadata API.
 *******************************************************************************/
public final class SecuredDataMetadata
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataMetadata()
   {
   }

   /*******************************************************************************
    ** Normalized trusted client channel.
    *******************************************************************************/
   public static String channel(QSession session)
   {
      return (session == null ? null : session.getClientChannelName());
   }

   /*******************************************************************************
    ** Read code classification without applying field/table precedence.
    *******************************************************************************/
   public static DataClassification classification(QTableMetaData table, QFieldMetaData field)
   {
      if(field == null)
      {
         AiTableMetaData ai = AiTableMetaData.of(table);
         return (ai == null ? null : ai.getClassification());
      }
      AiFieldMetaData ai = AiFieldMetaData.of(field);
      return (ai == null ? null : ai.getClassification());
   }

   /*******************************************************************************
    ** Protect the QBit's own AI routing metadata.
    *******************************************************************************/
   public static void classifyTable(QTableMetaData table)
   {
      AiTableMetaData.ofOrWithNew(table).withExposure(AiExposure.NONE).withClassification(DataClassification.CONFIDENTIAL);
   }

   /*******************************************************************************
    ** Seed opt-in name heuristics without replacing other AI field metadata.
    *******************************************************************************/
   public static void classifyField(QFieldMetaData field, DataClassification classification)
   {
      AiFieldMetaData ai = AiFieldMetaData.of(field);
      if(ai == null)
      {
         ai = new AiFieldMetaData();
         field.withSupplementalMetaData(ai);
      }
      ai.withClassification(classification);
   }

   /*******************************************************************************
    ** Register the assistant wall and both table features.
    *******************************************************************************/
   public static void register(QInstance instance)
   {
      ClientChannelsMetaData.ofOrWithNew(instance).withDeniedPattern("assistant", "secured_data_*");
      for(String suffix : new String[] {"secured_data_full", "secured_data_reveal"})
      {
         TableFeaturePermissionsMetaData.ofOrWithNew(instance).withPermission(new TableFeaturePermission()
            .withSuffix(suffix).withLabel("Secured data: " + suffix.substring("secured_data_".length())));
      }
   }

   /*******************************************************************************
    ** Use core feature semantics, including table READ and permission base names.
    *******************************************************************************/
   public static boolean hasFeature(QTableMetaData table, String suffix)
   {
      return (PermissionsHelper.hasTableFeaturePermission(table, suffix));
   }

   /*******************************************************************************
    ** Effective permission base name.
    *******************************************************************************/
   public static String permissionBase(QTableMetaData table)
   {
      QPermissionRules rules = PermissionsHelper.getEffectivePermissionRules(table, QContext.getQInstance());
      String base = rules.getPermissionBaseName();
      return (base == null || base.isBlank() ? table.getName() : base);
   }
}
