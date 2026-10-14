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


import java.lang.reflect.InvocationTargetException;
import com.kingsrook.qbits.secureddata.standin.ClientChannelsMetaData;
import com.kingsrook.qbits.secureddata.standin.DataClassification;
import com.kingsrook.qbits.secureddata.standin.TableFeaturePermissionsMetaData;
import com.kingsrook.qqq.backend.core.actions.ai.AiExposure;
import com.kingsrook.qqq.backend.core.actions.ai.AiFieldMetaData;
import com.kingsrook.qqq.backend.core.actions.ai.AiTableMetaData;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.actions.permissions.TablePermissionSubType;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;


/*******************************************************************************
 ** Adapters for #1141/#1142 APIs missing from the pinned released core.
 *******************************************************************************/
public final class CoreMetadataBridge
{
   private static final String PERMISSIONS = "com.kingsrook.qqq.backend.core.model.metadata.permissions.";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private CoreMetadataBridge()
   {
   }



   /*******************************************************************************
    ** Normalized client channel, with RC.5 session-adapter support.
    *******************************************************************************/
   public static String channel(QSession session)
   {
      return (session == null ? null : (String) optional(session, "getClientChannelName"));
   }



   /*******************************************************************************
    ** Read a code classification from released/future core or temporary metadata.
    *******************************************************************************/
   public static DataClassification classification(QTableMetaData table, QFieldMetaData field)
   {
      Object ai = field == null ? AiTableMetaData.of(table) : AiFieldMetaData.of(field);
      Object result = ai == null ? null : optional(ai, "getClassification");
      if(result != null)
      {
         return (DataClassification.valueOf(result.toString()));
      }
      Object fallback = field == null ? table.getSupplementalMetaData("securedDataAi") : field.getSupplementalMetaData("securedDataAi");
      return (fallback == null ? null : (DataClassification) optional(fallback, "getClassification"));
   }



   /*******************************************************************************
    ** Protect the QBit's own AI routing metadata on either core version.
    *******************************************************************************/
   public static void classifyTable(QTableMetaData table)
   {
      AiTableMetaData ai = AiTableMetaData.ofOrWithNew(table);
      ai.withExposure(AiExposure.NONE);
      setClassification(ai, DataClassification.CONFIDENTIAL);
      table.withSupplementalMetaData(new com.kingsrook.qbits.secureddata.standin.AiTableMetaData().withClassification(DataClassification.CONFIDENTIAL));
   }



   /*******************************************************************************
    ** Seed opt-in name heuristics without overriding explicit code metadata.
    *******************************************************************************/
   public static void classifyField(QFieldMetaData field, DataClassification classification)
   {
      AiFieldMetaData ai = AiFieldMetaData.of(field);
      if(ai == null)
      {
         ai = new AiFieldMetaData();
         field.withSupplementalMetaData(ai);
      }
      setClassification(ai, classification);
      field.withSupplementalMetaData(new com.kingsrook.qbits.secureddata.standin.AiFieldMetaData().withClassification(classification));
   }



   /*******************************************************************************
    ** Copy the classification into core when that property exists.
    *******************************************************************************/
   private static void setClassification(Object ai, DataClassification classification)
   {
      try
      {
         Class<?> type = Class.forName("com.kingsrook.qqq.backend.core.actions.ai.DataClassification");
         Object value = type.getMethod("valueOf", String.class).invoke(null, classification.name());
         ai.getClass().getMethod("withClassification", type).invoke(ai, value);
      }
      catch(ClassNotFoundException | NoSuchMethodException expected)
      {
         // RC.5 has exposure-only metadata; the stand-in carries classification.
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Unable to set core classification", e));
      }
   }



   /*******************************************************************************
    ** Register the assistant wall and both features. Catalog applies to all tables.
    *******************************************************************************/
   public static void register(QInstance instance)
   {
      ClientChannelsMetaData.ofOrWithNew(instance).withDeniedPattern("assistant", "secured_data_*");
      registerChannel(instance);
      for(String suffix : new String[] {"secured_data_full", "secured_data_reveal"})
      {
         String label = "Secured data: " + suffix.substring("secured_data_".length());
         TableFeaturePermissionsMetaData.ofOrWithNew(instance).withPermission(suffix, label);
         try
         {
            Class<?> registry = Class.forName(PERMISSIONS + "TableFeaturePermissionsMetaData");
            Class<?> entry = Class.forName(PERMISSIONS + "TableFeaturePermission");
            Object feature = entry.getConstructor().newInstance();
            entry.getMethod("withSuffix", String.class).invoke(feature, suffix);
            entry.getMethod("withLabel", String.class).invoke(feature, label);
            Object metadata = registry.getMethod("ofOrWithNew", QInstance.class).invoke(null, instance);
            registry.getMethod("withPermission", entry).invoke(metadata, feature);
         }
         catch(ClassNotFoundException expected)
         {
            // RC.5 uses the stand-in catalog until core exposes the registry.
         }
         catch(ReflectiveOperationException e)
         {
            throw (new IllegalStateException("Unable to register table features", e));
         }
      }
   }



   /*******************************************************************************
    ** Core channel enforcement when the #1141 API is installed.
    *******************************************************************************/
   private static void registerChannel(QInstance instance)
   {
      try
      {
         Class<?> type = Class.forName(PERMISSIONS + "ClientChannelsMetaData");
         Object metadata = type.getMethod("ofOrWithNew", QInstance.class).invoke(null, instance);
         type.getMethod("withDeniedPattern", String.class, String.class).invoke(metadata, "assistant", "secured_data_*");
      }
      catch(ClassNotFoundException expected)
      {
         // The RC.5 custom permission checker also enforces the local wall.
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Unable to register client channel wall", e));
      }
   }



   /*******************************************************************************
    ** Use core's feature semantics, including table READ and permission base names.
    *******************************************************************************/
   public static boolean hasFeature(QTableMetaData table, String suffix)
   {
      try
      {
         return ((Boolean) PermissionsHelper.class.getMethod("hasTableFeaturePermission", QTableMetaData.class, String.class).invoke(null, table, suffix));
      }
      catch(NoSuchMethodException expected)
      {
         if(table.getIsHidden() || !PermissionsHelper.hasTablePermission(new GetInput(table.getName()), table.getName(), TablePermissionSubType.READ))
         {
            return (false);
         }
         QPermissionRules rules = PermissionsHelper.getEffectivePermissionRules(table, QContext.getQInstance());
         String base = permissionBase(table);
         return (rules.getLevel() == PermissionLevel.NOT_PROTECTED || QContext.getQSession().hasPermission(base + "." + suffix));
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Core feature permission check failed", e));
      }
   }



   /*******************************************************************************
    ** Missing properties are expected only on RC.5; invocation errors fail closed.
    *******************************************************************************/
   private static Object optional(Object target, String name)
   {
      try
      {
         return (target.getClass().getMethod(name).invoke(target));
      }
      catch(NoSuchMethodException expected)
      {
         return (null);
      }
      catch(IllegalAccessException | InvocationTargetException e)
      {
         throw (new IllegalStateException("Core metadata adapter failed", e));
      }
   }


   /*******************************************************************************
    ** RC.5 keeps core's equivalent helper package-private.
    *******************************************************************************/
   public static String permissionBase(QTableMetaData table)
   {
      QPermissionRules rules = PermissionsHelper.getEffectivePermissionRules(table, QContext.getQInstance());
      String base = rules.getPermissionBaseName();
      return (base == null || base.isBlank() ? table.getName() : base);
   }



   /*******************************************************************************
    ** Promote temporary host code classifications so future core AI routing sees them.
    *******************************************************************************/
   public static void promoteClassifications(QInstance instance)
   {
      for(QTableMetaData table : instance.getTables().values())
      {
         DataClassification tableClassification = classification(table, null);
         if(tableClassification != null)
         {
            setClassification(AiTableMetaData.ofOrWithNew(table), tableClassification);
         }
         for(QFieldMetaData field : table.getFields().values())
         {
            DataClassification fieldClassification = classification(table, field);
            if(fieldClassification != null)
            {
               AiFieldMetaData ai = AiFieldMetaData.of(field);
               if(ai == null)
               {
                  ai = new AiFieldMetaData();
                  field.withSupplementalMetaData(ai);
               }
               setClassification(ai, fieldClassification);
            }
         }
      }
   }

}
