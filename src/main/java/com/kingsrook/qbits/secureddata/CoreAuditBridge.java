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

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import com.kingsrook.qbits.secureddata.standin.ClassifiedValueKeySource;
import com.kingsrook.qbits.secureddata.standin.ClassifiedValueTokens;
import com.kingsrook.qbits.secureddata.standin.DMLType;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.actions.audits.AuditAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.audits.AuditInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.ActionFlag;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** A single reflection boundary for #1182, failing closed for incompatible hooks.
 *******************************************************************************/
// STAND-IN(core=QRun-IO/qqq#1182, removeBy=RC.8)
public final class CoreAuditBridge
{
   private static final String TOKENS = "com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.";
   private static final String AUDITS = "com.kingsrook.qqq.backend.core.actions.audits.";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private CoreAuditBridge()
   {
   }

   /*******************************************************************************
    ** Core hook availability (RC.6 has none).
    *******************************************************************************/
   public static boolean available()
   {
      try
      {
         Class.forName(TOKENS + "ClassifiedValueTokens");
         return (true);
      }
      catch(ClassNotFoundException expected)
      {
         return (false);
      }
   }

   /*******************************************************************************
    ** Register exact #1182 contracts when present; no silent partial registration.
    *******************************************************************************/
   public static void register(QInstance instance, SecuredDataRuntime runtime)
   {
      if(!available())
      {
         return;
      }
      try
      {
         Class<?> contract = Class.forName(TOKENS + "ClassifiedValueKeySource");
         Object keyProxy = Proxy.newProxyInstance(contract.getClassLoader(), new Class<?>[] {contract}, (self, method, args) ->
         {
            if(method.getDeclaringClass() == Object.class)
            {
               return (objectMethod(self, method.getName(), args));
            }
            Optional<ClassifiedValueKeySource.KeyAndId> key = switch(method.getName())
            {
               case "instanceKey" -> runtime.keys().instanceKey();
               case "keyForRecordField" -> runtime.keys().keyForRecordField((String) args[0], (String) args[1], (Serializable) args[2], (Boolean) args[3]);
               default -> throw new UnsupportedOperationException(method.getName());
            };
            return (key.isEmpty() ? Optional.empty() : Optional.of(Class.forName(TOKENS + "ClassifiedValueKeySource$KeyAndId")
               .getConstructor(byte[].class, String.class).newInstance(key.get().key(), key.get().id())));
         });
         Class<?> metadata = Class.forName(TOKENS + "ClassifiedValueKeySourceMetaData");
         Object registry = metadata.getMethod("ofOrWithNew", QInstance.class).invoke(null, instance);
         metadata.getMethod("withKeySourceInstance", contract).invoke(registry, keyProxy);
         SecuredDataAuditProtector protector = new SecuredDataAuditProtector();
         Class<?> auditContract = Class.forName(AUDITS + "AuditValueProtectorInterface");
         Object auditProxy = Proxy.newProxyInstance(auditContract.getClassLoader(), new Class<?>[] {auditContract}, (self, method, args) ->
         {
            if(method.getDeclaringClass() == Object.class)
            {
               return (objectMethod(self, method.getName(), args));
            }
            if("classificationOf".equals(method.getName()))
            {
               return (protector.classificationOf((QTableMetaData) args[0], (QFieldMetaData) args[1]));
            }
            if(!"protect".equals(method.getName()))
            {
               throw (new UnsupportedOperationException(method.getName()));
            }
            var values = protector.protect((QTableMetaData) args[0], (QFieldMetaData) args[1], (Serializable) args[2], (Serializable) args[3], (Serializable) args[4], DMLType.valueOf(args[5].toString()));
            return (Class.forName(AUDITS + "ProtectedAuditValues").getConstructor(String.class, String.class, String.class)
               .newInstance(values.oldToken(), values.newToken(), values.message()));
         });
         metadata = Class.forName(AUDITS + "AuditValueProtectionMetaData");
         registry = metadata.getMethod("ofOrWithNew", QInstance.class).invoke(null, instance);
         metadata.getMethod("withProtectorInstance", auditContract).invoke(registry, auditProxy);
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Unable to register core audit protection", e));
      }
   }

   /*******************************************************************************
    ** Stable object behavior for registered service proxies.
    *******************************************************************************/
   private static Object objectMethod(Object self, String name, Object[] args)
   {
      return (switch(name)
      {
         case "toString" -> "Secured-data audit bridge";
         case "hashCode" -> System.identityHashCode(self);
         case "equals" -> self == args[0];
         default -> throw new UnsupportedOperationException(name);
      });
   }

   /*******************************************************************************
    ** Delegate to the installed core helper, with contract-identical RC.6 fallback.
    *******************************************************************************/
   public static String token(QTableMetaData table, QFieldMetaData field, Serializable pk, Serializable value)
   {
      if(!available())
      {
         return (ClassifiedValueTokens.forRecordField(table, field, pk, value));
      }
      try
      {
         return ((String) Class.forName(TOKENS + "ClassifiedValueTokens").getMethod("forRecordField", QTableMetaData.class, QFieldMetaData.class, Serializable.class, Serializable.class)
            .invoke(null, table, field, pk, value));
      }
      catch(InvocationTargetException e)
      {
         throw (new IllegalStateException("Classified token creation failed"));
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Incompatible core token API", e));
      }
   }

   /*******************************************************************************
    ** Real WipeAuditFlag on snapshot; RC.6 uses a value-free explicit audit below.
    *******************************************************************************/
   public static void flag(UpdateInput input, String ruleId)
   {
      if(!available())
      {
         input.setOmitDmlAudit(true);
         return;
      }
      try
      {
         ActionFlag flag = (ActionFlag) Class.forName("com.kingsrook.qqq.backend.core.model.actions.tables.WipeAuditFlag").getConstructor(String.class).newInstance(ruleId);
         input.setFlags(Set.of(flag));
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Incompatible core wipe API", e));
      }
   }

   /*******************************************************************************
    ** Append immutable value-free audit evidence in the batch transaction.
    *******************************************************************************/
   public static void detail(QTableMetaData table, Serializable pk, String field, String ruleId, boolean shredded, QBackendTransaction transaction) throws QException
   {
      if(shredded && available())
      {
         try
         {
            Class.forName(AUDITS + "AuditShreddedEvent").getMethod("shreddedDetail", QTableMetaData.class, Serializable.class, QFieldMetaData.class, String.class, QBackendTransaction.class)
               .invoke(null, table, pk, table.getField(field), ruleId, transaction);
            return;
         }
         catch(ReflectiveOperationException e)
         {
            throw (new QException("Unable to append shredded audit detail"));
         }
      }
      String message = (shredded ? "Audit values shredded" : "Wiped") + " per policy";
      QRecord detail = new QRecord().withValue("fieldName", field).withValue("newValue", (shredded ? "shredded:v1:" : "wiped:v1:") + ruleId).withValue("message", message);
      AuditInput input = new AuditInput();
      input.setTransaction(transaction);
      AuditAction.appendToInput(input, table.getName(), pk, AuditAction.getRecordSecurityKeyValues(table,
         new QRecord().withValue(table.getPrimaryKeyField(), pk), Optional.empty()), message, List.of(detail));
      new AuditAction().execute(input);
   }
}
