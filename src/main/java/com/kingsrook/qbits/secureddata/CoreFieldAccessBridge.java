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
import java.util.concurrent.atomic.AtomicBoolean;
import com.kingsrook.qbits.secureddata.standin.FieldAccessDecision;
import com.kingsrook.qbits.secureddata.standin.FieldAccessEvent;
import com.kingsrook.qbits.secureddata.standin.FieldAccessEventType;
import com.kingsrook.qbits.secureddata.standin.FieldAccessOutcome;
import com.kingsrook.qbits.secureddata.standin.FieldAccessResolverInterface;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** The only boundary between the temporary field-access API and unreleased core.
 *******************************************************************************/
public final class CoreFieldAccessBridge
{
   private static final String PACKAGE = "com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.";
   private static final QLogger LOG = QLogger.getLogger(CoreFieldAccessBridge.class);
   private static final AtomicBoolean WARNED = new AtomicBoolean();



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private CoreFieldAccessBridge()
   {
   }



   /*******************************************************************************
    ** Register only when core can actually enforce field access.
    *******************************************************************************/
   public static boolean register(QInstance instance, FieldAccessResolverInterface resolver)
   {
      try
      {
         Class<?> metadata = Class.forName(PACKAGE + "FieldAccessResolverMetaData");
         Class<?> contract = Class.forName(PACKAGE + "FieldAccessResolverInterface");
         Object proxy = Proxy.newProxyInstance(contract.getClassLoader(), new Class<?>[] {contract}, (self, method, args) ->
         {
            return (switch(method.getName())
            {
               case "resolve" -> decision(resolver.resolve((QTableMetaData) args[0], (QFieldMetaData) args[1]));
               case "getAccessFingerprint" -> resolver.getAccessFingerprint();
               case "isRevealActive" -> resolver.isRevealActive((String) args[0], (String) args[1], (Serializable) args[2]);
               case "fingerprintSearchValue" -> resolver.fingerprintSearchValue((Serializable) args[0]);
               case "checkExactMatch" ->
               {
                  resolver.checkExactMatch(event(args[0]));
                  yield null;
               }
               case "onAccess" ->
               {
                  resolver.onAccess(event(args[0]));
                  yield null;
               }
               case "toString" -> "SecuredData core bridge";
               case "hashCode" -> System.identityHashCode(self);
               case "equals" -> self == args[0];
               default -> throw new UnsupportedOperationException(method.getName());
            });
         });
         Object registry = metadata.getMethod("ofOrWithNew", QInstance.class).invoke(null, instance);
         metadata.getMethod("withResolverInstance", contract).invoke(registry, proxy);
         return (true);
      }
      catch(ClassNotFoundException e)
      {
         if(WARNED.compareAndSet(false, true))
         {
            LOG.info("Secured-data field enforcement needs QQQ RC.6+; policy and access-log services are available.");
         }
         return (false);
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Core field-access API is incompatible", unwrap(e)));
      }
   }



   /*******************************************************************************
    ** Construct the core record by its declared component types and enum names.
    *******************************************************************************/
   private static Object decision(FieldAccessDecision decision) throws ReflectiveOperationException
   {
      Class<?> type = Class.forName(PACKAGE + "FieldAccessDecision");
      Class<?> tier = type.getRecordComponents()[0].getType();
      Class<?> mask = type.getRecordComponents()[1].getType();
      return (type.getConstructor(tier, mask, String.class, boolean.class).newInstance(
         enumValue(tier, decision.tier().name()), decision.maskStyle() == null ? null : enumValue(mask, decision.maskStyle().name()),
         decision.reason(), decision.exactMatchAllowed()));
   }



   /*******************************************************************************
    ** Convert enum types without sharing class identity across the bridge.
    *******************************************************************************/
   private static Object enumValue(Class<?> type, String name) throws ReflectiveOperationException
   {
      return (type.getMethod("valueOf", String.class).invoke(null, name));
   }



   /*******************************************************************************
    ** Events carry identifiers and keyed fingerprints, never search literals.
    *******************************************************************************/
   @SuppressWarnings("unchecked")
   private static FieldAccessEvent event(Object source) throws ReflectiveOperationException
   {
      Class<?> type = source.getClass();
      Object outcome = type.getMethod("getOutcome").invoke(source);
      return (new FieldAccessEvent()
         .withType(FieldAccessEventType.valueOf(type.getMethod("getType").invoke(source).toString()))
         .withTableName((String) type.getMethod("getTableName").invoke(source))
         .withFieldNames((List<String>) type.getMethod("getFieldNames").invoke(source))
         .withPrimaryKeys((List<Serializable>) type.getMethod("getPrimaryKeys").invoke(source))
         .withRecordCount((Integer) type.getMethod("getRecordCount").invoke(source))
         .withActionName((String) type.getMethod("getActionName").invoke(source))
         .withOutcome(outcome == null ? null : FieldAccessOutcome.valueOf(outcome.toString()))
         .withSearchValueFingerprints((List<String>) type.getMethod("getSearchValueFingerprints").invoke(source)));
   }



   /*******************************************************************************
    ** Preserve the startup failure, including duplicate resolver registration.
    *******************************************************************************/
   private static Throwable unwrap(ReflectiveOperationException exception)
   {
      return (exception instanceof InvocationTargetException invocation ? invocation.getCause() : exception);
   }
}
