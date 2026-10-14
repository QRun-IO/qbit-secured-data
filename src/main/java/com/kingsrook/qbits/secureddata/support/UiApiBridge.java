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

import com.kingsrook.qqq.backend.core.model.metadata.QInstance;

/*******************************************************************************
 ** Optional UI API registration, with no linkage to unreleased middleware on RC.5.
 *******************************************************************************/
public final class UiApiBridge
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private UiApiBridge()
   {
   }

   /*******************************************************************************
    ** STAND-IN(core=QRun-IO/qqq#1128, removeBy=RC.6): register directly at RC.6.
    *******************************************************************************/
   public static void register(QInstance instance)
   {
      try
      {
         Class.forName("com.kingsrook.qqq.middleware.javalin.specs.extensions.MiddlewareSpecExtensionsMetaData");
         Class.forName("com.kingsrook.qbits.secureddata.uiapi.SecuredDataExtension").getMethod("register", QInstance.class).invoke(null, instance);
      }
      catch(ClassNotFoundException expected)
      {
         // RC.5 or a build without the uiapi source profile.
      }
      catch(ReflectiveOperationException e)
      {
         throw (new IllegalStateException("Unable to register secured-data UI API extension", e));
      }
   }
}
