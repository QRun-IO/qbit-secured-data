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

package com.kingsrook.qbits.secureddata.uiapi;

import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.middleware.javalin.specs.extensions.MiddlewareSpecExtension;
import com.kingsrook.qqq.middleware.javalin.specs.extensions.MiddlewareSpecExtensionsMetaData;

/*******************************************************************************
 ** STAND-IN(core=QRun-IO/qqq#1128, removeBy=RC.6): move to main source root.
 *******************************************************************************/
public final class SecuredDataExtension
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataExtension()
   {
   }

   /*******************************************************************************
    ** The secured-data UI API, version 1.0.0.
    *******************************************************************************/
   public static MiddlewareSpecExtension defineExtension()
   {
      return (new MiddlewareSpecExtension().withName("secured-data").withSemanticVersion("1.0.0")
         .withDescription("Reveal grants and break-glass status")
         .withSpec(SecuredDataRevealSpecV1.class).withSpec(SecuredDataRevealOptionsSpecV1.class).withSpec(SecuredDataStatusSpecV1.class));
   }

   /*******************************************************************************
    ** Called reflectively by the producer.
    *******************************************************************************/
   public static void register(QInstance instance)
   {
      MiddlewareSpecExtensionsMetaData.ofOrWithNew(instance).withExtension(defineExtension());
   }
}
