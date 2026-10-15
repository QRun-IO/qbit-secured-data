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

import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.StatusService;
import com.kingsrook.qqq.middleware.javalin.specs.BasicOperation;
import com.kingsrook.qqq.middleware.javalin.specs.extensions.AbstractJsonEndpointSpec;
import com.kingsrook.qqq.openapi.model.HttpMethod;
import com.kingsrook.qqq.openapi.model.Parameter;
import com.kingsrook.qqq.openapi.model.Schema;

/*******************************************************************************
 ** GET secured-data/status.
 *******************************************************************************/
public class SecuredDataStatusSpecV1 extends AbstractJsonEndpointSpec
{
   /*******************************************************************************
    ** Operation metadata.
    *******************************************************************************/
   @Override
   public BasicOperation defineBasicOperation()
   {
      return (new BasicOperation().withPath("/qbit/secured-data/status").withHttpMethod(HttpMethod.GET)
         .withTag(() -> "secured-data").withShortSummary("Status"));
   }

   /*******************************************************************************
    ** Request query parameters.
    *******************************************************************************/
   @Override
   public List<Parameter> defineRequestParameters()
   {
      return (List.of());
   }

   /*******************************************************************************
    ** Published component schemas.
    *******************************************************************************/
   @Override
   public Map<String, Schema> defineComponentSchemas()
   {
      Map<String, Schema> schemas = SecuredDataSchemas.all();
      return (Map.of("SecuredDataStatusResponseV1", schemas.get("SecuredDataStatusResponseV1"), "SecuredDataBreakGlassV1", schemas.get("SecuredDataBreakGlassV1"), "SecuredDataRevealAllowanceV1", schemas.get("SecuredDataRevealAllowanceV1")));
   }

   /*******************************************************************************
    ** Response component.
    *******************************************************************************/
   @Override
   protected String getResponseSchemaName()
   {
      return ("SecuredDataStatusResponseV1");
   }

   /*******************************************************************************
    ** Execute with the caller session supplied by the core middleware.
    *******************************************************************************/
   @Override
   protected Object handle(JsonInput input) throws Exception
   {
      return (new StatusService().status());
   }
}
