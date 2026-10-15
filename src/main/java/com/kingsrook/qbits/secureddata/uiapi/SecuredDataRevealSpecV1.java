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

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.reveal.RevealCappedException;
import com.kingsrook.qbits.secureddata.reveal.RevealService;
import com.kingsrook.qqq.backend.core.exceptions.QBadRequestException;
import com.kingsrook.qqq.middleware.javalin.specs.BasicOperation;
import com.kingsrook.qqq.middleware.javalin.specs.extensions.AbstractJsonEndpointSpec;
import com.kingsrook.qqq.middleware.javalin.specs.v1.responses.BasicErrorResponseV1;
import com.kingsrook.qqq.openapi.model.HttpMethod;
import com.kingsrook.qqq.openapi.model.Parameter;
import com.kingsrook.qqq.openapi.model.Schema;

/*******************************************************************************
 ** POST secured-data/reveal.
 *******************************************************************************/
public class SecuredDataRevealSpecV1 extends AbstractJsonEndpointSpec
{
   /*******************************************************************************
    ** Operation metadata.
    *******************************************************************************/
   @Override
   public BasicOperation defineBasicOperation()
   {
      return (new BasicOperation().withPath("/qbit/secured-data/reveal").withHttpMethod(HttpMethod.POST)
         .withTag(() -> "secured-data").withShortSummary("Reveal"));
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
      return (Map.of("SecuredDataRevealRequestV1", schemas.get("SecuredDataRevealRequestV1"), "SecuredDataRevealResponseV1", schemas.get("SecuredDataRevealResponseV1"), "SecuredDataErrorV1", schemas.get("SecuredDataErrorV1")));
   }

   /*******************************************************************************
    ** Response component.
    *******************************************************************************/
   @Override
   protected String getResponseSchemaName()
   {
      return ("SecuredDataRevealResponseV1");
   }

   /*******************************************************************************
    ** Standard error responses, including the daily-limit refusal.
    *******************************************************************************/
   @Override
   public List<com.kingsrook.qqq.middleware.javalin.specs.BasicResponse> defineAdditionalBasicResponses()
   {
      return (List.of(new com.kingsrook.qqq.middleware.javalin.specs.BasicResponse(io.javalin.http.HttpStatus.BAD_REQUEST, "Invalid reveal request", BasicErrorResponseV1.class.getSimpleName()),
         new com.kingsrook.qqq.middleware.javalin.specs.BasicResponse(io.javalin.http.HttpStatus.FORBIDDEN, "Reveal denied", BasicErrorResponseV1.class.getSimpleName()),
         new com.kingsrook.qqq.middleware.javalin.specs.BasicResponse(io.javalin.http.HttpStatus.NOT_FOUND, "Record not found or locked", BasicErrorResponseV1.class.getSimpleName()),
         new com.kingsrook.qqq.middleware.javalin.specs.BasicResponse(io.javalin.http.HttpStatus.TOO_MANY_REQUESTS, "Daily reveal cap reached", BasicErrorResponseV1.class.getSimpleName())));
   }

   /*******************************************************************************
    ** Required JSON request.
    *******************************************************************************/
   @Override
   protected Schema defineRequestBodySchema()
   {
      return (new Schema().withRefToSchema("SecuredDataRevealRequestV1"));
   }

   /*******************************************************************************
    ** Reject wrong JSON types with the standard 400 response.
    *******************************************************************************/
   private String string(Map<String, Object> body, String key) throws QBadRequestException
   {
      Object value = body.get(key);
      if(value != null && !(value instanceof String))
      {
         throw (new QBadRequestException(key + " must be a string."));
      }
      return ((String) value);
   }

   /*******************************************************************************
    ** Execute with the caller session supplied by the core middleware.
    *******************************************************************************/
   @Override
   protected Object handle(JsonInput input) throws Exception
   {
      Map<String, Object> body = input.getBody();
      Object pk = body.get("primaryKey");
      if(!(pk instanceof String || pk instanceof Number))
      {
         throw (new QBadRequestException("primaryKey must be a string or number."));
      }
      return (new RevealService().reveal(string(body, "tableName"), (Serializable) pk, string(body, "fieldName"),
         string(body, "reason"), string(body, "reasonText")));
   }

   /*******************************************************************************
    ** Preserve core error bodies and use 429 for exhausted daily allowances.
    *******************************************************************************/
   @Override
   protected void handleException(io.javalin.http.Context context, Exception e)
   {
      if(e instanceof RevealCappedException)
      {
         com.kingsrook.qqq.middleware.javalin.QJavalinUtils.respondWithError(context, org.eclipse.jetty.http.HttpStatus.Code.TOO_MANY_REQUESTS, e.getMessage());
      }
      else
      {
         super.handleException(context, e);
      }
   }
}
