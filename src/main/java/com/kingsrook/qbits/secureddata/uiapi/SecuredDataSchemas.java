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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qqq.openapi.model.Schema;
import com.kingsrook.qqq.openapi.model.Type;

/*******************************************************************************
 ** Published shapes of service responses; nullable allowances mean unlimited.
 *******************************************************************************/
public final class SecuredDataSchemas
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataSchemas()
   {
   }

   /*******************************************************************************
    ** Every request and response component carries the extension prefix and version.
    *******************************************************************************/
   public static Map<String, Schema> all()
   {
      Map<String, Schema> schemas = new LinkedHashMap<>();
      schemas.put("SecuredDataRevealRequestV1", object("tableName", type(Type.STRING), "fieldName", type(Type.STRING),
         "primaryKey", new Schema().withAnyOf(List.of(type(Type.STRING), type(Type.NUMBER))).withDescription("Record primary key (string or number)."),
         "reason", type(Type.STRING).withNullable(true).withMaxLength(500), "reasonText", type(Type.STRING).withNullable(true).withMaxLength(500))
         .withDescription("tableName, primaryKey and fieldName are required. Supply a policy reason or allowed free text; maximum 500 characters."));
      schemas.put("SecuredDataRevealResponseV1", object("value", new Schema().withNullable(true).withDescription("Authorized raw field value."),
         "displayValue", type(Type.STRING).withNullable(true), "expiresAt", type(Type.STRING).withFormat("date-time"), "revealId", type(Type.INTEGER)));
      schemas.put("SecuredDataRevealOptionsResponseV1", object("reasonOptions", type(Type.ARRAY).withItems(type(Type.STRING)),
         "allowFreeTextReason", type(Type.BOOLEAN), "requireFreeText", type(Type.BOOLEAN), "revealMinutes", type(Type.INTEGER),
         "remainingDailyAllowance", type(Type.INTEGER).withNullable(true)));
      schemas.put("SecuredDataBreakGlassV1", object("id", type(Type.INTEGER), "reason", type(Type.STRING), "expiresAt", type(Type.STRING).withFormat("date-time"),
         "scope", type(Type.STRING).withNullable(true), "ceiling", type(Type.STRING)));
      schemas.put("SecuredDataRevealAllowanceV1", object("tableName", type(Type.STRING), "fieldName", type(Type.STRING), "remainingDailyAllowance", type(Type.INTEGER).withNullable(true)));
      schemas.put("SecuredDataStatusResponseV1", object("breakGlass", new Schema().withRefToSchema("SecuredDataBreakGlassV1").withNullable(true),
         "revealsUsedToday", type(Type.INTEGER), "revealAllowances", type(Type.ARRAY).withItems(new Schema().withRefToSchema("SecuredDataRevealAllowanceV1"))));
      schemas.put("SecuredDataErrorV1", object("error", type(Type.STRING))
         .withDescription("Deprecated since 1.1.0: errors use BasicErrorResponseV1."));
      return (schemas);
   }

   /*******************************************************************************
    ** Object properties in stable order.
    *******************************************************************************/
   private static Schema object(Object... pairs)
   {
      Map<String, Schema> properties = new LinkedHashMap<>();
      for(int i = 0; i < pairs.length; i += 2)
      {
         properties.put((String) pairs[i], (Schema) pairs[i + 1]);
      }
      return (type(Type.OBJECT).withProperties(properties));
   }

   /*******************************************************************************
    ** Typed schema.
    *******************************************************************************/
   private static Schema type(Type type)
   {
      return (new Schema().withType(type));
   }
}
