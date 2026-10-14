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

package com.kingsrook.qbits.secureddata.metadata;


import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.secureddata.standin.FieldAccessTier;
import com.kingsrook.qbits.secureddata.standin.FieldMaskStyle;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValue;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSource;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSourceType;


/*******************************************************************************
 ** String-valued possible-value sources shared by UI metadata and the DDL.
 *******************************************************************************/
public final class SecuredDataEnums
{
   /*******************************************************************************
    ** Activity event names include the future Reveal and break-glass actions.
    *******************************************************************************/
   public enum EventType
   {
      VIEW, REVEAL, REVEAL_DENIED, EXACT_MATCH_FILTER, FILTER_DENIED, BREAK_GLASS_START, BREAK_GLASS_END,
      BREAK_GLASS_EXPIRED, POLICY_CHANGE, CLASSIFICATION_CHANGE
   }



   /*******************************************************************************
    ** Access outcomes.
    *******************************************************************************/
   public enum Outcome
   {
      ALLOWED, DENIED, CAPPED, MATCH, NO_MATCH, REFUSED
   }



   /*******************************************************************************
    ** Break-glass lifecycle.
    *******************************************************************************/
   public enum BreakGlassStatus
   {
      ACTIVE, ENDED, EXPIRED
   }



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataEnums()
   {
   }



   /*******************************************************************************
    ** All enum sources, keeping the stand-in core types exact copies.
    *******************************************************************************/
   public static List<QPossibleValueSource> sources()
   {
      return (List.of(source("classification", DataClassification.values()), source("tier", FieldAccessTier.values()),
         source("mask_style", FieldMaskStyle.values()), source("event_type", EventType.values()), source("outcome", Outcome.values()),
         source("break_glass_status", BreakGlassStatus.values())));
   }



   /*******************************************************************************
    ** Convert enum names to stored string ids.
    *******************************************************************************/
   private static QPossibleValueSource source(String name, Enum<?>[] values)
   {
      List<QPossibleValue<?>> options = new ArrayList<>();
      for(Enum<?> value : values)
      {
         options.add(new QPossibleValue<>(value.name(), value.name().replace('_', ' ')));
      }
      return (new QPossibleValueSource().withName("secured_data_" + name).withType(QPossibleValueSourceType.ENUM)
         .withIdType(QFieldType.STRING).withEnumValues(options));
   }
}
