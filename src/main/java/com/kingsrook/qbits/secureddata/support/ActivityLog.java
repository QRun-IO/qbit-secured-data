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

import com.kingsrook.qbits.secureddata.SecuredDataResolver;
import com.kingsrook.qbits.secureddata.SecuredDataRuntime;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.data.QRecord;

/*******************************************************************************
 ** Synchronous activity audit rows for state-changing operations.
 *******************************************************************************/
public final class ActivityLog
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private ActivityLog()
   {
   }

   /*******************************************************************************
    ** Capture the actor before entering the system session. No field values.
    *******************************************************************************/
   public static QRecord row(String event, String table, String outcome)
   {
      return (new QRecord().withValue("event_type", event).withValue("table_name", table)
         .withValue("user_id", SecuredDataResolver.userId())
         .withValue("user_name", QContext.getQSession().getUser() == null ? "system" : QContext.getQSession().getUser().getFullName())
         .withValue("client_channel", CoreMetadataBridge.channel(QContext.getQSession()))
         .withValue("created_at", SecuredDataRuntime.current().config().getClock().instant())
         .withValue("outcome", outcome).withValue("anomaly_flag", false));
   }
}
