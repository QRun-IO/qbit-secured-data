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

package com.kingsrook.qbits.secureddata.standin;


import java.util.Locale;
import com.kingsrook.qqq.backend.core.model.session.QSession;


/*******************************************************************************
 ** RC.5 host adapter for a trusted, server-supplied client channel.
 *******************************************************************************/
// STAND-IN(core=QRun-IO/qqq#1141, removeBy=RC.6): copy of com.kingsrook.qqq.backend.core.model.session.QSession client channel properties; delete when the pin moves to RC.6.
public class ClientChannelSession extends QSession
{
   private String clientChannel;



   /*******************************************************************************
    ** Trusted host channel value; never take this from an unvalidated request.
    *******************************************************************************/
   public ClientChannelSession withClientChannel(String clientChannel)
   {
      this.clientChannel = clientChannel;
      return (this);
   }



   /*******************************************************************************
    ** Full channel including optional request detail.
    *******************************************************************************/
   public String getClientChannel()
   {
      return (clientChannel);
   }



   /*******************************************************************************
    ** Normalized channel for policy matching.
    *******************************************************************************/
   public String getClientChannelName()
   {
      return (clientChannel == null || clientChannel.isBlank() ? null : clientChannel.strip().split("/", 2)[0].toLowerCase(Locale.ROOT));
   }
}
