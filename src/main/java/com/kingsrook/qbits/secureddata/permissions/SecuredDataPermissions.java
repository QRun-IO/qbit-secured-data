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

package com.kingsrook.qbits.secureddata.permissions;


import java.util.List;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;


/*******************************************************************************
 ** Administrative access is independent of access to classified application data.
 *******************************************************************************/
public final class SecuredDataPermissions
{
   public static final String ADMIN = "secured_data.admin";
   public static final String FULL = "secured_data_full";
   public static final String REVEAL = "secured_data_reveal";
   public static final List<String> ALL = List.of(ADMIN, "secured_data.hasAccess");



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataPermissions()
   {
   }



   /*******************************************************************************
    ** Standard QQQ custom checker, shared by tables, app and child widget.
    *******************************************************************************/
   public static QPermissionRules rules()
   {
      return (new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION).withPermissionBaseName("secured_data")
         .withCustomPermissionChecker(new QCodeReference(SecuredDataPermissionChecker.class)));
   }
}
