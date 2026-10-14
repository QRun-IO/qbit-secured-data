/*
 * QQQ - Low-code Application Framework for Engineers.
 * Copyright (C) 2021-2026.  Kingsrook, LLC
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




/*******************************************************************************
 ** Presentation rules for a restricted value.
 *******************************************************************************/
// STAND-IN(core=QRun-IO/qqq#1172, removeBy=RC.8): copy of com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldMaskStyle; delete when the pin moves to the first QQQ RC with #1172 and #1182 (RC.8).
public enum FieldMaskStyle
{
   AUTO, EMAIL, LAST_4, FIRST_LAST, FULL
}
