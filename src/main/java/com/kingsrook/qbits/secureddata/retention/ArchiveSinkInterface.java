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

package com.kingsrook.qbits.secureddata.retention;

import com.kingsrook.qqq.backend.core.exceptions.QException;

/*******************************************************************************
 ** Host adapter to qbit-object-storage. Receives only AES-GCM ciphertext.
 ** The host should use a locked WORM bucket when available. Return after durable write.
 *******************************************************************************/
@FunctionalInterface
public interface ArchiveSinkInterface
{
   /*******************************************************************************
    ** Store an encrypted JSON record at an opaque, unique object key.
    *******************************************************************************/
   void put(String storageName, String objectKey, byte[] ciphertext) throws QException;
}
