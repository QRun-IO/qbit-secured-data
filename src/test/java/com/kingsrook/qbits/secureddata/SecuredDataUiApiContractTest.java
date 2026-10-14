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

package com.kingsrook.qbits.secureddata;

import java.nio.file.Path;
import java.nio.file.Files;
import com.kingsrook.qqq.middleware.javalin.specs.v1.MiddlewareVersionV1;
import com.kingsrook.qqq.middleware.javalin.tools.UiApiContract;
import static org.assertj.core.api.Assertions.assertThat;
import com.kingsrook.qbits.secureddata.uiapi.SecuredDataExtension;
import org.junit.jupiter.api.Test;

class SecuredDataUiApiContractTest
{
   @Test
   void committedContractMatches() throws Exception
   {
      Path path = Path.of("src/main/resources/openapi/qqq-v1/secured-data.yaml");
      String generated = UiApiContract.generateExtensionYaml(new MiddlewareVersionV1(), SecuredDataExtension.defineExtension());
      if(Boolean.getBoolean("qqq.uiApi.regenerate"))
      {
         Files.writeString(path, generated);
      }
      assertThat(UiApiContract.check(generated, Files.readString(path), null, 1, "Regenerate secured-data.yaml")).isEmpty();
   }
}
