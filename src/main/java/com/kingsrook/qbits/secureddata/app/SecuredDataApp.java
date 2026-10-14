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

package com.kingsrook.qbits.secureddata.app;

import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.permissions.SecuredDataPermissions;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.WidgetType;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** One app and one home. Grants remain a child list; processes stay off the nav.
 *******************************************************************************/
public final class SecuredDataApp
{
   public static final String HOME_WIDGET = "securedDataHome";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataApp()
   {
   }

   /*******************************************************************************
    ** Admin-only home spanning the host's full grid.
    *******************************************************************************/
   public static QWidgetMetaData widget()
   {
      return (new QWidgetMetaData().withName(HOME_WIDGET).withLabel("Overview").withType(WidgetType.HTML.getType())
         .withCodeReference(new QCodeReference(HomeRenderer.class)).withGridColumns(12).withIsCard(false)
         .withPermissionRules(SecuredDataPermissions.rules()));
   }

   /*******************************************************************************
    ** Exactly four navigation tables.
    *******************************************************************************/
   public static QAppMetaData app(Map<String, QTableMetaData> tables)
   {
      QAppMetaData app = new QAppMetaData().withName("secured_data").withLabel("Secured Data")
         .withIcon(new QIcon("shield")).withPermissionRules(SecuredDataPermissions.rules()).withWidgets(List.of(HOME_WIDGET));
      SecuredDataTables.MAIN.forEach(name -> app.withChild(tables.get(name)));
      return (app);
   }

   /*******************************************************************************
    ** Standard HTML widget, following the webhooks home pattern.
    *******************************************************************************/
   public static class HomeRenderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       ** Render real viewer-scoped data.
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         return (new RenderWidgetOutput(new RawHTML(null, SecuredDataHomeView.render(SecuredDataHomeData.load()))));
      }
   }
}
