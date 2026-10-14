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

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import com.kingsrook.qqq.backend.core.model.data.QRecord;

/*******************************************************************************
 ** Inline styles survive Next's sanitizer. Full-width labelled card rows wrap at
 ** narrow widths; no inner scrollers. Inherited host text and theme border tokens.
 *******************************************************************************/
public final class SecuredDataHomeView
{
   private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("MMM d, HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);
   private static final String GRID = "display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,10rem),1fr));gap:.75rem;min-width:0;";
   private static final String CARD = "border:1px solid var(--qqq-grid-border,currentColor);border-radius:.5rem;padding:1rem;min-width:0;";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private SecuredDataHomeView()
   {
   }

   /*******************************************************************************
    ** KPI row followed by six full-width tables, never side by side.
    *******************************************************************************/
   public static String render(SecuredDataHomeData data)
   {
      StringBuilder html = new StringBuilder("<div style=\"display:flex;flex-direction:column;gap:1rem;min-width:0;color:inherit\">");
      html.append("<div aria-label=\"Secured data metrics\" style=\"").append(GRID).append("\">");
      data.getKpis().forEach((label, value) -> html.append("<div style=\"").append(CARD)
         .append("\"><div style=\"font-size:1.6rem;font-weight:600\">").append(value)
         .append("</div><div>").append(esc(label)).append("</div></div>"));
      html.append("</div>");
      for(String warning : data.getBackupWarnings())
      {
         html.append("<p role='alert'>").append(esc(warning)).append("</p>");
      }
      for(SecuredDataHomeData.Section section : data.getSections())
      {
         html.append("<section style=\"").append(CARD).append("\"><h3 style=\"margin:0;font-size:1rem\">")
            .append(esc(section.title())).append("</h3><p><a style=\"color:inherit\" aria-label=\"View all ")
            .append(esc(section.title())).append("\" href=\"")
            .append(esc(section.href())).append("\">View all</a></p>");
         if(section.rows().isEmpty())
         {
            html.append("<p>").append(esc(section.empty())).append("</p>");
         }
         for(QRecord row : section.rows())
         {
            html.append("<div style=\"").append(GRID).append("border-top:1px solid var(--qqq-grid-border,currentColor);padding:.75rem 0\">");
            for(int i = 0; i < section.fields().size(); i++)
            {
               String field = section.fields().get(i);
               String value = row.getValueString(field);
               boolean date = "created_at".equals(field);
               if(date && row.getValueInstant(field) != null)
               {
                  value = WHEN.format(row.getValueInstant(field));
               }
               if(value == null || value.isBlank())
               {
                  value = "—";
               }
               html.append("<div style=\"min-width:0\"><span style=\"display:block;font-size:.75rem;opacity:.7\">")
                  .append(esc(section.labels().get(i))).append("</span><span title=\"").append(esc(value))
                  .append("\" style=\"display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">")
                  .append(esc(value)).append("</span></div>");
            }
            html.append("</div>");
         }
         html.append("</section>");
      }
      return (html.append("</div>").toString());
   }

   /*******************************************************************************
    ** Escape every text, tooltip and URL attribute.
    *******************************************************************************/
   private static String esc(String value)
   {
      return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"));
   }
}
