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


import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.actions.permissions.TablePermissionSubType;
import com.kingsrook.qqq.backend.core.actions.values.QCustomPossibleValueProvider;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.values.SearchPossibleValueSourceInput;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValue;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Fields of the selected table; table_name is supplied through the dependent picker.
 *******************************************************************************/
public class FieldsOfTablePossibleValueSource implements QCustomPossibleValueProvider<String>
{
   /*******************************************************************************
    ** Stored ids are unqualified field names; labels are provided by search.
    *******************************************************************************/
   @Override
   public QPossibleValue<String> getPossibleValue(Serializable id)
   {
      return (id == null ? null : new QPossibleValue<>(id.toString(), id.toString()));
   }



   /*******************************************************************************
    ** Never offer fields from a table the administrator cannot read.
    *******************************************************************************/
   @Override
   public List<QPossibleValue<String>> search(SearchPossibleValueSourceInput input) throws QException
   {
      Object tableName = input.getOtherValues() == null ? null : input.getOtherValues().get("table_name");
      List<QPossibleValue<String>> values = new ArrayList<>();
      QTableMetaData table = tableName == null ? null : QContext.getQInstance().getTable(tableName.toString());
      if(table != null && PermissionsHelper.hasTablePermission(new GetInput(table.getName()), table.getName(), TablePermissionSubType.READ))
      {
         table.getFields().values().forEach(field -> values.add(new QPossibleValue<>(field.getName(), field.getLabel())));
      }
      return (completeCustomPVSSearch(input, values));
   }
}
