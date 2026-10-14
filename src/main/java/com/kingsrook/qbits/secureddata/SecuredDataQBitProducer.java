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


import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTableCustomizers;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.support.SecuredDataMetadata;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.actions.audits.AuditValueProtectionMetaData;
import com.kingsrook.qqq.backend.core.actions.customizers.TableCustomizers;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.ClassifiedValueKeySourceMetaData;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.FieldAccessResolverMetaData;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaDataProducer;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;

/*******************************************************************************
 ** Entry point for secured-data policy, classification and access logging.
 *******************************************************************************/
public class SecuredDataQBitProducer implements QBitMetaDataProducer<SecuredDataQBitConfig>
{
   public static final String GROUP_ID    = "com.kingsrook.qbits";
   public static final String ARTIFACT_ID = "qbit-secured-data";
   public static final String VERSION     = "1.0.0";

   private SecuredDataQBitConfig qBitConfig;
   private String namespace;



   /*******************************************************************************
    ** Fluent setter for the config.
    *******************************************************************************/
   public SecuredDataQBitProducer withQBitConfig(SecuredDataQBitConfig config)
   {
      this.qBitConfig = config;
      return (this);
   }



   /*******************************************************************************
    ** Getter for the config.
    *******************************************************************************/
   @Override
   public SecuredDataQBitConfig getQBitConfig()
   {
      return (qBitConfig);
   }



   /*******************************************************************************
    ** Fluent setter for the namespace.
    *******************************************************************************/
   public SecuredDataQBitProducer withNamespace(String namespace)
   {
      this.namespace = namespace;
      return (this);
   }



   /*******************************************************************************
    ** Getter for the namespace.
    *******************************************************************************/
   @Override
   public String getNamespace()
   {
      return (namespace);
   }



   /*******************************************************************************
    ** Identity and configuration of this qbit.
    *******************************************************************************/
   @Override
   public QBitMetaData getQBitMetaData()
   {
      return (new QBitMetaData().withGroupId(GROUP_ID).withArtifactId(ARTIFACT_ID).withVersion(VERSION).withNamespace(namespace).withConfig(qBitConfig));
   }



   /*******************************************************************************
    ** Package-scanned producers have no config: skip them.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (qBitConfig != null);
   }



   /*******************************************************************************
    ** Register tables, permissions, runtime and the optional core enforcement bridge.
    *******************************************************************************/
   @Override
   public MetaDataProducerMultiOutput produce(QInstance qInstance) throws QException
   {
      qBitConfig.validate();
      if(qInstance.getSupplementalMetaData(SecuredDataRuntime.NAME) != null)
      {
         throw (new IllegalStateException("Only one secured-data QBit may be registered per instance"));
      }
      QBitMetaData qBit = getQBitMetaData();
      qInstance.addQBit(qBit);
      MetaDataProducerMultiOutput output = new MetaDataProducerMultiOutput();
      SecuredDataTables.possibleValueSources(qInstance).forEach(output::add);

      Map<String, QTableMetaData> tables = new LinkedHashMap<>();
      for(QTableMetaData definition : SecuredDataTables.tables(qBitConfig))
      {
         QTableMetaData table = qBitConfig.getTableMetaDataCustomizer() == null ? definition
            : qBitConfig.getTableMetaDataCustomizer().customizeMetaData(qInstance, definition);
         for(TableCustomizers role : List.of(TableCustomizers.PRE_INSERT_RECORD, TableCustomizers.PRE_UPDATE_RECORD, TableCustomizers.PRE_DELETE_RECORD,
            TableCustomizers.POST_INSERT_RECORD, TableCustomizers.POST_UPDATE_RECORD, TableCustomizers.POST_DELETE_RECORD))
         {
            table.withCustomizer(role, new QCodeReference(SecuredDataTableCustomizers.class));
         }
         table.setSourceQBitName(qBit.getName());
         tables.put(table.getName(), table);
         output.add(table);
      }
      output.add(com.kingsrook.qbits.secureddata.app.SecuredDataApp.app(tables));
      output.add(com.kingsrook.qbits.secureddata.app.SecuredDataApp.widget());
      com.kingsrook.qbits.secureddata.processes.BreakGlassProcesses.processes(qBitConfig).forEach(output::add);
      com.kingsrook.qbits.secureddata.retention.WipeProcesses.processes(qBitConfig).forEach(output::add);
      output.add(com.kingsrook.qbits.secureddata.retention.RetentionWidgets.backups());
      output.add(com.kingsrook.qbits.secureddata.retention.RetentionWidgets.markersJoin());
      output.add(com.kingsrook.qbits.secureddata.retention.RetentionWidgets.markers());
      output.add(SecuredDataTables.revealsJoin());
      output.add(SecuredDataTables.revealsWidget());
      output.add(new com.kingsrook.qqq.backend.core.model.metadata.security.QSecurityKeyType().withName(com.kingsrook.qbits.secureddata.metadata.RetentionTables.KEY_LOCK));
      output.addSelfToInstance(qInstance);
      SecuredDataMetadata.register(qInstance);
      com.kingsrook.qbits.secureddata.uiapi.SecuredDataExtension.register(qInstance);
      if(qBitConfig.getNameHeuristics())
      {
         seedHeuristics(qInstance);
      }
      SecuredDataRuntime runtime = new SecuredDataRuntime(qInstance, qBitConfig);
      runtime.addSelfToInstance(qInstance);
      try
      {
         FieldAccessResolverMetaData.ofOrWithNew(qInstance).withResolverInstance(runtime.resolver());
         ClassifiedValueKeySourceMetaData.ofOrWithNew(qInstance).withKeySourceInstance(runtime.keys());
         AuditValueProtectionMetaData.ofOrWithNew(qInstance).withProtectorInstance(new SecuredDataAuditProtector());
      }
      catch(RuntimeException e)
      {
         runtime.close();
         throw e;
      }
      return (new MetaDataProducerMultiOutput());
   }



   /*******************************************************************************
    ** Opt-in common-name defaults, preserving existing field/table classifications.
    *******************************************************************************/
   private static void seedHeuristics(QInstance instance)
   {
      for(QTableMetaData table : instance.getTables().values())
      {
         if(SecuredDataTables.ALL.contains(table.getName()))
         {
            continue;
         }
         for(QFieldMetaData field : table.getFields().values())
         {
            if(SecuredDataMetadata.classification(table, field) != null || SecuredDataMetadata.classification(table, null) != null)
            {
               continue;
            }
            String name = field.getName().toLowerCase(Locale.ROOT);
            if(name.startsWith("diagnosis"))
            {
               SecuredDataMetadata.classifyField(field, DataClassification.PHI);
            }
            else if(List.of("ssn", "dob", "date_of_birth", "email", "phone").contains(name))
            {
               SecuredDataMetadata.classifyField(field, DataClassification.PII);
            }
         }
      }
   }
}
