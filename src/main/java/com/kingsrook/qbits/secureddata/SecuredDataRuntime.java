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


import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.QSupplementalInstanceMetaData;


/*******************************************************************************
 ** Instance-scoped services and invalidation clocks, never shared across applications.
 *******************************************************************************/
public class SecuredDataRuntime implements QSupplementalInstanceMetaData, AutoCloseable
{
   public static final String NAME = "securedDataRuntime";
   private static final AtomicLong STARTUP_VERSION = new AtomicLong(System.currentTimeMillis());
   private final AtomicLong classificationVersion = new AtomicLong(STARTUP_VERSION.incrementAndGet());
   private final AtomicLong policyVersion = new AtomicLong(STARTUP_VERSION.incrementAndGet());
   private final transient SecuredDataQBitConfig config;
   private final transient SecuredDataResolver resolver;
   private final transient SecuredDataAccessLogger logger;
   private transient long cachedClassificationVersion;
   private transient List<com.kingsrook.qqq.backend.core.model.data.QRecord> classificationRows = List.of();



   /*******************************************************************************
    ** Construct services only after tables have been registered.
    *******************************************************************************/
   public SecuredDataRuntime(QInstance instance, SecuredDataQBitConfig config)
   {
      this.config = config;
      this.resolver = new SecuredDataResolver(this);
      this.logger = new SecuredDataAccessLogger(instance, this);
   }



   /*******************************************************************************
    ** Supplemental metadata identity.
    *******************************************************************************/
   @Override
   public String getName()
   {
      return (NAME);
   }



   /*******************************************************************************
    ** Services for the current QContext.
    *******************************************************************************/
   public static SecuredDataRuntime current()
   {
      return (QContext.getQInstance() == null ? null : QSupplementalInstanceMetaData.of(QContext.getQInstance(), NAME));
   }



   /*******************************************************************************
    ** Code configuration.
    *******************************************************************************/
   public SecuredDataQBitConfig config()
   {
      return (config);
   }



   /*******************************************************************************
    ** Resolver service.
    *******************************************************************************/
   public SecuredDataResolver resolver()
   {
      return (resolver);
   }



   /*******************************************************************************
    ** Logger service and drop counter.
    *******************************************************************************/
   public SecuredDataAccessLogger logger()
   {
      return (logger);
   }



   /*******************************************************************************
    ** Classification invalidation clock.
    *******************************************************************************/
   public long classificationVersion()
   {
      return (classificationVersion.get());
   }



   /*******************************************************************************
    ** Policy/break-glass invalidation clock.
    *******************************************************************************/
   public long policyVersion()
   {
      return (policyVersion.get());
   }



   /*******************************************************************************
    ** Post-commit customizers and host distributed invalidation call this.
    *******************************************************************************/
   public void invalidateClassifications()
   {
      classificationVersion.incrementAndGet();
   }



   /*******************************************************************************
    ** Post-commit customizers and host distributed invalidation call this.
    *******************************************************************************/
   public void invalidatePolicies()
   {
      policyVersion.incrementAndGet();
   }



   /*******************************************************************************
    ** Read classification rows once per version, always as the system.
    *******************************************************************************/
   synchronized List<com.kingsrook.qqq.backend.core.model.data.QRecord> classificationRows()
   {
      long version = classificationVersion();
      if(cachedClassificationVersion != version)
      {
         classificationRows = List.copyOf(com.kingsrook.qbits.secureddata.support.SystemWrites.query(
            com.kingsrook.qbits.secureddata.metadata.SecuredDataTables.CLASSIFICATION, new com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter()));
         cachedClassificationVersion = version;
      }
      return (classificationRows);
   }



   /*******************************************************************************
    ** Drain the audit queue during normal host shutdown.
    *******************************************************************************/
   @Override
   public void close()
   {
      logger.close();
   }
}
