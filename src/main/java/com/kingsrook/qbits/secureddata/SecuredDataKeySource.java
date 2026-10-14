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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.retention.RetentionRules;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.actions.ai.DataClassification;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.ClassifiedValueKeySource;
import com.kingsrook.qqq.backend.core.actions.permissions.fieldaccess.ClassifiedValueTokens;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.instances.QMetaDataVariableInterpreter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;

/*******************************************************************************
 ** Per-instance audit DEKs. Cache hits still require the key row to exist, so
 ** another node's committed deletion takes effect immediately on the next lookup.
 *******************************************************************************/
public final class SecuredDataKeySource implements ClassifiedValueKeySource, AutoCloseable
{
   private final ThreadLocal<Boolean> instanceOnly = ThreadLocal.withInitial(() -> false);
   private static final SecureRandom RANDOM = new SecureRandom();
   private final Map<String, CachedKey> cache = new LinkedHashMap<>();

   /*******************************************************************************
    ** Short-lived cache; never populated by uncommitted work.
    *******************************************************************************/
   private record CachedKey(byte[] key, Instant expires)
   {
   }

   /*******************************************************************************
    ** Use core's interpreter directly: convenience environment getters log values.
    *******************************************************************************/
   public static String environment(String name)
   {
      return (new QMetaDataVariableInterpreter().interpret("${prop." + name + "}??${env." + name + "}"));
   }

   /*******************************************************************************
    ** Instance HMAC version, without retaining or logging configuration text.
    *******************************************************************************/
   @Override
   public Optional<KeyAndId> instanceKey()
   {
      String encoded = environment("QQQ_AUDIT_HMAC_KEY");
      if(encoded == null || encoded.isBlank())
      {
         return (Optional.empty());
      }
      try
      {
         String id = environment("QQQ_AUDIT_HMAC_KEY_ID");
         return (Optional.of(new KeyAndId(Base64.getDecoder().decode(encoded), id == null || id.isBlank() ? "env1" : id)));
      }
      catch(IllegalArgumentException e)
      {
         throw (new IllegalStateException("Invalid audit HMAC key configuration"));
      }
   }

   /*******************************************************************************
    ** Policies and entropy share the phase-b classification rules.
    *******************************************************************************/
   public boolean shreds(String table, String field)
   {
      var metadata = QContext.getQInstance().getTable(table);
      DataClassification classification = SecuredDataClassifications.effective(metadata, field);
      return (RetentionRules.active(table, field).stream().anyMatch(rule -> "SHREDDABLE".equals(rule.getValueString("audit_treatment")))
         || ((classification == DataClassification.PII || classification == DataClassification.PHI) && SecuredDataClassifications.lowEntropy(metadata, field)));
   }

   /*******************************************************************************
    ** Verification never creates. Missing KEK fails closed rather than falling back
    ** to an instance HMAC for a field that must be shredded.
    *******************************************************************************/
   @Override
   public synchronized Optional<KeyAndId> keyForRecordField(String table, String field, Serializable pk, boolean create)
   {
      if(instanceOnly.get())
      {
         return (Optional.empty());
      }
      String binding = table + "\u001f" + field + "\u001f" + pk;
      try
      {
         List<QRecord> rows = SystemWrites.call(() -> new QueryAction().execute(new QueryInput(SecuredDataTables.AUDIT_KEY)
            .withFilter(recordField(table, field, pk)).withShouldOmitHiddenFields(false)
            .withTransaction(QContext.getQBackendTransaction())).getRecords());
         if(rows.isEmpty())
         {
            evict(binding);
            if(!create || RetentionRules.changedOnly(table, field) || !shreds(table, field))
            {
               return (Optional.empty());
            }
            byte[] dek = new byte[32];
            RANDOM.nextBytes(dek);
            try
            {
               String wrapped = Base64.getEncoder().encodeToString(encrypt(dek, binding));
               QRecord row = SystemWrites.insertOne(SecuredDataTables.AUDIT_KEY, new QRecord()
                  .withValue("table_name", table).withValue("field_name", field).withValue("record_id", String.valueOf(pk))
                  .withValue("wrapped_key", wrapped).withValue("created_at", SecuredDataRuntime.current().config().getClock().instant()));
               return (Optional.of(new KeyAndId(dek.clone(), "dek" + row.getValueString("id"))));
            }
            finally
            {
               Arrays.fill(dek, (byte) 0);
            }
         }
         QRecord row = rows.getFirst();
         Instant now = SecuredDataRuntime.current().config().getClock().instant();
         CachedKey cached = cache.get(binding);
         if(cached != null && cached.expires().isAfter(now) && QContext.getQBackendTransaction() == null)
         {
            return (Optional.of(new KeyAndId(cached.key().clone(), "dek" + row.getValueString("id"))));
         }
         evict(binding);
         byte[] dek = decrypt(Base64.getDecoder().decode(row.getValueString("wrapped_key")), binding);
         try
         {
            if(QContext.getQBackendTransaction() == null)
            {
               if(cache.size() >= 128)
               {
                  close();
               }
               cache.put(binding, new CachedKey(dek.clone(), now.plusSeconds(5)));
            }
            return (Optional.of(new KeyAndId(dek.clone(), "dek" + row.getValueString("id"))));
         }
         finally
         {
            Arrays.fill(dek, (byte) 0);
         }
      }
      catch(QException e)
      {
         throw (new IllegalStateException("Unable to access audit key storage"));
      }
   }

   /*******************************************************************************
    ** Exact key identity, shared by deletion and lookups.
    *******************************************************************************/
   public static QQueryFilter recordField(String table, String field, Serializable pk)
   {
      return (new QQueryFilter().withCriteria(new QFilterCriteria("table_name", QCriteriaOperator.EQUALS, table))
         .withCriteria(new QFilterCriteria("field_name", QCriteriaOperator.EQUALS, field))
         .withCriteria(new QFilterCriteria("record_id", QCriteriaOperator.EQUALS, String.valueOf(pk))));
   }

   /*******************************************************************************
    ** Erase cached key bytes, including on rollback and runtime shutdown.
    *******************************************************************************/
   private void evict(String binding)
   {
      CachedKey old = cache.remove(binding);
      if(old != null)
      {
         Arrays.fill(old.key(), (byte) 0);
      }
   }

   /*******************************************************************************
    ** AES-GCM envelope: version byte, 12-byte random nonce, ciphertext and tag.
    ** The binding is authenticated additional data and prevents key-row swapping.
    *******************************************************************************/
   public static byte[] encrypt(byte[] plaintext, String binding)
   {
      byte[] nonce = new byte[12];
      RANDOM.nextBytes(nonce);
      byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, plaintext, nonce, binding);
      return (ByteBuffer.allocate(13 + ciphertext.length).put((byte) 1).put(nonce).put(ciphertext).array());
   }

   /*******************************************************************************
    ** Authenticate before exposing any plaintext.
    *******************************************************************************/
   public static byte[] decrypt(byte[] envelope, String binding)
   {
      if(envelope.length < 29 || envelope[0] != 1)
      {
         throw (new IllegalArgumentException("Invalid encrypted envelope"));
      }
      return (crypt(Cipher.DECRYPT_MODE, Arrays.copyOfRange(envelope, 13, envelope.length), Arrays.copyOfRange(envelope, 1, 13), binding));
   }

   /*******************************************************************************
    ** Require exactly a 256-bit KEK; never include secret text in failures.
    *******************************************************************************/
   private static byte[] crypt(int mode, byte[] input, byte[] nonce, String binding)
   {
      byte[] kek = null;
      try
      {
         String encoded = environment("QQQ_SECURED_DATA_KEK");
         kek = encoded == null ? new byte[0] : Base64.getDecoder().decode(encoded);
         if(kek.length != 32)
         {
            throw (new IllegalArgumentException("QQQ_SECURED_DATA_KEK must be base64 for 32 bytes"));
         }
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
         cipher.init(mode, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, nonce));
         cipher.updateAAD(binding.getBytes(StandardCharsets.UTF_8));
         return (cipher.doFinal(input));
      }
      catch(GeneralSecurityException | IllegalArgumentException e)
      {
         throw (new IllegalStateException("Unable to protect audit data; check QQQ_SECURED_DATA_KEK and envelope integrity"));
      }
      finally
      {
         if(kek != null)
         {
            Arrays.fill(kek, (byte) 0);
         }
      }
   }

   /*******************************************************************************
    ** Clear every decrypted cached key.
    *******************************************************************************/
   @Override
   public synchronized void close()
   {
      cache.values().forEach(key -> Arrays.fill(key.key(), (byte) 0));
      cache.clear();
   }

   /*******************************************************************************
    ** KEYED_HASH deliberately uses only the instance key and record binding.
    *******************************************************************************/
   public String instanceToken(com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData table,
      com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData field, Serializable pk, Serializable value)
   {
      if(instanceKey().isEmpty())
      {
         throw (new IllegalStateException("KEYED_HASH requires QQQ_AUDIT_HMAC_KEY"));
      }
      instanceOnly.set(true);
      try
      {
         return (ClassifiedValueTokens.forRecordField(table, field, pk, value));
      }
      finally
      {
         instanceOnly.remove();
      }
   }
}
