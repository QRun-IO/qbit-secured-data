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


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import com.kingsrook.qbits.secureddata.metadata.SecuredDataTables;
import com.kingsrook.qbits.secureddata.permissions.SecuredDataPermissions;
import com.kingsrook.qbits.secureddata.standin.DataClassification;
import com.kingsrook.qbits.secureddata.standin.FieldAccessDecision;
import com.kingsrook.qbits.secureddata.standin.FieldAccessEvent;
import com.kingsrook.qbits.secureddata.standin.FieldAccessResolverInterface;
import com.kingsrook.qbits.secureddata.standin.FieldAccessTier;
import com.kingsrook.qbits.secureddata.standin.FieldMaskStyle;
import com.kingsrook.qbits.secureddata.support.CoreMetadataBridge;
import com.kingsrook.qbits.secureddata.support.SystemWrites;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;


/*******************************************************************************
 ** Seven-step policy resolution with instance-versioned, bounded per-user state.
 *******************************************************************************/
public class SecuredDataResolver implements FieldAccessResolverInterface
{
   private final SecuredDataRuntime runtime;
   private final byte[] fingerprintKey;
   private final ThreadLocal<Boolean> resolving = ThreadLocal.withInitial(() -> false);
   private final Map<String, RevealCache> reveals = new HashMap<>();

   /*******************************************************************************
    ** Bounded per-user grant cache, with exact read-time expiry.
    *******************************************************************************/
   private record RevealCache(Instant until, List<QRecord> rows)
   {
   }

   private long cachedVersion;
   private List<QRecord> policies = List.of();
   private final Map<String, UserState> users = new HashMap<>();



   /*******************************************************************************
    ** Cached policy matches and break-glass rows. Expiration is checked on every use.
    *******************************************************************************/
   private record UserState(List<QRecord> policies, List<QRecord> breakGlass)
   {
   }



   /*******************************************************************************
    ** Zero thresholds disable that guardrail; positive thresholds combine by minimum.
    *******************************************************************************/
   public record Guardrails(int exactMatchPerHour, int missAlertConsecutive, int distinctValueAlert, boolean minEntropyEnabled)
   {
   }



   /*******************************************************************************
    ** Capture the supplied key once; default keys are shared within this JVM.
    *******************************************************************************/
   public SecuredDataResolver(SecuredDataRuntime runtime)
   {
      this.runtime = runtime;
      this.fingerprintKey = Objects.requireNonNull(runtime.config().getFingerprintKeySupplier().get()).clone();
      if(fingerprintKey.length < 16)
      {
         throw (new IllegalArgumentException("Fingerprint keys must contain at least 16 bytes"));
      }
   }



   /*******************************************************************************
    ** Resolve classification, grants, policies, channel caps and entropy.
    *******************************************************************************/
   @Override
   public FieldAccessDecision resolve(QTableMetaData table, QFieldMetaData field)
   {
      if(SystemWrites.active() || QContext.getQSession() instanceof QSystemUserSession
         || Objects.equals(table.getPrimaryKeyField(), field.getName()))
      {
         return (FieldAccessDecision.FULL);
      }
      if(resolving.get())
      {
         throw (new IllegalStateException("Recursive secured-data resolution outside a system lookup"));
      }
      resolving.set(true);
      try
      {
         DataClassification classification = SecuredDataClassifications.effective(table, field.getName());
         if(classification == null || classification == DataClassification.PUBLIC)
         {
            return (FieldAccessDecision.FULL);
         }
         QSession session = QContext.getQSession();
         if(SecuredDataTables.ALL.contains(table.getName()) && session != null && session.hasPermission(SecuredDataPermissions.ADMIN))
         {
            return (FieldAccessDecision.FULL);
         }
         List<QRecord> matches = matching(table, classification);
         FieldAccessTier tier = null;
         for(QRecord row : matches)
         {
            if(blank(row.getValueString("client_channel")))
            {
               FieldAccessTier candidate = FieldAccessTier.valueOf(row.getValueString("tier"));
               tier = tier == null ? candidate : tier.leastRestrictive(candidate);
            }
         }
         if(tier == null)
         {
            tier = runtime.config().defaultTier(classification);
         }
         if(session != null && CoreMetadataBridge.hasFeature(table, SecuredDataPermissions.REVEAL))
         {
            tier = tier.leastRestrictive(FieldAccessTier.REVEALABLE);
         }
         if(activeBreakGlass(table.getName(), classification) != null
            || (session != null && CoreMetadataBridge.hasFeature(table, SecuredDataPermissions.FULL)))
         {
            tier = FieldAccessTier.FULL;
         }
         for(QRecord row : matches)
         {
            if(!blank(row.getValueString("client_channel")))
            {
               tier = tier.mostRestrictive(FieldAccessTier.valueOf(row.getValueString("tier")));
            }
         }
         QRecord override = SecuredDataClassifications.row(table, field.getName());
         String style = override == null ? null : override.getValueString("mask_style");
         boolean exactAllowed = !guardrails(matches).minEntropyEnabled() || !lowCardinality(field, override);
         return (new FieldAccessDecision(tier, blank(style) ? null : FieldMaskStyle.valueOf(style), "Secured-data policy", exactAllowed));
      }
      finally
      {
         resolving.remove();
      }
   }



   /*******************************************************************************
    ** The field's matching policies also drive enumeration controls.
    *******************************************************************************/
   public Guardrails guardrails(QTableMetaData table, String fieldName)
   {
      return (guardrails(matching(table, SecuredDataClassifications.effective(table, fieldName))));
   }



   /*******************************************************************************
    ** Most restrictive enabled setting across matching rows; config when none match.
    *******************************************************************************/
   private Guardrails guardrails(List<QRecord> matches)
   {
      SecuredDataQBitConfig config = runtime.config();
      if(matches.isEmpty())
      {
         return (new Guardrails(config.getExactMatchPerHour(), config.getMissAlertConsecutive(), config.getDistinctValueAlert(), config.getMinEntropyEnabled()));
      }
      int rate = 0;
      int misses = 0;
      int distinct = 0;
      boolean entropy = false;
      for(QRecord row : matches)
      {
         rate = minimumEnabled(rate, setting(row, "exact_match_per_hour", config.getExactMatchPerHour()));
         misses = minimumEnabled(misses, setting(row, "miss_alert_consecutive", config.getMissAlertConsecutive()));
         distinct = minimumEnabled(distinct, setting(row, "distinct_value_alert", config.getDistinctValueAlert()));
         entropy |= row.getValueBoolean("min_entropy_enabled") == null ? config.getMinEntropyEnabled() : row.getValueBoolean("min_entropy_enabled");
      }
      return (new Guardrails(rate, misses, distinct, entropy));
   }



   /*******************************************************************************
    ** Read an optional numeric setting.
    *******************************************************************************/
   private static int setting(QRecord row, String name, int fallback)
   {
      Integer value = row.getValueInteger(name);
      return (value == null ? fallback : value);
   }



   /*******************************************************************************
    ** Zero means off, so an enabled row always wins over a disabled row.
    *******************************************************************************/
   private static int minimumEnabled(int left, int right)
   {
      return (left == 0 ? right : right == 0 ? left : Math.min(left, right));
   }



   /*******************************************************************************
    ** Explicit true/false wins over the field type/name heuristic.
    *******************************************************************************/
   static boolean lowCardinality(QFieldMetaData field, QRecord override)
   {
      Boolean explicit = override == null ? null : override.getValueBoolean("low_cardinality");
      if(explicit != null)
      {
         return (explicit);
      }
      QFieldType type = field.getType();
      String name = (field.getName() + " " + field.getLabel()).replaceAll("([a-z])([A-Z])", "$1 $2").toLowerCase(Locale.ROOT);
      return (type == QFieldType.BOOLEAN || type == QFieldType.DATE || type == QFieldType.DATE_TIME
         || field.getPossibleValueSourceName() != null || field.getInlinePossibleValueSource() != null
         || (type == QFieldType.INTEGER && name.contains("year"))
         || name.matches(".*(?:^|[^a-z])(state|region|province|zip3)(?:[^a-z]|$).*")
         || (type == QFieldType.STRING && field.getMaxLength() != null && field.getMaxLength() < 6));
   }



   /*******************************************************************************
    ** Policies for this user, classification, table and current normalized channel.
    *******************************************************************************/
   private List<QRecord> matching(QTableMetaData table, DataClassification classification)
   {
      String channel = CoreMetadataBridge.channel(QContext.getQSession());
      return (state().policies().stream().filter(row -> classification != null && classification.name().equals(row.getValueString("classification")))
         .filter(row -> blank(row.getValueString("table_name")) || table.getName().equals(row.getValueString("table_name")))
         .filter(row -> blank(row.getValueString("client_channel")) || Objects.equals(channel, row.getValueString("client_channel"))).toList());
   }



   /*******************************************************************************
    ** Granting rows only: channel rows cap tiers and never grant reveal settings.
    *******************************************************************************/
   public List<QRecord> revealPolicies(QTableMetaData table, String fieldName)
   {
      return (matching(table, SecuredDataClassifications.effective(table, fieldName)).stream()
         .filter(row -> blank(row.getValueString("client_channel")) && "REVEALABLE".equals(row.getValueString("tier"))).toList());
   }



   /*******************************************************************************
    ** Refresh policy rows once per version and matched state per relevant permissions.
    *******************************************************************************/
   private synchronized UserState state()
   {
      long version = runtime.policyVersion();
      if(cachedVersion != version)
      {
         policies = List.copyOf(SystemWrites.query(SecuredDataTables.POLICY, new QQueryFilter()));
         users.clear();
         cachedVersion = version;
      }
      QSession session = QContext.getQSession();
      TreeSet<String> held = new TreeSet<>();
      for(QRecord policy : policies)
      {
         String permission = policy.getValueString("permission_name");
         if(session != null && session.hasPermission(permission))
         {
            held.add(permission);
         }
      }
      String key = JsonUtils.toJson(List.of(userId(), held));
      UserState state = users.get(key);
      if(state == null)
      {
         if(users.size() >= 1024)
         {
            users.clear();
         }
         List<QRecord> matching = policies.stream().filter(row -> Boolean.TRUE.equals(row.getValueBoolean("is_active")))
            .filter(row -> held.contains(row.getValueString("permission_name"))).toList();
         List<QRecord> breaks = SystemWrites.query(SecuredDataTables.BREAK_GLASS, new QQueryFilter()
            .withCriteria(new QFilterCriteria("user_id", QCriteriaOperator.EQUALS, userId())));
         state = new UserState(matching, List.copyOf(breaks));
         users.put(key, state);
      }
      return (state);
   }



   /*******************************************************************************
    ** Exact expiry is checked at use time, independent of the future expiry job.
    *******************************************************************************/
   public List<QRecord> activeBreakGlass()
   {
      Instant now = runtime.config().getClock().instant();
      return (state().breakGlass().stream().filter(row -> "ACTIVE".equals(row.getValueString("status")))
         .filter(row -> row.getValueInstant("expires_at") != null && row.getValueInstant("expires_at").isAfter(now)).toList());
   }



   /*******************************************************************************
    ** A break-glass grant must cover both the table and classification.
    *******************************************************************************/
   QRecord activeBreakGlass(String table, DataClassification classification)
   {
      return (activeBreakGlass().stream().filter(row -> blank(row.getValueString("table_name")) || table.equals(row.getValueString("table_name")))
         .filter(row -> DataClassification.valueOf(Objects.requireNonNullElse(row.getValueString("classification_ceiling"), "PHI")).isAtLeast(classification))
         .findFirst().orElse(null));
   }



   /*******************************************************************************
    ** Stable across unrelated permissions/records; includes channel and exact expiry.
    *******************************************************************************/
   @Override
   public synchronized String getAccessFingerprint()
   {
      state();
      TreeSet<String> relevant = new TreeSet<>();
      QSession session = QContext.getQSession();
      for(QRecord row : policies)
      {
         String permission = row.getValueString("permission_name");
         if(session != null && session.hasPermission(permission))
         {
            relevant.add(permission);
         }
      }
      for(QTableMetaData table : QContext.getQInstance().getTables().values())
      {
         String base = CoreMetadataBridge.permissionBase(table);
         for(String suffix : List.of(SecuredDataPermissions.FULL, SecuredDataPermissions.REVEAL))
         {
            if(session != null && session.hasPermission(base + "." + suffix))
            {
               relevant.add(base + "." + suffix);
            }
         }
      }
      List<String> breaks = activeBreakGlass().stream().map(row -> row.getValueString("id")).sorted().toList();
      String payload = JsonUtils.toJson(List.of(userId(), relevant, runtime.policyVersion(), runtime.classificationVersion(), breaks,
         Objects.requireNonNullElse(CoreMetadataBridge.channel(session), "")));
      try
      {
         return (Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(payload.getBytes(StandardCharsets.UTF_8))));
      }
      catch(java.security.NoSuchAlgorithmException e)
      {
         throw (new IllegalStateException(e));
      }
   }



   /*******************************************************************************
    ** Existing grants are read as system; phase (c) owns their creation.
    *******************************************************************************/
   @Override
   public boolean isRevealActive(String tableName, String fieldName, Serializable primaryKey)
   {
      synchronized(reveals)
      {
         String user = userId();
         Instant now = runtime.config().getClock().instant();
         RevealCache cached = reveals.get(user);
         if(cached == null || !cached.until().isAfter(now))
         {
            if(reveals.size() >= 1024)
            {
               reveals.clear();
            }
            cached = new RevealCache(now.plusSeconds(5), SystemWrites.query(SecuredDataTables.REVEAL_GRANT, new QQueryFilter()
               .withCriteria(new QFilterCriteria("user_id", QCriteriaOperator.EQUALS, user))
               .withCriteria(new QFilterCriteria("expires_at", QCriteriaOperator.GREATER_THAN, now))));
            reveals.put(user, cached);
         }
         return (cached.rows().stream().anyMatch(row -> tableName.equals(row.getValueString("table_name"))
            && fieldName.equals(row.getValueString("field_name")) && String.valueOf(primaryKey).equals(row.getValueString("record_id"))
            && row.getValueInstant("expires_at").isAfter(now)));
      }
   }



   /*******************************************************************************
    ** Publish a newly created grant to all sessions on this instance immediately.
    *******************************************************************************/
   public void invalidateReveals()
   {
      synchronized(reveals)
      {
         reveals.clear();
      }
   }



   /*******************************************************************************
    ** Logging never throws into a core read.
    *******************************************************************************/
   @Override
   public void onAccess(FieldAccessEvent event)
   {
      runtime.logger().onAccess(event);
   }



   /*******************************************************************************
    ** Preflight enumeration limits; core reports the REFUSED outcome exactly once.
    *******************************************************************************/
   @Override
   public void checkExactMatch(FieldAccessEvent event) throws QPermissionDeniedException
   {
      runtime.logger().checkExactMatch(event);
   }



   /*******************************************************************************
    ** A keyed, non-reversible search identifier. No raw value leaves this method.
    *******************************************************************************/
   @Override
   public String fingerprintSearchValue(Serializable value)
   {
      try
      {
         Mac mac = Mac.getInstance("HmacSHA256");
         mac.init(new SecretKeySpec(fingerprintKey, "HmacSHA256"));
         ///////////////////////////////////////////////////////////////////////////////
         // keep only 16 bits: enough to count distinct searched values in an hour, //
         // far too few to confirm a guessed value (each fingerprint matches ~1 in  //
         // 65536 of the value space), so a persisted fingerprint is not a derivative //
         // of the searched value that could be brute-forced with the key.           //
         ///////////////////////////////////////////////////////////////////////////////
         byte[] digest = mac.doFinal(JsonUtils.toJson(value).getBytes(StandardCharsets.UTF_8));
         return (String.format("%02x%02x", digest[0], digest[1]));
      }
      catch(java.security.GeneralSecurityException e)
      {
         throw (new IllegalStateException("Unable to fingerprint search", e));
      }
   }



   /*******************************************************************************
    ** Stable user identity for all of that user's sessions.
    *******************************************************************************/
   public static String userId()
   {
      QSession session = QContext.getQSession();
      return (session == null || session.getUser() == null ? "anonymous" : Objects.requireNonNullElse(session.getUser().getIdReference(), "anonymous"));
   }



   /*******************************************************************************
    ** Treat empty optional selectors like null.
    *******************************************************************************/
   private static boolean blank(String value)
   {
      return (value == null || value.isBlank());
   }
}
