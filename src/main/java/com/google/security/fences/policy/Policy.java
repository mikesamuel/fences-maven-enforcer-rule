package com.google.security.fences.policy;

import java.util.Map;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Function;
import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.security.fences.config.Fence;
import com.google.security.fences.config.FenceVisitor;
import com.google.security.fences.config.Frenemies;
import com.google.security.fences.config.HumanReadableText;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.namespace.NamespaceTrie;

/**
 * Makes access decisions based on a configuration.
 */
public final class Policy {
  /**
   * Maps packages and classes that might access an API element to
   * API elements and the access level they have.
   */
  private final NamespaceTrie<AccessControlDecision, NamespacePolicy> trie
      = new NamespaceTrie<AccessControlDecision, NamespacePolicy>(
          NamespacePolicy.EMPTY_SUPPLIER,
          FOLD_POLICIES_TOGETHER);
  /**
   * Maps API elements to {@code <addendum />}s to show when a violation occurs
   * accessing that API element.
   */
  private final Map<ApiElement, HumanReadableText> addenda = Maps.newHashMap();

  private static final
  Function<NamespacePolicy, Function<AccessControlDecision, NamespacePolicy>>
    FOLD_POLICIES_TOGETHER
  = new Function<NamespacePolicy,
               Function<AccessControlDecision, NamespacePolicy>>() {
    public Function<AccessControlDecision, NamespacePolicy> apply(
        final NamespacePolicy policies) {
      return new Function<AccessControlDecision, NamespacePolicy>() {
        public NamespacePolicy apply(AccessControlDecision onePolicy) {
          policies.restrictAccess(onePolicy);
          return policies;
        }
      };
    }
  };

  /** The access policies for ns from most-specific to least. */
  public ImmutableList<NamespacePolicy> forNamespace(Namespace ns) {
    ImmutableList.Builder<NamespacePolicy> b = ImmutableList.builder();
    NamespaceTrie.Entry<NamespacePolicy> d = trie.getDeepest(ns);
    for (Optional<NamespaceTrie.Entry<NamespacePolicy>> e = Optional.of(d);
         e.isPresent();
         e = e.get().getParent()) {
      Optional<NamespacePolicy> accessLevels = e.get().getValue();
      if (accessLevels.isPresent()) {
        b.add(accessLevels.get());
      }
    }
    return b.build();
  }

  /**
   * All the addenda for the given API element.
   */
  public HumanReadableText getAddenda(ApiElement el) {
    HumanReadableText allAddenda = HumanReadableText.EMPTY;
    for (Optional<ApiElement> ancestor = Optional.of(el);
         ancestor.isPresent(); ancestor = ancestor.get().parent) {
      HumanReadableText addendum = addenda.get(ancestor.get());
      if (addendum != null) {
        allAddenda = addendum.concat(allAddenda);
      }
    }
    return allAddenda;
  }

  /**
   * An access control decision for a single API element.
   * This is a cell in the Namespace x ApiElement access control matrix.
   */
  public static final class AccessControlDecision {
    /**
     * The API element to which access is controlled.
     */
    public final ApiElement apiElement;
    /**
     * The access level granted to {@link #apiElement}.
     */
    public final AccessLevel accessLevel;
    /**
     * The reason if any for controlling access.
     */
    public final HumanReadableText rationale;

    AccessControlDecision(
        ApiElement apiElement, AccessLevel accessLevel,
        HumanReadableText rationale) {
      this.apiElement = apiElement;
      this.accessLevel = accessLevel;
      this.rationale = rationale;
    }

    @Override
    public String toString() {
      return "{" + apiElement + " " + accessLevel + "}";
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof AccessControlDecision)) {
        return false;
      }
      AccessControlDecision that = (AccessControlDecision) o;
      return this.accessLevel == that.accessLevel
          && this.apiElement.equals(that.apiElement)
          && this.rationale.equals(that.rationale);
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(accessLevel, apiElement, rationale);
    }

    static AccessControlDecision mostRestrictive(
        AccessControlDecision a, AccessControlDecision b) {
      Preconditions.checkArgument(a.apiElement.equals(b.apiElement));
      AccessLevel mostRestrictiveLevel = AccessLevel.mostRestrictive(
          a.accessLevel, b.accessLevel);
      HumanReadableText mergedRationale = a.rationale.concatDedupe(b.rationale);
      return new AccessControlDecision(
          a.apiElement, mostRestrictiveLevel, mergedRationale);
    }
  }

  /**
   * {@link com.google.security.fences.policy.Policy.AccessControlDecision}s
   * relevant to a particular namespace.
   * This is a row in the Namespace x ApiElement access control matrix.
   */
  public static final class NamespacePolicy {
    /** Supplies new instances for Trie nodes. */
    public static final Supplier<NamespacePolicy> EMPTY_SUPPLIER =
        new Supplier<NamespacePolicy>() {
      public NamespacePolicy get() {
        return new NamespacePolicy();
      }
    };

    private final Map<ApiElement, AccessControlDecision> apiElementToPolicy =
        Maps.newLinkedHashMap();

    /**
     * The access level for the given element if any.
     * This is based on looking for the most specific rule that applies to that
     * element or any containing api element.
     */
    public Optional<AccessControlDecision> accessPolicyForApiElement(
        ApiElement element) {
      for (Optional<ApiElement> e = Optional.of(element);
           e.isPresent();
           e = e.get().parent) {
        ApiElement el = e.get();
        AccessControlDecision p = apiElementToPolicy.get(el);
        if (p != null) {
          return Optional.of(p);
        }
      }
      return Optional.absent();
    }

    AccessControlDecision getAccessPolicy(ApiElement el) {
      return apiElementToPolicy.get(el);
    }

    void restrictAccess(AccessControlDecision p) {
      AccessControlDecision newPolicy = Preconditions.checkNotNull(p);
      ApiElement el = newPolicy.apiElement;
      AccessControlDecision oldPolicy = apiElementToPolicy.get(el);
      if (oldPolicy != null) {
        newPolicy = AccessControlDecision.mostRestrictive(oldPolicy, newPolicy);
      }
      apiElementToPolicy.put(el, newPolicy);
    }

    @VisibleForTesting
    static NamespacePolicy fromMap(Map<ApiElement, AccessControlDecision> m) {
      NamespacePolicy al = new NamespacePolicy();
      al.apiElementToPolicy.putAll(m);
      return al;
    }

    @VisibleForTesting
    static NamespacePolicy fromAccessLevelMap(Map<ApiElement, AccessLevel> m) {
      ImmutableMap.Builder<ApiElement, AccessControlDecision> b =
          ImmutableMap.builder();
      for (Map.Entry<ApiElement, AccessLevel> e : m.entrySet()) {
        ApiElement k = e.getKey();
        AccessLevel v = e.getValue();
        b.put(k, new AccessControlDecision(k, v, HumanReadableText.EMPTY));
      }
      return fromMap(b.build());
    }


    @Override
    public String toString() {
      return apiElementToPolicy.toString();
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof NamespacePolicy)) {
        return false;
      }
      NamespacePolicy that = (NamespacePolicy) o;
      return this.apiElementToPolicy.equals(that.apiElementToPolicy);
    }

    @Override
    public int hashCode() {
      return this.apiElementToPolicy.hashCode();
    }
  }

  /**
   * Produces a policy from beans typically populated from a POM
   * {@code <configuration>} element.
   */
  public static Policy fromFence(Fence fence) {
    final Policy policy = new Policy();
    FenceVisitor buildFencesVisitor = new FenceVisitor() {
      public void visit(Fence f, ApiElement apiElement) {
        Frenemies frenemies = f.getFrenemies();
        addToPolicy(
            frenemies.friends, AccessLevel.ALLOWED, apiElement,
            HumanReadableText.EMPTY);
        addToPolicy(
            frenemies.enemies, AccessLevel.DISALLOWED, apiElement,
            frenemies.rationale.body);
        if (!frenemies.rationale.addendum.isEmpty()) {
          addAddenda(apiElement, frenemies.rationale.addendum);
        }
      }

      @SuppressWarnings("synthetic-access")
      private void addToPolicy(
          Iterable<Namespace> nss, AccessLevel lvl, ApiElement el,
          HumanReadableText rationale) {
        AccessControlDecision d = new AccessControlDecision(el, lvl, rationale);
        for (Namespace ns : nss) {
          policy.trie.put(ns, d);
        }
      }

      @SuppressWarnings("synthetic-access")
      private void addAddenda(ApiElement el, HumanReadableText addendum) {
        HumanReadableText old = policy.addenda.get(el);
        if (old == null) { old = HumanReadableText.EMPTY; }
        policy.addenda.put(el, old.concat(addendum));
      }
    };
    fence.visit(buildFencesVisitor);
    return policy;
  }

  @Override
  public String toString() {
    return trie.toTree();
  }
}
