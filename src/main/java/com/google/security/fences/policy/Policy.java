package com.google.security.fences.policy;

import java.util.Map;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Function;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.security.fences.config.Fence;
import com.google.security.fences.config.FenceVisitor;
import com.google.security.fences.config.Frenemies;
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
  private final NamespaceTrie<ApiAccessPolicy, AccessLevels> trie
      = new NamespaceTrie<ApiAccessPolicy, AccessLevels>(
          AccessLevels.EMPTY_SUPPLIER,
          FOLD_POLICIES_TOGETHER);

  private static final
  Function<AccessLevels, Function<ApiAccessPolicy, AccessLevels>>
    FOLD_POLICIES_TOGETHER
  = new Function<AccessLevels,
               Function<ApiAccessPolicy, AccessLevels>>() {
    public Function<ApiAccessPolicy, AccessLevels> apply(
        final AccessLevels policies) {
      return new Function<ApiAccessPolicy, AccessLevels>() {
        public AccessLevels apply(ApiAccessPolicy onePolicy) {
          ApiElement apiElement = onePolicy.apiElement;
          policies.restrictAccess(apiElement, onePolicy.accessLevel);
          return policies;
        }
      };
    }
  };

  /** The access policies for ns from most-specific to least. */
  public ImmutableList<AccessLevels> forNamespace(Namespace ns) {
    ImmutableList.Builder<AccessLevels> b = ImmutableList.builder();
    NamespaceTrie.Entry<AccessLevels> d = trie.getDeepest(ns);
    for (Optional<NamespaceTrie.Entry<AccessLevels>> e = Optional.of(d);
         e.isPresent();
         e = e.get().getParent()) {
      Optional<AccessLevels> accessLevels = e.get().getValue();
      if (accessLevels.isPresent()) {
        b.add(accessLevels.get());
      }
    }
    return b.build();
  }

  static final class ApiAccessPolicy {
    final ApiElement apiElement;
    final AccessLevel accessLevel;

    ApiAccessPolicy(ApiElement apiElement, AccessLevel accessLevel) {
      this.apiElement = apiElement;
      this.accessLevel = accessLevel;
    }

    @Override
    public String toString() {
      return "{" + apiElement + " " + accessLevel + "}";
    }
  }

  /**
   * AccessLevels relevant to a particular namespace.
   */
  public static final class AccessLevels {
    /** Supplies new instances for Trie nodes. */
    public static final Supplier<AccessLevels> EMPTY_SUPPLIER =
        new Supplier<AccessLevels>() {
      public AccessLevels get() {
        return new AccessLevels();
      }
    };

    private final Map<ApiElement, AccessLevel> accessLevelMap =
        Maps.newLinkedHashMap();

    public Optional<AccessLevel> accessLevelForApiElement(ApiElement element) {
      for (Optional<ApiElement> e = Optional.of(element);
           e.isPresent();
           e = e.get().parent) {
        ApiElement el = e.get();
        AccessLevel lvl = accessLevelMap.get(el);
        if (lvl != null) {
          return Optional.of(lvl);
        }
      }
      return Optional.absent();
    }

    AccessLevel getAccessLevel(ApiElement el) {
      return accessLevelMap.get(el);
    }

    void restrictAccess(ApiElement el, AccessLevel lvl) {
      Preconditions.checkNotNull(el);
      Preconditions.checkNotNull(lvl);
      AccessLevel newLevel = lvl;
      AccessLevel oldLevel = accessLevelMap.get(el);
      if (oldLevel != null) {
        newLevel = AccessLevel.mostRestrictive(oldLevel, newLevel);
      }
      accessLevelMap.put(el, newLevel);
    }

    @VisibleForTesting
    static AccessLevels fromMap(Map<ApiElement, AccessLevel> m) {
      AccessLevels al = new AccessLevels();
      al.accessLevelMap.putAll(m);
      return al;
    }


    @Override
    public String toString() {
      return accessLevelMap.toString();
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof AccessLevels)) {
        return false;
      }
      AccessLevels that = (AccessLevels) o;
      return this.accessLevelMap.equals(that.accessLevelMap);
    }

    @Override
    public int hashCode() {
      return this.accessLevelMap.hashCode();
    }
  }

  /**
   * Produces a policy from beans typically populated from a POM
   * {@code <configuration>} element.
   */
  public static Policy fromFences(Iterable<? extends Fence> fences) {
    final Policy policy = new Policy();
    FenceVisitor buildFencesVisitor = new FenceVisitor() {
      public void visit(Fence f, ApiElement apiElement) {
        Frenemies frenemies = f.getFrenemies();
        addToPolicy(frenemies.friends, AccessLevel.ALLOWED, apiElement);
        addToPolicy(frenemies.enemies, AccessLevel.DISALLOWED, apiElement);
      }

      @SuppressWarnings("synthetic-access")
      private void addToPolicy(
          Iterable<Namespace> nss, AccessLevel lvl, ApiElement el) {
        for (Namespace ns : nss) {
          policy.trie.put(ns, new ApiAccessPolicy(el, lvl));
        }
      }
    };
    for (Fence f : fences) {
      f.visit(buildFencesVisitor);
    }
    return policy;
  }

  @Override
  public String toString() {
    return trie.toTree();
  }
}
