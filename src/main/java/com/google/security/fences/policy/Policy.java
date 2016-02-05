package com.google.security.fences.policy;

import java.util.LinkedHashMap;
import java.util.Map;

import com.google.common.base.Function;
import com.google.common.base.Optional;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.security.fences.Fence;
import com.google.security.fences.FenceVisitor;
import com.google.security.fences.Frenemies;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.namespace.NamespaceTrie;

public final class Policy {
  /**
   * Maps packages and classes that might access an API element to
   * API elements and the access level they have.
   */
  private final NamespaceTrie<ApiAccessPolicy, ApiAccessPolicies> trie
      = new NamespaceTrie<ApiAccessPolicy, ApiAccessPolicies>(
          ApiAccessPolicies.EMPTY_SUPPLIER,
          FOLD_POLICIES_TOGETHER);

  private static final
  Function<ApiAccessPolicies, Function<ApiAccessPolicy, ApiAccessPolicies>>
    FOLD_POLICIES_TOGETHER
  = new Function<ApiAccessPolicies,
               Function<ApiAccessPolicy, ApiAccessPolicies>>() {
    public Function<ApiAccessPolicy, ApiAccessPolicies> apply(
        final ApiAccessPolicies policies) {
      return new Function<ApiAccessPolicy, ApiAccessPolicies>() {
        public ApiAccessPolicies apply(ApiAccessPolicy onePolicy) {
          ApiElement apiElement = onePolicy.apiElement;
          AccessLevel oldLevel = policies.policies.get(apiElement);
          AccessLevel newLevel = onePolicy.accessLevel;
          if (oldLevel != null) {
            newLevel = AccessLevel.mostRestrictive(oldLevel, newLevel);
          }
          policies.policies.put(apiElement, newLevel);
          return policies;
        }
      };
    }
  };

  /** The access policies for ns from most-specific to least. */
  public ImmutableList<ApiAccessPolicies> forNamespace(Namespace ns) {
    ImmutableList.Builder<ApiAccessPolicies> b = ImmutableList.builder();
    NamespaceTrie.Entry<ApiAccessPolicies> d = trie.getDeepest(ns);
    System.err.println("deepest\n======\n" + d.toTree() + "\n========\n");
    for (Optional<NamespaceTrie.Entry<ApiAccessPolicies>> e = Optional.of(d);
         e.isPresent();
         e = e.get().getParent()) {
      Optional<ApiAccessPolicies> apiPolicies = e.get().getValue();
      System.err.println("deepest\n======\n" + e.get().toShallowString() + "\n========\n");
      if (apiPolicies.isPresent()) {
        b.add(apiPolicies.get());
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
  }

  public static final class ApiAccessPolicies {
    public static final Supplier<ApiAccessPolicies> EMPTY_SUPPLIER =
        new Supplier<ApiAccessPolicies>() {
      public ApiAccessPolicies get() {
        return new ApiAccessPolicies();
      }
    };
    final Map<ApiElement, AccessLevel> policies =
        new LinkedHashMap<ApiElement, AccessLevel>();

    public Optional<AccessLevel> forApiElement(ApiElement element) {
      for (Optional<ApiElement> e = Optional.of(element);
           e.isPresent();
           e = e.get().parent) {
        ApiElement el = e.get();
        AccessLevel lvl = policies.get(el);
        if (lvl != null) {
          return Optional.of(lvl);
        }
      }
      return Optional.absent();
    }
  }

  public static Policy fromFences(Iterable<? extends Fence> fences) {
    System.err.println("Making policy from fences " + fences);
    final Policy policy = new Policy();
    FenceVisitor buildFencesVisitor = new FenceVisitor() {
      public void visit(Fence f, ApiElement apiElement) {
        System.err.println("Visiting fence " + f);
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
