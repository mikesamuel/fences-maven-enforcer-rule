package com.google.security.fences;

import java.util.List;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import com.google.common.collect.Lists;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.ApiElement;

/**
 * An API element or collection thereof to which access can be restricted.
 */
public abstract class Fence {
  private final List<Namespace> trusts = Lists.newArrayList();
  private final List<Namespace> distrusts = Lists.newArrayList();

  Fence() {
    // package private
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setTrusts(String s) throws EnforcerRuleException {
    trusts.add(Namespace.fromDottedString(s));
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setDistrusts(String s) throws EnforcerRuleException {
    distrusts.add(Namespace.fromDottedString(s));
  }

  /** By default, just checks children. */
  public void check() throws EnforcerRuleException {
    for (Fence childFence : getChildFences()) {
      childFence.check();
    }
  }

  public abstract Iterable<Fence> getChildFences();

  public final Frenemies getFrenemies() {
    Frenemies.Builder b = Frenemies.builder();
    for (Namespace ns : trusts) {
      b.addFriend(ns);
    }
    for (Namespace ns : distrusts) {
      b.addEnemy(ns);
    }
    return b.build();
  }

  /**
   * Modifies children in place so that no node in the fence tree has a dotted
   * name.
   * @return the split node so that parents may modify their child lists.
   */
  public abstract Fence splitDottedNames();

  void mergeTrustsFrom(Fence that) {
    this.trusts.addAll(that.trusts);
    this.distrusts.addAll(that.distrusts);
  }

  abstract void visit(FenceVisitor v, ApiElement el);

  public final void visit(FenceVisitor v) {
    visit(v, ApiElement.DEFAULT_PACKAGE);
  }
}