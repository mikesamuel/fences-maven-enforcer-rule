package com.google.security.fences.config;

import java.util.List;

import javax.annotation.Nullable;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.ApiElement;

/**
 * A bean object that can be populated from a POM file {@code <configuration>}
 * element to specify a {@link com.google.security.fences.policy.Policy}.
 */
public abstract class Fence {
  private final List<Namespace> trusts = Lists.newArrayList();
  private final List<Namespace> distrusts = Lists.newArrayList();
  private final Rationale.Builder rationale = new Rationale.Builder();
  /**
   * We keep track of the round in which this is imported, so that when
   * combining configurations into policies, we can drop imported rationales
   * in fovor of project-level ones that override them for a particular
   * API element.
   */
  private int importOrder = -1;

  Fence() {
    // package private
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setTrusts(String s) throws EnforcerRuleException {
    trusts.add(Namespace.fromDottedString(s));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setDistrusts(String s) throws EnforcerRuleException {
    distrusts.add(Namespace.fromDottedString(s));
  }

  /**
   * A human readable string shown when a policy violation is detected that
   * explains how to work within the policy and where to find more help.
   * <p>
   * The documentation at src/site/markdown/configuration.md explains how
   * to write a good one.
   *
   * @param s Human-readable text that may contain maven property expressions.
   */
  public void setRationale(@Nullable String s) throws EnforcerRuleException {
    if (s != null) {
      rationale.addBody(s);
    }
  }

  /**
   * A human readable string like a {@link #setRationale rationale} but which
   * is appended at the end regardless of whether there is a more specific
   * rationale.
   * <p>
   * The documentation at src/site/markdown/configuration.md explains how
   * to use addenda.
   *
   * @param s Human-readable text that may contain maven property expressions.
   */
  public void setAddendum(@Nullable String s) throws EnforcerRuleException {
    if (s != null) {
      rationale.addAddendum(s);
    }
  }

  /** By default, just checks children. */
  public void check() throws EnforcerRuleException {
    for (Fence childFence : getChildFences()) {
      childFence.check();
    }
  }

  /** Fences contained herein. */
  public abstract Iterable<Fence> getChildFences();

  /**
   * The API elements trusted or distrusted by the API element specified by
   * this fence.
   */
  public final Frenemies getFrenemies() {
    Frenemies.Builder b = Frenemies.builder();
    for (Namespace ns : trusts) {
      b.addFriend(ns);
    }
    for (Namespace ns : distrusts) {
      b.addEnemy(ns);
    }
    b.setRationale(rationale.build());
    return b.build();
  }

  /**
   * Called to specify the import order used when resolving duplicate
   * rationales for a particular API element.
   */
  public final void assignImportOrder(int newImportOrder) {
    Preconditions.checkState(this.importOrder == -1);
    Preconditions.checkArgument(newImportOrder >= 0);
    this.importOrder = newImportOrder;
    for (Fence child : getChildFences()) {
      child.assignImportOrder(newImportOrder);
    }
  }

  /**
   * Modifies children in place so that no node in the fence tree has a dotted
   * name.
   * @return the split node so that parents may modify their child lists.
   */
  public abstract Fence splitDottedNames();

  void mergeFrom(Fence that) {
    this.trusts.addAll(that.trusts);
    this.distrusts.addAll(that.distrusts);
    // Merge rationales, giving preference to bodies with a lower import order.
    if (this.importOrder > that.importOrder
        && !that.rationale.getBody().isEmpty()) {
      this.rationale.setBodyFrom(that.rationale.build());
    } else if (this.importOrder == that.importOrder) {
      this.rationale.addBodyFrom(that.rationale.build());
    }
    this.rationale.addAddendumFrom(that.rationale.build());
  }

  abstract void visit(FenceVisitor v, ApiElement el);

  /** Start recursively walking the fence tree. */
  public final void visit(FenceVisitor v) {
    visit(v, ApiElement.DEFAULT_PACKAGE);
  }
}