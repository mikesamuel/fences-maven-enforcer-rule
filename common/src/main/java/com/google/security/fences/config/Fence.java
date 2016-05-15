package com.google.security.fences.config;

import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.util.MisconfigurationException;

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
   * A key used to group children that refer to the same API element.
   * When used, the key will be prefixed with the class name, which has the
   * effect of segregating method/field/class namespaces.
   * <p>
   * This must be independent of children, trusts, distrusts, and rationale --
   * all of the state that can be merged with another node.
   */
  abstract String getKey();

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setTrusts(String s) throws MisconfigurationException {
    trusts.add(parsePrinciple(s));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setDistrusts(String s) throws MisconfigurationException {
    distrusts.add(parsePrinciple(s));
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
  public void setRationale(@Nullable String s)
  throws MisconfigurationException {
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
  public void setAddendum(@Nullable String s) throws MisconfigurationException {
    if (s != null) {
      rationale.addAddendum(s);
    }
  }

  /** By default, just checks children. */
  public void check() throws MisconfigurationException {
    for (Fence childFence : getChildFences()) {
      childFence.check();
    }
  }

  /** Fences contained herein. */
  public abstract Iterable<Fence> getChildFences();

  /** Updates the list from {@link #getChildFences}. */
  abstract void replaceChildFences(Iterable<? extends Fence> newChildren);

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
  public abstract Fence splitDottedNames(ApiElement parent, InheritanceGraph g)
  throws MisconfigurationException;

  /**
   * Does minimal wrapping to produce a top-level API fence.
   */
  public ApiFence promoteToApi() {
    throw new IllegalStateException("Cannot promote " + getClass());
  }

  final void mergeFrom(Fence that) {
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

  /**
   * Merge the salient details of the given configuration into this one,
   * guaranteeing that there is only one child with a given name.
   */
  public final void mergeDeep(Fence f) {
    mergeFrom(f);

    // Group children by key, merging recursively.
    Map<String, Fence> childrenByKey = Maps.newLinkedHashMap();
    ImmutableList<Fence> childrenToMerge = ImmutableList.<Fence>builder()
        .addAll(getChildFences())
        .addAll(f.getChildFences())
        .build();
    for (Fence childToMerge : childrenToMerge) {
      String fullKey = childToMerge.getClass().getName()
          + " : " + childToMerge.getKey();
      Fence previousChild = childrenByKey.get(fullKey);
      if (previousChild != null) {
        previousChild.mergeDeep(childToMerge);
      } else {
        childrenByKey.put(fullKey, childToMerge);
      }
    }

    replaceChildFences(childrenByKey.values());
  }

  abstract void visit(FenceVisitor v, ApiElement el);

  /** Start recursively walking the fence tree. */
  public final void visit(FenceVisitor v) {
    visit(v, ApiElement.DEFAULT_PACKAGE);
  }

  abstract String getConfigurationElementName();

  void fleshOutEffectiveConfiguration(Element el) {
    Document doc = el.getOwnerDocument();
    for (Namespace ns : trusts) {
      Element trustElement = doc.createElement("trusts");
      trustElement.appendChild(doc.createTextNode(toTextNode(ns)));
      el.appendChild(trustElement);
    }
    for (Namespace ns : distrusts) {
      Element trustElement = doc.createElement("distrusts");
      trustElement.appendChild(doc.createTextNode(toTextNode(ns)));
      el.appendChild(trustElement);
    }
    HumanReadableText rbody = rationale.getBody();
    if (!rbody.isEmpty()) {
      Element rationaleElement = doc.createElement("rationale");
      rationaleElement.appendChild(doc.createTextNode(rbody.text));
      el.appendChild(rationaleElement);
    }
    HumanReadableText addendum = rationale.getAddendum();
    if (!addendum.isEmpty()) {
      Element addendumElement = doc.createElement("addendum");
      addendumElement.appendChild(doc.createTextNode(addendum.text));
      el.appendChild(addendumElement);
    }
    for (Fence child : getChildFences()) {
      Element childEl = doc.createElement(child.getConfigurationElementName());
      el.appendChild(childEl);
      child.fleshOutEffectiveConfiguration(childEl);
    }
  }

  private static String toTextNode(Namespace ns) {
    if (Namespace.DEFAULT_PACKAGE.equals(ns)) {
      return "*";
    }
    return ns.toString();
  }

  private static Namespace parsePrinciple(String s)
  throws MisconfigurationException {
    String trimmed = s.trim();
    if (!"*".equals(trimmed) && trimmed.contains("*")) {
      throw new MisconfigurationException(
          "Globs not allowed in namespace names: " + trimmed);
    }
    return Namespace.fromDottedString(trimmed);
  }
}