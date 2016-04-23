package com.google.security.fences.config;

import java.util.Arrays;
import java.util.List;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;

/** A Fence for a package. */
public final class PackageFence extends NamedFence {
  private final List<PackageFence> packages = Lists.newArrayList();
  private final List<ClassFence> classes = Lists.newArrayList();

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setPackage(PackageFence x) {
    packages.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) {
    classes.add(Preconditions.checkNotNull(x));
  }

  @Override
  public Iterable<Fence> getChildFences() {
    return ImmutableList.<Fence>builder()
        .addAll(packages)
        .addAll(classes)
        .build();
  }

  @Override
  void visit(FenceVisitor v, ApiElement el) {
    String name = getName();
    ApiElement pkgEl = el.child(name, ApiElementType.PACKAGE);
    v.visit(this, pkgEl);
    for (Fence child : getChildFences()) {
      child.visit(v, pkgEl);
    }
  }

  @Override
  public Fence splitDottedNames(ApiElement parentEl, InheritanceGraph g)
  throws EnforcerRuleException {
    List<String> nameParts;
    String name = getName();
    if (name.isEmpty()) {
      nameParts = ImmutableList.of();
    } else {
      nameParts = ImmutableList.copyOf(Arrays.asList(name.split("[./]")));
    }

    ImmutableList.Builder<Fence> splitChildren = ImmutableList.builder();
    ApiElement el = parentEl;
    for (String namePart : nameParts) {
      el = el.child(namePart, ApiElementType.PACKAGE);
    }
    for (Fence unsplitChild : getChildFences()) {
      splitChildren.add(unsplitChild.splitDottedNames(el, g));
    }
    replaceChildFences(splitChildren.build());

    int nParts = nameParts.size();
    if (nParts == 0) {
      ApiFence apiFence = new ApiFence();
      apiFence.mergeFrom(this);
      for (PackageFence pkg : this.packages) {
        apiFence.setPackage(pkg);
      }
      for (ClassFence cls : this.classes) {
        apiFence.setClass(cls);
      }
      return apiFence;
    } else {
      PackageFence pkg = this;
      this.setName(nameParts.get(nParts - 1));
      for (int i = nParts - 1; --i >= 0;) {
        String part = nameParts.get(i);
        PackageFence parent = new PackageFence();
        parent.setName(part);
        parent.setPackage(pkg);
        pkg = parent;
      }
      return pkg;
    }
  }

  @Override
  void replaceChildFences(Iterable<? extends Fence> newChildren) {
    packages.clear();
    classes.clear();
    for (Fence newChild : newChildren) {
      if (newChild instanceof PackageFence) {
        packages.add((PackageFence) newChild);
      } else if (newChild instanceof ClassFence) {
        classes.add((ClassFence) newChild);
      } else if (newChild instanceof ApiFence) {
        ApiFence apiChild = (ApiFence) newChild;
        mergeFrom(apiChild);
        packages.addAll(apiChild.getPackages());
        classes.addAll(apiChild.getClasses());
      } else {
        throw new IllegalArgumentException(newChild.getClass().getName());
      }
    }
  }

  @Override
  String getConfigurationElementName() {
    return "package";
  }

  @Override
  public ApiFence promoteToApi() {
    ApiFence api = new ApiFence();
    api.setPackage(this);
    return api;
  }
}
