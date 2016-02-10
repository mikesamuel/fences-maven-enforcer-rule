package com.google.security.fences.config;

import java.util.List;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.security.fences.policy.ApiElement;

/** An unnammed collection of fences. */
public final class ApiFence extends Fence {
  private final List<PackageFence> packages = Lists.newArrayList();
  private final List<ClassFence> classes = Lists.newArrayList();

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setPackage(PackageFence x) {
    packages.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) {
    classes.add(Preconditions.checkNotNull(x));
  }

  ImmutableList<PackageFence> getPackages() {
    return ImmutableList.copyOf(packages);
  }

  ImmutableList<ClassFence> getClasses() {
    return ImmutableList.copyOf(classes);
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
    // ApiFence should not be a child of another fence.
    Preconditions.checkArgument(el.equals(ApiElement.DEFAULT_PACKAGE));
    v.visit(this, ApiElement.DEFAULT_PACKAGE);
    for (Fence child : getChildFences()) {
      child.visit(v, ApiElement.DEFAULT_PACKAGE);
    }
  }

  @Override
  public ApiFence splitDottedNames() {
    ImmutableList<Fence> unsplitChildren = ImmutableList.copyOf(
        getChildFences());
    packages.clear();
    classes.clear();
    for (Fence unsplitChild : unsplitChildren) {
      Fence splitChild = unsplitChild.splitDottedNames();
      if (splitChild instanceof PackageFence) {
        packages.add((PackageFence) splitChild);
      } else if (splitChild instanceof ClassFence) {
        classes.add((ClassFence) splitChild);
      } else if (splitChild instanceof ApiFence) {
        ApiFence apiChild = (ApiFence) splitChild;
        mergeTrustsFrom(apiChild);
        packages.addAll(apiChild.packages);
        classes.addAll(apiChild.classes);
      } else {
        throw new AssertionError(splitChild.getClass());
      }
    }
    return this;
  }
}
