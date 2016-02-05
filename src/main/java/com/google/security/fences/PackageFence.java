package com.google.security.fences;

import java.util.List;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
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
    ApiElement pkgEl = el.child(getName(), ApiElementType.PACKAGE);
    v.visit(this, pkgEl);
    for (Fence child : getChildFences()) {
      child.visit(v, pkgEl);
    }
  }
}
