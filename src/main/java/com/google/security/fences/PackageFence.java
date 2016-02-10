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
    String name = getName();
    ApiElement pkgEl = el.child(name, ApiElementType.PACKAGE);
    v.visit(this, pkgEl);
    for (Fence child : getChildFences()) {
      child.visit(v, pkgEl);
    }
  }

  @Override
  public Fence splitDottedNames() {
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
        packages.addAll(apiChild.getPackages());
        classes.addAll(apiChild.getClasses());
      } else {
        throw new AssertionError(splitChild.getClass());
      }
    }

    String name = getName();
    if (name.isEmpty()) {
      ApiFence apiFence = new ApiFence();
      apiFence.mergeTrustsFrom(this);
      for (PackageFence pkg : this.packages) {
        apiFence.setPackage(pkg);
      }
      for (ClassFence cls : this.classes) {
        apiFence.setClass(cls);
      }
      return apiFence;
    } else {
      String[] parts = name.split("[.]");
      if (parts.length == 1) {
        return this;
      }
      PackageFence pkg = this;
      this.setName(parts[parts.length - 1]);
      for (int i = parts.length - 1; --i >= 0;) {
        String part = parts[i];
        PackageFence parent = new PackageFence();
        parent.setName(part);
        parent.setPackage(pkg);
        pkg = parent;
      }
      return pkg;
    }
  }
}
