package com.google.security.fences.config;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

abstract class NamedLeafFence extends NamedFence {
  @Override
  public Iterable<Fence> getChildFences() {
    return ImmutableList.of();
  }

  @Override
  void replaceChildFences(Iterable<? extends Fence> newChildren) {
    Preconditions.checkArgument(!newChildren.iterator().hasNext());
  }

  protected abstract void addToClass(ClassFence container);

  @Override
  public Fence splitDottedNames() {
    String name = getName();
    String[] parts = name.split("[.]");
    if (parts.length == 1) {
      return this;
    }

    int i = parts.length - 1;
    this.setName(parts[i]);
    String className = parts[--i];
    ClassFence c = new ClassFence();
    c.setName(className);
    addToClass(c);

    Fence f = c;
    while (--i >= 0) {
      String part = parts[i];
      PackageFence pkg = new PackageFence();
      pkg.setName(part);
      if (f instanceof ClassFence) {
        pkg.setClass((ClassFence) f);
      } else {
        pkg.setPackage((PackageFence) f);
      }
      f = pkg;
    }
    return f;
  }
}