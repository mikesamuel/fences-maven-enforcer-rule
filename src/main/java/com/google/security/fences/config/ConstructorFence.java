package com.google.security.fences.config;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;

/** A fence for a class's constructors. */
public final class ConstructorFence extends Fence {

  @Override
  String getKey() {
    return ApiElement.CONSTRUCTOR_SPECIAL_METHOD_NAME;
  }

  @Override
  void visit(FenceVisitor v, ApiElement el) {
    v.visit(this, el.child(
        ApiElement.CONSTRUCTOR_SPECIAL_METHOD_NAME,
        ApiElementType.CONSTRUCTOR));
  }

  @Override
  public Fence splitDottedNames(ApiElement parentEl, InheritanceGraph g) {
    return this;
  }

  @Override
  public Iterable<Fence> getChildFences() {
    return ImmutableList.of();
  }

  @Override
  void replaceChildFences(Iterable<? extends Fence> newChildren) {
    Preconditions.checkArgument(!newChildren.iterator().hasNext());
  }

  @Override
  String getConfigurationElementName() {
    return "constructor";
  }
}