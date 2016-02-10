package com.google.security.fences.config;

import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;

/** A class for a field in a class. */
public final class FieldFence extends NamedLeafFence {

  @Override
  void visit(FenceVisitor v, ApiElement el) {
    v.visit(this, el.child(getName(), ApiElementType.FIELD));
  }

  @Override
  protected void addToClass(ClassFence container) {
    container.setField(this);
  }
}