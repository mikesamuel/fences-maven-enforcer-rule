package com.google.security.fences.config;

import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;

/**
 * A fence for all methods with a given name in a class regardless of
 * parameter, return type and other non-name based signature elements.
 */
public final class MethodFence extends NamedLeafFence {
  @Override
  void visit(FenceVisitor v, ApiElement el) {
    v.visit(this, el.child(getName(), ApiElementType.METHOD));
  }

  @Override
  protected void addToClass(ClassFence container) {
    container.setMethod(this);
  }

  @Override
  String getConfigurationElementName() {
    return "method";
  }
}
