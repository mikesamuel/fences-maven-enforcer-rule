package com.google.security.fences;

import com.google.security.fences.policy.ApiElement;

public interface FenceVisitor {
  void visit(Fence f, ApiElement apiElement);
}
