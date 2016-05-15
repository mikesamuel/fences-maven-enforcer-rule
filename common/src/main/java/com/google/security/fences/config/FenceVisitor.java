package com.google.security.fences.config;

import com.google.security.fences.policy.ApiElement;

/**
 * Can be used with {@link Fence#visit(FenceVisitor)} to recursively walk
 * a fence config tree.
 */
public interface FenceVisitor {
  /**
   * @param f the fence visited.
   * @param apiElement the context in which f was visited derived from its
   *   ancestors.
   */
  void visit(Fence f, ApiElement apiElement);
}
