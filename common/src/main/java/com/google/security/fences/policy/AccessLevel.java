package com.google.security.fences.policy;

/**
 * An access control decision.
 */
public enum AccessLevel {
  // TODO: augment DISALLOWED to bundle human-readable text explaining why
  // access was/might-have-been denied.
  /** Access is not allowed. */
  DISALLOWED,
  /** Access is allowed. */
  ALLOWED,
  ;

  static AccessLevel mostRestrictive(AccessLevel... levels) {
    AccessLevel least = ALLOWED;
    for (AccessLevel level : levels) {
      if (level.compareTo(least) < 0) {
        least = level;
      }
    }
    return least;
  }
}
