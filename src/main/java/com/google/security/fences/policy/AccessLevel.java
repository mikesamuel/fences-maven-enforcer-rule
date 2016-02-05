package com.google.security.fences.policy;

public enum AccessLevel {
  DISALLOWED,
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
