package com.google.security.fences.policy;

/**
 * The kind of an API element.
 * <p>
 * Java puts inner classes, fields, and methods in different namespaces, so
 * <tt>class x { int x; int x() { return new x().x; } }<tt>
 * contains no reference cycles.
 * <p>
 * Tagging the kind of thing a name refers to can help disambiguate.
 */
public enum ApiElementType {
  PACKAGE,
  CLASS,
  FIELD,
  METHOD,
  CONSTRUCTOR,
  ;
}
