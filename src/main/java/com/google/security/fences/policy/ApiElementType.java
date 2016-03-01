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
  /** A namespace for a Java package. */
  PACKAGE,
  /** A namespace for a Java class, possibly an inner class. */
  CLASS,
  /** A namespace for a field within a class. */
  FIELD,
  /** A namespace for a method within a class. */
  METHOD,
  /** A namespace for a constructor within a class. */
  CONSTRUCTOR,
  ;
}
