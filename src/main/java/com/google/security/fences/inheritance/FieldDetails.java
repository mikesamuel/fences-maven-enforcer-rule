package com.google.security.fences.inheritance;

import org.objectweb.asm.Opcodes;

/**
 * Details about a Java field.
 */
public final class FieldDetails {
  /** A java identifier, the name of the methods. */
  public final String name;
  /** Bitfield of {@code ACC_*} constants from {@link Opcodes}. */
  public final int access;

  FieldDetails(String name, int access) {
    this.name = name;
    this.access = access;
  }

  /**
   * True if the field is private.
   * A private field does not mask fields from its super-class.
   */
  public boolean isPrivate() {
    return (access & Opcodes.ACC_PRIVATE) != 0;
  }

  /**
   * A form that contains only Java internal identifier characters and '/'
   * suitable for storage in the Berkeley DB.
   */
  public String toCompactString() {
    return name + "/" + Integer.toString(access, 16);
  }

  /**
   * Reverse of {@link #toCompactString()}.
   */
  public static FieldDetails fromCompactString(String compactString) {
    int slash = compactString.indexOf('/');
    return new FieldDetails(
        compactString.substring(0, slash),
        Integer.valueOf(compactString.substring(slash + 1), 16));
  }

  @Override
  public String toString() {
    return name;
  }
}
