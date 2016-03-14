package com.google.security.fences.inheritance;

import org.objectweb.asm.Opcodes;

/**
 * Details about a Java method.
 */
public final class MethodDetails {
  /** A java identifier, the name of the methods. */
  public final String name;
  /** The method descriptor. */
  public final String desc;
  /** Bitfield of {@code ACC_*} constants from {@link Opcodes}. */
  public final int access;

  MethodDetails(String name, String desc, int access) {
    this.name = name;
    this.desc = desc;
    this.access = access;
  }

  /**
   * True if the method is private.
   * A private method does not override methods from its super-class.
   */
  public boolean isPrivate() {
    return (access & Opcodes.ACC_PRIVATE) != 0;
  }

  /**
   * A form that contains only Java internal identifier characters and '/'
   * suitable for storage in the Berkeley DB.
   */
  public String toCompactString() {
    return name + "/" + desc + "/" + Integer.toString(access, 16);
  }

  /**
   * Reverse of {@link #toCompactString()}.
   */
  public static MethodDetails fromCompactString(String compactString) {
    int firstSlash = compactString.indexOf('/');
    int lastSlash = compactString.lastIndexOf('/');
    return new MethodDetails(
        compactString.substring(0, firstSlash),
        compactString.substring(firstSlash + 1, lastSlash),
        Integer.valueOf(compactString.substring(lastSlash + 1), 16));
  }

  @Override
  public String toString() {
    return name + " " + desc;
  }
}
