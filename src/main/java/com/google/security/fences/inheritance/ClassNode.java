package com.google.security.fences.inheritance;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

/**
 * A node in the inheritance graph.
 */
public final class ClassNode implements Comparable<ClassNode> {
  /**
   * The internal class name of the class post inner-class to top-level
   * conversion.
   * Internal class names have the form {@code com/example/Outer$Inner}, not
   * dotted fully-qualified names.
   */
  public final String name;
  /**
   * The internal name of the super-type if any.  {@code java.lang.Object} does
   * not have a super-type.
   * ASM treats interfaces as having super-type {@code java.lang.Object}.
   */
  public final Optional<String> superType;
  /**
   * For classes, the internal names of interfaces it {@code implements}, and
   * for interfaces the interfaces it {@code extends}.
   */
  public final ImmutableList<String> interfaces;

  ClassNode(
      String name,
      Optional<String> superType, Iterable<? extends String> interfaces) {
    // Names should be of form com/example/Name, not com.example.Name.
    Preconditions.checkArgument(!name.contains("."), name);
    this.name = name;
    this.superType = superType;
    this.interfaces = ImmutableList.<String>copyOf(interfaces);
  }

  public int compareTo(ClassNode x) {
    return name.compareTo(x.name);
  }

  @Override
  public String toString() {
    return name;
  }
}

