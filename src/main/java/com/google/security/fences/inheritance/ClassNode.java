package com.google.security.fences.inheritance;

import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

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
  /**
   * Names and signatures of declared methods.
   */
  public final ImmutableSet<MethodDetails> methods;
  /**
   * Names of declared fields.
   */
  public final ImmutableSet<FieldDetails> fields;

  ClassNode(
      String name,
      Optional<String> superType, Iterable<? extends String> interfaces,
      Iterable<? extends MethodDetails> methods,
      Iterable<? extends FieldDetails> fields) {
    // Names should be of form com/example/Name, not com.example.Name.
    Preconditions.checkArgument(!name.contains("."), name);
    this.name = name;
    this.superType = superType;
    this.interfaces = ImmutableList.copyOf(interfaces);
    this.methods = ImmutableSet.copyOf(methods);
    this.fields = ImmutableSet.copyOf(fields);
  }

  /**
   * The method with the given name and descriptor if any.
   */
  public Optional<MethodDetails> getMethod(
      String methodName, String descriptor) {
    for (MethodDetails m : methods) {
      if (m.name.equals(methodName) && m.desc.equals(descriptor)) {
        return Optional.of(m);
      }
    }
    return Optional.absent();
  }

  /**
   * The field with the given name if any.
   */
  public Optional<FieldDetails> getField(String fieldName) {
    for (FieldDetails f : fields) {
      if (f.name.equals(fieldName)) {
        return Optional.of(f);
      }
    }
    return Optional.absent();
  }

  /**
   * True if a method with the given name and descriptor is visible from
   * a super-type through this type.
   * In other words, there is no compatible method declaration that would
   * prevent a sub-type from inheriting the method from a super-type.
   *
   * @param methodName the name of a method available on this class.
   * @param descriptor the Java internal descriptor consisting of the
   *     parameter types in order in parentheses followed by the return type.
   */
  public boolean isMethodVisibleThrough(String methodName, String descriptor) {
    for (MethodDetails m : methods) {
      // Method return-type specialization and generic parameter specialization
      // do not affect descriptors because javac creates two methods --
      // the specialized version and an unspecialized version that calls the
      // former.
      if (m.name.equals(methodName) && m.desc.equals(descriptor)) {
        // Methods do not inherit from private methods and private methods
        // do not override methods declared in super-types.
        if ((m.access & Opcodes.ACC_PRIVATE) == 0) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * True if the named field is visible from a super-type through this type.
   * In other words, there is no masking field declaration in this class visible
   * to sub-types.
   */
  public boolean isFieldVisibleThrough(String fieldName) {
    for (FieldDetails f : fields) {
      if (f.name.equals(fieldName)) {
        // Private fields do not mask fields in super-tpes.
        if ((f.access & Opcodes.ACC_PRIVATE) == 0) {
          return false;
        }
      }
    }
    return true;
  }

  public int compareTo(ClassNode x) {
    return name.compareTo(x.name);
  }

  @Override
  public String toString() {
    return name;
  }
}

