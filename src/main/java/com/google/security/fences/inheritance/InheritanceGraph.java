package com.google.security.fences.inheritance;

import java.util.Map;

import com.google.common.base.Function;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;

/**
 * A lazy-ish graph of sub/super-type relationships between Java classes.
 */
public final class InheritanceGraph {
  private final Map<String, ClassNode> classNodes;
  private final Function<String, ClassNode> fallback;

  InheritanceGraph(
      Map<String, ClassNode> classNodes,
      Function<String, ClassNode> fallback) {
    this.classNodes = Maps.newLinkedHashMap(classNodes);
    this.fallback = fallback;
  }

  /**
   * Returns the named node.
   *
   * @param name an internal class name like {@code com/example/MyClass}.
   */
  public Optional<ClassNode> named(String name) {
    ClassNode node = classNodes.get(name);
    if (node == null && !classNodes.containsKey(name)) {
      classNodes.put(name, node = fallback.apply(name));
    }
    return Optional.fromNullable(node);
  }

  /** A builder that uses the pre-baked system class graph. */
  public static Builder builder() {
    return new Builder(SystemInheritanceGraph.LAZY_LOADER);
  }

  static Builder builder(Function<String, ClassNode> fallback) {
    return new Builder(fallback);
  }

  /** A builder for {InheritanceGraph}s. */
  public static final class Builder {
    private final Map<String, ClassNode> classNodes = Maps.newLinkedHashMap();
    private final Function<String, ClassNode> lazyLoadSystemClass;
    private final Map<String, String> outers = Maps.newLinkedHashMap();

    Builder(final Function<String, ClassNode> lazyLoadSystemClass) {
      this.lazyLoadSystemClass = lazyLoadSystemClass;
    }

    /**
     * Defines a relationship between name and its super-interfaces.
     */
    public DeclarationBuilder declare(String name, int access) {
      return new DeclarationBuilder(name, access);
    }

    /** Single use builder.  State is cleared after call to build(). */
    public InheritanceGraph build() {
      return new InheritanceGraph(classNodes, lazyLoadSystemClass);
    }

    void classContains(String outer, String inner) {
      ClassNode innerNode = classNodes.get(inner);
      if (innerNode != null) {
        innerNode = new ClassNode(
            innerNode.name, innerNode.access, innerNode.superType,
            Optional.of(outer), innerNode.interfaces, innerNode.methods,
            innerNode.fields);
        classNodes.put(inner, innerNode);
      } else {
        outers.put(inner, outer);
      }
    }

    /**
     * Used to add additional details about a class.
     */
    public final class DeclarationBuilder {
      private final String name;
      private final int access;

      private Optional<String> superClassName = Optional.of("java/lang/Object");
      private Optional<String> outerClassName = Optional.absent();
      private ImmutableList.Builder<String> interfaceNames =
          ImmutableList.builder();
      private ImmutableList.Builder<MethodDetails> methods =
          ImmutableList.builder();
      private ImmutableList.Builder<FieldDetails> fields =
          ImmutableList.builder();

      DeclarationBuilder(String name, int access) {
        this.name = name;
        this.access = access;
      }

      /** Sets the super-class name if any.  Null only for "java/lang/Object" */
      public DeclarationBuilder superClassName(
          Optional<String> newSuperClassName) {
        this.superClassName = newSuperClassName;
        return this;
      }
      /** Sets the outer-class name if any. */
      public DeclarationBuilder outerClassName(
          Optional<String> newOuterClassName) {
        this.outerClassName = newOuterClassName;
        return this;
      }
      /** Sets the interface list. */
      public DeclarationBuilder interfaceNames(
          Iterable<? extends String> newInterfaceNames) {
        this.interfaceNames.addAll(newInterfaceNames);
        return this;
      }
      /** Sets the list of declared methods. */
      public DeclarationBuilder methods(
          Iterable<? extends MethodDetails> newMethods) {
        this.methods.addAll(newMethods);
        return this;
      }
      /** Sets the list of declared fields. */
      public DeclarationBuilder fields(
          Iterable<? extends FieldDetails> newFields) {
        this.fields.addAll(newFields);
        return this;
      }

      /** Commit the built declaration into the parent builders map. */
      public Builder commit() {
        @SuppressWarnings("synthetic-access")
        Map<String, ClassNode> classNodesMap = Builder.this.classNodes;
        @SuppressWarnings("synthetic-access")
        Map<String, String> outersMap = Builder.this.outers;
        ClassNode node = classNodesMap.get(name);
        if (node == null) {
          Optional<String> outer = outerClassName;
          if (!outer.isPresent()) {
            outer = Optional.fromNullable(outersMap.remove(name));
          }
          node = new ClassNode(
              name, access, superClassName, outer,
              interfaceNames.build(), methods.build(), fields.build());
          classNodesMap.put(name, node);
        }
        // Otherwise assume that subsequent declarations are from masked
        // class-files on the same class-path.
        return Builder.this;
      }
    }

  }

  /** All the names of class declared, or lazily fetched. */
  public Iterable<String> allDeclaredNames() {
    return ImmutableList.copyOf(classNodes.keySet());
  }

  /** All the names of class declared, or lazily fetched. */
  public Iterable<ClassNode> allDeclaredNodes() {
    return ImmutableList.copyOf(classNodes.values());
  }
}
