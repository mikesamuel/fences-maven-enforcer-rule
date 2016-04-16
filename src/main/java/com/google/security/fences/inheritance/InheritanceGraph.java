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

    /**
     * Used to add additional details about a class.
     */
    public final class DeclarationBuilder {
      private final String name;
      private final int access;

      private Optional<String> superClassName = Optional.of("java/lang/Object");
      private Optional<String> outerClassName = Optional.absent();
      private ImmutableList<String> interfaceNames = ImmutableList.of();
      private ImmutableList<MethodDetails> methods = ImmutableList.of();
      private ImmutableList<FieldDetails> fields = ImmutableList.of();

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
        this.interfaceNames = ImmutableList.<String>builder()
            .addAll(interfaceNames)
            .addAll(newInterfaceNames)
            .build();
        return this;
      }
      /** Sets the list of declared methods. */
      public DeclarationBuilder methods(
          Iterable<? extends MethodDetails> newMethods) {
        this.methods = ImmutableList.<MethodDetails>builder()
            .addAll(methods)
            .addAll(newMethods)
            .build();
        return this;
      }
      /** Sets the list of declared fields. */
      public DeclarationBuilder fields(
          Iterable<? extends FieldDetails> newFields) {
        this.fields = ImmutableList.<FieldDetails>builder()
            .addAll(fields)
            .addAll(newFields)
            .build();
        return this;
      }

      /** Commit the built declaration into the parent builders map. */
      public Builder commit() {
        @SuppressWarnings("synthetic-access")
        Map<String, ClassNode> classNodesMap = Builder.this.classNodes;
        ClassNode node = classNodesMap.get(name);
        if (node == null) {
          node = new ClassNode(
              name, access, superClassName, outerClassName,
              interfaceNames, methods, fields);
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
