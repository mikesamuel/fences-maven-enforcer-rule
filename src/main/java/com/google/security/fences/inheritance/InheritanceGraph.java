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
    public Builder declare(
        String name, int access, Optional<String> superClassName,
        Iterable<? extends String> interfaceNames,
        Iterable<? extends MethodDetails> methods,
        Iterable<? extends FieldDetails> fields) {
      ClassNode node = classNodes.get(name);
      if (node == null) {
        node = new ClassNode(
            name, access, superClassName, interfaceNames, methods, fields);
        classNodes.put(name, node);
      }
      // Otherwise assume that subsequent declarations are from masked
      // class-files on the same class-path.
      return this;
    }

    /** Single use builder.  State is cleared after call to build(). */
    public InheritanceGraph build() {
      return new InheritanceGraph(classNodes, lazyLoadSystemClass);
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
