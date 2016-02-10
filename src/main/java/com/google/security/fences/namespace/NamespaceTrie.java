package com.google.security.fences.namespace;

import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import com.google.common.base.Function;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableMap;

/**
 * Maps package and class names to values.
 *
 * @param <COMPLEX_VALUE> The value type stored at a Trie node.
 * @param <SIMPLE_VALUE> The type that can be added to a Trie node.
 *    This can be a part of the COMPLEX_VALUE allowing the trie to easily
 *    function as a MultiTrie.
 */
public final class NamespaceTrie<SIMPLE_VALUE, COMPLEX_VALUE> {
  final Entry<COMPLEX_VALUE> root = new Entry<COMPLEX_VALUE>(null);
  final Supplier<COMPLEX_VALUE> makeEmpty;
  final Function<COMPLEX_VALUE, Function<SIMPLE_VALUE, COMPLEX_VALUE>> folder;

  /**
   * @param makeEmpty a supplier for empty complex values.
   * @param folder combines a previous complex value and a simple value being
   *    added to a node together to produce the new complex value.
   */
  public NamespaceTrie(
      Supplier<COMPLEX_VALUE> makeEmpty,
      Function<COMPLEX_VALUE, Function<SIMPLE_VALUE, COMPLEX_VALUE>> folder) {
    this.makeEmpty = makeEmpty;
    this.folder = folder;
  }

  /** The minimal collection of entries that includes all overlapping ns. */
  public Map<Namespace, COMPLEX_VALUE> overlapping(Namespace ns) {
    Entry<COMPLEX_VALUE> e = getEntry(ns, false, false);
    ImmutableMap.Builder<Namespace, COMPLEX_VALUE> b =
        ImmutableMap.builder();
    if (e != null) {
      e.addTransitively(ns, b);
    }
    return b.build();
  }

  /**
   * The node specified by the given namespace if any.
   */
  public Entry<COMPLEX_VALUE> get(Namespace ns) {
    return getEntry(ns, false, false);
  }

  /**
   * Folds a simple value into the node specified by ns,
   * creating a new node if necessary.
   */
  public Entry<COMPLEX_VALUE> put(Namespace ns, SIMPLE_VALUE simpleValue) {
    Entry<COMPLEX_VALUE> e = Preconditions.checkNotNull(
        getEntry(ns, true, false));
    e.putValue(this.makeEmpty, this.folder, simpleValue);
    return e;
  }

  /**
   * The value at namespace or one of its ancestors giving preferences to
   * deeper nodes.
   */
  public Entry<COMPLEX_VALUE> getDeepest(Namespace ns) {
    return getEntry(ns, false, true);
  }

  private Entry<COMPLEX_VALUE> getEntry(
      Namespace ns, boolean manufacture, boolean bestEffort) {
    Entry<COMPLEX_VALUE> parentEntry;
    Optional<Namespace> parent = ns.getParent();
    if (parent.isPresent()) {
      parentEntry = getEntry(parent.get(), manufacture, bestEffort);
      if (parentEntry == null) { return null; }
    } else {
      parentEntry = root;
    }
    Optional<String> nameOpt = ns.getName();
    if (nameOpt.isPresent()) {
      String name = nameOpt.get();
      @SuppressWarnings("synthetic-access")
      SortedMap<String, Entry<COMPLEX_VALUE>> children = parentEntry.children;
      Entry<COMPLEX_VALUE> child = children.get(name);
      if (child == null) {
        if (manufacture) {
          child = new Entry<COMPLEX_VALUE>(parentEntry);
          children.put(name, child);
        } else if (bestEffort) {
          return parentEntry;
        }
      }
      return child;
    } else {
      return parentEntry;
    }
  }

  /**
   * A diagnostic text representation of the trie with one line per entry.
   */
  public String toTree() {
    return root.toTree();
  }


  /** A trie entry. */
  public static final class Entry<T> {
    private Optional<T> value = Optional.absent();
    private final Entry<T> parent;
    private final SortedMap<String, Entry<T>> children =
        new TreeMap<String, Entry<T>>();

    Entry(Entry<T> parent) {
      this.parent = parent;
    }

    <X>
    void putValue(
        Supplier<T> emptyValue, Function<T, Function<X, T>> fold,
        X newValuePart) {
      T newValue = fold.apply(value.or(emptyValue)).apply(newValuePart);
      value = Optional.of(newValue);
    }

    public Optional<T> getValue() {
      return value;
    }

    public Optional<Entry<T>> getParent() {
      return Optional.fromNullable(parent);
    }

    void addTransitively(Namespace ns, ImmutableMap.Builder<Namespace, T> out) {
      if (value.isPresent()) {
        out.put(ns, value.get());
      }
      for (Map.Entry<String, Entry<T>> e : children.entrySet()) {
        e.getValue().addTransitively(ns.child(e.getKey()), out);
      }
    }

    @Override
    public String toString() {
      return toShallowString();
    }

    public String toShallowString() {
      return "Entry " + value;
    }

    public String toTree() {
      StringBuilder sb = new StringBuilder();
      toTree(sb, 0);
      return sb.toString();
    }

    public void toTree(StringBuilder sb, int n) {
      sb.append(toShallowString());
      int childDepth = n + 1;
      for (Map.Entry<String, Entry<T>> e : children.entrySet()) {
        sb.append('\n');
        for (int i = childDepth; --i >= 0;) { sb.append(". "); }
        sb.append(e.getKey()).append(" => ");
        e.getValue().toTree(sb, childDepth);
      }
    }
  }
}
