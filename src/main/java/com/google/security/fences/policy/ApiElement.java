package com.google.security.fences.policy;

import java.util.List;

import javax.annotation.Nullable;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;

/**
 * An element of a Java API that can be identified by a dotted name.
 */
public class ApiElement implements Comparable<ApiElement> {
  /** The parent element if any. */
  public final Optional<ApiElement> parent;
  /** Unqualified name. */
  public final String name;
  /** The type of API element. */
  public final ApiElementType type;
  private final int hashCode;

  /** From JVM specification edition 8 chapter 2.9 */
  public static final String CONSTRUCTOR_SPECIAL_METHOD_NAME = "<init>";

  /**
   * The package to which Java source files without a {@code package}
   * declaration contribute classes.
   */
  public static final ApiElement DEFAULT_PACKAGE = new ApiElement(
      Optional.<ApiElement>absent(), "", ApiElementType.PACKAGE);

  private ApiElement(
      Optional<ApiElement> parent, String name, ApiElementType type) {
    this.parent = parent;
    this.name = name;
    this.type = type;
    this.hashCode = Objects.hashCode(parent, name, type);

    Preconditions.checkArgument(
        (name.length() == 0)
        == (type == ApiElementType.PACKAGE && !parent.isPresent()));
    Preconditions.checkArgument(!name.contains("."), name);
    Preconditions.checkArgument(parent.isPresent() || name.length() == 0);
    switch (type) {
      case CLASS:
        Preconditions.checkArgument(
            parent.get().type == ApiElementType.PACKAGE
            || parent.get().type == ApiElementType.CLASS);
        return;
      case CONSTRUCTOR:
        Preconditions.checkArgument(
            name.equals(CONSTRUCTOR_SPECIAL_METHOD_NAME));
        Preconditions.checkArgument(
            parent.isPresent()
            && parent.get().type == ApiElementType.CLASS);
        return;
      case FIELD:
      case METHOD:
        Preconditions.checkArgument(
            parent.isPresent()
            && parent.get().type == ApiElementType.CLASS);
        return;
      case PACKAGE:
        Preconditions.checkArgument(
            !parent.isPresent() || parent.get().type == ApiElementType.PACKAGE);
        return;
    }
    throw new AssertionError(type);
  }

  /** Constructs a child of this API element. */
  public ApiElement child(String childName, ApiElementType childType) {
    return new ApiElement(Optional.of(this), childName, childType);
  }

  /**
   * @param name a JVM internal class name.
   * @return An API element such that name equals {@link #toInternalName}.
   */
  public static ApiElement fromInternalClassName(String name) {
    try {
      ApiElement apiElement = ApiElement.DEFAULT_PACKAGE;
      String[] nameParts = name.split("/");
      for (int i = 0, n = nameParts.length; i < n - 1; ++i) {
        apiElement = apiElement.child(nameParts[i], ApiElementType.PACKAGE);
      }
      String className = nameParts[nameParts.length - 1];
      for (String classNamePart : splitClassName(className)) {
        apiElement = apiElement.child(classNamePart, ApiElementType.CLASS);
      }
      return apiElement;
    } catch (RuntimeException ex) {
      // Make sure the trace includes the whole input.
      throw new IllegalArgumentException(
          "Bad internal class name `" + name + "`", ex);
    }
  }

  static Iterable<String> splitClassName(String className) {
    int n = className.length();
    if (n == 0) {
      throw new IllegalArgumentException();
    }
    List<String> parts = Lists.newArrayList();
    int start = 0;
    for (int i = start + 1; i < n - 1; ++i) {
      if (className.charAt(i) == '$') {
        assert i != start;
        parts.add(className.substring(start, i));
        start = ++i;
      }
    }
    parts.add(className.substring(start));
    return parts;
  }

  /**
   * The containing class if any.
   * {@code this} if {@link #type} is {@link ApiElementType#CLASS}.
   */
  public Optional<ApiElement> containingClass() {
    switch (type) {
      case CLASS:
        return Optional.of(this);
      case CONSTRUCTOR:
      case FIELD:
      case METHOD:
        return parent.get().containingClass();
      case PACKAGE:
        return Optional.absent();
    }
    throw new AssertionError(type);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof ApiElement)) {
      return false;
    }
    ApiElement that = (ApiElement) o;
    return type == that.type && name.equals(that.name)
        && parent.equals(that.parent);
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  public int compareTo(ApiElement that) {
    int delta = (this.parent.isPresent() ? 1 : 0)
        - (that.parent.isPresent() ? 1 : 0);
    if (delta == 0) {
      if (this.parent.isPresent()) {
        delta = this.parent.get().compareTo(that.parent.get());
      }
      if (delta == 0) {
        delta = this.name.compareTo(that.name);
        if (delta == 0) {
          delta = this.type.compareTo(that.type);
        }
      }
    }
    return delta;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append('[').append(type).append(" : ");
    toName(false, sb);
    sb.append(']');
    return sb.toString();
  }

  /**
   * A string, like {@link #toInternalName()} but with dots, so more
   * recognizable to Java devs familiar with fully qualified Java names.
   */
  public String toDottedName() {
    return toName(false, null).toString();
  }

  /**
   * Returns an internal class name.
   * If this is a {@link ApiElementType#CLASS} then this is a Java internal
   * class name.
   * If this is a {@link ApiElementType#PACKAGE} then this is a relative
   * directory name for the package under a class root.
   */
  public String toInternalName() {
    return toName(true, null).toString();
  }

  private CharSequence toName(boolean internal, @Nullable StringBuilder out) {
    if (DEFAULT_PACKAGE.equals(this)) {
      return "";
    }
    // We build in reverse so that we don't have to recurse to parent.
    StringBuilder sb = out;
    if (sb == null) {
      sb = new StringBuilder();
    }
    int startPosition = sb.length();
    switch (type) {
      case PACKAGE:
        // Treat package names as directories to disambiguate those namespaces.
        if (internal) { sb.append('/'); }
        break;
      case METHOD: case CONSTRUCTOR:
        // Disambiguate callables and fields.
        // Constructors are disambiguated from methods by the presence of
        // angle brackets in the name: <init> and <clinit>.
        sb.append(")(");
        break;
      case FIELD: case CLASS:
        break;
    }
    ApiElement el = this;
    while (true) {
      ApiElement parentEl = el.parent.get();
      appendInReverse(el.name, sb);
      if (DEFAULT_PACKAGE.equals(parentEl)) {
        break;
      }
      switch (el.type) {
        case CLASS:
          sb.append(
              internal
              ? (parentEl.type == ApiElementType.CLASS ? '$' : '/')
              : '.');
          break;
        case PACKAGE:
          sb.append(internal ? '/' : '.');
          break;
        case CONSTRUCTOR:
        case METHOD:
        case FIELD:
          sb.append(internal ? '#' : '.');
          break;
      }
      el = parentEl;
    }
    reverse(sb, startPosition, sb.length());
    return sb;
  }


  /** Statically-importable methods that create ApiElements. */
  public static final class Factory {
    static ApiElement pkg(String name, ApiElement parent) {
      return parent.child(name, ApiElementType.PACKAGE);
    }

    static ApiElement pkg(String name) {
      return pkg(name, ApiElement.DEFAULT_PACKAGE);
    }

    static ApiElement clazz(String name, ApiElement parent) {
      return parent.child(name, ApiElementType.CLASS);
    }

    static ApiElement field(String name, ApiElement parent) {
      return parent.child(name, ApiElementType.FIELD);
    }

    static ApiElement method(String name, ApiElement parent) {
      return parent.child(name, ApiElementType.METHOD);
    }
  }

  private static void appendInReverse(String s, StringBuilder sb) {
    for (int i = s.length(); --i >= 0;) {
      sb.append(s.charAt(i));
    }
  }

  private static void reverse(StringBuilder sb, int start, int end) {
    for (int i = start, j = end; --j > i; ++i) {
      char c = sb.charAt(i), d = sb.charAt(j);
      sb.setCharAt(i, d);
      sb.setCharAt(j, c);
    }
  }
}
