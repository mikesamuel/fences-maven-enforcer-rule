package com.google.security.fences.policy;

import javax.annotation.Nullable;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;

/**
 * An element of a Java API that can be identified by a dotted name.
 */
public class ApiElement {
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
        name.length() != 0
        || (type == ApiElementType.PACKAGE && !parent.isPresent()));
    Preconditions.checkArgument(!name.contains("."), name);
    switch (type) {
      case CLASS:
        Preconditions.checkArgument(
            !parent.isPresent() || (
                parent.get().type == ApiElementType.PACKAGE
                || parent.get().type == ApiElementType.CLASS));
        return;
      case CONSTRUCTOR:
        Preconditions.checkArgument(
            name.equals(CONSTRUCTOR_SPECIAL_METHOD_NAME));
        // $FALL-THROUGH$
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
    Optional<ApiElement> parentOpt;
    if (DEFAULT_PACKAGE.equals(this)) {
      parentOpt = Optional.absent();
    } else {
      parentOpt = Optional.of(this);
    }
    return new ApiElement(parentOpt, childName, childType);
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

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append('[').append(type).append(" : ");
    appendDottedName(sb);
    sb.append(']');
    return sb.toString();
  }

  private void appendDottedName(StringBuilder sb) {
    if (parent.isPresent()) {
      parent.get().appendDottedName(sb);
      sb.append('.');
    }
    sb.append(name);
  }

  /**
   * Returns an internal class name.
   * If this is a {@link ApiElementType#CLASS} then this is a Java internal
   * class name.
   * If this is a {@link ApiElementType#PACKAGE} then this is a relative
   * directory name for the package under a class root.
   */
  public String toInternalName() {
    // We build in reverse so that we don't have to recurse to parent.
    StringBuilder sb = new StringBuilder();
    // Treat package names as directories to disambiguate those namespaces.
    if (type == ApiElementType.PACKAGE && !DEFAULT_PACKAGE.equals(this)) {
      sb.append('/');
    }
    ApiElement el = this;
    while (true) {
      @Nullable ApiElement parentEl = el.parent.isPresent()
          ? el.parent.get() : null;
      appendInReverse(el.name, sb);
      if (parentEl == null) {
        break;
      }
      switch (el.type) {
        case CLASS:
          sb.append(parentEl.type == ApiElementType.CLASS ? '$' : '/');
          break;
        case PACKAGE:
          sb.append('/');
          break;
        case CONSTRUCTOR:
        case METHOD:
        case FIELD:
          sb.append('#');
          break;
      }
      el = parentEl;
    }
    return sb.reverse().toString();
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
}
