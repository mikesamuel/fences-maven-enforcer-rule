package com.google.security.fences.policy;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;

public class ApiElement {
  final Optional<ApiElement> parent;
  final String name;
  final ApiElementType type;
  private final int hashCode;

  /** From JVM specification edition 8 chapter 2.9 */
  public static final String CONSTRUCTOR_SPECIAL_METHOD_NAME = "<init>";

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

  public ApiElement child(String childName, ApiElementType childType) {
    Optional<ApiElement> parentOpt;
    if (DEFAULT_PACKAGE.equals(this)) {
      parentOpt = Optional.absent();
    } else {
      parentOpt = Optional.of(this);
    }
    return new ApiElement(parentOpt, childName, childType);
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
}
