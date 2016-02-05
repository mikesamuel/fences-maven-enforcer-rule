package com.google.security.fences.policy;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;

public class ApiElement {
  final Optional<ApiElement> parent;
  final String name;
  final ApiElementType type;

  /** From JVM specification edition 8 chapter 2.9 */
  public static final String CONSTRUCTOR_SPECIAL_METHOD_NAME = "<init>";

  public static final ApiElement DEFAULT_PACKAGE = new ApiElement(
      Optional.<ApiElement>absent(), "", ApiElementType.PACKAGE);

  private ApiElement(
      Optional<ApiElement> parent, String name, ApiElementType type) {
    this.parent = parent;
    this.name = name;
    this.type = type;
    Preconditions.checkArgument(
        name.length() != 0
        || (type == ApiElementType.PACKAGE && !parent.isPresent()));
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
    return Objects.hashCode(parent, name, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append('[').append(type).append(" : ");
    appendDottedName(sb);
    return sb.append(']').toString();
  }

  private void appendDottedName(StringBuilder sb) {
    if (parent.isPresent()) {
      parent.get().appendDottedName(sb);
      sb.append('.');
    }
    sb.append(name);
  }
}
