package com.google.security.fences.namespace;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.security.fences.util.MisconfigurationException;

/**
 * A principle or group of principles that can be granted or denied access to
 * an API element.  Typically a class or package.
 */
public final class Namespace {
  private final Namespace parent;
  private final String name;

  private Namespace() {
    this.parent = null;
    this.name = null;
  }

  private Namespace(Namespace parent, String name) {
    Preconditions.checkArgument(name.length() != 0 && name.indexOf('.') < 0);
    this.parent = Preconditions.checkNotNull(parent);
    this.name = Preconditions.checkNotNull(name);
  }

  /**
   * The namespace that directly contains this if any.
   * Absent for the default package.
   */
  public Optional<Namespace> getParent() {
    return Optional.fromNullable(parent);
  }

  /** The name of this namespace.  Absent for the default package. */
  public Optional<String> getName() {
    return Optional.fromNullable(name);
  }

  /**
   * A child namespace.
   */
  public Namespace child(String childName) {
    return new Namespace(this, childName);
  }

  /**
   * The namespace in which a class with no {@code package} declaration appears.
   */
  public static final Namespace DEFAULT_PACKAGE = new Namespace();

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Namespace)) { return false; }
    Namespace that = (Namespace) o;
    return Objects.equal(name, that.name)
        && Objects.equal(parent, that.parent);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(name, parent);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    toStringBuilder(sb);
    return sb.toString();
  }

  /**
   * appends a dotted path to sb.
   */
  public void toStringBuilder(StringBuilder sb) {
    if (parent != null) {
      int n = sb.length();
      parent.toStringBuilder(sb);
      if (sb.length() != n) {
        sb.append('.');
      }
      sb.append(name);
    } else {
      assert name == null;
    }
  }

  /**
   * @param dottedString a package name or fully-qualified class name.
   */
  public static Namespace fromDottedString(String dottedString)
  throws MisconfigurationException {
    if ("*".equals(dottedString)) {
      // Maven configuration object decoding doesn't deal well with the empty
      // string because there is no text node.
      return Namespace.DEFAULT_PACKAGE;
    }
    return fromSeparatedString("dotted name", dottedString, "[.]");
  }

  /**
   * See <a href="https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.2">JVMS 4.2</a>
   */
  public static Namespace fromInternalClassName(String icn)
  throws MisconfigurationException {
    return fromSeparatedString("internal class name", icn, "/");
  }

  static Namespace fromSeparatedString(
      String description,
      String string, String separatorPattern)
  throws MisconfigurationException {
    Namespace ns = DEFAULT_PACKAGE;
    if (string.length() != 0) {
      for (String part : string.split(separatorPattern)) {
        if (part.length() == 0) {
          throw new MisconfigurationException(
              "Invalid " + description + ": " + string);
        }
        ns = ns.child(part);
      }
    }
    return ns;
  }
}
