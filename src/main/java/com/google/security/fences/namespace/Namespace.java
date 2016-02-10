package com.google.security.fences.namespace;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;

/**
 * A principle or group of principles that can be granted or denied access to
 * an API element.
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

  public Optional<Namespace> getParent() {
    return Optional.fromNullable(parent);
  }

  public Optional<String> getName() {
    return Optional.fromNullable(name);
  }

  public Namespace child(String childName) {
    return new Namespace(this, childName);
  }

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

  public static Namespace fromDottedString(String dottedString)
  // TODO: more appropriate exception type here.
  throws EnforcerRuleException {
    if ("*".equals(dottedString)) {
      // Maven configuration object decoding doesn't deal well with the empty
      // string because there is no text node.
      return Namespace.DEFAULT_PACKAGE;
    }
    return fromSeparatedString("dotted name", dottedString, "[.]");
  }

  public static Namespace fromInternalClassName(String icn)
  // TODO: more appropriate exception type here.
  throws EnforcerRuleException {
    return fromSeparatedString("internal class name", icn, "/");
  }

  static Namespace fromSeparatedString(
      String description,
      String string, String separatorPattern)
  // TODO: more appropriate exception type here.
  throws EnforcerRuleException {
    Namespace ns = DEFAULT_PACKAGE;
    if (string.length() != 0) {
      for (String part : string.split(separatorPattern)) {
        if (part.length() == 0) {
          throw new EnforcerRuleException(
              "Invalid " + description + ": " + string);
        }
        ns = ns.child(part);
      }
    }
    return ns;
  }
}
