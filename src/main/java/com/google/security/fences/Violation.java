package com.google.security.fences;

import org.apache.maven.artifact.Artifact;

import com.google.common.base.Objects;
import com.google.security.fences.config.Rationale;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.ApiElement;

final class Violation implements Comparable<Violation> {
  /** The artifact containing the use of the sensitive API that was denied. */
  final Artifact artifact;
  /** The namespace in which the violation occurred. */
  final Namespace useSiteContainer;
  /**
   * The source of the use of the sensitive API that was denied.
   * This is a human-readable form of {@link #useSiteContainer}, and probably
   * corresponds to a relative path of a .java file in the file-system on
   * which artifact was compiled, but nothing obviously available to the
   * currently running process.
   */
  final String useSiteSource;
  /**
   * The line number of the use of the sensitive API that was banned
   * or -1 if the user was compiled without debug symbols.
   */
  final int useSiteLineNumber;
  /** An API element on a sub-type (non-strict) of sensitiveApiElement. */
  final ApiElement useSiteApiElement;
  /** The API element to which access was denied. */
  final ApiElement sensitiveApiElement;
  /** The reason for denying access. */
  final Rationale rationale;

  Violation(
      Artifact artifact,
      Namespace useSiteContainer,
      String useSiteSource,
      int useSiteLineNumber,
      ApiElement useSiteApiElement,
      ApiElement sensitiveApiElement,
      Rationale rationale) {
    this.artifact = artifact;
    this.useSiteContainer = useSiteContainer;
    this.useSiteSource = useSiteSource;
    this.useSiteLineNumber = useSiteLineNumber;
    this.useSiteApiElement = useSiteApiElement;
    this.sensitiveApiElement = sensitiveApiElement;
    this.rationale = rationale;
  }

  @Override
  public int compareTo(Violation that) {
    @SuppressWarnings("unchecked")
    int delta = this.artifact.compareTo(that.artifact);
    if (delta == 0) {
      delta = this.useSiteSource.compareTo(that.useSiteSource);
      if (delta == 0) {
        delta = Integer.compare(useSiteLineNumber, that.useSiteLineNumber);
        if (delta == 0) {
          delta = this.useSiteApiElement.compareTo(that.useSiteApiElement);
          if (delta == 0) {
            delta = this.sensitiveApiElement.compareTo(
                that.sensitiveApiElement);
          }
        }
      }
    }
    return delta;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Violation)) {
      return false;
    }
    Violation that = (Violation) o;
    return 0 == compareTo(that);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(
        artifact, useSiteSource, useSiteLineNumber,
        useSiteApiElement, sensitiveApiElement);
  }

}