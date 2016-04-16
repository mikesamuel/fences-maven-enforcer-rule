package com.google.security.fences.config;

import com.google.common.base.Optional;
import com.google.security.fences.inheritance.ClassNode;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;

/**
 * Resolves ambiguity between
 * <pre>
 * class Foo {
 *   class Bar {
 *     ...
 *   }
 * }</pre>
 * and
 * <pre>
 * class Foo$Bar { ... }
 * </pre>
 * by looking up classes in the inheritance graph derived from the class path.
 */
final class ClassNameDisambiguator {
  private final InheritanceGraph g;
  private final String partiallyQualifiedName;

  ClassNameDisambiguator(InheritanceGraph g, String partiallyQualifiedName) {
    this.g = g;
    this.partiallyQualifiedName = partiallyQualifiedName;
  }

  Optional<ApiElement> resolve(ApiElement parent) {
    return resolve(parent, 0, 0);
  }

  private Optional<ApiElement> resolve(
      ApiElement parent, int nameStartIndex, int nameIndex) {
    ApiElementType parentType = parent.type;
    int n = partiallyQualifiedName.length();
    if (nameIndex == n) {
      if (nameStartIndex == nameIndex) {
        if (parentType == ApiElementType.CLASS) {
          return Optional.of(parent);
        }
      } else {
        char boundaryType = nameStartIndex >= 0
            ? partiallyQualifiedName.charAt(nameStartIndex - 1)
            : '.';
        if (boundaryType == '$' || boundaryType == '.') {
          String name = partiallyQualifiedName.substring(
              nameStartIndex + 1, nameIndex);
          return Optional.of(parent.child(name, ApiElementType.CLASS));
        }
      }
      return Optional.absent();
    }
    int nameEndIndex;
    boolean canBeClassBoundary = true;
    boolean canBePackageBoundary = false;
    boolean optional = false;
    for (nameEndIndex = nameIndex; ++nameEndIndex < n;) {
      // By pre-incrementing we ensure that there is never an empty identifier
      // to the left of the split-point, and by checking here, we ensure that
      // there is never an empty identifier to the right of the split point.
      if (nameEndIndex + 1 == n) {
        continue;
      }
      char ch = partiallyQualifiedName.charAt(nameEndIndex);
      if (ch == '.') {
        canBeClassBoundary = canBePackageBoundary = true;
        optional = false;
        break;
      } else if (ch == '$') {
        canBeClassBoundary = true;
        canBePackageBoundary = false;
        optional = true;
        break;
      } else if (ch == '/') {
        canBeClassBoundary = false;
        canBePackageBoundary = true;
        optional = false;
        break;
      }
    }

    if (optional && nameEndIndex < n && nameEndIndex != nameIndex) {
      // Bias towards longer names since the split version can always be
      // specified in a <configuration> with more elements as in
      // <class>
      //   <name>Foo</name>
      //   <class>
      //     <name>Bar</name>
      //   </class>
      // </class>
      // but there is only one way to specify a class with a `$` in its name:
      // <class><name>Foo$Bar</name>...</class>
      Optional<ApiElement> longerOption = resolve(
          parent, nameStartIndex, nameEndIndex);
      if (longerOption.isPresent()) {
        return longerOption;
      }
    }

    String partName = partiallyQualifiedName.substring(
        nameStartIndex, nameEndIndex);
    if (partName.indexOf('/') >= 0 || partName.indexOf('.') >= 0) {
      return Optional.absent();
    }
    int nextStartIndex = nameEndIndex < n ? nameEndIndex + 1 : nameEndIndex;

    // Bias towards packages.
    //   foo.bar.baz -> foo/bar/baz
    // instead of
    //   foo/bar$baz
    // for no particular reason.
    if (canBePackageBoundary && nameEndIndex < n) {
      ApiElement newParent = parent.child(partName, ApiElementType.PACKAGE);
      Optional<ApiElement> packageOption = resolve(
          newParent, nextStartIndex, nextStartIndex);
      if (packageOption.isPresent()) {
        return packageOption;
      }
    }

    if (canBeClassBoundary) {
      ApiElement newParent = parent.child(partName, ApiElementType.CLASS);
      // This allows us to deal with unambiguously specified provided
      // dependencies.
      Optional<ClassNode> classNode = g.named(newParent.toInternalName());
      if (classNode.isPresent() && isContainedIn(classNode.get(), parent)) {
        Optional<ApiElement> classOption = resolve(
            newParent, nextStartIndex, nextStartIndex);
        if (classOption.isPresent()) {
          return classOption;
        }
      }
    }

    // Handle unambiguous provided dependencies.
    if (nameStartIndex == 0 && nameEndIndex == n
        && partiallyQualifiedName.indexOf('/') < 0
        && partiallyQualifiedName.indexOf('.') < 0
        && partiallyQualifiedName.indexOf('$') < 0) {
      return Optional.of(
          parent.child(partiallyQualifiedName, ApiElementType.CLASS));
    }

    return Optional.absent();
  }

  private static boolean isContainedIn(ClassNode inner, ApiElement outer) {
    Optional<String> outerClass = inner.outerClass;
    if (outer.type == ApiElementType.PACKAGE && !inner.outerClass.isPresent()) {
      return true;
    }
    if (outerClass.isPresent()) {
      return outer.toInternalName().equals(outerClass.get());
    }
    return false;
  }
}