package com.google.security.fences.config;

import java.util.Collections;
import java.util.List;

import org.objectweb.asm.Opcodes;

import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class ClassNameDisambiguatorTest extends TestCase {
  final InheritanceGraph GRAPH = InheritanceGraph.builder()
      .declare("com/example/TopLevel", Opcodes.ACC_PUBLIC).commit()
      .declare("com/example/Outer", Opcodes.ACC_PUBLIC).commit()
      .declare("com/example/Outer$Inner", Opcodes.ACC_PUBLIC)
          .outerClassName(Optional.of("com/example/Outer"))
          .commit()
      .declare("com/example/Not$An$Inner", Opcodes.ACC_PUBLIC).commit()
      .declare("InDefaultPackage", Opcodes.ACC_PUBLIC).commit()
      .declare("com/example/$", Opcodes.ACC_PUBLIC).commit()
      .declare("com/example/$A", Opcodes.ACC_PUBLIC).commit()
      .declare("com/example/A$", Opcodes.ACC_PUBLIC).commit()
      .build();

  private void assertResolution(
      ApiElement parent,
      String input,
      String internalName,
      String... partNames) {
    Optional<ApiElement> result = new ClassNameDisambiguator(GRAPH, input)
        .resolve(parent);
    assertTrue(input, result.isPresent());
    ApiElement el = result.get();
    assertEquals(internalName, el.toInternalName());
    assertEquals(
        Joiner.on("\n").join(partNames),
        Joiner.on("\n").join(namesOf(el)));
  }

  private void assertUnresolved(
      ApiElement parent,
      String input) {
    Optional<ApiElement> result = new ClassNameDisambiguator(GRAPH, input)
        .resolve(parent);
    assertFalse(result.toString(), result.isPresent());
  }

  public final void testResolveOfSimpleClass() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com.example.TopLevel",
        "com/example/TopLevel",
        "com", "example", "TopLevel");

    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com/example/TopLevel",
        "com/example/TopLevel",
        "com", "example", "TopLevel");

    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE),
        "example.TopLevel",
        "com/example/TopLevel",
        "com", "example", "TopLevel");

    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "TopLevel",
        "com/example/TopLevel",
        "com", "example", "TopLevel");
  }

  public final void testResolveOfProvidedUnambiguousClass() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "Provided",
        "com/example/Provided",
        "com", "example", "Provided");
  }

  public final void testResolveOfUnambiguousInnerClass() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com/example/Outer$Inner",
        "com/example/Outer$Inner",
        "com", "example", "Outer", "Inner");

    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "Outer$Inner",
        "com/example/Outer$Inner",
        "com", "example", "Outer", "Inner");

    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com.example.Outer.Inner",
        "com/example/Outer$Inner",
        "com", "example", "Outer", "Inner");

    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com.example.Outer$Inner",
        "com/example/Outer$Inner",
        "com", "example", "Outer", "Inner");
  }

  public final void testResolveOfStrangelyNamedTopLevelClass() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com/example/Not$An$Inner",
        "com/example/Not$An$Inner",
        "com", "example", "Not$An$Inner");

    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "Not$An$Inner",
        "com/example/Not$An$Inner",
        "com", "example", "Not$An$Inner");

    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        "com.example.Not.An.Inner");

    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "Not.An.Inner");

    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE)
            .child("Not", ApiElementType.CLASS),
        "An$Inner");
  }

  public final void testResolveOfClassInDefaultPackage() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "InDefaultPackage",
        "InDefaultPackage",
        "InDefaultPackage");
  }

  public final void testResolveOfClassWithDollarAtStart() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com.example.$A",
        "com/example/$A",
        "com", "example", "$A");
    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "$A",
        "com/example/$A",
        "com", "example", "$A");
  }

  public final void testResolveOfClassDollar() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com.example.$",
        "com/example/$",
        "com", "example", "$");
    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "$",
        "com/example/$",
        "com", "example", "$");
  }

  public final void testResolveOfClassWithDollarAtEnd() {
    assertResolution(
        ApiElement.DEFAULT_PACKAGE,
        "com.example.A$",
        "com/example/A$",
        "com", "example", "A$");
    assertResolution(
        ApiElement.DEFAULT_PACKAGE
            .child("com", ApiElementType.PACKAGE)
            .child("example", ApiElementType.PACKAGE),
        "A$",
        "com/example/A$",
        "com", "example", "A$");
  }

  public final void testMisplacedSlashFailsGracefully() {
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        "com//example/Foo");
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        "com/example//Foo");
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        "/com/example/Foo");
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        "/com/example/");
  }

  public final void testMisplacedDotFailsGracefully() {
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        "com..example.Foo");
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        "com.example..Foo");
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        ".com.example.Foo");
    assertUnresolved(
        ApiElement.DEFAULT_PACKAGE,
        ".com.example.");
  }

  private static ImmutableList<String> namesOf(ApiElement el) {
    List<String> names = Lists.newArrayList();
    ApiElement e = el;
    while (!ApiElement.DEFAULT_PACKAGE.equals(e)) {
      names.add(e.name);
      e = e.parent.get();
    }
    Collections.reverse(names);
    return ImmutableList.copyOf(names);
  }
}
