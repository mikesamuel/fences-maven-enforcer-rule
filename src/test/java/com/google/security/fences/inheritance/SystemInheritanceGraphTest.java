package com.google.security.fences.inheritance;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class SystemInheritanceGraphTest extends TestCase {
  private static void assertClassNodeEquals(
      InheritanceGraph g,
      String name,
      String superType,
      String... interfaces) {
    assertClassNodeEquals(g, name, Optional.of(superType), interfaces);
  }

  private static void assertClassNodeEquals(
      InheritanceGraph g,
      String name,
      Optional<String> superType,
      String... interfaces) {
    Optional<ClassNode> got = g.named(name);
    assertTrue(name, got.isPresent());
    ClassNode cn = got.get();
    assertEquals(name, cn.name);
    assertEquals(name + " supertype", superType, cn.superType);
    assertEquals(
        name + " interfaces",
        ImmutableList.of(interfaces),
        cn.interfaces);
  }

  public static final void testInheritanceGraph() {
    InheritanceGraph g = InheritanceGraph.builder()
        .declare(
            "com/example/SillyInputStream",
            Optional.of("java/io/InputStream"),
            ImmutableList.of("java/io/Serializable"))
        .build();
    assertClassNodeEquals(
        g,
        "com/example/SillyInputStream",
        "java/io/InputStream",
        "java/io/Serializable");

    assertClassNodeEquals(
        g,
        "java/io/InputStream",
        "java/lang/Object",
        "java/io/Closeable");

    assertClassNodeEquals(
        g,
        "java/lang/Object",
        Optional.<String>absent());

    assertClassNodeEquals(
        g,
        "java/io/Serializable",
        "java/lang/Object"  // TODO: Why do interfaces have a super-class?
        );

    assertClassNodeEquals(
        g,
        "java/io/Closeable",
        "java/lang/Object",  // TODO: Why do interfaces have a super-class?
        // Our baked in system inheritance graph is based on Java 8 which
        // introduced AutoCloseable.
        "java/lang/AutoCloseable"
        );

    assertFalse(g.named("java/lang/NoSuchClass").isPresent());
  }
}
