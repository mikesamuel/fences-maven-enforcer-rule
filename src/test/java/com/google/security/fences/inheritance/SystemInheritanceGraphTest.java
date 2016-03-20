package com.google.security.fences.inheritance;

import org.objectweb.asm.Opcodes;

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
            Opcodes.ACC_PUBLIC,
            Optional.of("java/io/InputStream"),
            ImmutableList.of("java/io/Serializable"),
            ImmutableList.<MethodDetails>of(),
            ImmutableList.<FieldDetails>of())
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

  public static void testFieldsAndMethods() {
    InheritanceGraph g = InheritanceGraph.builder()
        .declare(
            "com/example/MyReader",
            Opcodes.ACC_PUBLIC,
            Optional.of("java/io/Reader"),
            ImmutableList.<String>of(),
            ImmutableList.of(
                new MethodDetails("close", "()V", Opcodes.ACC_PUBLIC),
                new MethodDetails("read", "([CII)I", Opcodes.ACC_PUBLIC),
                new MethodDetails("reset", "()V", Opcodes.ACC_PRIVATE)),
            ImmutableList.of(
                new FieldDetails("x", /*"I",*/ Opcodes.ACC_PRIVATE),
                new FieldDetails(
                    "DEFAULT_CAPACITY", /*"I",*/
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL
                    | Opcodes.ACC_STATIC)))
        .build();
    {
      Optional<ClassNode> pushbackReader = g.named("java/io/PushbackReader");
      assertTrue(pushbackReader.isPresent());
      assertTrue((pushbackReader.get().access & Opcodes.ACC_PUBLIC) != 0);
      Optional<MethodDetails> close = pushbackReader.get()
          .getMethod("close", "()V");
      assertEquals(Opcodes.ACC_PUBLIC, close.get().access);
      assertEquals("close", close.get().name);
      assertEquals("()V", close.get().desc);

      assertFalse(
          pushbackReader.get()
          .getMethod("toString", "()Ljava/lang/String;")
          .isPresent());

      assertTrue(
          pushbackReader.get()
          .isMethodVisibleThrough("toString", "()Ljava/lang/String;"));
      assertFalse(
          pushbackReader.get()
          .isMethodVisibleThrough("ready", "()Z"));

      assertEquals(
          "java/io/FilterReader",
          pushbackReader.get().superType.get());
    }

    {
      Optional<ClassNode> myReader = g.named("com/example/MyReader");
      assertTrue(myReader.isPresent());

      assertTrue(myReader.get().isFieldVisibleThrough("x"));
      assertFalse(myReader.get().isFieldVisibleThrough("DEFAULT_CAPACITY"));

      assertEquals(
          "java/io/Reader",
          myReader.get().superType.get());
    }
  }
}
