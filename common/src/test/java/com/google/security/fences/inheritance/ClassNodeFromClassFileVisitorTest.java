package com.google.security.fences.inheritance;

import java.io.IOException;
import java.io.InputStream;

import org.objectweb.asm.ClassReader;

import com.google.common.base.Optional;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class ClassNodeFromClassFileVisitorTest extends TestCase {

  public static final class MyInnerClass {
    public int x;

    public int x() {
      return x;
    }
  }

  private static final String innerClassName(Class<?> cl) {
    return cl.getName().replace('.', '/');
  }

  private static final String resourcePath(Class<?> cl) {
    return "/" + cl.getName().replace('.', '/') + ".class";
  }

  private static InheritanceGraph graphFor(Class<?>... classes)
  throws IOException {
    InheritanceGraph.Builder b = InheritanceGraph.builder();
    for (Class<?> cl : classes) {
      ClassNodeFromClassFileVisitor v = new ClassNodeFromClassFileVisitor(b);
      String pathToClassFile = resourcePath(cl);
      InputStream classIn = cl.getResourceAsStream(pathToClassFile);
      try {
        assertNotNull(pathToClassFile, classIn);
        ClassReader reader = new ClassReader(classIn);
        reader.accept(v, 0 /* flags */);
      } finally {
        if (classIn != null) {
          classIn.close();
        }
      }
    }
    return b.build();
  }

  public static final void testInnerClassNode() throws Exception {
    InheritanceGraph g = graphFor(
        MyInnerClass.class, MyInnerClass.class.getEnclosingClass());
    String innerInternalName = innerClassName(MyInnerClass.class);
    Optional<ClassNode> nodeOpt = g.named(innerInternalName);
    assertTrue(nodeOpt.isPresent());
    ClassNode node = nodeOpt.get();
    assertEquals(
        "com/google/security/fences/inheritance/"
        + "ClassNodeFromClassFileVisitorTest$MyInnerClass",
        node.name);
    assertTrue(node.outerClass.isPresent());
  }

  public static final void testTopLevelClassThatExtendsInnerClass()
  throws IOException {
    InheritanceGraph g = graphFor(
        Outer.class, Outer.BaseInner.class, Sub.class);
    Optional<ClassNode> subOpt = g.named(innerClassName(Sub.class));
    assertTrue(subOpt.isPresent());
  }
}

class Outer {
  static class BaseInner {
    // This class left intentionally blank.
  }
}

class Sub extends Outer.BaseInner {
  // This class left intentionally blank.
}

