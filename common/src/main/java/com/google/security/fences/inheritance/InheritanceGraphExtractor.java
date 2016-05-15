package com.google.security.fences.inheritance;

import java.io.IOException;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;

import com.google.security.fences.classpath.AbstractClassesVisitor;
import com.google.security.fences.classpath.ClassRoot;

/**
 * Walks all classes in class roots to build an inheritance graph.
 */
public final class InheritanceGraphExtractor extends AbstractClassesVisitor {
  private final InheritanceGraph.Builder builder = InheritanceGraph.builder();

  @Override
  protected ClassVisitor makeVisitorForClass(
      ClassRoot root, String relPath, ClassReader r) throws IOException {
    return new ClassNodeFromClassFileVisitor(builder);
  }

  /**
   * An inheritance graph that includes all classes available from the given
   * class roots.
   */
  public static InheritanceGraph fromClassRoots(
      Iterable<? extends ClassRoot> classRoots)
  throws IOException {
    InheritanceGraphExtractor extractor = new InheritanceGraphExtractor();
    extractor.visitAll(classRoots);
    return extractor.builder.build();
  }

}
