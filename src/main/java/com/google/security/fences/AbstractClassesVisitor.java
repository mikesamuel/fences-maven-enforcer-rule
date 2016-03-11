package com.google.security.fences;

import java.io.IOException;
import java.io.InputStream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;

import com.google.common.base.Predicate;

/**
 * Visits all the classes performing some operation.
 */
abstract class AbstractClassesVisitor {

  /** Called to construct an ASM ClassVisitor which is then visited. */
  protected abstract ClassVisitor makeVisitorForClass(
      ClassRoot root, String relPath, ClassReader r)
  throws IOException;

  /** Called before the classes in a root are enumerated. */
  @SuppressWarnings("unused")
  protected void startClassRoot(ClassRoot cr) throws IOException {
    // Does nothing by default
  }

  /** Called after the last class, if any, in a root has been visited. */
  @SuppressWarnings("unused")
  protected void finishClassRoot(ClassRoot cr) throws IOException {
    // Does nothing by default
  }

  /**
   * Visits all the given roots in order.
   * The order in which classes under a root are visited depends on the
   * underlying file-system.
   */
  final void visitAll(Iterable<? extends ClassRoot> roots)
  throws IOException {
    for (ClassRoot root : roots) {
      startClassRoot(root);
      root.readEachPathMatching(
          new Predicate<String>() {
            public boolean apply(String relativePath) {
              return relativePath.endsWith(".class");
            }
          },
          new ClassRoot.IOConsumer<InputStream, Boolean>() {
            public Boolean consume(
                ClassRoot cr, String relPath, InputStream is)
            throws IOException {
              ClassReader reader = new ClassReader(is);
              ClassVisitor classChecker = makeVisitorForClass(
                  cr, relPath, reader);
              reader.accept(classChecker, 0 /* flags */);
              return true;
            }
          });
      finishClassRoot(root);
    }
  }

}
