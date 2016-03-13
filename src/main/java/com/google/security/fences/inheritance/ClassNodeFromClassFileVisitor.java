package com.google.security.fences.inheritance;

import java.util.Arrays;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;

/**
 * A class visitor that visits an ASM class to declare
 * its inheritance relationships to an {@link InheritanceGraph.Builder}.
 */
public final class ClassNodeFromClassFileVisitor extends ClassVisitor {
  private final InheritanceGraph.Builder graphBuilder;

  /**
   * @param graphBuilder receives declarations for classes visited.
   */
  public ClassNodeFromClassFileVisitor(InheritanceGraph.Builder graphBuilder) {
    super(Opcodes.ASM5);
    this.graphBuilder = graphBuilder;
  }

  @Override
  public void visit(
      int version, int access, String name, String signature,
      String superName, String[] interfaces) {
    graphBuilder.declare(
        name, Optional.fromNullable(superName),
        Arrays.asList(interfaces));
  }
}
