package com.google.security.fences.inheritance;

import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;

/**
 * A class visitor that visits an ASM class to declare
 * its inheritance relationships to an {@link InheritanceGraph.Builder}.
 */
public final class ClassNodeFromClassFileVisitor extends ClassVisitor {
  private final InheritanceGraph.Builder graphBuilder;

  private String name;
  private int access;
  private Optional<String> superName;
  private Iterable<String> interfaces;
  private List<FieldDetails> fields;
  private List<MethodDetails> methods;
  private boolean includePrivates = true;

  /**
   * @param graphBuilder receives declarations for classes visited.
   */
  public ClassNodeFromClassFileVisitor(InheritanceGraph.Builder graphBuilder) {
    super(Opcodes.ASM6);
    this.graphBuilder = graphBuilder;
  }

  void setIncludePrivates(boolean newIncludePrivates) {
    this.includePrivates = newIncludePrivates;
  }

  @Override
  public void visit(
      int version, int accessFlags, String className, String signature,
      @Nullable String superClassName, String[] interfaceNames) {
    Preconditions.checkState(this.name == null);
    this.name = className;
    this.access = accessFlags;
    this.superName = Optional.fromNullable(superClassName);
    this.interfaces = Arrays.asList(interfaceNames);
    this.fields = Lists.newArrayList();
    this.methods = Lists.newArrayList();
  }

  @Override
  public void visitEnd() {
    graphBuilder
        .declare(name, access)
        .superClassName(superName)
        .interfaceNames(interfaces)
        .methods(methods)
        .fields(fields)
        .commit();
    this.name = null;
  }

  @Override
  public void visitInnerClass(String innerInternalName,
      String outerName,
      String innerName,
      int innerClassAccess) {
    if (outerName != null) {
      // There are inner class declarations on the outer and inner classes and
      // sub-classes of each, so handle these out of band because there is no
      // clear relationship between this.name and outerName or innerInternalName
      graphBuilder.classContains(outerName, innerInternalName);
    }
  }

  @Override
  public FieldVisitor visitField(
      int fieldAccess, String fieldName, String desc,
      String signature, Object value) {
    if (includePrivates || (access & Opcodes.ACC_PRIVATE) == 0) {
      this.fields.add(new FieldDetails(fieldName, fieldAccess));
    }
    return null;
  }

  @Override
  public MethodVisitor visitMethod(
      int methodAccess, String methodName, String desc,
      String signature, String[] exceptions) {
    if (includePrivates || (access & Opcodes.ACC_PRIVATE) == 0) {
      this.methods.add(new MethodDetails(methodName, desc, methodAccess));
    }
    return null;
  }
}
