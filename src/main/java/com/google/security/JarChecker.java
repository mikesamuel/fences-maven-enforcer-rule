package com.google.security;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.plugin.logging.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;
import com.google.common.collect.Sets;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.AccessLevel;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;
import com.google.security.fences.policy.Policy;

final class JarChecker {
  final Log log;
  final Policy policy;
  private int errorCount;

  JarChecker(Log log, Policy policy) {
    this.log = log;
    this.policy = policy;
  }

  int getErrorCount() {
    return errorCount;
  }

  synchronized void incrementErrorCount() {
    if (errorCount != Integer.MAX_VALUE) {
      ++errorCount;
    }
  }

  void checkJar(Artifact art, InputStream in)
  throws IOException, EnforcerRuleException {
    log.debug("Visiting artifact " + Utils.artToString(art));
    ZipInputStream zipIn = new ZipInputStream(in);
    try {
      for (ZipEntry zipEntry; (zipEntry = zipIn.getNextEntry()) != null;) {
        if (!zipEntry.isDirectory()) {
          String entryName = zipEntry.getName();
          if (entryName.endsWith(".class")) {
            ClassReader reader = new ClassReader(zipIn);
            ClassVisitor classChecker = new ClassChecker(art, reader);
            reader.accept(classChecker, 0 /* flags */);
          }
        }
        zipIn.closeEntry();
      }
    } finally {
      zipIn.close();
    }
  }

  final class ClassChecker extends ClassVisitor {
    final Artifact art;
    final ClassReader reader;
    final String className;
    final Namespace ns;

    ClassChecker(Artifact art, ClassReader reader)
    throws EnforcerRuleException {
      super(Opcodes.ASM5);
      this.art = art;
      this.reader = reader;
      this.className = reader.getClassName();
      this.ns = Namespace.fromInternalClassName(className);
    }

    @Override
    public void visit(
        int version, int access, String name, String signature,
        String superName, String[] interfaces) {
      log.debug(". Visiting class " + className);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String desc, String signature,
        String[] exceptions) {
      return new MethodChecker(art, reader, ns, name);
    }
  }

  final class MethodChecker extends MethodVisitor {
    final Artifact art;
    final ClassReader reader;
    final String className;
    final Namespace ns;
    final String methodName;
    private final Set<ApiElement> alreadyChecked = Sets.newHashSet();

    MethodChecker(
        Artifact art, ClassReader reader, Namespace ns, String methodName) {
      super(Opcodes.ASM5);
      this.art = art;
      this.reader = reader;
      this.className = reader.getClassName();
      this.ns = ns;
      this.methodName = methodName;
    }

    @Override
    public void visitCode() {
      log.debug(". . Visiting method " + methodName);
    }

    @Override
    public void visitFieldInsn(
        int opcode, String owner, String name, String desc) {
      ApiElement classEl = apiElementFromInternalClassName(owner);
      ApiElement fieldApiElement = classEl.child(name, ApiElementType.FIELD);
      checkAllowed(fieldApiElement);
    }

    @Override
    public void visitInvokeDynamicInsn(
        String name, String desc, Handle bsm, Object... bsmArgs) {
      // TODO: Should we do some kind of worst-case analysis here?
    }

    @Override
    public void visitMethodInsn(
        int opcode, String owner, String name, String desc, boolean itf) {
      ApiElement classEl = apiElementFromInternalClassName(owner);
      ApiElement methodApiElement = classEl.child(
          name,
          ApiElement.CONSTRUCTOR_SPECIAL_METHOD_NAME.equals(name)
          ? ApiElementType.CONSTRUCTOR : ApiElementType.METHOD);
      checkAllowed(methodApiElement);
    }

    void checkAllowed(ApiElement el) {
      if (alreadyChecked.add(el)) {
        JarChecker.this.checkAllowed(art, ns, el);
      }
    }
  }

  void checkAllowed(
      final Artifact art, final Namespace ns, final ApiElement el) {
    log.debug(new LazyString() {
        @Override
        protected String makeString() {
          return ". . . Checking whether " + el + " allowed from " + ns
              + " in " + Utils.artToString(art);
        }
    });
    AccessLevel levelFromPolicy = AccessLevel.ALLOWED;  // Defer to java rules.
    Iterable<Policy.AccessLevels> applicable = policy.forNamespace(ns);
    for (Policy.AccessLevels al : applicable) {
      Optional<AccessLevel> lvl = al.accessLevelForApiElement(el);
      if (lvl.isPresent()) {
        levelFromPolicy = lvl.get();
        break;
      }
    }
    switch (levelFromPolicy) {
      case ALLOWED:
        break;
      case DISALLOWED:
        log.error(
            Utils.artToString(art)
            + ": access denied to " + el + " from " + ns);
        incrementErrorCount();
        break;
    }
  }

  static ApiElement apiElementFromInternalClassName(String name) {
    ApiElement apiElement = ApiElement.DEFAULT_PACKAGE;
    String[] nameParts = name.split("/");
    for (int i = 0, n = nameParts.length; i < n - 1; ++i) {
      apiElement = apiElement.child(nameParts[i], ApiElementType.PACKAGE);
    }
    String className = nameParts[nameParts.length - 1];
    for (String classNamePart : className.split("[$]")) {
      apiElement = apiElement.child(classNamePart, ApiElementType.CLASS);
    }
    return apiElement;
  }
}
