package com.google.security.fences;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.plugin.logging.Log;
import org.codehaus.plexus.interpolation.InterpolationException;
import org.codehaus.plexus.interpolation.Interpolator;
import org.codehaus.plexus.interpolation.MapBasedValueSource;
import org.codehaus.plexus.interpolation.ObjectBasedValueSource;
import org.codehaus.plexus.interpolation.RegexBasedInterpolator;
import org.codehaus.plexus.interpolation.ValueSource;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.AccessLevel;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;
import com.google.security.fences.policy.Policy;
import com.google.security.fences.util.LazyString;
import com.google.security.fences.util.Utils;

/**
 * Given a bundle of class files, checks each ".class" file against a policy.
 */
final class Checker {
  final Log log;
  final Policy policy;
  final Interpolator interpolator;
  private int errorCount;

  Checker(Log log, Policy policy) {
    this.log = log;
    this.policy = policy;
    this.interpolator = new RegexBasedInterpolator();
  }

  /** Greater than zero if there were one or more policy violations. */
  int getErrorCount() {
    return errorCount;
  }

  private synchronized void incrementErrorCount() {
    if (errorCount != Integer.MAX_VALUE) {
      ++errorCount;
    }
  }

  void checkClassRoot(Artifact art, File directory)
  throws IOException, EnforcerRuleException{
    log.debug(
        "Visiting dir " + directory
        + " for artifact " + Utils.artToString(art));
    Preconditions.checkArgument(directory.isDirectory(), directory.getPath());
    File[] contents = directory.listFiles();
    if (contents == null) {
      throw new IOException("Cannot list contents of " + directory);
    } else {
      for (File child : contents) {
        if (child.isDirectory()) {
          // Maven does not create symlink trees AFAICT.
          checkClassRoot(art, child);
        } else if (child.getName().endsWith(".class")) {
          InputStream in = new FileInputStream(child);
          try {
            ClassReader reader = new ClassReader(in);
            ClassVisitor classChecker = new ClassChecker(art, reader);
            reader.accept(classChecker, 0 /* flags */);
          } finally {
            in.close();
          }
        }
      }
    }
  }

  /**
   * Given a JAR file, checks each ".class" file against a policy.
   *
   * @param art The artifact containing the JAR file.
   *    Used in diagnostic messages.
   * @param in An input stream containing a well-formed ZIP file.
   * @throws IOException if there is a problem reading in.
   */
  void checkJar(Artifact art, InputStream in)
  throws IOException, EnforcerRuleException {
    log.debug("Visiting JAR for artifact " + Utils.artToString(art));
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

  private final class MethodChecker extends MethodVisitor {
    final Artifact art;
    final ClassReader reader;
    final String className;
    final Namespace ns;
    final String methodName;
    private final Set<ApiElement> alreadyChecked = Sets.newHashSet();
    // TODO: Keep track of line number hints so we can include those in the
    // error message.

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

    @SuppressWarnings("synthetic-access")
    void checkAllowed(ApiElement el) {
      if (alreadyChecked.add(el)) {
        Checker.this.checkAllowed(art, ns, el);
      }
    }
  }

  private void checkAllowed(
      final Artifact art, final Namespace ns, final ApiElement el) {
    log.debug(new LazyString() {
        @Override
        protected String makeString() {
          return ". . . Checking whether " + el + " allowed from " + ns
              + " in " + Utils.artToString(art);
        }
    });
    AccessLevel levelFromPolicy = AccessLevel.ALLOWED; // Default to java rules.
    Iterable<Policy.NamespacePolicy> applicable = policy.forNamespace(ns);
    for (Policy.NamespacePolicy nsp : applicable) {
      Optional<Policy.AccessControlDecision> d =
          nsp.accessPolicyForApiElement(el);
      if (d.isPresent()) {
        levelFromPolicy = d.get().accessLevel;
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
        // Find the most-specific rationale.
        Optional<String> rationale = Optional.absent();
        for (Policy.NamespacePolicy nsp : applicable) {
          Optional<Policy.AccessControlDecision> d =
              nsp.accessPolicyForApiElement(el);
          if (d.isPresent()) {
            rationale = d.get().rationale;
            if (rationale.isPresent()) {
              break;
            }
          }
        }
        if (rationale.isPresent()) {
          String rationaleText = rationale.get();
          ValueSource artifactValueSource = new ObjectBasedValueSource(art);
          ValueSource failedAccessValueSource = new MapBasedValueSource(
              ImmutableMap.of(
                  "fences.api", el,
                  "fences.distrusted", ns));
          interpolator.addValueSource(artifactValueSource);
          interpolator.addValueSource(failedAccessValueSource);
          try {
            rationaleText = interpolator.interpolate(rationaleText);
          } catch (InterpolationException ex) {
            log.warn(ex);
          } finally {
            interpolator.removeValuesSource(failedAccessValueSource);
            interpolator.removeValuesSource(artifactValueSource);
          }
          log.error(rationaleText);
        }
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
