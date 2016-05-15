package com.google.security.fences.checker;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.logging.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.security.fences.classpath.AbstractClassesVisitor;
import com.google.security.fences.classpath.ClassRoot;
import com.google.security.fences.config.Rationale;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.AccessLevel;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;
import com.google.security.fences.policy.Policy;
import com.google.security.fences.policy.PolicyApplicationOrder;
import com.google.security.fences.reporting.Violation;
import com.google.security.fences.util.LazyString;
import com.google.security.fences.util.MisconfigurationException;
import com.google.security.fences.util.Utils;

/**
 * Given a bundle of class files, checks each ".class" file against a policy.
 */
public final class Checker extends AbstractClassesVisitor {
  final Log log;
  final Policy policy;
  final InheritanceGraph inheritanceGraph;
  private final List<Violation> violations =
      Lists.newArrayList();

  /**
   * @param inheritanceGraph used to resolve super-types so that policies that
   *     apply to super-types can be applied to sub-types.
   * @param policy the policy to apply.
   */
  public Checker(Log log, InheritanceGraph inheritanceGraph, Policy policy) {
    this.log = log;
    this.inheritanceGraph = inheritanceGraph;
    this.policy = policy;
  }

  /**
   * @return the count of errors logged.
   *     Greater than zero if there were one or more policy violations.
   */
  public ImmutableList<Violation> getViolations() {
    return ImmutableList.copyOf(violations);
  }

  @Override
  protected void startClassRoot(ClassRoot root) {
    log.debug("Visiting " + root);
  }

  @Override
  protected ClassVisitor makeVisitorForClass(
      ClassRoot root, String relPath, ClassReader reader)
  throws IOException {
    try {
      return new ClassChecker(root.art, reader);
    } catch (MisconfigurationException ex) {
      throw new IOException("Failed to check " + root, ex);
    }
  }

  final class ClassChecker extends ClassVisitor {
    final Artifact art;
    final ClassReader reader;
    final String className;
    final Namespace ns;
    private Optional<String> sourceFilePath = Optional.absent();

    ClassChecker(Artifact art, ClassReader reader)
    throws MisconfigurationException {
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
    public void visitSource(String source, String debug) {
      this.sourceFilePath = Optional.fromNullable(source);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String desc, String signature,
        String[] exceptions) {
      return new MethodChecker(art, reader, sourceFilePath, ns, name);
    }
  }

  private final class MethodChecker extends MethodVisitor {
    final Artifact art;
    final Optional<String> sourceFilePath;
    final String className;
    final Namespace ns;
    final String methodName;
    private final Map<ApiElement, Map<String, PolicyResult>> memoTable =
        Maps.newLinkedHashMap();
    private int latestLineNumber = -1;

    MethodChecker(
        Artifact art, ClassReader reader, Optional<String> sourceFilePath,
        Namespace ns, String methodName) {
      super(Opcodes.ASM5);
      this.art = art;
      this.sourceFilePath = sourceFilePath;
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
      ApiElement classEl = ApiElement.fromInternalClassName(owner);
      ApiElement fieldApiElement = classEl.child(name, ApiElementType.FIELD);
      requireAccessAllowed(fieldApiElement, desc);
    }

    @Override
    public void visitInvokeDynamicInsn(
        String name, String desc, Handle bsm, Object... bsmArgs) {
      // TODO: Should we do some kind of worst-case analysis here?
    }

    @Override
    public void visitMethodInsn(
        int opcode, String owner, String name, String desc, boolean itf) {
      ApiElement classEl = ApiElement.fromInternalClassName(owner);
      ApiElement methodApiElement = classEl.child(
          name,
          ApiElement.CONSTRUCTOR_SPECIAL_METHOD_NAME.equals(name)
          ? ApiElementType.CONSTRUCTOR : ApiElementType.METHOD);
      requireAccessAllowed(methodApiElement, desc);
    }

    @Override
    public void visitLineNumber(int lineNumber, Label start) {
      // Keep track of line number hints so we can include those in
      // error messages.
      this.latestLineNumber = lineNumber;
    }

    /**
     * Applies the policy and makes any violation available to
     * {@link Checker#getViolations()}.
     */
    @SuppressWarnings("synthetic-access")
    void requireAccessAllowed(final ApiElement el, String descriptor) {
      Map<String, PolicyResult> descriptorMemoTable = memoTable.get(el);
      if (descriptorMemoTable == null) {
        descriptorMemoTable = Maps.newLinkedHashMap();
        memoTable.put(el, descriptorMemoTable);
      }
      PolicyResult r = descriptorMemoTable.get(descriptor);
      if (r == null) {
        log.debug(new LazyString() {
          @Override
          protected String makeString() {
            return ". . . Checking whether " + el + " allowed from " + ns
                + " in " + Utils.artToString(art);
          }
        });
        r = Checker.this.applyAccessPolicy(ns, el, descriptor);
        descriptorMemoTable.put(descriptor, r);
      }
      switch (r.accessLevel) {
        case ALLOWED:
          return;
        case DISALLOWED:
          Violation v = new Violation(
              art,
              ns,
              sourceFilePath.or(className),
              latestLineNumber,
              el,
              r.target,
              r.rationale);
          Checker.this.violations.add(v);
          return;
      }
      throw new AssertionError(r.accessLevel);
    }
  }

  static final class PolicyResult {
    /** The policy decision. */
    final AccessLevel accessLevel;
    /** The rationale for the decision. */
    final Rationale rationale;
    /**
     * The API element based upon which the decision was made.
     * This may be an API element defined on an ancestor of the
     * element accessed in code defined in the trusted/distrusted namespace.
     */
    final ApiElement target;

    static PolicyResult defaultResult(ApiElement target) {
      return new PolicyResult(
        AccessLevel.ALLOWED,  // Default to plain old Java rules.
        Rationale.EMPTY,
        target);
    }

    PolicyResult(
        AccessLevel accessLevel, Rationale rationale, ApiElement target) {
      this.accessLevel = accessLevel;
      this.rationale = rationale;
      this.target = target;
    }
  }

  PolicyResult applyAccessPolicy(
      Namespace from, ApiElement to, String descriptor) {
    // Find the most-specific rationale.
    Iterable<Policy.NamespacePolicy> applicable = policy.forNamespace(from);

    for (ApiElement el :
         new PolicyApplicationOrder(to, descriptor, inheritanceGraph, log)) {
      AccessLevel levelFromPolicy = null;
      Rationale.Builder rationaleBuilder = new Rationale.Builder();
      for (Policy.NamespacePolicy nsp : applicable) {
        Optional<Policy.AccessControlDecision> d =
            nsp.accessPolicyForApiElement(el);
        if (d.isPresent()) {
          Policy.AccessControlDecision acd = d.get();
          AccessLevel dLvl = acd.accessLevel;
          if (levelFromPolicy == null) {
            levelFromPolicy = dLvl;
          }
          if (dLvl == levelFromPolicy && !acd.rationale.isEmpty()) {
            try {
              rationaleBuilder.addBody(acd.rationale);
            } catch (MisconfigurationException ex) {
              // Should not happen since this came from a rationale.
              throw new AssertionError(null, ex);
            }
            break;
          }
        }
      }

      try {
        rationaleBuilder.addAddendum(policy.getAddenda(to));
      } catch (MisconfigurationException ex) {
        // Should not happen since this came from a rationale.
        throw new AssertionError(null, ex);
      }

      if (levelFromPolicy != null) {
        return new PolicyResult(
            // Default to java rules.
            levelFromPolicy,
            rationaleBuilder.build(),
            el);
      }
    }
    return PolicyResult.defaultResult(to);
  }
}
