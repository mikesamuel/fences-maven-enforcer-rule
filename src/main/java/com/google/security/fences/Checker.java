package com.google.security.fences;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.List;
import java.util.Set;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
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
import com.google.common.collect.Sets;
import com.google.security.fences.inheritance.ClassNode;
import com.google.security.fences.inheritance.InheritanceGraph;
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
final class Checker extends AbstractClassesVisitor {
  final Log log;
  final Policy policy;
  final InheritanceGraph inheritanceGraph;
  private final List<Violation> violations =
      Lists.newArrayList();

  Checker(Log log, InheritanceGraph inheritanceGraph, Policy policy) {
    this.log = log;
    this.inheritanceGraph = inheritanceGraph;
    this.policy = policy;
  }

  private synchronized void accessDeniedTo(
      Artifact art,
      Namespace useSiteContainer,
      String classDebugString,
      int latestLineNumber,
      ApiElement el,
      PolicyResult policyResult) {
    assert policyResult.accessLevel != AccessLevel.ALLOWED;
    this.violations.add(new Violation(
        art,
        useSiteContainer,
        classDebugString,
        latestLineNumber,
        el,
        policyResult.target,
        policyResult.rationale
        ));
  }

  /**
   * @return the count of errors logged.
   *     Greater than zero if there were one or more policy violations.
   */
  ImmutableList<Violation> getViolations() {
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
    } catch (EnforcerRuleException ex) {
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
    private final Set<ApiElement> alreadyChecked = Sets.newHashSet();
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

    @Override
    public void visitLineNumber(int lineNumber, Label start) {
      // Keep track of line number hints so we can include those in
      // error messages.
      this.latestLineNumber = lineNumber;
    }

    @SuppressWarnings("synthetic-access")
    void checkAllowed(ApiElement el) {
      if (alreadyChecked.add(el)) {
        Checker.this.checkAllowed(
            art, sourceFilePath.or(className), latestLineNumber, ns, el);
      }
    }
  }

  private void checkAllowed(
      final Artifact art, String classDebugString, int latestLineNumber,
      final Namespace ns, final ApiElement el) {
    log.debug(new LazyString() {
        @Override
        protected String makeString() {
          return ". . . Checking whether " + el + " allowed from " + ns
              + " in " + Utils.artToString(art);
        }
    });
    PolicyResult policyResult = applyAccessPolicy(ns, el);
    AccessLevel levelFromPolicy = policyResult.accessLevel;
    switch (levelFromPolicy) {
      case ALLOWED:
        break;
      case DISALLOWED:
        accessDeniedTo(
            art, ns, classDebugString, latestLineNumber, el, policyResult);
        break;
    }
  }

  static final class PolicyResult {
    /** The policy decision. */
    final AccessLevel accessLevel;
    /** The rationale for the decision if any. */
    final Optional<String> rationale;
    /**
     * The API element based upon which the decision was made.
     * This may be an API element defined on an ancestor of the
     * element accessed in code defined in the trusted/distrusted namespace.
     */
    final ApiElement target;

    static PolicyResult defaultResult(ApiElement target) {
      return new PolicyResult(
        AccessLevel.ALLOWED,  // Default to plain old Java rules.
        Optional.<String>absent(),
        target);
    }

    PolicyResult(
        AccessLevel accessLevel, Optional<String> rationale,
        ApiElement target) {
      this.accessLevel = accessLevel;
      this.rationale = rationale;
      this.target = target;
    }
  }

  PolicyResult applyAccessPolicy(Namespace from, ApiElement to) {
    // Find the most-specific rationale.
    Iterable<Policy.NamespacePolicy> applicable =
        policy.forNamespace(from);

    // We check all classes before the interfaces since method implementations
    // specified in concrete and abstract classes override interface default
    // methods and we want the order of application of policies to mimic the
    // order in
    Deque<ApiElement> typesToCheck = new ArrayDeque<ApiElement>();
    Deque<ApiElement> interfaces = new ArrayDeque<ApiElement>();
    typesToCheck.add(to);

    Set<ApiElement> checked = Sets.newLinkedHashSet();

    while (true) {
      boolean isInterface = false;
      ApiElement el;
      el = typesToCheck.pollFirst();
      if (el == null) {
        el = interfaces.pollFirst();
        if (el == null) {
          break;
        } else {
          isInterface = true;
        }
      }
      if (!checked.add(el)) {
        continue;
      }

      AccessLevel levelFromPolicy = null;
      Optional<String> rationale = Optional.absent();
      for (Policy.NamespacePolicy nsp : applicable) {
        Optional<Policy.AccessControlDecision> d =
            nsp.accessPolicyForApiElement(el);
        if (d.isPresent()) {
          AccessLevel dLvl = d.get().accessLevel;
          if (levelFromPolicy == null) {
            levelFromPolicy = dLvl;
          }
          if (dLvl == levelFromPolicy) {
            rationale = d.get().rationale;
            if (rationale.isPresent()) {
              break;
            }
          }
        }
      }

      if (levelFromPolicy != null) {
        return new PolicyResult(
            // Default to java rules.
            levelFromPolicy,
            rationale,
            el);
      } else {
        Optional<ApiElement> elClass = el.containingClass();
        if (elClass.isPresent()) {
          String elInternalName = elClass.get().toInternalName();
          Optional<ClassNode> nodeOpt = inheritanceGraph.named(elInternalName);
          if (nodeOpt.isPresent()) {
            ClassNode node = nodeOpt.get();
            if (!isInterface && node.superType.isPresent()) {
              addIfPresent(
                  typesToCheck,
                  apiElementFromSuper(el, node.superType.get()));
            }
            for (String interfaceNodeName : node.interfaces) {
              addIfPresent(
                  typesToCheck,
                  apiElementFromSuper(el, interfaceNodeName));
            }
          }
        }
      }
    }
    return PolicyResult.defaultResult(to);
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

  static Optional<ApiElement> apiElementFromSuper(
      ApiElement el, String superTypeName) {
    switch (el.type) {
      case CLASS:
        return Optional.of(apiElementFromInternalClassName(superTypeName));
      case CONSTRUCTOR:
      case FIELD:
      case METHOD:
        return Optional.of(
            apiElementFromSuper(el.parent.get(), superTypeName).get()
            .child(el.name, el.type));
      case PACKAGE:
        return Optional.absent();
    }
    throw new AssertionError(el.type);
  }

  static <T> void addIfPresent(
      Collection<? super T> c, Optional<? extends T> el) {
    if (el.isPresent()) {
      c.add(el.get());
    }
  }
}
