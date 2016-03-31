package com.google.security.fences.policy;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.security.fences.config.ClassFence;
import com.google.security.fences.config.FieldFence;
import com.google.security.fences.config.PackageFence;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.Policy.NamespacePolicy;

import junit.framework.TestCase;

import static com.google.security.fences.policy.ApiElement.Factory.clazz;
import static com.google.security.fences.policy.ApiElement.Factory.field;
import static com.google.security.fences.policy.ApiElement.Factory.pkg;
import static com.google.security.fences.policy.AccessLevel.ALLOWED;
import static com.google.security.fences.policy.AccessLevel.DISALLOWED;

@SuppressWarnings("javadoc")
public final class PolicyTest extends TestCase {
  private Policy p;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    FieldFence serialVersionUid = new FieldFence();
    serialVersionUid.setName("SERIAL_VERSION_UID");
    serialVersionUid.setTrusts("*");

    ClassFence unsafeClazz = new ClassFence();
    unsafeClazz.setName("Unsafe");
    unsafeClazz.setField(serialVersionUid);
    unsafeClazz.setDistrusts("*");
    unsafeClazz.setTrusts("org.example.ExceptionToRule");

    PackageFence examplePkg = new PackageFence();
    examplePkg.setName("example");
    examplePkg.setClass(unsafeClazz);

    PackageFence comPkg = new PackageFence();
    comPkg.setName("com");
    comPkg.setPackage(examplePkg);

    p = Policy.fromFence(comPkg);
  }

  @Override
  public void tearDown() throws Exception {
    p = null;
    super.tearDown();
  }

  private static void assertNamespacePolicyEqual(
      ImmutableList<NamespacePolicy> want, ImmutableList<NamespacePolicy> got) {
    if (!want.equals(got)) {
      assertEquals(want.toString(), got.toString());  // Nicer diff in eclipse
      fail();
    }
  }

  public void testForNamespace() throws EnforcerRuleException {
    NamespacePolicy defaultNamespacePolicy = NamespacePolicy.fromAccessLevelMap(
        ImmutableMap.of(
            // By default, access is disallowed
            clazz("Unsafe", pkg("example", pkg("com"))), DISALLOWED,
            // Except to this specific field.
            field("SERIAL_VERSION_UID",
                clazz("Unsafe", pkg("example", pkg("com")))),
            ALLOWED
            ));

    ImmutableList<NamespacePolicy> etrNmspPol = p.forNamespace(
        Namespace.fromDottedString("org.example.ExceptionToRule"));
    assertNamespacePolicyEqual(
        ImmutableList.of(
            // The most specific one says the exception to the rule is allowed.
            NamespacePolicy.fromAccessLevelMap(ImmutableMap.of(
                clazz("Unsafe", pkg("example", pkg("com"))), ALLOWED
                )),
            defaultNamespacePolicy
        ),
        etrNmspPol);

    ImmutableList<NamespacePolicy> scNmspPol = p.forNamespace(
        Namespace.fromDottedString("org.example.SomeClass"));
    assertNamespacePolicyEqual(
        ImmutableList.of(defaultNamespacePolicy),
        scNmspPol);

    ImmutableList<NamespacePolicy> otherNmspPol = p.forNamespace(
        Namespace.fromDottedString("java.lang.String"));
    assertNamespacePolicyEqual(
        ImmutableList.of(defaultNamespacePolicy),
        otherNmspPol);
  }

}
