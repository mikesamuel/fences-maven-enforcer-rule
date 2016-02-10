package com.google.security.fences.policy;

import static org.junit.Assert.*;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.security.fences.config.ClassFence;
import com.google.security.fences.config.FieldFence;
import com.google.security.fences.config.PackageFence;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.Policy.AccessLevels;

import static com.google.security.fences.policy.ApiElement.Factory.clazz;
import static com.google.security.fences.policy.ApiElement.Factory.field;
import static com.google.security.fences.policy.ApiElement.Factory.pkg;
import static com.google.security.fences.policy.AccessLevel.ALLOWED;
import static com.google.security.fences.policy.AccessLevel.DISALLOWED;

@SuppressWarnings("javadoc")
public final class PolicyTest {
  private Policy p;

  @Before
  public void setUp() throws EnforcerRuleException {
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

    p = Policy.fromFences(ImmutableList.of(comPkg));
  }

  @After
  public void tearDown() {
    p = null;
  }

  private static void assertAccessLevelsEqual(
      ImmutableList<AccessLevels> want, ImmutableList<AccessLevels> got) {
    if (!want.equals(got)) {
      assertEquals(want.toString(), got.toString());  // Nicer diff in eclipse
      fail();
    }
  }

  @Test
  public void testForNamespace() throws EnforcerRuleException {
    AccessLevels defaultAccessLevels = AccessLevels.fromMap(ImmutableMap.of(
        // By default, access is disallowed
        clazz("Unsafe", pkg("example", pkg("com"))), DISALLOWED,
        // Except to this specific field.
        field("SERIAL_VERSION_UID",
              clazz("Unsafe", pkg("example", pkg("com")))),
        ALLOWED
        ));

    ImmutableList<AccessLevels> etrAccLvls = p.forNamespace(
        Namespace.fromDottedString("org.example.ExceptionToRule"));
    assertAccessLevelsEqual(
        ImmutableList.of(
            // The most specific one says the exception to the rule is allowed.
            AccessLevels.fromMap(ImmutableMap.of(
                clazz("Unsafe", pkg("example", pkg("com"))), ALLOWED
                )),
            defaultAccessLevels
        ),
        etrAccLvls);

    ImmutableList<AccessLevels> scAccLvls = p.forNamespace(
        Namespace.fromDottedString("org.example.SomeClass"));
    assertAccessLevelsEqual(
        ImmutableList.of(defaultAccessLevels),
        scAccLvls);

    ImmutableList<AccessLevels> otherAccLvls = p.forNamespace(
        Namespace.fromDottedString("java.lang.String"));
    assertAccessLevelsEqual(
        ImmutableList.of(defaultAccessLevels),
        otherAccLvls);
  }

}
