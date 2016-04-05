package com.google.security.fences.config;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class FenceTest extends TestCase {

  public static final void testStarInTrustsElement() throws Exception {
    Fence f = new ApiFence();
    f.setTrusts("*");

    boolean threw = false;
    try {
      f.setTrusts("*Test");
    } catch (EnforcerRuleException ex) {
      threw = true;

      String message = ex.getMessage();
      assertTrue(message, message.startsWith("Globs not allowed"));
    }
    assertTrue(threw);
  }

  public static final void testStarInDistrustsElement() throws Exception {
    Fence f = new ApiFence();
    f.setDistrusts("*");
    f.setDistrusts(" * ");
    boolean threw = false;
    try {
      f.setDistrusts("*Test");
    } catch (EnforcerRuleException ex) {
      threw = true;

      String message = ex.getMessage();
      assertTrue(message, message.startsWith("Globs not allowed"));
    }
    assertTrue(threw);
  }
}
