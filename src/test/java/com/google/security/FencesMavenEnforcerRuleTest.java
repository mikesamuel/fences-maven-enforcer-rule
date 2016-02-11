package com.google.security;

import java.io.File;

import org.apache.maven.it.VerificationException;
import org.apache.maven.it.Verifier;
import org.apache.maven.it.util.ResourceExtractor;
import org.junit.Test;

import junit.framework.TestCase;

public class FencesMavenEnforcerRuleTest extends TestCase {

  @Test
  public void testBannedUseProject() throws Exception {
    File testDir = ResourceExtractor.simpleExtractResources(
        getClass(), "/test-banned-use-project");

    Verifier verifier = new Verifier(testDir.getAbsolutePath());
    // Clean up after previous runs.
    verifier.deleteArtifacts("test");
    boolean goalFailed = false;
    try {
      verifier.executeGoal("package");

      verifier.verifyTextInLog("BUILD FAILURE");
    } catch (@SuppressWarnings("unused") VerificationException ex) {
      goalFailed = true;
    }
    assertTrue(goalFailed);
  }

}
