package com.google.security.fences;

import java.io.File;

import org.apache.maven.it.VerificationException;
import org.apache.maven.it.Verifier;
import org.apache.maven.it.util.ResourceExtractor;
import org.junit.Test;

import com.google.common.collect.ImmutableList;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class FencesMavenEnforcerRuleTest extends TestCase {

  @Test
  public void testBannedUseProject() throws Exception {
    // Typically, the log file is in
    // target/test-classes/test-banned-use-project/log.txt

    File testDir = ResourceExtractor.simpleExtractResources(
        getClass(), "/test-banned-use-project");

    Verifier verifier = new Verifier(
        testDir.getAbsolutePath(),
        null, false /* debug */, true /* forkJvm */);
    // Clean up after previous runs.
    verifier.deleteArtifacts("test");
    boolean goalFailed = false;
    // We use the -N flag so that Maven won't recurse.
    verifier.setCliOptions(ImmutableList.of("-N"));
    try {
      // Compile the jars so that the Jar Checker can find them.
      verifier.executeGoal("compile");
      // Package it up so that the verifier runs.
      verifier.executeGoal("package");
    } catch (@SuppressWarnings("unused") VerificationException ex) {
      goalFailed = true;
    }
    verifier.verifyTextInLog("BUILD FAILURE");
    assertTrue(goalFailed);
  }

}
