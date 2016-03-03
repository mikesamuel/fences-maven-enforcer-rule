package com.google.security.fences;

import java.io.File;

import org.apache.maven.it.VerificationException;
import org.apache.maven.it.Verifier;
import org.apache.maven.it.util.ResourceExtractor;

import com.google.common.collect.ImmutableList;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class FencesMavenEnforcerRuleTest extends TestCase {

  private void verifyTestProject(
      String testProjectName,
      boolean expectFailure,
      String...expectedTexts)
  throws Exception {

    // Typically, the log file is in
    // target/test-classes/<test-project-name>/log.txt
    File testDir = ResourceExtractor.simpleExtractResources(
        getClass(), "/" + testProjectName);

    Verifier verifier = new Verifier(
        testDir.getAbsolutePath(),
        null, false /* debug */, true /* forkJvm */);
    // Clean up after previous runs.
    verifier.deleteArtifacts("test");
    boolean goalFailed = false;
    // We use the -N flag so that Maven won't recurse.
    verifier.setCliOptions(ImmutableList.of("-N"));
    try {
      verifier.executeGoal("verify");
    } catch (@SuppressWarnings("unused") VerificationException ex) {
      goalFailed = true;
    }
    for (String expectedText : expectedTexts) {
      verifier.verifyTextInLog(expectedText);
    }
    assertEquals(expectFailure, goalFailed);
  }

  public final void testBannedUseProject() throws Exception {
    verifyTestProject(
        "test-banned-use-project",
        true,

        "BUILD FAILURE",

        "access denied to [METHOD : java.lang.System.exit] from"
        + " foo.bar.NotAllowedToCallExit",

        "1 access policy violation");
  }

}
