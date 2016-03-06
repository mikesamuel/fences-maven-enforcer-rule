package com.google.security.fences;

import java.io.File;

import org.apache.maven.it.VerificationException;
import org.apache.maven.it.Verifier;
import org.apache.maven.it.util.ResourceExtractor;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class FencesMavenEnforcerRuleTest extends TestCase {

  enum Result {
    PASS,
    FAIL,
    ;
  }

  enum Debug {
    QUIET,
    VERBOSE,
  }

  private void verifyTestProject(
      String testProjectName,
      Result expectedResult,
      Debug debug,
      String...expectedTexts)
  throws Exception {

    // Typically, the log file is in
    // target/test-classes/<test-project-name>/log.txt
    File testDir = ResourceExtractor.simpleExtractResources(
        getClass(), "/" + testProjectName);

    Verifier verifier = new Verifier(
        testDir.getAbsolutePath(),
        null, debug == Debug.VERBOSE, true /* forkJvm */);
    // Clean up after previous runs.
    verifier.deleteArtifacts("test");
    Result goalResult = Result.PASS;
    // We use the -N flag so that Maven won't recurse.
    //verifier.setCliOptions(ImmutableList.of("-N"));
    try {
      verifier.executeGoal("verify");
    } catch (@SuppressWarnings("unused") VerificationException ex) {
      goalResult = Result.FAIL;
    }
    for (String expectedText : expectedTexts) {
      verifier.verifyTextInLog(expectedText);
    }
    assertEquals(expectedResult, goalResult);
    if (expectedResult == Result.PASS) {
      verifier.verifyErrorFreeLog();
    }
  }

  public final void testBannedUseProject() throws Exception {
    verifyTestProject(
        "test-banned-use-project",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "test:test-banned-use-project:1.0-SNAPSHOT"
        + " : NotAllowedToCallExit.java:7: "
        + "access denied to [METHOD : java.lang.System.exit] from"
        + " foo.bar.NotAllowedToCallExit",

        "1 access policy violation");
  }

  public final void testAllUsesOkProject() throws Exception {
    verifyTestProject(
        "test-all-uses-ok-project",
        Result.PASS,
        Debug.QUIET,

        "BUILD SUCCESS",

        "enforce (enforce) @ test",

        "No access policy violations");
  }

  public final void testBannedCtorAccess() throws Exception {
    verifyTestProject(
        "test-banned-ctor-access-project",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "access denied to [CONSTRUCTOR : java.net.URL.<init>] from foo.bar.Baz",

        "1 access policy violation",

        "Use java.net.URI instead.");
  }

  public final void testBannedUseInTransitiveDependency() throws Exception {
    verifyTestProject(
        "test-banned-use-in-transitive-dependency-project",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "access denied to [METHOD : java.lang.Runtime.getRuntime]"
        + " from foo.dependee.Dependee",

        "access denied to [METHOD : java.lang.Runtime.exec]"
        + " from foo.dependee.Dependee",

        "2 access policy violations",

        // <rationale> from the POM.
        "[ERROR] Code that uses [METHOD : java.lang.Runtime.exec]",
        "to execute shell scripts or check environment variables",
        "will probably break when we move to new hosting.");
  }

  public final void testBannedField() throws Exception {
    verifyTestProject(
        "test-banned-field-access",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "Baz.java:5: access denied to [FIELD : java.util.Locale.US]",

        "1 access policy violation",

        "We have to support users from many countries, so please");
  }

}
