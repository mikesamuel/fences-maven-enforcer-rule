package com.google.security.fences;

import java.io.File;

import com.google.common.collect.ImmutableList;

import org.apache.maven.it.VerificationException;
import org.apache.maven.it.Verifier;
import org.apache.maven.it.util.ResourceExtractor;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class FencesMavenEnforcerRuleIT extends TestCase {

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

    if (debug == Debug.VERBOSE) {
      verifier.setCliOptions(ImmutableList.of("-X"));
    }
    try {
      verifier.executeGoals(ImmutableList.of("verify"));
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

  public final void testMethodCall() throws Exception {
    verifyTestProject(
        "test-method-call",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "[ERROR] test:test-method-call:jar:1.0-SNAPSHOT"
        + " : NotAllowedToCallExit.java : L7 :"
        + " [METHOD : java.lang.System.exit] cannot be accessed from"
        + " foo.bar.NotAllowedToCallExit",

        "1 access policy violation");
  }

  public final void testAllOk() throws Exception {
    verifyTestProject(
        "test-all-ok",
        Result.PASS,
        Debug.QUIET,

        "BUILD SUCCESS",

        "enforce (enforce) @ test",

        "No access policy violations");
  }

  public final void testCtorAccess() throws Exception {
    verifyTestProject(
        "test-ctor-access",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "[CONSTRUCTOR : java.net.URL.<init>]"
        + " cannot be accessed from foo.bar.Baz",

        "1 access policy violation",

        "Use java.net.URI instead.");
  }

  public final void testTransitiveDependency() throws Exception {
    verifyTestProject(
        "test-transitive-dependency",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "[METHOD : java.lang.Runtime.getRuntime]"
        + " cannot be accessed from foo.dependee.Dependee",

        "[METHOD : java.lang.Runtime.exec]"
        + " cannot be accessed from foo.dependee.Dependee",

        "2 access policy violations",

        // <rationale> from the POM.
        "Code that uses [METHOD : java.lang.Runtime.exec]",
        "to execute shell scripts or check environment variables",
        "will probably break when we move to new hosting.");
  }

  public final void testFieldRead() throws Exception {
    verifyTestProject(
        "test-field-read",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "Baz.java : L5",
        "[FIELD : java.util.Locale.US] cannot be accessed from foo.bar.Baz",
        "We have to support users from many countries, so please",

        "1 access policy violation");
  }

  public final void testImports() throws Exception {
    verifyTestProject(
        "test-imports",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "[ERROR] test:partially-safe-client:jar:1.0-SNAPSHOT : Roulette.java",
        ". L8",
        // Banned direct ctor access.
        ". . [CONSTRUCTOR : com.example.api.Unsafe.<init>] cannot be accessed from com.example.client.Roulette",
        // Banned direct method access.
        ". . [METHOD : com.example.api.Unsafe.pushRedButton] cannot be accessed from com.example.client.Roulette",
        ". . Lorem ipsum dangerous.",
        ". L10",
        // Banned implicit call to super-class ctor.
        ". . [CONSTRUCTOR : com.example.api.Unsafe.<init>] cannot be accessed from com.example.client.Roulette$1",
        // Banned use of method defined on super-class.
        ". . [METHOD : com.example.client.Roulette.1.pushRedButton] cannot be accessed from com.example.client.Roulette because access to [METHOD : com.example.api.Unsafe.pushRedButton] is restricted",
        ". . Lorem ipsum dangerous.",

        "4 access policy violations");
  }

}
