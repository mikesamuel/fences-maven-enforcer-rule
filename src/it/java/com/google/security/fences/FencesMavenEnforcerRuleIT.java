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

        "test:test-method-call:1.0-SNAPSHOT"
        + " : NotAllowedToCallExit.java:7: access denied to [METHOD"
        + " : java.lang.System.exit] from foo.bar.NotAllowedToCallExit",

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

        "access denied to [CONSTRUCTOR : java.net.URL.<init>] from foo.bar.Baz",

        "1 access policy violation",

        "Use java.net.URI instead.");
  }

  public final void testTransitiveDependency() throws Exception {
    verifyTestProject(
        "test-transitive-dependency",
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

  public final void testFieldRead() throws Exception {
    verifyTestProject(
        "test-field-read",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "Baz.java:5: access denied to [FIELD : java.util.Locale.US]",

        "1 access policy violation",

        "We have to support users from many countries, so please");
  }

  public final void testImports() throws Exception {
    verifyTestProject(
        "test-imports",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "Roulette.java:8: access denied to [CONSTRUCTOR : com.example.api.Unsafe.<init>]",
        "Roulette.java:8: access denied to [METHOD : com.example.api.Unsafe.pushRedButton]",
        "Roulette.java:10: access denied to [CONSTRUCTOR : com.example.api.Unsafe.<init>]",
        // TODO: vet the other 3 that are a result of inheritance,
        // improve error messages to show the inheritance chain by which they
        // were arrived at, and check that error message here.

        "6 access policy violations");
  }

}
