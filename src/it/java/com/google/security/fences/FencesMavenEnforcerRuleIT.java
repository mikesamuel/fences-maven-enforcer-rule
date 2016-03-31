package com.google.security.fences;

import java.io.File;
import java.io.IOException;

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

  private Verifier verifyTestProject(
      String testProjectName,
      Result expectedResult,
      Debug debug,
      String...expectedTexts)
  throws IOException, VerificationException {

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
    return verifier;
  }

  public final void testMethodCall() throws Exception {
    verifyTestProject(
        "test-method-call",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "[ERROR] test:test-method-call:jar:1.0-SNAPSHOT"
        + " : NotAllowedToCallExit.java : L7 :"
        + " java.lang.System.exit() cannot be accessed from"
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

        "java.net.URL.<init>()"
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

        "java.lang.Runtime.getRuntime()"
        + " cannot be accessed from foo.dependee.Dependee",

        "java.lang.Runtime.exec()"
        + " cannot be accessed from foo.dependee.Dependee",

        "2 access policy violations",

        // <rationale> from the POM.
        "Code that uses java.lang.Runtime.exec()",
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
        "java.util.Locale.US cannot be accessed from foo.bar.Baz",
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
        ". . com.example.api.Unsafe.<init>() cannot be accessed"
        + " from com.example.client.Roulette",
        // Banned direct method access.
        ". . com.example.api.Unsafe.pushRedButton() cannot be accessed"
        + " from com.example.client.Roulette (2 times)",
        ". . Lorem ipsum dangerous.",
        ". L11",
        // Banned implicit call to super-class ctor.
        // But the call to the local constructor itself is not banned.
        ". . com.example.api.Unsafe.<init>() cannot be accessed"
        + " from com.example.client.Roulette$1",
        // Banned use of method defined on super-class.
        ". . com.example.client.Roulette.1.pushRedButton() cannot be"
        + " accessed from com.example.client.Roulette because"
        + " com.example.api.Unsafe.pushRedButton() is restricted",
        ". . Lorem ipsum dangerous.",

        "5 access policy violations");
  }

  public final void testAddenda() throws Exception {
    Verifier v = verifyTestProject(
        "test-addenda",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        ". java.lang.System.exit() cannot be accessed from com.example.Foo",
        ". Our launch scripts depend upon the exit code",
        ". Throw don't exit.",
        ". For more info code-quality@example.com",

        "1 access policy violation"
        );
    notInLog(v, "SHOULD NOT BE PRESENT IN LOG");
  }

  public final void testRationaleOverridden() throws Exception {
    Verifier v = verifyTestProject(
        "test-rationale-overridden",
        Result.FAIL,
        Debug.QUIET,

        "BUILD FAILURE",

        "test:internal-project:jar:1.0-SNAPSHOT : Main.java : L7",
        ". com.third_party.Unsafe.unsafe() cannot be accessed from com.example.Main",
        ". Prefer com.example.SaferThanUnsafe to com.third_party.Unsafe.unsafe().",
        ". ",
        ". security@example.com | http://wiki/security/guidelines",
        ". ",
        ". See http://wiki/com.third_party__tips_and_pitfalls",

        "1 access policy violation"
        );
    notInLog(v,
        "Unsafe is prone to misuse.",
        "Use the safe builder APIs.");
  }

  private static void notInLog(Verifier v, String... shouldNotBePresent) {
    boolean inLog;
    for (String s : shouldNotBePresent) {
      try {
        v.verifyTextInLog(s);
        inLog = true;
      } catch (@SuppressWarnings("unused") VerificationException ex) {
        inLog = false;
      }
      assertFalse(s, inLog);
    }
  }
}
