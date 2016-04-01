package com.google.security.fences;

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.annotation.CheckReturnValue;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

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

  static final class TestBuilder {
    private final String testProjectName;
    private Result expectedResult = Result.FAIL;
    private Debug debug = Debug.QUIET;
    private List<String> extraCliOptions = Lists.newArrayList();
    private List<String> textInLog = Lists.newArrayList();
    private List<String> textNotInLog = Lists.newArrayList();

    TestBuilder(String testProjectName) {
      this.testProjectName = testProjectName;
    }

    @CheckReturnValue
    TestBuilder with(Debug newDebug) {
      this.debug = newDebug;
      return this;
    }

    @CheckReturnValue
    TestBuilder with(Result newExpectedResult) {
      this.expectedResult = newExpectedResult;
      return this;
    }

    @CheckReturnValue
    TestBuilder extraCliOptions(String... argv) {
      extraCliOptions.addAll(ImmutableList.of(argv));
      return this;
    }

    @CheckReturnValue
    TestBuilder inLog(String... strings) {
      textInLog.addAll(ImmutableList.of(strings));
      return this;
    }

    @CheckReturnValue
    TestBuilder notInLog(String... strings) {
      textNotInLog.addAll(ImmutableList.of(strings));
      return this;
    }

    Verifier run() throws IOException, VerificationException {
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

      ImmutableList.Builder<String> cliOptions = ImmutableList.builder();
      if (debug == Debug.VERBOSE) {
        cliOptions.add("-X");
      }
      cliOptions.addAll(this.extraCliOptions);
      verifier.setCliOptions(cliOptions.build());

      try {
        verifier.executeGoals(ImmutableList.of("verify"));
      } catch (@SuppressWarnings("unused") VerificationException ex) {
        goalResult = Result.FAIL;
      }
      for (String expectedText : textInLog) {
        verifier.verifyTextInLog(expectedText);
      }

      for (String s : textNotInLog) {
        boolean inLog;
        try {
          verifier.verifyTextInLog(s);
          inLog = true;
        } catch (@SuppressWarnings("unused") VerificationException ex) {
          inLog = false;
        }
        assertFalse(s, inLog);
      }

      assertEquals(expectedResult, goalResult);
      if (expectedResult == Result.PASS) {
        verifier.verifyErrorFreeLog();
      }
      return verifier;
    }
  }

  public static final void testMethodCall() throws Exception {
    new TestBuilder("test-method-call")
        .with(Result.FAIL)
        .inLog(
            "BUILD FAILURE",

            "[ERROR] test:test-method-call:jar:1.0-SNAPSHOT"
                + " : NotAllowedToCallExit.java : L7 :"
                + " java.lang.System.exit() cannot be accessed from"
                + " foo.bar.NotAllowedToCallExit",

            "1 access policy violation")
        .run();
  }

  public static final void testMethodCallInExperimentalMode() throws Exception {
    new TestBuilder("test-method-call")
        .with(Result.PASS)
        .inLog(
            "BUILD SUCCESS",

            "[WARNING] test:test-method-call:jar:1.0-SNAPSHOT"
                + " : NotAllowedToCallExit.java : L7 :"
                + " java.lang.System.exit() cannot be accessed from"
                + " foo.bar.NotAllowedToCallExit",

            "1 access policy violation ignored in experimental mode")
        .extraCliOptions(
            "-D" + RelevantSystemProperties.PROPERTY_EXPERIMENTAL_MODE)
        .run();
  }

  public static final void testAllOk() throws Exception {
    new TestBuilder("test-all-ok")
        .with(Result.PASS)
        .inLog(
            "BUILD SUCCESS",

            "enforce (enforce) @ test",

            "No access policy violations")
        .run();
    new TestBuilder("test-all-ok")
        .with(Result.PASS)
        .inLog(
            "BUILD SUCCESS",

            "enforce (enforce) @ test",

            "No access policy violations")
        .extraCliOptions(
            "-D" + RelevantSystemProperties.PROPERTY_EXPERIMENTAL_MODE)
        .run();
  }

  public static final void testCtorAccess() throws Exception {
    new TestBuilder("test-ctor-access")
        .with(Result.FAIL)
        .inLog(
            "BUILD FAILURE",

            "java.net.URL.<init>()"
            + " cannot be accessed from foo.bar.Baz",

            "1 access policy violation",

            "Use java.net.URI instead.")
        .run();
  }

  public static final void testTransitiveDependency() throws Exception {
    new TestBuilder("test-transitive-dependency")
        .with(Result.FAIL)
        .inLog(
            "BUILD FAILURE",

            "java.lang.Runtime.getRuntime()"
            + " cannot be accessed from foo.dependee.Dependee",

            "java.lang.Runtime.exec()"
            + " cannot be accessed from foo.dependee.Dependee",

            "2 access policy violations",

            // <rationale> from the POM.
            "Code that uses java.lang.Runtime.exec()",
            "to execute shell scripts or check environment variables",
            "will probably break when we move to new hosting.")
        .run();
  }

  public static final void testFieldRead() throws Exception {
    new TestBuilder("test-field-read")
        .with(Result.FAIL)
        .inLog(
            "BUILD FAILURE",

            "Baz.java : L5",
            "java.util.Locale.US cannot be accessed from foo.bar.Baz",
            "We have to support users from many countries, so please",

            "1 access policy violation")
        .run();
  }

  public static final void testImports() throws Exception {
    new TestBuilder("test-imports")
        .with(Result.FAIL)
        .inLog(
            "BUILD FAILURE",

            "[ERROR] test:partially-safe-client:jar:1.0-SNAPSHOT"
            + " : Roulette.java",

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

            "5 access policy violations")
        .run();
  }

  public static final void testAddenda() throws Exception {
    new TestBuilder("test-addenda")
        .with(Result.FAIL)
        .inLog(
            "BUILD FAILURE",

            ". java.lang.System.exit() cannot be accessed from com.example.Foo",
            ". Our launch scripts depend upon the exit code",
            ". Throw don't exit.",
            ". For more info code-quality@example.com",

            "1 access policy violation")
        .notInLog("SHOULD NOT BE PRESENT IN LOG")
        .run();
  }

  public static final void testRationaleOverridden() throws Exception {
    new TestBuilder("test-rationale-overridden")
        .with(Result.FAIL)
        .inLog(
            "BUILD FAILURE",

            "test:internal-project:jar:1.0-SNAPSHOT : Main.java : L7",
            ". com.third_party.Unsafe.unsafe() cannot be accessed from com.example.Main",
            ". Prefer com.example.SaferThanUnsafe to com.third_party.Unsafe.unsafe().",
            ". ",
            ". security@example.com | http://wiki/security/guidelines",
            ". ",
            ". See http://wiki/com.third_party__tips_and_pitfalls",

            "1 access policy violation")
      .notInLog(
            "Unsafe is prone to misuse.",
            "Use the safe builder APIs.")
      .run();
  }
}
