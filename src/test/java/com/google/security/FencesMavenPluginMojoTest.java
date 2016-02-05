package com.google.security;

import java.io.File;

import org.apache.maven.plugin.Mojo;
import org.apache.maven.plugin.testing.AbstractMojoTestCase;
import org.junit.Test;

public class FencesMavenPluginMojoTest extends AbstractMojoTestCase {

  @Test
  public void testBannedUseProject() throws Exception {
    File baseDir = getTestFile("src/test/resources/test-banned-use-project/");
    File pom = new File(baseDir, "pom.xml");

    Mojo mojo = lookupMojo("verify", pom);
    assertNotNull(mojo);
    mojo.execute();
  }

}
