package com.google.security.fences;

import java.util.Locale;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;

abstract class NamedFence extends Fence {
  @Parameter
  private String name;

  public String getName() { return name; }

  @Override
  public void check() throws MojoExecutionException {
    super.check();
    if (name == null) {
      throw new MojoExecutionException(
          getClass().getSimpleName().replaceFirst("Fence$", "")
          .toLowerCase(Locale.ENGLISH)
          + " is missing a name");
    }
  }
}