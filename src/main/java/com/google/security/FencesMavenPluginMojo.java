package com.google.security;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Execute;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.security.fences.Fence;
import com.google.security.fences.ApiFence;
import com.google.security.fences.ClassFence;
import com.google.security.fences.PackageFence;
import com.google.security.fences.policy.Policy;

import java.io.IOException;
import java.util.List;

/**
 * Augments Java access control by verifying that a project and its dependencies
 * don't statically violate a policy.
 */
@Mojo(
    name="check-access",
    defaultPhase=LifecyclePhase.VERIFY,
    requiresProject=true,
    requiresDependencyResolution=ResolutionScope.COMPILE_PLUS_RUNTIME,
    requiresDependencyCollection=ResolutionScope.COMPILE_PLUS_RUNTIME)
@Execute(
    goal="check-access",
    phase=LifecyclePhase.VERIFY)
public final class FencesMavenPluginMojo extends AbstractMojo {
  // TODO: This doesn't work under AbstractMojoTestCase but does at CL.
  @Parameter(defaultValue="${project}", readonly=true, required=true)
  private MavenProject project;

  private final List<ApiFence> apis = Lists.newArrayList();
  private final List<PackageFence> packages = Lists.newArrayList();
  private final List<ClassFence> classes = Lists.newArrayList();

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setApi(ApiFence x) throws MojoExecutionException {
    System.err.println("plugin.setApi " + x);
    x.check();
    apis.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setPackage(PackageFence x) throws MojoExecutionException {
    System.err.println("plugin.setPackage " + x);
    x.check();
    packages.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) throws MojoExecutionException {
    System.err.println("plugin.setClass " + x);
    x.check();
    classes.add(Preconditions.checkNotNull(x));
  }


  public void execute() throws MojoExecutionException {
    ImmutableList<Fence> allFences = ImmutableList.<Fence>builder()
        .addAll(apis)
        .addAll(packages)
        .addAll(classes)
        .build();

    if (allFences.isEmpty()) {
      throw new MojoExecutionException("No fences");
    }

    Policy p = Policy.fromFences(allFences);
    Log log = getLog();
    JarChecker jarChecker = new JarChecker(log, p);

    @SuppressWarnings("unchecked")
    ImmutableSet<Artifact> allArtifacts = ImmutableSet.<Artifact>builder()
        .add(project.getArtifact())
        .addAll(project.getArtifacts())
        .build();
    for (Artifact art : allArtifacts) {
      // TODO: Do we need to handle wars, etc.?
      String artType = art.getType();
      if ("jar".equals(artType)) {
        try {
          jarChecker.checkJar(art);
        } catch (IOException ex) {
          // TODO: recent versions of ArtifactUtils do group:art:ver
          throw new MojoExecutionException(
              "Failed to check " + art.getGroupId() + ":" + art.getArtifactId()
              + ":" + art.getBaseVersion(), ex);
        }
      } else {
        // TODO: recent versions of ArtifactUtils do group:art:ver
        log.info("Not checking artifact " + art.getGroupId()
                 + ":" + art.getArtifactId() + ":" + art.getBaseVersion()
                 + " with type " + artType);
      }
    }
  }
}
