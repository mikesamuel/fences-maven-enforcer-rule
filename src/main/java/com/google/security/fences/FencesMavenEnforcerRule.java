package com.google.security.fences;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactNotFoundException;
import org.apache.maven.artifact.resolver.ArtifactResolutionException;
import org.apache.maven.artifact.resolver.ArtifactResolver;
import org.apache.maven.enforcer.rule.api.EnforcerRule;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.enforcer.rule.api.EnforcerRuleHelper;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilder;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilderException;
import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.security.fences.config.ApiFence;
import com.google.security.fences.config.ClassFence;
import com.google.security.fences.config.Fence;
import com.google.security.fences.config.PackageFence;
import com.google.security.fences.policy.Policy;
import com.google.security.fences.util.LazyString;
import com.google.security.fences.util.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * Augments Java access control by verifying that a project and its dependencies
 * don't statically violate a policy.
 */
public final class FencesMavenEnforcerRule implements EnforcerRule {

  private final List<Fence> fences = Lists.newArrayList();

  private void addFence(Fence f) throws EnforcerRuleException {
    f.check();
    fences.add(f.splitDottedNames());
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setApi(ApiFence x) throws EnforcerRuleException {
    addFence(x);
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setPackage(PackageFence x) throws EnforcerRuleException {
    addFence(x);
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) throws EnforcerRuleException {
    addFence(x);
  }

  public void execute(EnforcerRuleHelper helper) throws EnforcerRuleException {
    Log log = helper.getLog();

    ArtifactResolver resolver;
    DependencyTreeBuilder treeBuilder;
    try {
      resolver = (ArtifactResolver) helper.getComponent(ArtifactResolver.class);
      treeBuilder = (DependencyTreeBuilder)
          helper.getComponent(DependencyTreeBuilder.class);
    } catch (ComponentLookupException ex) {
      throw new EnforcerRuleException(
          "Failed to locate component: " + ex.getLocalizedMessage(), ex);
    }

    MavenProject project;
    ArtifactRepository localRepository;
    List<ArtifactRepository> remoteRepositories;
    String projectBuildOutputDirectory;
    try {
      project = (MavenProject) helper.evaluate("${project}");
      localRepository = (ArtifactRepository) helper.evaluate("${localRepository}");
      @SuppressWarnings("unchecked")
      List<ArtifactRepository> rr = (List<ArtifactRepository>)
          helper.evaluate("${project.remoteArtifactRepositories}");
      remoteRepositories = rr;
      // Per https://books.sonatype.com/mvnref-book/reference/resource-filtering-sect-properties.html
      projectBuildOutputDirectory = (String)
          helper.evaluate("${project.build.outputDirectory}");
    } catch (ExpressionEvaluationException ex) {
      throw new EnforcerRuleException(
          "Failed to locate component: " + ex.getLocalizedMessage(), ex);
    }

    ArtifactFinder finder = new ArtifactFinder(
        project, resolver, treeBuilder, localRepository, remoteRepositories);

    Set<Artifact> artifacts;
    try {
      artifacts = finder.getArtifacts(false);
    } catch (DependencyTreeBuilderException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    } catch (ArtifactResolutionException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    } catch (ArtifactNotFoundException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    }

    checkAllClasses(project, log, projectBuildOutputDirectory, artifacts);
  }

  protected void checkAllClasses(
      MavenProject project, Log log,
      String projectClassRoot, Set<Artifact> artifacts)
  throws EnforcerRuleException {
    ImmutableList<Fence> allFences = ImmutableList.copyOf(fences);
    Set<Artifact> allArtifacts = ImmutableSet.<Artifact>builder()
        .addAll(artifacts)
        .build();

    if (allFences.isEmpty()) {
      throw new EnforcerRuleException("No fences");
    }

    final Policy p = Policy.fromFences(allFences);
    log.debug(new LazyString() {
      @Override
      protected String makeString() {
        return "Using policy\n" + p.toString();
      }
    });

    Checker checker = new Checker(log, p);

    try {
      checker.checkClassRoot(project.getArtifact(), new File(projectClassRoot));
    } catch (IOException ex) {
      throw new EnforcerRuleException(
          "Failed to check " + Utils.artToString(project.getArtifact()), ex);
    }

    for (Artifact art : allArtifacts) {
      // TODO: Do we need to handle wars, etc.?
      String artType = art.getType();
      String artScope = art.getScope();
      if ("jar".equals(artType)) {
        log.info(
            "Checking " + Utils.artToString(art) + " from scope " + artScope);
        File f = art.getFile();
        if (f == null) {
          throw new EnforcerRuleException(
              "Cannot check artifact " + Utils.artToString(art)
              + " since it has not been packaged.");
        }

        try {
          FileInputStream in = new FileInputStream(f);
          try {
            checker.checkJar(art, in);
          } finally {
            in.close();
          }
        } catch (IOException ex) {
          throw new EnforcerRuleException(
              "Failed to check " + Utils.artToString(art), ex);
        }
      } else {
        log.info("Not checking artifact " + Utils.artToString(art)
                 + " with type " + artType);
      }
    }

    int errorCount = checker.getErrorCount();
    if (errorCount != 0) {
      throw new EnforcerRuleException(
          errorCount + " access policy violation"
          + (errorCount == 1 ? "" : "s"));
    }
  }

  public String getCacheId() {
    return null;
  }

  public boolean isCacheable() {
    return false;
  }

  public boolean isResultValid(EnforcerRule arg0) {
    return false;
  }

}
