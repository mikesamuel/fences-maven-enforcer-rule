package com.google.security;

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
import org.apache.maven.shared.dependency.tree.DependencyNode;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilder;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilderException;
import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.security.fences.Fence;
import com.google.security.fences.ApiFence;
import com.google.security.fences.ClassFence;
import com.google.security.fences.PackageFence;
import com.google.security.fences.policy.Policy;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Collection;
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
    try {
      project = (MavenProject) helper.evaluate("${project}");
      localRepository = (ArtifactRepository) helper.evaluate("${localRepository}");
      @SuppressWarnings("unchecked")
      List<ArtifactRepository> rr = (List<ArtifactRepository>)
          helper.evaluate("${project.remoteArtifactRepositories}");
      remoteRepositories = rr;
    } catch (ExpressionEvaluationException ex) {
      throw new EnforcerRuleException(
          "Failed to locate component: " + ex.getLocalizedMessage(), ex);
    }

    ArtifactFinder finder = new ArtifactFinder(
        project, resolver, treeBuilder, localRepository, remoteRepositories);

    Set<Artifact> artifacts;
    try {
      artifacts = finder.getArtifacts();
    } catch (DependencyTreeBuilderException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    } catch (ArtifactResolutionException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    } catch (ArtifactNotFoundException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    }

    checkAllArtifacts(log, artifacts);
  }

  protected void checkAllArtifacts(Log log, Set<Artifact> artifacts)
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

    JarChecker jarChecker = new JarChecker(log, p);

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
            jarChecker.checkJar(art, in);
          } finally {
            in.close();
          }
        } catch (IOException ex) {
          // TODO: recent versions of ArtifactUtils do group:art:ver
          throw new EnforcerRuleException(
              "Failed to check " + Utils.artToString(art), ex);
        }
      } else {
        // TODO: recent versions of ArtifactUtils do group:art:ver
        log.info("Not checking artifact " + Utils.artToString(art)
        + " with type " + artType);
      }
    }

    int errorCount = jarChecker.getErrorCount();
    if (errorCount != 0) {
      throw new EnforcerRuleException(
          errorCount + " access policy violation"
          + (errorCount == 1 ? "" : "s"));
    }
  }

  public String getCacheId() {
    // TODO Auto-generated method stub
    return null;
  }

  public boolean isCacheable() {
    // TODO Auto-generated method stub
    return false;
  }

  public boolean isResultValid(EnforcerRule arg0) {
    // TODO Auto-generated method stub
    return false;
  }



  /**
   * Recursively finds artifacts.
   * Largely adapted from https://github.com/mojohaus/extra-enforcer-rules
   * but that does not resolve modules or the project itself.
   */
  private static final class ArtifactFinder {
    private final MavenProject project;
    private final ArtifactResolver resolver;
    private final DependencyTreeBuilder treeBuilder;
    private final ArtifactRepository localRepository;
    private final List<ArtifactRepository> remoteRepositories;

    ArtifactFinder(
        MavenProject project,
        ArtifactResolver resolver,
        DependencyTreeBuilder treeBuilder,
        ArtifactRepository localRepository,
        List<ArtifactRepository> remoteRepositories) {
      this.project = Preconditions.checkNotNull(project);
      this.resolver = Preconditions.checkNotNull(resolver);
      this.treeBuilder = Preconditions.checkNotNull(treeBuilder);
      this.localRepository = Preconditions.checkNotNull(localRepository);
      this.remoteRepositories = ImmutableList.copyOf(remoteRepositories);
    }

    Set<Artifact> getArtifacts()
    throws ArtifactNotFoundException, ArtifactResolutionException, DependencyTreeBuilderException {
      Set<Artifact> dependencies = Sets.newLinkedHashSet();
      DependencyNode node = treeBuilder.buildDependencyTree(project, localRepository, null);
      addAllDescendants(node, dependencies);
      return dependencies;
    }

    private void addAllDescendants(
        DependencyNode node, Collection<? super Artifact> out)
    throws ArtifactNotFoundException, ArtifactResolutionException {
      Artifact artifact = node.getArtifact();
      resolver.resolve(artifact, remoteRepositories, localRepository);
      out.add(artifact);

      List<DependencyNode> childNodes = node.getChildren();
      if (childNodes != null) {
        for(DependencyNode depNode : childNodes) {
          addAllDescendants(depNode, out);
        }
      }
    }
  }

}
