package com.google.security.fences;

import java.io.File;
import java.util.List;
import java.util.Set;

import javax.annotation.Nullable;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactNotFoundException;
import org.apache.maven.artifact.resolver.ArtifactResolutionException;
import org.apache.maven.artifact.resolver.ArtifactResolver;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.dependency.tree.DependencyNode;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilder;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilderException;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import com.google.security.fences.util.LazyString;
import com.google.security.fences.util.Utils;

/**
 * Recursively finds artifacts.
 * Largely adapted from https://github.com/mojohaus/extra-enforcer-rules
 * but that does not resolve modules or the project itself.
 */
final class ArtifactFinder {
  private final ArtifactResolver resolver;
  private final DependencyTreeBuilder treeBuilder;
  private final ArtifactRepository localRepository;
  private final List<ArtifactRepository> remoteRepositories;
  private final Log log;
  /** IDs of projects seen. */
  private final Set<String> seen = Sets.newLinkedHashSet();
  /**
   * IDs of projects available as MavenProject instances,
   * not just artifacts.
   */
  private final Set<String> availableAsProject = Sets.newLinkedHashSet();
  private final ImmutableList.Builder<ClassRoot> classRoots
      = ImmutableList.builder();


  ArtifactFinder(
      ArtifactResolver resolver,
      DependencyTreeBuilder treeBuilder,
      ArtifactRepository localRepository,
      List<ArtifactRepository> remoteRepositories,
      Log log) {
    this.resolver = Preconditions.checkNotNull(resolver);
    this.treeBuilder = Preconditions.checkNotNull(treeBuilder);
    this.localRepository = Preconditions.checkNotNull(localRepository);
    this.remoteRepositories = ImmutableList.copyOf(remoteRepositories);
    this.log = log;
  }

  ImmutableList<ClassRoot> getClassRoots() {
    return classRoots.build();
  }

  private void markAvailableAsProject(MavenProject project) {
    if (this.availableAsProject.add(project.getId())) {
      @SuppressWarnings("unchecked")
      List<MavenProject> collectedProjects = project.getCollectedProjects();
      if (collectedProjects != null) {
        for (MavenProject collectedProject : collectedProjects) {
          markAvailableAsProject(collectedProject);
        }
      }
    }
  }

  /**
   * Explores all dependencies and modules transitively.
   */
  void findClassRoots(MavenProject project)
  throws ArtifactNotFoundException, ArtifactResolutionException,
         DependencyTreeBuilderException, EnforcerRuleException {
    markAvailableAsProject(project);
    String id = project.getId();
    if (!seen.add(id)) {
      return;
    }

    // Build the dependency tree.
    // We do this before trying to create a ZIP since resolving
    // these dependencies makes the location of the ZIP file
    // available to us.
    // TODO: Do we need to check the scope of the dependency
    // to filter out test dependencies.
    DependencyNode node = treeBuilder.buildDependencyTree(
        project, localRepository, null);
    Artifact art = node.getArtifact();

    // We need to find a JAR or a directory with the classes
    // if its not a <packaging>pom</packaging>
    boolean hasClassRoot = !"pom".equals(project.getPackaging());
    File buildOutputDirectory = null;

    // TODO: Do we need to descend into WARs and other packaging types?
    if (hasClassRoot) {
      // First, figure out whether to get the classes from an output
      // directory or from a packaged ZIP file like a JAR.
      Build build = project.getBuild();
      if (build != null) {
        String buildOutputDirectoryPath = build.getOutputDirectory();
        if (buildOutputDirectoryPath != null) {
          buildOutputDirectory = new File(buildOutputDirectoryPath);
          if (!buildOutputDirectory.exists()) {
            // When compiling an aggregating project, sub-modules seem
            // to be installed and their output directories cleaned
            // before control returns to the parent project builder.
            // TODO: confirm this is what actually happens.
            // So if there is no build output directory, expect to find
            // the artifact in the local repository.
            log.debug(
                "Build output directory " + buildOutputDirectory
                + " does not exist for " + id
                + ".  Falling back to local repository.");
            buildOutputDirectory = null;
          }
        }
      }

      if (buildOutputDirectory != null) {
        log.info(
                 "Found directory class root " + buildOutputDirectory
                 + " for " + project.getId());
        classRoots.add(new ClassRoot(
            art, buildOutputDirectory,
            ClassRoot.ClassRootKind.BUILD_OUTPUT_DIRECTORY));
      } else {
        resolver.resolve(art, remoteRepositories, localRepository);
        addZipClassRoot(art);
      }
    }

    @SuppressWarnings("unchecked")
    List<MavenProject> collectedProjects = project.getCollectedProjects();
    if (collectedProjects != null) {
      for (MavenProject collectedProject : collectedProjects) {
        findClassRoots(collectedProject);
      }
    }

    addAllDescendants(node);
  }

  private void addAllDescendants(DependencyNode node)
  throws ArtifactNotFoundException, ArtifactResolutionException,
         EnforcerRuleException {
    List<DependencyNode> childNodes = node.getChildren();
    if (childNodes != null) {
      for (DependencyNode depNode : childNodes) {
        Artifact artifact = depNode.getArtifact();
        if (availableAsProject.contains(artifact.getId())) {
          continue;
        }
        resolver.resolve(artifact, remoteRepositories, localRepository);

        boolean isProductionCode = true;  // until proven otherwise.
        if (depNode.getState() != DependencyNode.INCLUDED
            // TODO: How does artifact.getScope
            // relate to the DependencyNode's scopes?
            || Artifact.SCOPE_TEST.equals(scopeOfDependency(depNode))) {
          // IMHO, test code should be allowed to break abstractions
          // like debug hooks, so we don't limit test code's ability
          // to access non-private APIs in the same way that we
          // do for production code which has to work to preserve
          // abstractions and system properties.
          isProductionCode = false;
        }

        if (isProductionCode) {
          addZipClassRoot(artifact);
        }

        // Non-production code and non-class-generating modules may have
        // dependencies which are themselves available during production,
        // so we recurse regardless.
        addAllDescendants(depNode);
      }
    }
  }

  private static @Nullable String scopeOfDependency(DependencyNode depNode) {
    String scope = null;
    Artifact art = depNode.getArtifact();
    if (art != null) {
      scope = art.getScope();
    }
    if (scope == null) {
      scope = depNode.getOriginalScope();
    }
    if (scope == null) {
      scope = depNode.getPremanagedScope();
    }
    return scope;
  }

  private void addZipClassRoot(final Artifact art)
  throws EnforcerRuleException {
    final File artFile = art.getFile();
    if (artFile == null) {
      throw new EnforcerRuleException(
          "Cannot check artifact " + Utils.artToString(art)
          + " since it has not been packaged.");
    }
    log.info(new LazyString() {
      @Override
      protected String makeString() {
        return "Found zip file " + artFile + " for " + Utils.artToString(art);
      }
    });
    classRoots.add(new ClassRoot(
        art, artFile, ClassRoot.ClassRootKind.ZIPFILE));
  }
}
