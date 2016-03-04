package com.google.security.fences;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactNotFoundException;
import org.apache.maven.artifact.resolver.ArtifactResolutionException;
import org.apache.maven.artifact.resolver.ArtifactResolver;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.dependency.tree.DependencyNode;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilder;
import org.apache.maven.shared.dependency.tree.DependencyTreeBuilderException;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

/**
 * Recursively finds artifacts.
 * Largely adapted from https://github.com/mojohaus/extra-enforcer-rules
 * but that does not resolve modules or the project itself.
 */
final class ArtifactFinder {
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

  /**
   * Gets all dependencies transitively.
   *
   * @param includeProjectArtifact if true, then the current project artifact
   *     will be included.
   *     If the project is not yet packaged, then there's no use trying to
   *     resolve its artifact.
   */
  ImmutableSet<Artifact> getArtifacts(boolean includeProjectArtifact)
  throws ArtifactNotFoundException, ArtifactResolutionException,
         DependencyTreeBuilderException {
    Set<Artifact> dependencies = Sets.newLinkedHashSet();
    DependencyNode node = treeBuilder.buildDependencyTree(
        project, localRepository, null);
    addAllDescendants(node, includeProjectArtifact, dependencies);
    return ImmutableSet.copyOf(dependencies);
  }

  private void addAllDescendants(
      DependencyNode node, boolean addToOut, Collection<? super Artifact> out)
  throws ArtifactNotFoundException, ArtifactResolutionException {
    Artifact artifact = node.getArtifact();
    if (addToOut) {
      resolver.resolve(artifact, remoteRepositories, localRepository);
      out.add(artifact);
    }

    List<DependencyNode> childNodes = node.getChildren();
    if (childNodes != null) {
      for(DependencyNode depNode : childNodes) {
        addAllDescendants(depNode, true, out);
      }
    }
  }
}