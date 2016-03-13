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
import org.codehaus.plexus.component.configurator.BasicComponentConfigurator;
import org.codehaus.plexus.component.configurator.ComponentConfigurator;
import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.codehaus.plexus.interpolation.PropertiesBasedValueSource;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.security.fences.config.ApiFence;
import com.google.security.fences.config.ClassFence;
import com.google.security.fences.config.Fence;
import com.google.security.fences.config.PackageFence;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.Policy;
import com.google.security.fences.util.LazyString;
import com.google.security.fences.util.Utils;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Augments Java access control by verifying that a project and its dependencies
 * don't statically violate a policy.
 */
public final class FencesMavenEnforcerRule implements EnforcerRule {

  private final List<Fence> fences = Lists.newArrayList();
  private final LinkedList<ConfigurationImport> imports = Lists.newLinkedList();
  private final Set<ConfigurationImport.PartialArtifactKey> alreadyImported =
      Sets.newLinkedHashSet();

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

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setImport(String x) throws EnforcerRuleException {
    imports.add(new ConfigurationImport(x));
  }

  public void execute(EnforcerRuleHelper helper) throws EnforcerRuleException {
    Log log = helper.getLog();

    // TODO: maybe check MavenSession.getGoals() to see if this is being
    // run at phase "validate" instead of phase "verify" to warn of a
    // missing <phase>verify</phase> in the enforcer plugin configuration.

    ArtifactResolver resolver;
    DependencyTreeBuilder treeBuilder;
    ComponentConfigurator configurator;
    try {
      resolver = (ArtifactResolver) helper.getComponent(ArtifactResolver.class);
      treeBuilder = (DependencyTreeBuilder)
          helper.getComponent(DependencyTreeBuilder.class);
      if (false) {
        // This seems "the right way" since plexus is supposed to inject
        // dependencies, but when run without -X to turn on debugging,
        // we get a MapOrientedComponentConfigurator which cannot configure
        // this object.
        // http://stackoverflow.com/questions/35919157/using-xmlplexusconfiguration-to-import-more-configuration-for-a-bean-style-maven
        // explains the symptoms.
        configurator = (ComponentConfigurator) helper.getComponent(
            ComponentConfigurator.class);
      } else {
        configurator = new BasicComponentConfigurator();
      }
    } catch (ComponentLookupException ex) {
      throw new EnforcerRuleException(
          "Failed to locate component: " + ex.getLocalizedMessage(), ex);
    }

    MavenProject project;
    ArtifactRepository localRepository;
    List<ArtifactRepository> remoteRepositories;
    try {
      project = (MavenProject) helper.evaluate("${project}");
      localRepository = (ArtifactRepository)
          helper.evaluate("${localRepository}");
      @SuppressWarnings("unchecked")
      List<ArtifactRepository> rr = (List<ArtifactRepository>)
          helper.evaluate("${project.remoteArtifactRepositories}");
      remoteRepositories = rr;
    } catch (ExpressionEvaluationException ex) {
      throw new EnforcerRuleException(
          "Failed to locate component: " + ex.getLocalizedMessage(), ex);
    }

    ArtifactFinder finder = new ArtifactFinder(
        resolver, treeBuilder, localRepository, remoteRepositories, log);

    try {
      finder.findClassRoots(project);
    } catch (DependencyTreeBuilderException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    } catch (ArtifactResolutionException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    } catch (ArtifactNotFoundException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    }

    ImmutableList<ClassRoot> classRoots = finder.getClassRoots();

    // Do the imports.
    // Since an import might load a configuration that adds more imports, we
    // just walk the list destructively.
    while (!imports.isEmpty()) {
      ConfigurationImport imp = imports.removeFirst();
      if (alreadyImported.add(imp.key)) {
        log.debug("Importing " + imp.key);
        imp.configure(
            this, configurator,
            new ConfigurationImport.ClassRoots(classRoots.iterator()),
            log);
      } else {
        log.info("Not importing " + imp.key + " a second time");
      }
    }

    checkAllClasses(project, log, classRoots);
  }

  protected void checkAllClasses(
      MavenProject project, Log log, Iterable<? extends ClassRoot> classRoots)
  throws EnforcerRuleException {
    InheritanceGraph inheritanceGraph;
    try {
      inheritanceGraph = InheritanceGraphExtractor
          .fromClassRoots(classRoots);
    } catch (IOException ex) {
      throw new EnforcerRuleException(
          "Failed to read classes to find inheritance relationships",
          ex);
    }
    ImmutableList<Fence> allFences = ImmutableList.copyOf(fences);

    if (allFences.isEmpty()) {
      throw new EnforcerRuleException(
          "No fences.  Please configure this rule with a policy."
          + "  See https://github.com/mikesamuel/"
          + "fences-maven-enforcer-rule/blob/master/src/site/markdown/usage.md"
          + " for details");
    }

    final Policy p = Policy.fromFences(allFences);
    log.debug(new LazyString() {
      @Override
      protected String makeString() {
        return "Using policy\n" + p.toString();
      }
    });

    Checker checker = new Checker(log, inheritanceGraph, p);
    checker.interpolator.addValueSource(
        new PropertiesBasedValueSource(project.getProperties()));

    for (ClassRoot classRoot : classRoots) {
      Artifact art = classRoot.art;
      log.info("Checking " + art.getId() + " from scope " + art.getScope());
      try {
        checker.visitAll(ImmutableList.of(classRoot));
      } catch (IOException ex) {
        throw new EnforcerRuleException(
            "Failed to check " + Utils.artToString(art), ex);
      }
    }

    int errorCount = checker.getErrorCount();
    if (errorCount != 0) {
      throw new EnforcerRuleException(
          errorCount + " access policy violation"
          + (errorCount == 1 ? "" : "s"));
    } else {
      log.info("No access policy violations");
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
