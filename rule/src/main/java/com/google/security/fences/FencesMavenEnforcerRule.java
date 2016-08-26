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
import org.w3c.dom.Element;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSink;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;
import com.google.security.fences.RecordingLog.Entry;
import com.google.security.fences.checker.Checker;
import com.google.security.fences.classpath.ArtifactFinder;
import com.google.security.fences.classpath.ClassRoot;
import com.google.security.fences.classpath.ConfigurationImport;
import com.google.security.fences.config.ApiFence;
import com.google.security.fences.config.ClassFence;
import com.google.security.fences.config.Fence;
import com.google.security.fences.config.PackageFence;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.inheritance.InheritanceGraphExtractor;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.Policy;
import com.google.security.fences.reporting.PolicyViolationReporter;
import com.google.security.fences.reporting.Violation;
import com.google.security.fences.util.LazyString;
import com.google.security.fences.util.MisconfigurationException;
import com.google.security.fences.util.RelevantSystemProperties;
import com.google.security.fences.util.Utils;

import java.io.Externalizable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.StringWriter;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * Augments Java access control by verifying that a project and its dependencies
 * don't statically violate a policy.
 */
public final class FencesMavenEnforcerRule implements EnforcerRule {

  private final List<Fence> fences = Lists.newArrayList();
  private final LinkedList<ConfigurationImport> imports = Lists.newLinkedList();
  private final Set<ConfigurationImport.PartialArtifactKey> alreadyImported =
      Sets.newLinkedHashSet();

  private void addFence(Fence f) throws MisconfigurationException {
    f.check();
    fences.add(f);
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setApi(ApiFence x) throws MisconfigurationException {
    addFence(x);
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setPackage(PackageFence x) throws MisconfigurationException {
    addFence(x);
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) throws MisconfigurationException {
    addFence(x);
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setImport(String x) throws MisconfigurationException {
    imports.add(new ConfigurationImport(x));
  }

  /**
   * A setter called by reflection during configuration.  Actually adds
   * an {@code <api>} with an {@code <addendum>} instead of blowing away prior
   * value.
   */
  public void setAddendum(String x) throws MisconfigurationException {
    Fence api = new ApiFence();
    api.setAddendum(x);
    fences.add(api);
  }

  @Override
  public void execute(EnforcerRuleHelper helper) throws EnforcerRuleException {
    final Log log = helper.getLog();

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

      // This seems "the right way" since plexus is supposed to inject
      // dependencies, but when run without -X to turn on debugging,
      // we get a MapOrientedComponentConfigurator which cannot configure
      // this object.
      // http://stackoverflow.com/questions/35919157/using-xmlplexusconfiguration-to-import-more-configuration-for-a-bean-style-maven
      // explains the symptoms.
      //  configurator = (ComponentConfigurator) helper.getComponent(
      //      ComponentConfigurator.class);
      configurator = new BasicComponentConfigurator();
    } catch (ComponentLookupException ex) {
      throw new EnforcerRuleException(
          "Failed to locate component: " + ex.getLocalizedMessage(), ex);
    }

    MavenProject project;
    ArtifactRepository localRepository;
    List<ArtifactRepository> remoteRepositories;
    File buildDirectory;
    try {
      project = (MavenProject) helper.evaluate("${project}");
      localRepository = (ArtifactRepository)
          helper.evaluate("${localRepository}");
      @SuppressWarnings("unchecked")
      List<ArtifactRepository> rr = (List<ArtifactRepository>)
          helper.evaluate("${project.remoteArtifactRepositories}");
      remoteRepositories = rr;
      buildDirectory = new File(
          (String) helper.evaluate("${project.build.directory}"));
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
    } catch (MisconfigurationException ex) {
      throw new EnforcerRuleException("Failed to find artifacts", ex);
    }

    ImmutableList<ClassRoot> classRoots = finder.getClassRoots();

    InheritanceGraph inheritanceGraph;
    try {
      inheritanceGraph = InheritanceGraphExtractor
          .fromClassRoots(classRoots);
    } catch (IOException ex) {
      throw new EnforcerRuleException(
          "Failed to read classes to find inheritance relationships",
          ex);
    }

    try {
      int nAssignedImportOrder = 0;
      int importOrder = 0;
      // Do the imports.
      // Since an import might load a configuration that adds more imports, we
      // just walk the list destructively.
      for (; !imports.isEmpty(); ++importOrder) {
        nAssignedImportOrder = rerootAndAssignImportOrder(
            inheritanceGraph, nAssignedImportOrder, importOrder);
        ConfigurationImport imp = imports.removeFirst();
        if (alreadyImported.add(imp.key)) {
          log.debug("Importing " + imp.key);
          try {
            imp.configure(
                this, configurator,
                new ConfigurationImport.ClassRoots(classRoots.iterator()),
                log);
          } catch (MisconfigurationException ex) {
            throw new EnforcerRuleException("Failed to import " + imp.key, ex);
          }
        } else {
          log.info("Not importing " + imp.key + " a second time");
        }
      }
      rerootAndAssignImportOrder(
          inheritanceGraph, nAssignedImportOrder, importOrder);
    } catch (MisconfigurationException ex) {
      throw new EnforcerRuleException(ex.getMessage(), ex);
    }

    ImmutableList<Fence> allFences = ImmutableList.copyOf(fences);

    if (allFences.isEmpty()) {
      throw new EnforcerRuleException(
          "No fences.  Please configure this rule with a policy."
          + "  See https://github.com/mikesamuel/"
          + "fences-maven-enforcer-rule/blob/master/src/site/markdown/usage.md"
          + " for details");
    }

    // Merge all the fences into one master.
    final ApiFence mergedFence = new ApiFence();
    for (Fence f : allFences) {
      mergedFence.mergeDeep(f);
    }

    // Log the effective configuration
    boolean showConfig = RelevantSystemProperties.shouldShowEffectiveConfig();
    if (showConfig || log.isDebugEnabled()) {
      try {
        Element config = mergedFence.buildEffectiveConfiguration();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty(
            "{http://xml.apache.org/xslt}indent-amount", "2");

        StringWriter xmlOut = new StringWriter();
        xmlOut.write("Effective Fences Rule Configuration:\n");
        transformer.transform(
            new DOMSource(config),
            new StreamResult(xmlOut));
        String xml = xmlOut.toString();
        if (showConfig) {
          log.info(xml);
        } else {
          log.debug(xml);
        }
      } catch (ParserConfigurationException ex) {
        log.error(ex);
      } catch (TransformerException ex) {
        log.error(ex);
      }
    }

    File artifactFindingsFile = new File(buildDirectory, ".fences-cache.ser");
    // TODO: store in the file, a hash of the effective policy so we can do
    // a master check that the policy hasn't changed.
    ArtifactFindingsHash afHash = ArtifactFindingsHash.readFrom(
        Files.asByteSource(artifactFindingsFile));

    checkAllClasses(
        project, log, inheritanceGraph, mergedFence, classRoots, afHash);

    ignore(artifactFindingsFile.getParentFile().mkdirs());
    afHash.writeTo(Files.asByteSink(artifactFindingsFile));
  }

  private int rerootAndAssignImportOrder(
      InheritanceGraph inheritanceGraph, int start, int importOrder)
  throws MisconfigurationException {
    int end = fences.size();
    for (int i = start; i < end; ++i) {
      Fence f = fences.get(i);
      f = f.splitDottedNames(ApiElement.DEFAULT_PACKAGE, inheritanceGraph)
          .promoteToApi();
      f.assignImportOrder(importOrder);
      fences.set(i, f);
    }
    return end;
  }

  protected static void checkAllClasses(
      MavenProject project, Log backingLog, InheritanceGraph inheritanceGraph,
      ApiFence mergedFence, Iterable<? extends ClassRoot> classRoots,
      ArtifactFindingsHash afHash)
  throws EnforcerRuleException {
    final Policy p = Policy.fromFence(mergedFence);

    RecordingLog log = new RecordingLog(backingLog);

    log.debug(new LazyString() {
      @Override
      protected String makeString() {
        return "Using policy\n" + p.toString();
      }
    });

    Checker checker = new Checker(log, inheritanceGraph, p);

    for (ClassRoot classRoot : classRoots) {
      HashCode hashcode = null;

      Artifact art = classRoot.art;

      // If we have cached findings for this artifact, replay them instead
      // of scanning the whole thing again.
      String artId = art.getId();
      switch (classRoot.kind) {
        case ZIPFILE:
          if (classRoot.classRoot.exists()) {
            try {
              hashcode = ArtifactFindingsHash.HASH_FUNCTION.hashBytes(
                  Files.toByteArray(classRoot.classRoot));
            } catch (IOException ex) {
              log.warn("Trouble hashing zipfile", ex);
            }
          }
          break;
        default:
          break;
      }

      if (hashcode != null) {
        Optional<ImmutableList<RecordingLog.Entry>> hashedResults =
            afHash.get(artId, hashcode);
        if (hashedResults.isPresent()) {
          backingLog.debug("Replaying cached results for " + artId);
          for (RecordingLog.Entry e : hashedResults.get()) {
            e.apply(backingLog);
          }
          continue;
        }
      }

      log.info("Checking " + artId + " from scope " + art.getScope());
      log.reset();
      try {
        checker.visitAll(ImmutableList.of(classRoot));
      } catch (IOException ex) {
        throw new EnforcerRuleException(
            "Failed to check " + Utils.artToString(art), ex);
      }
      if (hashcode != null) {
        afHash.store(artId, hashcode, log.getEntriesSinceLastReset());
      }
    }

    ImmutableList<Violation> violations = checker.getViolations();
    PolicyViolationReporter reporter = new PolicyViolationReporter(log);
    reporter.interpolator.addValueSource(
        new PropertiesBasedValueSource(project.getProperties()));
    int errorCount = reporter.report(violations);
    if (errorCount != 0) {
      String message = errorCount + " access policy violation"
          + (errorCount == 1 ? "" : "s");
      if (RelevantSystemProperties.inExperimentalMode()) {
        log.info(message + " ignored in experimental mode");
      } else {
        throw new EnforcerRuleException(message);
      }
    }
  }

  @Override
  public String getCacheId() {
    return null;
  }

  @Override
  public boolean isCacheable() {
    return false;
  }

  @Override
  public boolean isResultValid(EnforcerRule arg0) {
    return false;
  }



  static final class ArtifactFindingsHash implements Serializable {

    private static final long serialVersionUID = 3323962310197443927L;

    static final HashFunction HASH_FUNCTION = Hashing.sha512();

    private final Map<String, HashedResult> hashedResults =
        Maps.newLinkedHashMap();

    Optional<ImmutableList<RecordingLog.Entry>> get(
        String artId, HashCode hashcode) {
      HashedResult r = hashedResults.get(artId);
      if (r != null && r.getHashcode().equals(hashcode)) {
        return Optional.of(r.getEntries());
      }
      return Optional.absent();
    }

    void store(String artId, HashCode hashcode,
               Iterable<? extends RecordingLog.Entry> entries) {
      hashedResults.put(
          artId,
          new HashedResult(hashcode, ImmutableList.copyOf(entries)));
    }

    static ArtifactFindingsHash readFrom(ByteSource byteSource)
    throws EnforcerRuleException {
      Object read;
      try {
        InputStream in = byteSource.openStream();
        try {
          ObjectInputStream objIn = new ObjectInputStream(in);
          try {
            read = objIn.readObject();
            if (in.read() >= 0) {
              throw new IOException("Extraneous content in " + byteSource);
            }
          } finally {
            objIn.close();
          }
        } finally {
          in.close();
        }
      } catch (ClassNotFoundException ex) {
        throw new EnforcerRuleException(
            "Failed to read artifact findings cache", ex);
      } catch (@SuppressWarnings("unused") FileNotFoundException ex) {
        // If there's no hash, just create a blank one.
        read = new ArtifactFindingsHash();
      } catch (IOException ex) {
        throw new EnforcerRuleException(
            "Failed to read artifact findings cache", ex);
      }
      return Preconditions.checkNotNull((ArtifactFindingsHash) read);
    }

    void writeTo(ByteSink byteSink) throws EnforcerRuleException {
      try {
        OutputStream out = byteSink.openStream();
        try {
          ObjectOutputStream objOut = new ObjectOutputStream(out);
          try {
            objOut.writeObject(this);
          } finally {
            objOut.close();
          }
        } finally {
          out.close();
        }
      } catch (IOException ex) {
        throw new EnforcerRuleException(
            "Failed to write artifact findings cache", ex);
      }
    }
  }

  static final class HashedResult implements Externalizable {
    private HashCode hashcode;
    private ImmutableList<RecordingLog.Entry> entries;

    public HashedResult() {
      // for externalizable
    }

    public ImmutableList<Entry> getEntries() {
      return entries;
    }

    public HashCode getHashcode() {
      return hashcode;
    }

    HashedResult(HashCode hashcode, ImmutableList<RecordingLog.Entry> entries) {
      this.hashcode = hashcode;
      this.entries = entries;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
      out.writeObject(hashcode.asBytes());
      out.writeObject(entries);
    }

    @Override
    public void readExternal(ObjectInput in)
    throws IOException, ClassNotFoundException {
      hashcode = HashCode.fromBytes((byte[]) in.readObject());
      ImmutableList.Builder<RecordingLog.Entry> b = ImmutableList.builder();
      for (Object entry : (Iterable<?>)  in.readObject()) {
        b.add((RecordingLog.Entry) entry);
      }
      entries = b.build();
    }
  }

  private static void ignore(@SuppressWarnings("unused") boolean b) {
    // Deal with findbugs complaint.
  }
}
