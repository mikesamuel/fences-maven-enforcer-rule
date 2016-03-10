package com.google.security.fences;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.plugin.logging.Log;
import org.codehaus.plexus.classworlds.realm.ClassRealm;
import org.codehaus.plexus.component.configurator.ComponentConfigurationException;
import org.codehaus.plexus.component.configurator.ComponentConfigurator;
import org.codehaus.plexus.configuration.PlexusConfiguration;
import org.codehaus.plexus.configuration.xml.XmlPlexusConfiguration;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.codehaus.plexus.util.xml.Xpp3DomBuilder;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import com.google.security.fences.util.Utils;


/**
 * Created from {@code <import>group:artifact:version</import>} to load extra
 * configuration from that artifacts META-INF/fences.xml file.
 */
final class ConfigurationImport {

  final PartialArtifactKey key;

  ConfigurationImport(String s) throws EnforcerRuleException {
    this.key = new PartialArtifactKey(s.trim());
  }

  static final String FENCES_CONFIGURATION_XML_RELATIVE_PATH
      = "META-INF/fences.xml";

  void configure(
      Object configurable, ComponentConfigurator configurator,
      ClassRoots classRoots, Log log)
  throws EnforcerRuleException {
    Optional<ClassRoot> cr = classRoots.lookup(key);
    if (cr.isPresent()) {
      PlexusConfiguration configuration;
      try {
        configuration = loadConfiguration(
            log, cr.get(), FENCES_CONFIGURATION_XML_RELATIVE_PATH);
      } catch (IOException ex) {
        throw new EnforcerRuleException(
            "Failed to load " + FENCES_CONFIGURATION_XML_RELATIVE_PATH
            + " from " + key, ex);
      }

      // TODO: is this right.
      // Newer versions have a MavenProject.getClassRealm() says
      // """
      // Warning: This is an internal utility method that is only public for
      // technical reasons, it is not part of the public API. In particular,
      // this method can be changed or deleted without prior notice and must
      // not be used by plugins.
      // """
      ClassRealm realm = null;

      try {
        configurator.configureComponent(configurable, configuration, realm);
      } catch (ComponentConfigurationException ex) {
        ex.printStackTrace();  // HACK DEBUG
        throw new EnforcerRuleException(
            "Failed to process configuration "
            + FENCES_CONFIGURATION_XML_RELATIVE_PATH + " from " + key,
            ex);
      }
    } else {
      log.error("Cannot import " + key + ", no such artifact depended upon");
    }
  }


  static final class PartialArtifactKey {
    final String groupId;
    final String artifactId;
    final Optional<String> version;

    PartialArtifactKey(String artifact)
    // TODO: more appropriate exception type
    throws EnforcerRuleException {
      Optional<String> versionSoFar = Optional.absent();
      String[] parts = artifact.split(":");
      switch (parts.length) {
        case 3:
          versionSoFar = Optional.of(parts[2]);
          //$FALL-THROUGH$
        case 2:
          groupId = parts[0];
          artifactId = parts[1];
          break;
        default:
          throw new EnforcerRuleException("Bad artifact key: " + artifact);
      }
      this.version = versionSoFar;
    }

    PartialArtifactKey(String gid, String aid, Optional<String> ver) {
      this.groupId = Preconditions.checkNotNull(gid);
      this.artifactId = Preconditions.checkNotNull(aid);
      this.version = Preconditions.checkNotNull(ver);
    }

    PartialArtifactKey(String gid, String aid) {
      this(gid, aid, Optional.<String>absent());
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof PartialArtifactKey)) {
        return false;
      }
      PartialArtifactKey that = (PartialArtifactKey) o;
      return groupId.equals(that.groupId)
          && artifactId.equals(that.artifactId)
          && version.equals(that.version);
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(groupId, artifactId, version);
    }

    @Override
    public String toString() {
      return groupId + ":" + artifactId
          + (version.isPresent() ? ":" + version.get() : "");
    }
  }

  /** Lazy map of artifact keys to artifacts. */
  static final class ClassRoots {
    private final Map<PartialArtifactKey, ClassRoot> map =
        Maps.newLinkedHashMap();
    private final Iterator<ClassRoot> classRoots;
    private final Log log;

    ClassRoots(Iterator<ClassRoot> classRoots, Log log) {
      this.classRoots = classRoots;
      this.log = log;
    }

    Optional<ClassRoot> lookup(PartialArtifactKey k) {
      ClassRoot result = map.get(k);
      if (result == null) {
        while (classRoots.hasNext()) {
          ClassRoot cr = classRoots.next();
          Artifact art = cr.art;
          PartialArtifactKey full = new PartialArtifactKey(
              art.getGroupId(), art.getArtifactId(),
              Optional.of(art.getVersion()));
          PartialArtifactKey partial = new PartialArtifactKey(
              full.groupId, full.artifactId);
          map.putIfAbsent(full, cr);
          map.putIfAbsent(partial, cr);
          if (k.equals(full) || k.equals(partial)) {
            result = cr;
            break;
          }
        }
      }
      return Optional.fromNullable(result);
    }
  }

  static XmlPlexusConfiguration loadConfiguration(
      Log log,
      ClassRoot cr,
      String path)
  throws EnforcerRuleException, IOException {
    log.debug("Loading " + path + " from " + Utils.artToString(cr.art));
    File classRootFile = cr.classRoot;
    if (classRootFile == null) {
      throw new EnforcerRuleException(
          "Cannot import configuration from unresolved artifact "
          + Utils.artToString(cr.art));
    }
    Xpp3Dom dom = cr.readRelativePath(
        path,
        new ClassRoot.IOConsumer<InputStream, Xpp3Dom>() {
          public Xpp3Dom read(InputStream is) throws IOException {
            try {
              return Xpp3DomBuilder.build(is, "UTF-8", true);
            } catch (XmlPullParserException ex) {
              throw new IOException("Malformed XML", ex);
            } finally {
              is.close();
            }
          }
        });
    return new XmlPlexusConfiguration(dom);
  }
}
