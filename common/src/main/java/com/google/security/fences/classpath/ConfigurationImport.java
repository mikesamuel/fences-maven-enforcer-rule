package com.google.security.fences.classpath;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;

import org.apache.maven.artifact.Artifact;
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
import com.google.security.fences.util.MisconfigurationException;
import com.google.security.fences.util.Utils;


/**
 * Created from {@code <import>group:artifact:version</import>} to load extra
 * configuration from that artifacts META-INF/fences.xml file.
 */
public final class ConfigurationImport {
  /** Specifies the artifact being imported. */
  public final PartialArtifactKey key;

  /**
   * @param s Specifies the group and artifact at least of the artifact whose
   *     fences.xml is being imported.
   */
  public ConfigurationImport(String s) throws MisconfigurationException {
    this.key = new PartialArtifactKey(s.trim());
  }

  /** Path of the importable configuration file within an artifact's jar. */
  public static final String FENCES_CONFIGURATION_XML_RELATIVE_PATH
      = "META-INF/fences.xml";

  /**
   * Looks for an {@code <configuration>} element in a META-INF/fences.xml file
   * and applies it to configurable as if that configuration were part of the
   * same element appearing directly in a POM.
   */
  @SuppressWarnings("resource")  // Realm not owned by this method
  public void configure(
      Object configurable, ComponentConfigurator configurator,
      ClassRoots classRoots, Log log)
  throws MisconfigurationException {
    Optional<ClassRoot> cr = classRoots.lookup(key);
    if (cr.isPresent()) {
      PlexusConfiguration configuration;
      try {
        configuration = loadConfiguration(
            log, cr.get(), FENCES_CONFIGURATION_XML_RELATIVE_PATH);
      } catch (IOException ex) {
        throw new MisconfigurationException(
            "Failed to load " + FENCES_CONFIGURATION_XML_RELATIVE_PATH
            + " from " + key, ex);
      }

      // TODO: Is this right?
      // Newer versions have a MavenProject.getClassRealm() says
      // """
      // Warning: This is an internal utility method that is only public for
      // technical reasons, it is not part of the public API. In particular,
      // this method can be changed or deleted without prior notice and must
      // not be used by plugins.
      // """
      // so trying to get it directly seems dodgy.
      ClassRealm realm = null;
      ClassLoader cl = configurable.getClass().getClassLoader();
      if (cl instanceof ClassRealm) {
        realm = (ClassRealm) cl;
      }

      try {
        configurator.configureComponent(configurable, configuration, realm);
      } catch (ComponentConfigurationException ex) {
        throw new MisconfigurationException(
            "Failed to process configuration "
            + FENCES_CONFIGURATION_XML_RELATIVE_PATH + " from " + key,
            ex);
      }
    } else {
      log.error("Cannot import " + key + ", no such artifact depended upon");
    }
  }


  /**
   * Specifies an artifact from among the set of artifacts on the classpath
   * after maven has eliminated version conflicts.
   */
  public static final class PartialArtifactKey {
    /** A group name. */
    public final String groupId;
    /** An artifact name. */
    public final String artifactId;
    /** An optional artifact version. */
    public final Optional<String> version;

    /** @param artifact of the form g:a or g:a:v. */
    public PartialArtifactKey(String artifact)
    throws MisconfigurationException {
      String[] parts = artifact.split(":");
      switch (parts.length) {
        case 3:
          groupId = parts[0];
          artifactId = parts[1];
          version = Optional.of(parts[2]);
          break;
        case 2:
          groupId = parts[0];
          artifactId = parts[1];
          version = Optional.absent();
          break;
        default:
          throw new MisconfigurationException("Bad artifact key: " + artifact);
      }
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
  public static final class ClassRoots {
    private final Map<PartialArtifactKey, ClassRoot> map =
        Maps.newLinkedHashMap();
    private final Iterator<ClassRoot> classRoots;

    /**
     * @param classRoots the class roots to resolve partial keys against.
     */
    public ClassRoots(Iterator<ClassRoot> classRoots) {
      this.classRoots = classRoots;
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
          putIfAbsent(map, full, cr);
          putIfAbsent(map, partial, cr);
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
  throws MisconfigurationException, IOException {
    log.debug("Loading " + path + " from " + Utils.artToString(cr.art));
    File classRootFile = cr.classRoot;
    if (classRootFile == null) {
      throw new MisconfigurationException(
          "Cannot import configuration from unresolved artifact "
          + Utils.artToString(cr.art));
    }
    Xpp3Dom dom = cr.readRelativePath(
        path,
        new ClassRoot.IOConsumer<InputStream, Xpp3Dom>() {
          @Override
          public Xpp3Dom consume(
              ClassRoot root, String relPath, InputStream is)
          throws IOException {
            try {
              return Xpp3DomBuilder.build(is, "UTF-8", true);
            } catch (XmlPullParserException ex) {
              throw new IOException("Malformed XML " + relPath + " in " + root.art.getId(), ex);
            } finally {
              is.close();
            }
          }
        });
    return new XmlPlexusConfiguration(dom);
  }


  /** Map.putIfAbsent is @since Java 8. */
  static <K, V> void putIfAbsent(Map<K, V> m, K k, V v) {
    if (!m.containsKey(k)) {
      m.put(k, v);
    }
  }
}
