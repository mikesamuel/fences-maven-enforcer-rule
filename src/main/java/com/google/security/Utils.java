package com.google.security;

import org.apache.maven.artifact.Artifact;

final class Utils {
  static String artToString(Artifact art) {
    // TODO: Replace once we update to a version of ArtifactUtils that has
    // key(Artifact)?
    return art.getGroupId() + ":" + art.getArtifactId()
        + ":" + art.getBaseVersion();
  }
}
