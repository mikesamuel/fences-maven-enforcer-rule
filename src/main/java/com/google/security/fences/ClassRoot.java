package com.google.security.fences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.maven.artifact.Artifact;

import com.google.security.fences.util.Utils;

final class ClassRoot {
  final Artifact art;
  /** Either a JAR (ZIP) file or a class root directory. */
  final File classRoot;
  final ClassRoot.ClassRootKind kind;

  ClassRoot(Artifact art, File classRoot, ClassRoot.ClassRootKind kind) {
    this.art = art;
    this.classRoot = classRoot;
    this.kind = kind;
  }

  <T>
  T readRelativePath(
      String path,
      IOConsumer<? super InputStream, ? extends T> c)
  throws IOException {
    switch (kind) {
      case ZIPFILE:
        ZipFile zf = new ZipFile(classRoot);
        try {
          ZipEntry e = zf.getEntry(path);
          if (e == null) {
            throw new FileNotFoundException(
                "Could not find " + path + " in " + Utils.artToString(art));
          }
          InputStream is = zf.getInputStream(e);
          try {
            return c.read(is);
          } finally {
            is.close();
          }
        } finally {
          zf.close();
        }

      case BUILD_OUTPUT_DIRECTORY:
        File f = classRoot;
        String[] pathElements = path.split("/");
        for (String pathElement : pathElements) {
          if ("".equals(pathElement)) { continue; }
          f = new File(f, pathElement);
        }
        FileInputStream is = new FileInputStream(f);
        try {
          return c.read(is);
        } finally {
          is.close();
        }
    }
    throw new AssertionError(kind);
  }

  enum ClassRootKind {
    ZIPFILE,
    BUILD_OUTPUT_DIRECTORY,
    ;
  }

  interface IOConsumer<I, O> {
    O read(I x) throws IOException;
  }
}