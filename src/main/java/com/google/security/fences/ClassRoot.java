package com.google.security.fences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.maven.artifact.Artifact;

import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableMap;
import com.google.security.fences.util.Utils;

/**
 * Encapsulates a bundle of classes that might appear as an entry in a class
 * path.
 */
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

  /**
   * Reads the relative path, giving an input stream to the given consumer
   * and returning the result of the consumer.
   * This method is responsible for closing the stream.
   */
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
            return c.consume(this, path, is);
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
          return c.consume(this, path, is);
        } finally {
          is.close();
        }
    }
    throw new AssertionError(kind);
  }

  <T>
  Map<String, T> readEachPathMatching(
      Predicate<String> relativePathFilter,
      IOConsumer<? super InputStream, ? extends T> c)
  throws IOException {
    ImmutableMap.Builder<String, T> b = ImmutableMap.builder();
    switch (kind) {
      case ZIPFILE:
        InputStream in = new FileInputStream(classRoot);
        try {
          ZipInputStream zipIn = new ZipInputStream(in);
          try {
            for (ZipEntry zipEntry;
                 (zipEntry = zipIn.getNextEntry()) != null;) {
              if (!zipEntry.isDirectory()) {
                String entryName = zipEntry.getName();
                if (relativePathFilter.apply(entryName)) {
                  b.put(entryName, c.consume(this, entryName, zipIn));
                }
              }
              zipIn.closeEntry();
            }
          } finally {
            zipIn.close();
          }
        } finally {
          in.close();
        }
        return b.build();

      case BUILD_OUTPUT_DIRECTORY:
        find("", classRoot, relativePathFilter, c, b);
        return b.build();
    }
    throw new AssertionError(kind);
  }

  private <T> void find(
      String relativePath, File directory,
      Predicate<String> relativePathFilter,
      IOConsumer<? super InputStream, ? extends T> c,
      ImmutableMap.Builder<String, T> b)
  throws IOException {
    Preconditions.checkArgument(directory.isDirectory(), directory.getPath());
    File[] contents = directory.listFiles();
    if (contents == null) {
      throw new IOException("Cannot list contents of " + directory);
    } else {
      StringBuilder childRelPathBuilder = new StringBuilder();
      childRelPathBuilder.append(relativePath);
      if (childRelPathBuilder.length() != 0) {
        childRelPathBuilder.append('/');
      }
      int childRelPathPrefixLength = childRelPathBuilder.length();

      for (File child : contents) {
        childRelPathBuilder.setLength(childRelPathPrefixLength);
        String childRelPath = childRelPathBuilder.append(child.getName())
            .toString();
        if (child.isDirectory()) {
          find(childRelPath, child, relativePathFilter, c, b);
        } else if (relativePathFilter.apply(childRelPath)) {
          InputStream in = new FileInputStream(child);
          try {
            T result = c.consume(this, childRelPath, in);
            b.put(childRelPath, result);
          } finally {
            in.close();
          }
        }
      }
    }
  }

  @Override
  public String toString() {
    switch (kind) {
      case ZIPFILE:
        return "zip " + this.classRoot + " from " + art.getId();
      case BUILD_OUTPUT_DIRECTORY:
        return "dir " + this.classRoot + " from " + art.getId();
    }
    throw new AssertionError(kind);
  }

  enum ClassRootKind {
    ZIPFILE,
    BUILD_OUTPUT_DIRECTORY,
    ;
  }

  interface IOConsumer<I, O> {
    O consume(ClassRoot root, String relativePath, I x) throws IOException;
  }
}