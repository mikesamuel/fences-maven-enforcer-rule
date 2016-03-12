package com.google.security.fences.inheritance;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.annotation.Nonnull;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Charsets;
import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.io.ByteStreams;
import com.sleepycat.je.Database;
import com.sleepycat.je.DatabaseConfig;
import com.sleepycat.je.DatabaseEntry;
import com.sleepycat.je.Environment;
import com.sleepycat.je.EnvironmentConfig;
import com.sleepycat.je.LockMode;
import com.sleepycat.je.OperationStatus;
import com.sleepycat.je.Transaction;

/**
 * Maps the names of system classes to ClassNodes.
 */
public class SystemInheritanceGraph {
  /**
   * Maps class names to nodes by lazily loading them from a read-only
   * DB extracted from the Java system libraries.
   */
  public static final Function<String, ClassNode> LAZY_LOADER
  = new Function<String, ClassNode>() {
    @Nonnull
    public ClassNode apply(@Nonnull String name) {
      if (name == null) {
        throw new NullPointerException();
      }
      // Java's late binding delays initializing the berkeley db until
      // this is called.
      return LazyLoader.INSTANCE.get(name);
    }
  };

  /**
   * Name of a database that maps internal names to
   * internal names of super-types.
   */
  private static final String SUPERTYPE_DB_NAME = "supertype";
  /**
   * Name of a database that maps internal names to
   * comma separated interface names.
   */
  private static final String INTERFACE_DB_NAME = "interface";

  private static final class LazyLoader {
    static final LazyLoader INSTANCE = new LazyLoader();
    private final ConcurrentHashMap<String, ClassNode> classNodes
        = new ConcurrentHashMap<String, ClassNode>();
    private final Environment env;
    private final Database supertypeDb;
    private final Database interfaceDb;

    private LazyLoader() {
      try {
        env = init();
      } catch (IOException ex) {
        ex.printStackTrace();
        AssertionError err = new AssertionError(
            "Cannot unpack system class inheritance graph to a temp file");
        err.initCause(ex);
        throw err;
      }
      DatabaseConfig dbConfig = new DatabaseConfig();
      dbConfig.setAllowCreate(false);
      dbConfig.setReadOnly(true);
      this.supertypeDb = env.openDatabase(null, SUPERTYPE_DB_NAME, dbConfig);
      this.interfaceDb = env.openDatabase(null, INTERFACE_DB_NAME, dbConfig);
    }

    private Environment init() throws IOException {
      // Berkeley DB requires a home directory.
      File home = File.createTempFile(
          "system-inheritance-graph-", "-home");
      home.delete();
      home.mkdirs();

      // Copy databases to the home directory so we can point BDB at them.
      String dbBaseName = "00000000.jdb";
      InputStream in = getClass().getResourceAsStream(
          "system-inheritance-graph/" + dbBaseName);
      try {
        OutputStream out = new FileOutputStream(new File(home, dbBaseName));
        try {
          ByteStreams.copy(in, out);
        } finally {
          out.close();
        }
      } finally {
        in.close();
      }

      EnvironmentConfig config = new EnvironmentConfig();
      config.setAllowCreate(false);
      config.setReadOnly(true);
      return new Environment(home, config);
    }

    ClassNode get(String name) {
      ClassNode inMap = classNodes.get(name);
      if (inMap != null) {
        return inMap;
      }
      DatabaseEntry interfaces = new DatabaseEntry();
      OperationStatus ifaceStatus = interfaceDb.get(
          null, utf8(name), interfaces, LockMode.DEFAULT);
      if (!OperationStatus.SUCCESS.equals(ifaceStatus)) {
        return null;
      }
      DatabaseEntry supertype = new DatabaseEntry();

      OperationStatus stypeStatus = supertypeDb.get(
          null, utf8(name), supertype, LockMode.DEFAULT);

      Optional<String> supertypeName = Optional.absent();
      if (OperationStatus.SUCCESS.equals(stypeStatus)) {
        supertypeName = Optional.of(utf8(supertype));
      }

      String interfaceNamesCsv = utf8(interfaces);
      List<String> interfaceNames = ImmutableList.of();
      if (!interfaceNamesCsv.isEmpty()) {
        interfaceNames = Arrays.asList(interfaceNamesCsv.split(","));

      }
      ClassNode node = new ClassNode(name, supertypeName, interfaceNames);
      inMap = this.classNodes.putIfAbsent(name, node);
      return inMap != null ? inMap : node;
    }
  }


  static String utf8(DatabaseEntry e) {
    return Charsets.UTF_8.decode(ByteBuffer.wrap(e.getData())).toString();
  }

  static DatabaseEntry utf8(String s) {
    ByteBuffer bb = Charsets.UTF_8.encode(s);
    byte[] bytes = new byte[bb.remaining()];
    bb.get(bytes);
    return new DatabaseEntry(bytes);
  }


  /* I generated the DB file in src/main/resources using the command line
     below run from the project root.

    mvn compile
    rm -rf /tmp/bdb
    mkdir /tmp/bdb
    java -cp target/classes:$HOME/.m2/repository/com/google/guava/guava/19.0/guava-19.0.jar:$HOME/.m2/repository/org/ow2/asm/asm/5.0.4/asm-5.0.4.jar:$HOME/.m2/repository/com/sleepycat/je/5.0.73/je-5.0.73.jar com/google/security/fences/inheritance/SystemInheritanceGraph /tmp/bdb $JAVA_HOME/jre/lib/rt.jar
    cp /tmp/bdb/00*.jdb src/main/resources/com/google/security/fences/inheritance/system-inheritance-graph/
  */


  /**
   * Used to build the Berkeley DB resource file that holds the inheritance
   * relationships for the system libraries.
   */
  public static void main(String... argv) throws IOException {
    boolean argsOk = argv.length > 1;

    File bdbHome = null;
    if (argsOk) {
      bdbHome = new File(argv[0]);
      if (!bdbHome.isDirectory()) {
        System.err.println("Expected directory for BDB files, not " + bdbHome);
        argsOk = false;
      }
    }

    List<String> jars = null;
    if (argsOk) {
      jars = Arrays.asList(argv);
      jars = jars.subList(1, jars.size());

      if (!Iterables.all(
              jars,
              new Predicate<String>() {
                public boolean apply(@Nonnull String arg) {
                  if (arg == null) { throw new NullPointerException(); }
                  return arg.endsWith(".jar") && new File(arg).isFile();
                }
              })) {
        System.err.println("Not all are jars : " + jars);
        argsOk = false;
      }
    }
    if (!argsOk) {
      System.err.println(
          "Usage: " + SystemInheritanceGraph.class.getName()
          + " path/to/bdb-home"
          + " path/to/rt.jar path/to/other-system.jar ...");
      return;
    }

    final InheritanceGraph.Builder graphBuilder = InheritanceGraph.builder(
        new Function<String, ClassNode>() {
          public ClassNode apply(String name) {
            return null;
          }
        });
    for (String arg : Preconditions.checkNotNull(jars)) {
      File jarFile = new File(arg);
      if (!jarFile.isFile()) {
        System.err.println("Not a valid jar file : " + jarFile);
        return;
      }
      InputStream in = new FileInputStream(jarFile);
      try {
        ZipInputStream zipIn = new ZipInputStream(in);
        try {
          for (ZipEntry zipEntry;
               (zipEntry = zipIn.getNextEntry()) != null;) {
            if (!zipEntry.isDirectory()) {
              String entryName = zipEntry.getName();
              if (entryName.endsWith(".class")) {
                ClassReader reader = new ClassReader(zipIn);
                ClassVisitor visitor = new ClassVisitor(Opcodes.ASM5) {
                  @Override
                  public void visit(
                      int version, int access, String name, String signature,
                      String superName, String[] interfaces) {
                    System.err.println(
                        "Declaring " + name + " extends " + superName
                        + " implements " + Arrays.toString(interfaces)
                        + " signature " + signature);
                    graphBuilder.declare(
                        name, Optional.fromNullable(superName),
                        Arrays.asList(interfaces));
                  }
                };
                reader.accept(visitor, 0 /* flags */);
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
      InheritanceGraph graph = graphBuilder.build();

      EnvironmentConfig envConfig = new EnvironmentConfig();
      envConfig.setAllowCreate(true);
      Environment env = new Environment(bdbHome, envConfig);
      Transaction txn = null;

      DatabaseConfig dbConfig = new DatabaseConfig();
      dbConfig.setAllowCreate(false);
      dbConfig.setAllowCreateVoid(true);
      dbConfig.setReadOnly(false);
      Database supertypeDb = env.openDatabase(txn, SUPERTYPE_DB_NAME, dbConfig);
      Database interfaceDb = env.openDatabase(txn, INTERFACE_DB_NAME, dbConfig);

      for (ClassNode node : graph.allDeclaredNodes()) {
        String name = node.name;
        if (node.superType.isPresent()) {
          supertypeDb.put(txn, utf8(name), utf8(node.superType.get()));
        }
        interfaceDb.put(
            txn, utf8(name), utf8(Joiner.on(",").join(node.interfaces)));
      }

      interfaceDb.close();
      supertypeDb.close();
      env.close();
    }
  }
}
