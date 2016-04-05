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

import com.google.common.base.Charsets;
import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
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
   * access flag bitsets.
   */
  private static final String ACCESS_DB_NAME = "access";
  /**
   * Name of a database that maps internal names to
   * internal names of super-types.
   */
  private static final String SUPERTYPE_DB_NAME = "supertype";
  /**
   * Name of a database that maps internal names to
   * comma separated interface names.
   */
  private static final String INTERFACE_DB_NAME = "interfaces";
  /**
   * Names of a database that maps internal class names to comma separated
   * lists of the names and signatures of methods declared therein.
   */
  private static final String METHOD_DB_NAME = "methods";
  /**
   * Names of a database that maps internal class names to comma separated
   * lists of the names of fields declared therein.
   */
  private static final String FIELD_DB_NAME = "fields";

  private static final class LazyLoader {
    static final LazyLoader INSTANCE = new LazyLoader();
    private final ConcurrentHashMap<String, ClassNode> classNodes
        = new ConcurrentHashMap<String, ClassNode>();
    private final Environment env;
    private final Database accessDb;
    private final Database supertypeDb;
    private final Database interfaceDb;
    private final Database methodDb;
    private final Database fieldDb;

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
      this.accessDb = env.openDatabase(null, ACCESS_DB_NAME, dbConfig);
      this.supertypeDb = env.openDatabase(null, SUPERTYPE_DB_NAME, dbConfig);
      this.interfaceDb = env.openDatabase(null, INTERFACE_DB_NAME, dbConfig);
      this.methodDb = env.openDatabase(null, METHOD_DB_NAME, dbConfig);
      this.fieldDb = env.openDatabase(null, FIELD_DB_NAME, dbConfig);
    }

    private Environment init() throws IOException {
      // Berkeley DB requires a home directory.
      File home = File.createTempFile(
          "system-inheritance-graph-", "-home");
      if (home.exists() && !home.delete()) {
        throw new IOException("Could not delete temp file " + home);
      }
      if (!home.mkdirs()) {
        throw new IOException("Could not make temp dir " + home);
      }

      // Copy databases to the home directory so we can point BDB at them.
      String[] dbBaseNames = {
          "00000000.jdb",
          "00000001.jdb",
          "00000002.jdb",
      };
      for (String dbBaseName : dbBaseNames) {
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
      DatabaseEntry nameData = utf8(name);

      DatabaseEntry interfaces = new DatabaseEntry();
      OperationStatus ifaceStatus = interfaceDb.get(
          null, nameData, interfaces, LockMode.DEFAULT);
      if (!OperationStatus.SUCCESS.equals(ifaceStatus)) {
        return null;
      }

      DatabaseEntry accessEntry = new DatabaseEntry();
      int access = 0;
      OperationStatus accessStates = accessDb.get(
          null, nameData, accessEntry, LockMode.DEFAULT);
      if (OperationStatus.SUCCESS.equals(accessStates)) {
        access = int32(accessEntry);
      }

      DatabaseEntry supertype = new DatabaseEntry();
      OperationStatus stypeStatus = supertypeDb.get(
          null, nameData, supertype, LockMode.DEFAULT);
      Optional<String> supertypeName = Optional.absent();
      if (OperationStatus.SUCCESS.equals(stypeStatus)) {
        supertypeName = Optional.of(utf8(supertype));
      }

      String interfaceNamesCsv = utf8(interfaces);
      List<String> interfaceNames = ImmutableList.of();
      if (!interfaceNamesCsv.isEmpty()) {
        interfaceNames = Arrays.asList(interfaceNamesCsv.split(","));
      }

      DatabaseEntry methodSigs = new DatabaseEntry();
      OperationStatus methodStatus = methodDb.get(
          null, nameData, methodSigs, LockMode.DEFAULT);
      List<MethodDetails> methods = ImmutableList.of();
      if (OperationStatus.SUCCESS.equals(methodStatus)) {
        String methodCsv = utf8(methodSigs);
        if (!methodCsv.isEmpty()) {
          methods = Lists.newArrayList();
          for (String compactString : methodCsv.split(",")) {
            methods.add(MethodDetails.fromCompactString(compactString));
          }
        }
      }

      DatabaseEntry fieldSigs = new DatabaseEntry();
      OperationStatus fieldStatus = fieldDb.get(
          null, nameData, fieldSigs, LockMode.DEFAULT);
      List<FieldDetails> fields = ImmutableList.of();
      if (OperationStatus.SUCCESS.equals(fieldStatus)) {
        String fieldCsv = utf8(fieldSigs);
        if (!fieldCsv.isEmpty()) {
          fields = Lists.newArrayList();
          for (String compactString : fieldCsv.split(",")) {
            fields.add(FieldDetails.fromCompactString(compactString));
          }
        }
      }

      ClassNode node = new ClassNode(
          name, access, supertypeName, interfaceNames, methods, fields);
      inMap = this.classNodes.putIfAbsent(name, node);
      return inMap != null ? inMap : node;
    }
  }


  static String utf8(DatabaseEntry e) {
    if (e.getSize() == 0) { return ""; }
    return Charsets.UTF_8.decode(ByteBuffer.wrap(e.getData())).toString();
  }

  static DatabaseEntry utf8(String s) {
    ByteBuffer bb = Charsets.UTF_8.encode(s);
    byte[] bytes = new byte[bb.remaining()];
    bb.get(bytes);
    return new DatabaseEntry(bytes);
  }

  static int int32(DatabaseEntry e) {
    int x = 0;
    byte[] data = e.getData();
    for (int i = 0, n = data.length; i < n; ++i) {
      x = (x << 8) | (data[i] & 0xff);
    }
    return x;
  }

  static DatabaseEntry int32(int n) {
    int nBytes =
        n < 0x10000
        ? n < 0x100 ? (n == 0 ? 0 : 1) : 2
        : n < 0x1000000 ? 3 : 4;
    byte[] bytes = new byte[nBytes];
    int x = n;
    for (int i = nBytes; --i >= 0; x = x >>> 8) {
      bytes[i] = (byte) (x & 0xFF);
    }
    DatabaseEntry e = new DatabaseEntry(bytes);
    if (int32(e) != n) {
      throw new AssertionError(
          "n=" + n + ", nBytes=" + nBytes
          + ", bytes=" + Arrays.toString(bytes));
    }
    return e;
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
                ClassNodeFromClassFileVisitor visitor =
                    new ClassNodeFromClassFileVisitor(graphBuilder);
                visitor.setIncludePrivates(false);
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
      Database accessDb = env.openDatabase(txn, ACCESS_DB_NAME, dbConfig);
      Database supertypeDb = env.openDatabase(txn, SUPERTYPE_DB_NAME, dbConfig);
      Database interfaceDb = env.openDatabase(txn, INTERFACE_DB_NAME, dbConfig);
      Database methodDb = env.openDatabase(txn, METHOD_DB_NAME, dbConfig);
      Database fieldDb = env.openDatabase(txn, FIELD_DB_NAME, dbConfig);

      for (ClassNode node : graph.allDeclaredNodes()) {
        String name = node.name;
        int access = node.access;
        DatabaseEntry nameData = utf8(name);
        if (access != 0) {
          accessDb.put(txn, nameData, int32(access));
        }
        if (node.superType.isPresent()) {
          supertypeDb.put(txn, nameData, utf8(node.superType.get()));
        }
        interfaceDb.put(
            txn, nameData, utf8(Joiner.on(",").join(node.interfaces)));
        if (!node.fields.isEmpty()) {
          StringBuilder sb = new StringBuilder();
          for (FieldDetails f : node.fields) {
            if (sb.length() != 0) { sb.append(','); }
            sb.append(f.toCompactString());
          }
          fieldDb.put(txn, nameData, utf8(sb.toString()));
        }
        if (!node.methods.isEmpty()) {
          StringBuilder sb = new StringBuilder();
          for (MethodDetails m : node.methods) {
            if (sb.length() != 0) { sb.append(','); }
            sb.append(m.toCompactString());
          }
          methodDb.put(txn, nameData, utf8(sb.toString()));
        }
      }

      fieldDb.close();
      methodDb.close();
      interfaceDb.close();
      supertypeDb.close();
      accessDb.close();
      env.close();
    }
  }
}
