package com.google.security.fences.policy;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.CheckReturnValue;

import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.security.fences.inheritance.FieldDetails;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.inheritance.MethodDetails;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class PolicyApplicationOrderTest extends TestCase {

  @SuppressWarnings("synthetic-access")
  private static class TestBuilder {
    private List<ApiElement> wanted = Lists.newArrayList();
    private final String descriptor;
    private final ApiElement useElement;
    private final InheritanceGraph.Builder inheritanceGraphBuilder =
        InheritanceGraph.builder();
    private final Log log = new SystemStreamLog();

    TestBuilder(String useStr) {
      Matcher m = API_ELEMENT_RE.matcher(useStr);
      assertTrue(m.find());
      descriptor = m.group(4);
      useElement = el(useStr);
    }

    @CheckReturnValue
    TestBuilder expect(String... expected) {
      for (String elStr : expected) {
        wanted.add(el(elStr));
      }
      return this;
    }

    @CheckReturnValue
    TestBuilder declare(
        String name, int access, Optional<String> superName,
        Iterable<? extends String> interfaceNames,
        Iterable<? extends MethodDetails> methods,
        Iterable<? extends FieldDetails> fields) {
      inheritanceGraphBuilder.declare(
          name, access, superName, interfaceNames, methods, fields);
      return this;
    }

    void test() {
      InheritanceGraph graph = inheritanceGraphBuilder.build();
      ImmutableList<ApiElement> got = ImmutableList.copyOf(
          new PolicyApplicationOrder(useElement, descriptor, graph, log));
      assertEquals(  // Produces a better diff.
          internalFormOnePerLine(wanted),
          internalFormOnePerLine(got));
      assertEquals(wanted, got);  // What we actually want to check.
    }
  }

  private static final Pattern API_ELEMENT_RE = Pattern.compile(
      "^(?:(.*?)/)?([^#/()]+)?(?:#([^#/()]*))?(\\([^#()]*\\)[^#/()]?)?$"
      );

  /**
   * pkg1/pkg2/Class1$Class2#memberName(descriptorArguments)descriptorReturnType
   */
  private static ApiElement el(String s) {
    ApiElement el = ApiElement.DEFAULT_PACKAGE;
    Matcher m = API_ELEMENT_RE.matcher(s);
    if (!m.find()) { throw new IllegalArgumentException(s); }
    String packageGroup = m.group(1);
    String classGroup = m.group(2);
    String memberName = m.group(3);
    String descriptor = m.group(4);
    if (packageGroup != null) {
      for (String packageName
           : packageGroup.replaceFirst("/$", "").split("/")) {
        el = el.child(packageName, ApiElementType.PACKAGE);
      }
    }
    if (classGroup != null) {
      for (String className : classGroup.split("[$]")) {
        el = el.child(className, ApiElementType.CLASS);
      }
    }
    if (memberName != null) {
      ApiElementType type;
      if (ApiElement.CONSTRUCTOR_SPECIAL_METHOD_NAME.equals(memberName)) {
        type = ApiElementType.CONSTRUCTOR;
      } else if (descriptor != null) {
        type = ApiElementType.METHOD;
      } else {
        type = ApiElementType.FIELD;
      }
      el = el.child(memberName, type);
    }
    return el;
  }

  private static String internalFormOnePerLine(
      Iterable<? extends ApiElement> ls) {
    StringBuilder sb = new StringBuilder();
    for (ApiElement el : ls) {
      if (sb.length() != 0) { sb.append('\n'); }
      sb.append(el.toInternalName());
    }
    return sb.toString();
  }

  public static void testSimpleMethod() {
    new TestBuilder("com/example/Foo#bar()V")
        .declare(
            "com/example/Foo",
            Opcodes.ACC_PUBLIC,
            Optional.of("java/lang/Object"),
            ImmutableList.of("java/lang/Comparable"),
            ImmutableList.of(
                new MethodDetails(
                    "compareTo",  "compareTo(Ljava/lang/Object;)I",
                    Opcodes.ACC_PUBLIC),
                new MethodDetails(
                    "bar", "()V",
                    Opcodes.ACC_PUBLIC)),
            ImmutableList.of(
                new FieldDetails("x", Opcodes.ACC_PRIVATE)))
        .expect(
            // Exact
            "com/example/Foo#bar()",
            // On super-class
            //"java/lang/Object#bar()",  // No such method defined.
            // On interface
            "java/lang/Comparable#bar()",  // TODO: Why?
            // Exact class
            "com/example/Foo",
            // Super class
            "java/lang/Object",  // TODO: Why?
            // Interface
            "java/lang/Comparable",
            // Packages in descending specificity
            "com/example/",
            "java/lang/",
            "com/",
            "java/",
            // The default package
            ApiElement.DEFAULT_PACKAGE.toInternalName()
            )
        .test();
  }

  public static void testLangObjectMethod() {
    new TestBuilder("com/example/Foo#equals(Ljava/lang/Object;)Z")
        .declare(
            "com/example/Foo",
            Opcodes.ACC_PUBLIC,
            Optional.of("java/lang/Object"),
            ImmutableList.of("java/lang/Comparable"),
            ImmutableList.<MethodDetails>of(),
            ImmutableList.of(
                new FieldDetails("x", Opcodes.ACC_PRIVATE)))
        .expect(
            // Exact
            "com/example/Foo#equals()",
            // On super-class
            "java/lang/Object#equals()",
            // On interface
            "java/lang/Comparable#equals()",
            // Exact class
            "com/example/Foo",
            // Super class
            "java/lang/Object",
            // Interface
            "java/lang/Comparable",
            // Packages in descending specificity
            "com/example/",
            "java/lang/",
            "com/",
            "java/",
            // The default package
            ApiElement.DEFAULT_PACKAGE.toInternalName()
            )
        .test();
  }

  public static void testSimpleField() {
    new TestBuilder("com/example/Foo#x")
    .declare(
        "com/example/Foo",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/lang/Object"),
        ImmutableList.of("java/lang/Comparable"),
        ImmutableList.of(
            new MethodDetails(
                "compareTo",  "compareTo(Ljava/lang/Object;)I",
                Opcodes.ACC_PUBLIC),
            new MethodDetails(
                "bar", "()V",
                Opcodes.ACC_PUBLIC)),
        ImmutableList.of(
            new FieldDetails("x", Opcodes.ACC_PRIVATE)))
    .expect(
        // Exact
        "com/example/Foo#x",
        // Exact class
        "com/example/Foo",
        // Super class
        // "java/lang/Object",  // field not defined on Object.
        // Interface
        // "java/lang/Comparable",   // field not defined on an interface.
        // Packages in descending specificity
        "com/example/",
        "com/",
        // The default package
        ApiElement.DEFAULT_PACKAGE.toInternalName()
        )
    .test();
  }

  public static void testOverriddenMethod() {
    new TestBuilder("com/example/Sub#isEmpty()Z")
    .declare(
        "com/example/Base",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/util/AbstractList"),
        ImmutableList.<String>of(),
        ImmutableList.of(
            new MethodDetails(
                "isEmpty",
                "()Z",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL
                )
            ),
        ImmutableList.<FieldDetails>of()
        )
    .declare(
        "com/example/Sub",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Base"),
        ImmutableList.<String>of(),
        ImmutableList.of(
            new MethodDetails(
                "isEmpty",
                "()Z",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL
                )
            ),
        ImmutableList.<FieldDetails>of()
        )
    .expect(
        "com/example/Sub#isEmpty()",
        "java/util/List#isEmpty()",
        "java/util/Collection#isEmpty()",
        "java/lang/Iterable#isEmpty()",
        "com/example/Sub",
        "com/example/Base",
        "java/util/AbstractList",
        "java/util/AbstractCollection",
        "java/lang/Object",
        "java/util/List",
        "java/util/Collection",
        "java/lang/Iterable",
        "com/example/",
        "java/util/",
        "java/lang/",
        "com/",
        "java/",
        "")
    .test();
  }

  public static void testOverriddenAbstractMethod() {
    new TestBuilder("com/example/Sub#isEmpty()Z")
    .declare(
        "com/example/Base",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/util/AbstractList"),
        ImmutableList.<String>of(),
        ImmutableList.of(
            new MethodDetails(
                "isEmpty",
                "()Z",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT
                )
            ),
        ImmutableList.<FieldDetails>of()
        )
    .declare(
        "com/example/Sub",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Base"),
        ImmutableList.<String>of(),
        ImmutableList.of(
            new MethodDetails(
                "isEmpty",
                "()Z",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL
                )
            ),
        ImmutableList.<FieldDetails>of()
        )
    .expect(
        "com/example/Sub#isEmpty()",
        "com/example/Base#isEmpty()",  // Base is abstract.
        "java/util/List#isEmpty()",
        "java/util/Collection#isEmpty()",
        "java/lang/Iterable#isEmpty()",
        "com/example/Sub",
        "com/example/Base",
        "java/util/AbstractList",
        "java/util/AbstractCollection",
        "java/lang/Object",
        "java/util/List",
        "java/util/Collection",
        "java/lang/Iterable",
        "com/example/",
        "java/util/",
        "java/lang/",
        "com/",
        "java/",
        "")
    .test();
  }

  public static void testPrivateMethod() {
    new TestBuilder("com/example/Sub#isEmpty()Z")
    .declare(
        "com/example/Baser",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/util/AbstractList"),
        ImmutableList.<String>of(),
        ImmutableList.of(
            new MethodDetails(
                "isEmpty",
                "()Z",
                Opcodes.ACC_PUBLIC
                )
            ),
        ImmutableList.<FieldDetails>of()
        )
    .declare(
        "com/example/Base",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Baser"),
        ImmutableList.<String>of(),
        ImmutableList.of(
            new MethodDetails(
                "isEmpty",
                "()Z",
                Opcodes.ACC_PRIVATE
                )
            ),
        ImmutableList.<FieldDetails>of()
        )
    .declare(
        "com/example/Sub",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Base"),
        ImmutableList.<String>of(),
        ImmutableList.<MethodDetails>of(
            new MethodDetails(
                "isEmpty",
                "()Z",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL
                )
            ),
        ImmutableList.<FieldDetails>of()
        )
    .expect(
        "com/example/Sub#isEmpty()",
        "com/example/Baser#isEmpty()",  // Base is abstract.
        "java/util/List#isEmpty()",
        "java/util/Collection#isEmpty()",
        "java/lang/Iterable#isEmpty()",
        "com/example/Sub",
        "com/example/Base",
        "com/example/Baser",
        "java/util/AbstractList",
        "java/util/AbstractCollection",
        "java/lang/Object",
        "java/util/List",
        "java/util/Collection",
        "java/lang/Iterable",
        "com/example/",
        "java/util/",
        "java/lang/",
        "com/",
        "java/",
        "")
    .test();
  }

  public static void testMaskedField() {
    new TestBuilder("com/example/Sub#x")
    .declare(
        "com/example/Sub",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Base"),
        ImmutableList.<String>of(),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            new FieldDetails("x", Opcodes.ACC_PROTECTED)))
    .declare(
        "com/example/Base",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/lang/Object"),
        ImmutableList.of("java/lang/Comparable"),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            // Masked
            new FieldDetails("x", Opcodes.ACC_PROTECTED)))
    .expect(
        // Exact
        "com/example/Sub#x",
        // Exact class
        "com/example/Sub",
        // Packages in descending specificity
        "com/example/",
        "com/",
        // The default package
        ApiElement.DEFAULT_PACKAGE.toInternalName()
        )
    .test();
  }

  public static void testFieldInSuper() {
    new TestBuilder("com/example/Sub#x")
    .declare(
        "com/example/Sub",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Base"),
        ImmutableList.<String>of(),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            new FieldDetails("y", Opcodes.ACC_PROTECTED)))
    .declare(
        "com/example/Base",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/lang/Object"),
        ImmutableList.of("java/lang/Comparable"),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            // Masked
            new FieldDetails("x", Opcodes.ACC_PROTECTED)))
    .expect(
        // Exact
        "com/example/Sub#x",
        // Corresponding field
        "com/example/Base#x",
        // Exact class
        "com/example/Sub",
        // Super classes
        "com/example/Base",
        // Packages in descending specificity
        "com/example/",
        "com/",
        // The default package
        ApiElement.DEFAULT_PACKAGE.toInternalName()
        )
    .test();
  }

  public static void testPrivateField() {
    new TestBuilder("com/example/Sub#x")
    .declare(
        "com/example/Sub",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Base"),
        ImmutableList.<String>of(),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            new FieldDetails("x", Opcodes.ACC_PRIVATE)))
    .declare(
        "com/example/Base",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/lang/Object"),
        ImmutableList.of("java/lang/Comparable"),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            // Masked
            new FieldDetails("x", Opcodes.ACC_PROTECTED)))
    .expect(
        // Exact
        "com/example/Sub#x",
        // Exact class
        "com/example/Sub",
        // Packages in descending specificity
        "com/example/",
        "com/",
        // The default package
        ApiElement.DEFAULT_PACKAGE.toInternalName()
        )
    .test();
  }

  public static void testPrivateFieldInSuperType() {
    new TestBuilder("com/example/Sub#x")
    .declare(
        "com/example/Sub",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Base"),
        ImmutableList.<String>of(),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.<FieldDetails>of())
    .declare(
        "com/example/Base",
        Opcodes.ACC_PUBLIC,
        Optional.of("com/example/Baser"),
        ImmutableList.<String>of(),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            new FieldDetails("x", Opcodes.ACC_PRIVATE)))
    .declare(
        "com/example/Baser",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/lang/Object"),
        ImmutableList.<String>of(),
        ImmutableList.<MethodDetails>of(),
        ImmutableList.of(
            // Masked
            new FieldDetails("x", Opcodes.ACC_PROTECTED)))
    .expect(
        // Exact
        "com/example/Sub#x",
        // Corresponding fields
        "com/example/Baser#x",
        // Exact class
        "com/example/Sub",
        // Super classes that have the field.
        // Even though the name x does not refer to Baser.x inside Base,
        // Base still has a field Baser.x because every instance of Baser
        // has a Baser.x and every instance of Base is-a Baser.
        "com/example/Base",
        "com/example/Baser",
        // Packages in descending specificity
        "com/example/",
        "com/",
        // The default package
        ApiElement.DEFAULT_PACKAGE.toInternalName()
        )
    .test();
  }

  public static void testConstructor() {
    new TestBuilder("com/example/Foo#<init>()")
    .declare(
        "com/example/Foo",
        Opcodes.ACC_PUBLIC,
        Optional.of("java/lang/Object"),
        ImmutableList.of("java/lang/Comparable"),
        ImmutableList.of(
            new MethodDetails(
                "compareTo",  "compareTo(Ljava/lang/Object;)I",
                Opcodes.ACC_PUBLIC),
            new MethodDetails(
                "bar", "()V",
                Opcodes.ACC_PUBLIC)),
        ImmutableList.of(
            new FieldDetails("x", Opcodes.ACC_PRIVATE)))
    .expect(
        // Exact
        "com/example/Foo#<init>()",
        // Exact class
        "com/example/Foo",
        // Packages in descending specificity
        "com/example/",
        "com/",
        // The default package
        ApiElement.DEFAULT_PACKAGE.toInternalName()
        )
    .test();
  }


}
