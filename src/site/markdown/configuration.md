# Configuration

The following table shows which tags can appear in which contexts.
The first four can appear in any of the rest so are not listed in the content column explicitly.

| Configuration | Content | Meaning |
| ------------- | ------- | ------- |
| `<trusts>` | Name of the class or package or `*` for all. | Who can access the containing API element. |
| `<distrusts>` | Ditto | Like `<trusts>` but revokes access. |
| `<name>` | A dotted Java identifier | Specifies a Java package, class, or class member. |
| `<rationale>` | Human readable text | An error message shown when a sibling `<distrusts>` triggers. |
| <hr /> | <hr /> | <hr /> |
| `<api>` | Many `<package>`, `<class>` | A group of sensitive API elements. |
| `<package>` | 1 `<name>`, many `<package>`, `<class>` | A java package. |
| `<class>` | 1 `<name>`, many `<class>`, `<method>`, `<field>`, `<constructor>` | A Java class. |
| `<method>` | 1 `<name>` | Specifies a method in the enclosing `<class>` |
| `<field>` | 1 `<name>` | Specifies a field in the enclosing `<class>` |
| `<constructor>`| | Specifies a constructor in the enclosing `<class>` |
| <hr /> | <hr /> | <hr /> |
| `<import>` | *Group*:*Artifact*:*Version* | Load more configuration from `META-INF/fences.xml` in that artifact's JAR |

For example,

```XML
<api>
  <package>
    <name>com</name>
    <package>
      <name>example</name>
      <class>
      <name>MisusableClass</name>
        <!-- Distrust by default. -->
        <distrusts>*</distrusts>
        <!-- White-list of approved exceptions to the rule. -->
        <trusts>com.example.foo.TrustworthyAccessor</trusts>
        <rationale>
          NameOfClass exposes authority that must be used in
          accordance with strict guidelines (see ...).

          Try to use com.example.SimplerSaferAlternative instead.

          If that doesn't suffice, open a ticket at http://jira/
          and security team will work with you to find a way to use
          the simpler APIs or add your code to the white-list of
          exceptions to the rule.  (http://shortlink/misusable-faq)
        </rationale>
      </class>
    </package>
  </package>
</api>
```

specifies that `org.trustworthy.Accessor` can use
`com.example.NameOfClass` but not other classes.

Names can be dotted, so the configuration above can be simplified to

```XML
<class>
  <name>com.example.NameOfClass</name>
  <trusts>org.trustworthy.Accessor</trusts>
  <distrusts>*</distrusts>
  <rationale>...</rationale>
</class>
```

## Writing good `<rationale>`s. <a name="writing_good_rationales"></a>

The error message shown when a policy is violated is composed from
the `<rationale>`...`</rationale>` and `<addendum>`...`</addendum>`
elements.

Let's look at a policy in two parts:

1. An aggregating POM maintained by the project lead which `<import/>`s
2. A third-party dependency that bundles an `META-INF/fences.xml` file.

These two files can be used as templates.  The `<!---`...`-->`
comments are non-normative.

### Project POM

```xml
<configuration>
  <import>com.third_party:library</import>

  <!--
    A high-level addendum points developers to sources of
    information within the organization possibly including

    1. FAQs or documentation that they can read *and*
    2. user groups, issue trackers, IRC channels that
       can field questions.

    Keep this short.
    Users appreciate it the first time they see it but
    boiler-plate in logs obscures important details.

  -->
  <addendum>
    http://wiki/java-policy-FAQ | security-team@example.com
  </addendum>
  <!-- Use short URLs since URLs in logs are rarely clickable. -->

  <package>
    <name>com.third_party</name>
    <class>
      <name>Unsafe</name>
      <method>
        <name>foo</name>
        <!-- A white-list of exceptions to the imported rules. -->
        <trusts>com.example.aardvark.ConsistentTransactionr</trusts>

        <!-- There may be alternatives within the organization that
             are not available to all users of the third-party library.

             An additional rationale can supplement those docs.
        -->
        <rationale>
          Prefer com.example.SafeAlternative to ${fences.api}.
          Ping alice@example.com if that doesn't suffice.
        </rationale>
      </method>
    </class>
  </package>
</configuration>
```

### Third-party `META-INF/fences.xml`

```xml
<configuration>
<package>
  <name>com.third_party</name>
  <class>
    <name>Unsafe</name>
    <trusts>com.third_party.builders</trusts>
    <distrusts>*</distrusts>

    <rationale>
      Uses of Unsafe must be carefully reviewed by experts in XYZ.
      Please use the safe builders in com.third_party.builders
      before rolling your own.
    </rationale>
    <!--
      Not all members of a public user support list have signed
      NDAs with com.example, so mentioning that support lists
      are public or non-confidential can help developers decide
      what level of detail is appropriate.
    -->
    <rationale>
      User support (non-confidential) : users@third_party.com
      Public issue tracker : third_party.com/issues
    </rationale>
  </class>
</package>
```

### Property Interpolation

Rationales and addenda may include maven property expressions.

In addition to the normal maven properties, these properties are available:

| Property Name     | Meaning                                                  |
| ----------------- | -------------------------------------------------------- |
| fences.api        | The sensitive API.                                       |
| fences.distrusted | The distrusted namespace which accessed `${fences.api}`. |
| fences.trusts     | The namespaces which `${fences.api}` trusts.             |

The documentation on plexus-interpolation (the module Maven uses to do
property substitution) is pretty sparse, but
[the unittests](https://github.com/codehaus-plexus/plexus-interpolation/blob/master/src/test/java/org/codehaus/plexus/interpolation/StringSearchInterpolatorTest.java)
provide some guidance.

## Importing configuration

Sometimes a library author needs to use sensitive APIs.
They can include, in their JAR a `META-INF/fences.xml` file with content like

```xml
<configuration>
   <package>
     ...
   </package>
   <import>...</import>
</configuration>
```

to specify what they require to do their jobs by **proposing** that they be
trusted to use certain APIs and/or that certain of their APIs be distrusted
by default.  The API elements and namespaces involved in trust relationships
in imported configurations are not limited to those relating to classes
defined in that JAR.

This allows different versions to request access to different sensitive APIs,
and when the artifacts are stored in Maven central, the APIs they request
access to are a matter of public record.

A project-lead can then **second** their requests by adding to the Fences
configuration a line like

```xml
   <import>group:artifact:version</import>
```

which says, find the JAR for the dependency with ID `group:artifact:version`,
load the `META-INF/fences.xml` file, parse it, and incorporate its `<trusts>`
and `<distrusts>`.

The version may be omitted : `<import>group:artifact</import>`.
