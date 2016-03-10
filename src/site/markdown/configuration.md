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
        <name>NameOfClass</name>
        <trusts>org.trustworthy.Accessor</trusts>
        <distrusts>*</distrusts>
        <rationale>
          NameOfClass exposes authority that must be used in
          accordance with strict guidelines (see ...).

          Try to use com.example.SimplerSaferAlternative instead.

          If that doesn't suffice, email security@example.com and
          they will work with you to find a way to use the simpler
          APIs or approve your uses.
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

The `<rationale>...</rationale>` element may appear in any API element.
When a user builds code that violates the policy, the rationale is shown.

It should

1. Explain or give short link to documents explaining how to work within
   the policy.
2. Include contact information (email, IRC) where help can be found.
3. Include bug-tracker information if you track bugs in policies or
   white-list requests there.

Rationales may include maven property expressions.

In addition to the normal maven properties, these properties are available:

| Property Name     | Meaning                                                  |
| ----------------- | -------------------------------------------------------- |
| fences.api        | The sensitive API.                                       |
| fences.distrusted | The distrusted namespace which accessed `${fences.API}`. |
| fences.trusts     | The namespaces which `${fences.API}` trusts.             |

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
