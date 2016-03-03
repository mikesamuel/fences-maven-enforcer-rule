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
| `<class>` | 1 `<name>`, many `<class>`, `<method>`, `<field>` | Names a class. |
| `<method>` | 1 `<name>` | Specifies a method in the enclosing `<class>` |
| `<field>` | 1 `<name>` | Specifies a field in the enclosing `<class>` |
| `<new>` | | Specifies a constructor for the containing class |

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

## Writing good `<rationale>`s.

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
