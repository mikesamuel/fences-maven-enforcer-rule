# Configuration

The following table shows which tags can appear in which contexts.
The first three can appear in any of the rest so are not listed in the content column explicitly.

| Configuration | Content | Meaning |
| ------------- | ------- | ------- |
| `<trusts>` | Name of the class or package or `*` for all. | Who can access the containing API element. |
| `<distrusts>` | Ditto | Like `<trusts>` but revokes access. |
| `<name>` | A dotted Java identifier | Specifies a Java package, class, or class member. |
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
