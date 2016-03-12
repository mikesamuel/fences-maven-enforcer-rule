# Caveats

Our goal with this project is to prevent a developer from *plausibly
denying* that they are avoiding security review for security critical
code while making it as easy as possible for developers to navigate
the review process on the (hopefully infrequent) occasions they need to,
and helping security reviewers focus and prioritize.

-----

This does static analysis only.  It does not restrict how Java
**reflection** is used so can be worked around via `java.lang.reflect`
and [proxy classes](http://docs.oracle.com/javase/1.5.0/docs/guide/reflection/proxy.html).
[Some reflection APIs](https://www.securecoding.cert.org/confluence/display/java/SEC05-J.+Do+not+use+reflection+to+increase+accessibility+of+classes,+methods,+or+fields)
intentionally break Java's access control restrictions, and
similarly affect the additional restrictions imposed by this tool.

Similarly, this tool cannot prevent access to private
constructors or fields done by Java [deserialization](https://www.securecoding.cert.org/confluence/display/java/SER12-J.+Prevent+deserialization+of+untrusted+classes)
or other abstraction breaking mechanisms built into the JVM.

-----

This tool does not currently restrict uses of
[invokedynamic](http://docs.oracle.com/javase/7/docs/technotes/guides/vm/multiple-language-support.html#invokedynamic)
so can be worked around by **embedded scripting languages**.

-----

Granting access to a package grants all access to that package.
Any artifact can introduce classes into
[**unsealed packages**](https://docs.oracle.com/javase/tutorial/deployment/jar/sealman.html)
and thereby escalate privileges to that package's privileges.
Sealing is [easy in Maven](http://stackoverflow.com/questions/13527235/maven-how-do-i-mark-a-jar-as-sealed).

----

**Inner class** support is
[dodgy](https://github.com/mikesamuel/fences-maven-enforcer-rule/issues/10).
Denying access to an inner class while granting it to the
outer class may not work.

----

This rule checks all and only Maven **`<dependency>`s**.
It assumes that all code
loaded is available as a dependency and cannot vet other code loaded at
runtime like that dynamically compiled from JSPs or loaded via **classloaders**
from resources.

----

This rule does not **enumerate sub-types** so policies should be applied to
the type at which an API element is declared.  Specifically,

```java
package com.example;

interface A {
  void unsafe();
}

class B implements A {
  @Override
  public void unsafe() {
    ...
  }
}

class C {
  void f(B b) {
    A a = b;  // Cast B to A.
    a.unsafe();
  }
}
```

If a policy distrusted `B.unsafe()` thus

```
<method>
  <name>com.example.B.unsafe</name>
  <distrusts>*</distrusts>
</method>
```

then the call to `A.unsafe()` would not
violate the policy.

`unsafe` is declared on `A` and implemented
by `B` so the policy should target `A.unsafe`.
