# Caveats

This does static analysis only.  It does not restrict how Java
reflection is used so can be worked around via `java.lang.reflect`.

It does not currently restrict how
[*invokedynamic*](http://docs.oracle.com/javase/7/docs/technotes/guides/vm/multiple-language-support.html#invokedynamic)
so can be worked around by embedded scripting languages.

Our goal with this project is to prevent a developer from plausibly
denying that they are avoiding security review for security critical
code while making it as easy as possible for developers to navigate
the review process on the infrequent occasions they need to.

Denying access by an interface or base class to a critical piece of code
will not prevent subclasses from accessing that critical piece of code.

Granting access to a package grants all access to that package.  Such
critical packages can be
[sealed](https://docs.oracle.com/javase/tutorial/deployment/jar/sealman.html)
to prevent other Jars from introducing classes that then have
privileges.

Inner class support is dodgy because this project conflates
fully-qualified class names and internal JVM class names.
Denying access to an inner class while granting it to the
outer class may not work.

This rule checks all and only dependencies.  It assumes that all code loaded is
available as a dependency and cannot vet other code loaded at runtime
like that dynamically compiled from JSPs or loaded via classloaders
from resources.

This rule checks static accesses, and so cannot prevent access to private
constructors or fields done by java deserialization or other abstraction
breaking mechanisms built into the JVM.
