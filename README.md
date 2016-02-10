# Fences Maven Enforcer Rule

Augments Java's access control by checking that a Maven Project and all its
dependencies conform to a policy that specifies which classes/pacakges can
link to which others.

Java's access control exposes the public API of every package to every
other package.  JigSaw will address this eventually, but is not
available now.

## Background

Application developers need to focus on application features and
computer security specialists need to focus on the security & robustness
of the application.  If even a moderate number of application code changes
require security review, development won't scale.

Security specialists can help application development scale by limiting the
amount of code that they need to review.

["Securing the Tangled Web"](http://static.googleusercontent.com/media/research.google.com/en//pubs/archive/42934.pdf)
outlines an approach to building secure & robust applications based
around *inherently safe APIs*, *type contracts*, and leveraging
language tools to minimize the amount of code that has to be reviewed
by security specialists.

> with this approach, an application is structured such that most of
> its code cannot be responsible for XSS bugs. The potential for
> vulnerabilities is therefore confined to infrastructure code such as
> Web application frameworks and HTML templating engines, as well as
> small, self-contained applicationspecific utility modules.

> A second, equally important goal is to provide a developer
> experience that does not add an unacceptable degree of friction as
> compared with existing developer workflows.

> ...

> ### Security type contracts.

> such security-sensitive code is encapsulated in a small number of
> special-purpose libraries; application code uses those libraries but
> is itself not relied upon to correctly create instances of such
> types and hence does not need to be security-reviewed.

> ...

> To actually create values of these types, unchecked conversion
> factory methods are provided that consume an arbitrary string and
> return an instance of a given wrapper type.

> ...

> Every use of such unchecked conversions must be carefully security
> reviewed to ensure that in all possible program states, strings passed
> to the conversion satisfy the resulting type’s contract.

Restricting which classes and packages can access which other classes
and packages makes it easy to make sure these unchecked conversions get
reviewed, and allow pieces of security critical machinery to be developed
separately, and link to one another, while minimizing the amount of code
that can misuse that machinery.

Once something has been approved, that fact can be recorded in the
project's POM.


## Caveats

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


## Usage

The Fences Enforcer is a custom rule for the [*maven-enforcer-plugin*](http://maven.apache.org/enforcer/maven-enforcer-plugin/).

Add the following to your POM.

```XML
<project>
  ...
  <build>
    ...
    <plugins>
      ...
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-enforcer-plugin</artifactId>
        <version>1.4.1</version>
        <dependencies>
          <dependency>
            <groupId>com.google.security</groupId>
            <artifactId>fences-maven-enforcer-rule</artifactId>
            <version>1.0</version>
          </dependency>
        </dependencies>
        <executions>
          <execution>
            <id>enforce</id>
            <configuration>
              <rules>
                <fences
                 implementation="com.google.security.fences.FencesMavenEnforcerRule">
                 <!-- SEE CONFIGURATION BELOW
                      One or more of (<package>, <class>, and/or <api>).
                   -->
                </fences>
              </rules>
            </configuration>
            <goals>
              <goal>enforce</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
  ...
</project>
```


## Configuration

The following tag can appear in a 

Configuration | Content | Meaning
============= | ======= | =======
`<trusts>` | Name of the class or package or `*` for all. | Who can access the parent API element.
`<distrusts>` | Ditto | Like `<trusts>` but revokes access.
`<name>` | A dotted Java identifier | Specifies a Java package, class, or class member.
 | | 
`<api>` | Many `<package>`, `<class>` | A group of sensitive API elements.
`<package>` | 1 `<name>`, many `<package>`, `<class>` |
`<class>` | 1 `<name>`, many `<class>`, `<method>`, `<field>` | Names a class.
`<method>` | 1 `<name>` | Specifies a method in the enclosing `<class>`
`<field>` | 1 `<name>` | Specifies a field in the enclosing `<class>`
`<new>` | | Specifies a constructor for the containing class

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

