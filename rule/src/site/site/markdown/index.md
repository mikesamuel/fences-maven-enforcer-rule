# Fences

Fecnes is a [maven-enforcer] rule that augments Java's access control
by checking that a Maven Project and all its dependencies conform to a
policy that specifies which classes/packages can link to which others.

See the links on the left for more detail.  Here's an example of how
the tool smooths interactions between different specialists contributing
to a large project.


## A tale of development gone wry.

Sally the security specialist is responsible for seeing that
a particular security property for the project she's working.
She wants to do her job without requiring every other developer to
keep her goals in mind -- development won't scale any other way.

Sally wants to craft a solution from three packages

1. the parts of her code that are specific to her employer,
2. those that are generally useful that she can
   give back to the open-source community,
3. some existing open-source code that fits well.

Sally has structured things so that there is a *safe API* --
one whose use won't compromise the security property she's
responsible for.  But these various packages can't work
together except via the `public`/`protected` API so that API
must be larger than just the safe APIs

Development is going quickly; Sally sees so many commits going by she
knows there's no way she can review all of them to see that only the
safe API is used or that the larger `public` API is only used in ways
that preserve the security property.

Sally puts together a patch to the [project POM][multi-module-projects]
that [uses the fences rule](getting_started.md).
The policy restricts access to the sensitive portions of Sally's
APIs to code that she knows was reviewed with the system's security
properties in mind.

Her team-lead integrates the patch, and adds an
[`<addendum>`](configuration.md#writing_good_rationales) that
points to the internal developer list and a FAQ that they plan
to flesh-out as questions come in.

----

Alex is an application-developer who knows his user-base and tools
well.  While Alex cares about the security of the system, he's got
more than enough on his plate juggling feature work, the new design,
etc.

Alex is a master of git-'er-done style development -- using
auto-complete to explore APIs instead of reading documentation.  He
stumbles upon some of Sally's sensitive APIs and writes code that
links directly with public-but-not-safe code.

Next time he builds he gets an error message and he reads Sally's
explanation:

> Please use com.example.FooBuilder instead of
> new com.example.foo.FooImpl().<br />
> Ping sally@ for more details.

He's not quite sure how to proceed, so he fires off a quick
email to sally, does a quick search finds a [workaround](faq.md)
and continues development in experimental mode.

----

Sally returns from lunch responds and writes a more finely tuned
`<rationale>` for the specific API element Alex used.

----

After several months on the project, Sally has fielded lots
of questions about her work fleshing out the FAQ and policy docs
as she goes; she's open-sourced some useful
tools; and extended the policy to integrate with some common
infrastructure that she's reviewed.

She knows that, while many developers build their development
branches in experimental mode, the QA and production branches
must pass the policy, so the amount of code she has to keep
track of to do her job is limited by the policy.

Reviewers of pull-requests into release-candidate branches
often address how to adjust code to match the policy, so
the questions that reach Sally often have otherwise-functional
code attached.

----

The tech lead has found some other uses too:

1. Developers keep adding `<dependency>`s on a poorly written and
   unmaintained project, so the tech lead crafted a policy rule to ban
   its packages with a `<rationale>` that points them to another
   `<dependency>` that serves the same purpose better.
2. A policy with a white-list of `<trusts>` elements allowed them
   to aggressively deprecate some old internal APIs while
   grandfathering some tricky old code that no-one wanted to
   rewrite just now.



[multi-module-projects]: https://books.sonatype.com/mvnref-book/reference/pom-relationships-sect-pom-best-practice.html#pom-relationships-sect-multi-vs-inherit
