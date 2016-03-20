# Policies

## To what do policies apply?

Policies apply to all production classes available to Maven:

1. All `<dependency>`s and `<module>`s, transitively that
2. are not in `<scope>test</scope>`, and
3. are not excluded by Maven as a result of version conflicts.

## Policy Application Algorithm

A policy is violated when their exists a bytecode instruction
in an untrusted namespace that uses a protected API.

<a name="def_use"></a>
*Uses* of APIs come in several forms:

1. Reads and writes of fields (*getfield*, *getstatic*, *putfield*, *putstatic*)
2. Calls of methods (*invokestatic*, *invokeinterface*, *invokestatic*)
3. Calls of constructors (*invokespecial*)

For a use, we also have a
[*descriptor*](https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3.3)
which encapsulates the signature.
For methods this includes the static parameter types and return type as in
`(I[Ljava/lang/String;)V` which is the signature of a void method that takes
an `int` and an array of strings.

<!-- ] -->

----

<a name="def_api_element"></a>
An *API element* is a triple (identifier, type, parent) where type is one of

1. constructor
2. method
3. field
4. class
5. package

corresponding to the elements of the same name.

----

Once we have an API element, a namespace, and a descriptor, we can
come up with an ordering of API elements.

The first API element in this ordering that trusts or distrusts the
using namespace determines the policy result.  If there is no such
element, then the namespace is trusted by default per the JVM's
normal access rules.

We use the following principles to figure out how rules apply to uses.

1. The [*is-a*](https://en.wikipedia.org/wiki/Is-a) rule:
   Rules that apply to a super-type
   apply to instances of a sub-type.
2. The abstraction rule: Rules that apply to an abstract or interface
   method apply to all implementations of that method.
3. The works-with rule: A namespace applies to everything declared within
   it.  Java packages and classes define namespaces.
   Java does not attach any special significance to the fact that the package
   `com.example.foo` is a sub-package of `com.example`, but since packages
   prefixes tend to predict who authored the code therein, we do.
4. The specificity rule: More specific rules win.
   We judge speficity on how tightly it constrains
   [has-a](https://en.wikipedia.org/wiki/Has-a),
   [is-a](https://en.wikipedia.org/wiki/Is-a), and
   works-with relationships.
   Roughly: member > exact class > super type > super interface
   > exact package > super package.

The table below shows the level of specificity of various kinds in
order from greatest to least.

We compute our ordered list of API elements by computing the API
elements that match these rules and concatenating them.
The first of these API elements that corresponds to a `<trust>` or
`<distrust>` for the current namespace determines the policy result.

| Has-a | Is-a | Works-with | Description |
| ----- | ---- | ---------- | ----------- |
| High  | High | /          | A `<constructor>`, `<method>` or `<field>` rule applies when the [receiver](#def_receiver) is the same as the `<class>` that directly contains the rule. |
| High  | Med  | /          | A `<method>` or `<field>` rule applies on the sub-types of the `<class>` that directly contains it unless the sub-type overrides or masks it.
| High  | Low  | /          | An abstract `<method>` rule applies to all sub-types of the `<class>`. |
| /     | High | /          | A `<class>` rule applies to all [uses](#def_use) on a receiver whose static type is that class. |
| /     | Low  | /          | A `<class>` rule applies to all uses on a receiver whose static type is a *subtype* of that class. |
| /     | /    | High       | A `<class>` rule applies to all uses on a receiver that is an inner class (transitively) of that class. |
| /     | /    | Med        | A `<package>` rule applies to all uses on a receiver whose static type is in that package. |
| /     | /    | Low        | A `<package>` rule applies to all uses on a receiver whose static type is in a sub-package of that package. |
| /     | /    | /          | An `<api>` rule applies to all uses. |

----

<a name="def_receiver"></a>
A "receiver" is the object or class
that a use operates upon.  This is the static type of the `this`
in the body of a called method, the static type of the object whose
field is being read, the class being constructed by a constructor invocation,
or the class containing a static member.
