# Policies

## To what do policies apply?

Policies apply to all production classes available to Maven:

1. All `<dependency>`s and `<module>`s, transitively that
2. are not in `<scope>test</scope>`, and
3. are not excluded by Maven as a result of version conflicts.

## Policy Application Algorithm

A policy is violated when their exists a bytecode instruction
in an untrusted namespace that uses a protected API.

*Uses* of APIs come in several forms:

1. Reads and writes of fields (*getfield*, *getstatic*, *putfield*, *putstatic*)
2. Calls of methods (*invokestatic*, *invokeinterface*, *invokestatic*)
3. Calls of constructors (*invokespecial*)

For a use, we also have a *descriptor* which encapsulates the signature.
For methods this includes the static parameter types and return type as in
`(I[Ljava/lang/String;)V` which is the signature of a void method that takes
an `int` and an array of strings.

----

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

The list of API elements in order is

1. The API element used.
2. The corresponding API elements on the containing
   class's super-types in order of inheritance depth.
   These are filtered to remove any that the API
   element masks or overrides.<br>
   Only methods with bodies are considered overridden.
   Others are pure declarations so their trust
   decisions apply broadly.<br>
   Private fields and methods do not mask or override,
   and arguably are not "API elements."<br>
   Constructors do not have corresponding API elements
   in super-types but this does not matter since
   all constructors other than `Object`'s contain
   an explicit call to the super-class's constructor.
3. The corresponding API elements on interfaces
   ordered by the depth of the type in the super-type
   list that implements them, and ordered within that
   by the order they appear in the class.
   Fields do not have corresponding API elements on
   interfaces.
4. The parent API element and its ancestors transitively.
   This includes the classes and packages containing the
   API element.
