# FAQ

## What?  Why?  How?

The fences rule is a Maven enforcer plugin rule that augments Java's
access control by checking that a Maven Project and all its
dependencies conform to a policy that specifies which classes/pacakges
can link to which others.

See the
[README](https://github.com/mikesamuel/fences-maven-enforcer-rule/blob/master/README.md)
for more info.


## How can I disable policy checking temporarily?

Experimenting and figuring out whether you need a policy change
is important, and so you can show concrete results as grounds
for a policy change.

Run Maven with `-Dfences.experimental` to turn policy violations into
warnings.  You can also turn off the enforcer plugin as a whole via
`-Denforcer.skip=true`.

```sh
$ mvn verify -Dfences.experimental
```

