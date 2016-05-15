# Alternatives

Java's access control exposes the public API of every package to every
other package.
[OSGi's x-friends](http://www.vogella.com/tutorials/OSGi/article.html#osgiarch_provitionalapi_friends)
provides one side of this but in a different direction -- instead of
the project lead saying who in her project may use which packages, the
packages declare who may use them.  There is value in this but it
serves different use cases.

JigSaw&[JEP201](http://openjdk.java.net/jeps/201) may
address this eventually, but does not in current versions of Java.
