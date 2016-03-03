# Background

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

> ## Security type contracts.

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
