package foo.bar;

import java.net.*;

class Baz {
  private static String doSomethingWithAURL(String url)
  throws MalformedURLException {
    return new URL(url).getRef();  // Banned use here.  See the POM.
  }

  public void foo(String s) throws MalformedURLException {
    System.out.println(doSomethingWithAURL(s));
  }
}
