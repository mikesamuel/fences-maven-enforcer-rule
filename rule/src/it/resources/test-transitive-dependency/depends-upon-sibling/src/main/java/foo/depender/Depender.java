package foo.depender;

import foo.dependee.Dependee;

public final class Depender {
  public static void f() throws Exception {
    Dependee.f();
  }
}
