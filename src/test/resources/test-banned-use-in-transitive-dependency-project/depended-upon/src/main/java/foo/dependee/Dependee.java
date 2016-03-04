package foo.dependee;

public final class Dependee {
  public static void f() throws Exception {
    Runtime rt = Runtime.getRuntime();
    rt.exec(new String[] { "echo", "Hello", "World!" });
  }
}
