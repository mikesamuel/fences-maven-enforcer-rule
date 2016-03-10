package foo.bar;

public class NotAllowedToCallExit {
  public static void main(String... argv) {
    // This is kosher since non-white-listed classes still have access to
    // the public API of white-listed classes.
    AllowedToCallExit.main(argv);
  }
}
