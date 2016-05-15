package foo.bar;

public class NotAllowedToCallExit {
  public static void main(String... argv) {
    // The number of the call to exit appears in test code to
    // check that we get line numbers in error messages right.
    System.exit(-1);  // Line 7
  }
}
