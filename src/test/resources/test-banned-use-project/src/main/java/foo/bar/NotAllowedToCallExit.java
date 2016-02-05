package foo.bar;

public class NotAllowedToCallExit {
  public static void main(String... argv) {
    System.exit(-1);
  }
}
