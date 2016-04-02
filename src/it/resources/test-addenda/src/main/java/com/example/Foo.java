package com.example;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class Foo {
  public final String s;

  @SuppressFBWarnings("DM_EXIT")
  public Foo(String s) {
    if (s == null) { System.exit(-1); }
    this.s = s;
  }
}
