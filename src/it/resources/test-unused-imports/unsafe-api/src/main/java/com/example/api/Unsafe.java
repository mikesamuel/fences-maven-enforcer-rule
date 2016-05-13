package com.example.api;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class Unsafe {
  @SuppressFBWarnings("DM_EXIT")
  public Unsafe pushRedButton() {
    for (int i = 10; --i >= 0;) {
      System.err.println("T - " + i);
    }
    System.exit(-1);
    return this;
  }
}
