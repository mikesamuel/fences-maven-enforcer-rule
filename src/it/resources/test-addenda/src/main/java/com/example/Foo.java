package com.example;

public class Foo {
  public final String s;

  public Foo(String s) {
    if (s == null) { System.exit(-1); }
    this.s = s;
  }
}
