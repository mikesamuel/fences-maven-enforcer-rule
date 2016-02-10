package com.google.security;

import com.google.common.base.Preconditions;

abstract class LazyString implements CharSequence {
  private String s;

  public int length() {
    return toString().length();
  }

  public char charAt(int index) {
    return toString().charAt(index);
  }

  public CharSequence subSequence(int start, int end) {
    return toString().substring(start, end);
  }

  @Override
  public final String toString() {
    if (s == null) {
      s = Preconditions.checkNotNull(makeString());
    }
    return s;
  }

  protected abstract String makeString();
}
