package com.google.security.fences.util;

import com.google.common.base.Preconditions;

/**
 * A CharSequence that lazily computes a string which can be useful when a
 * debug log message might be unbounded in length.
 */
public abstract class LazyString implements CharSequence {
  private String s;

  @Override
  public int length() {
    return toString().length();
  }

  @Override
  public char charAt(int index) {
    return toString().charAt(index);
  }

  @Override
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
