package com.google.security.fences.util;

import java.util.Iterator;

import com.google.common.base.Preconditions;

/**
 * A single enumeration over a {@link CountingIterator}.
 */
public final class CountingIterator implements Iterator<Integer> {
  private int i;
  private final int rightExclusive;

  CountingIterator(int leftInclusive, int rightExclusive) {
    Preconditions.checkArgument(leftInclusive <= rightExclusive);
    this.i = leftInclusive;
    this.rightExclusive = rightExclusive;
  }

  @Override
  public synchronized String toString() {
    return "[" + i + ".." + rightExclusive + ")";
  }

  public synchronized boolean hasNext() {
    return i < rightExclusive;
  }

  public synchronized Integer next() {
    if (i >= rightExclusive) {
      throw new IndexOutOfBoundsException(i + " >= " + rightExclusive);
    }
    return i++;
  }

  public void remove() {
    throw new UnsupportedOperationException();
  }
}