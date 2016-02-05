package com.google.security.fences.util;

import java.util.Iterator;

import com.google.common.base.Preconditions;

/**
 * Each integer between two end-points in natural order once.
 */
public final class CountingIterable implements Iterable<Integer> {
  private final int leftInclusive;
  private final int rightExclusive;

  CountingIterable(int leftInclusive, int rightExclusive) {
    Preconditions.checkArgument(leftInclusive <= rightExclusive);
    this.leftInclusive = leftInclusive;
    this.rightExclusive = rightExclusive;
  }

  public Iterator<Integer> iterator() {
    return new CountingIterator(leftInclusive, rightExclusive);
  }

  @Override
  public String toString() {
    return "[" + leftInclusive + ".." + rightExclusive + ")";
  }
}