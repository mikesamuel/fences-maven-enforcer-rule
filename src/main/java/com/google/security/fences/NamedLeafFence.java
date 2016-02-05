package com.google.security.fences;

import com.google.common.collect.ImmutableList;

abstract class NamedLeafFence extends NamedFence {
  @Override
  public Iterable<Fence> getChildFences() {
    return ImmutableList.of();
  }
}