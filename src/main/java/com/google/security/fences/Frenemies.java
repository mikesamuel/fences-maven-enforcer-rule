package com.google.security.fences;

import java.util.LinkedHashSet;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import com.google.security.fences.namespace.Namespace;

public final class Frenemies {
  public final ImmutableSet<Namespace> friends;
  public final ImmutableSet<Namespace> enemies;

  private Frenemies(
      ImmutableSet<Namespace> friends, ImmutableSet<Namespace> enemies) {
    this.friends = friends;
    this.enemies = enemies;
  }

  @SuppressWarnings("synthetic-access")
  static Builder builder() {
    return new Builder();
  }

  static final class Builder {
    private Builder() {}

    private final Set<Namespace> friends = new LinkedHashSet<Namespace>();
    private final Set<Namespace> enemies = new LinkedHashSet<Namespace>();

    Builder addFriend(Namespace ns) {
      friends.add(ns);
      return this;
    }

    Builder addEnemy(Namespace ns) {
      enemies.add(ns);
      return this;
    }

    @SuppressWarnings("synthetic-access")
    Frenemies build() {
      return new Frenemies(
          ImmutableSet.copyOf(friends), ImmutableSet.copyOf(enemies));
    }
  }
}
