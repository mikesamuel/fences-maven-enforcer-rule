package com.google.security.fences.config;

import java.util.LinkedHashSet;
import java.util.Set;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableSet;
import com.google.security.fences.namespace.Namespace;

/**
 * Keep your friends close, your enemies closer,
 * and your frenemies somewhere in between.
 */
public final class Frenemies {
  /** Namespaces explicitly trusted. */
  public final ImmutableSet<Namespace> friends;
  /** Namespaces explicitly distrusted. */
  public final ImmutableSet<Namespace> enemies;
  /** Explains how to work within the policy and get more help. */
  public final Optional<String> rationale;

  private Frenemies(
      ImmutableSet<Namespace> friends, ImmutableSet<Namespace> enemies,
      Optional<String> rationale) {
    this.friends = friends;
    this.enemies = enemies;
    this.rationale = rationale;
  }

  @SuppressWarnings("synthetic-access")
  static Builder builder() {
    return new Builder();
  }

  static final class Builder {
    private Builder() {}

    private final Set<Namespace> friends = new LinkedHashSet<Namespace>();
    private final Set<Namespace> enemies = new LinkedHashSet<Namespace>();
    private String rationale;

    Builder addFriend(Namespace ns) {
      friends.add(ns);
      return this;
    }

    Builder addEnemy(Namespace ns) {
      enemies.add(ns);
      return this;
    }

    Builder setRationale(String s) {
      rationale = s;
      return this;
    }

    @SuppressWarnings("synthetic-access")
    Frenemies build() {
      return new Frenemies(
          ImmutableSet.copyOf(friends), ImmutableSet.copyOf(enemies),
          Optional.fromNullable(rationale));
    }
  }
}
