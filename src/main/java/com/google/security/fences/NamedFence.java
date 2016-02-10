package com.google.security.fences;

import java.util.Locale;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import com.google.common.base.Preconditions;

abstract class NamedFence extends Fence {
  private String name;

  public String getName() { return name; }

  public void setName(String newName) {
    this.name = Preconditions.checkNotNull(newName);
  }

  @Override
  public void check() throws EnforcerRuleException {
    super.check();
    if (name == null) {
      throw new EnforcerRuleException(
          getClass().getSimpleName().replaceFirst("Fence$", "")
          .toLowerCase(Locale.ENGLISH)
          + " is missing a name");
    }
  }

  @Override
  public String toString() {
    String type = getClass().getSimpleName().replaceFirst("Fence$", "")
        .toLowerCase(Locale.ENGLISH);
    return "{" + type + " " + name + "}";
  }
}