package com.google.security.fences.config;

import java.util.List;

import javax.annotation.Nullable;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.codehaus.plexus.interpolation.InterpolationException;
import org.codehaus.plexus.interpolation.RegexBasedInterpolator;
import org.codehaus.plexus.interpolation.ValueSource;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.security.fences.namespace.Namespace;
import com.google.security.fences.policy.ApiElement;

/**
 * A bean object that can be populated from a POM file {@code <configuration>}
 * element to specify a {@link com.google.security.fences.policy.Policy}.
 */
public abstract class Fence {
  private final List<Namespace> trusts = Lists.newArrayList();
  private final List<Namespace> distrusts = Lists.newArrayList();
  private String rationale;

  Fence() {
    // package private
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setTrusts(String s) throws EnforcerRuleException {
    trusts.add(Namespace.fromDottedString(s));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setDistrusts(String s) throws EnforcerRuleException {
    distrusts.add(Namespace.fromDottedString(s));
  }

  /**
   * A human readable string shown when a policy violation is detected that
   * explains how to work within the policy and where to find more help.
   * <p>
   * The documentation at src/site/markdown/configuration.md explains how
   * to write a good one.
   *
   * @param s May contain maven property expressions.
   */
  public void setRationale(@Nullable String s) throws EnforcerRuleException {
    if (s == null) {
      this.rationale = null;
    } else {
      String trimmed = trimMinimalWhitespaceFromAllLines(s);
      // TODO: Can we pre-validate it as a valid plexus expression?
      RegexBasedInterpolator interpolator = new RegexBasedInterpolator();
      interpolator.addValueSource(new ValueSource() {
        public void clearFeedback() {
          // Nothing to do.
        }

        @SuppressWarnings("rawtypes")
        public List getFeedback() {
          return ImmutableList.of();
        }

        public Object getValue(String key) {
          return key;
        }
      });
      try {
        interpolator.interpolate(trimmed);
      } catch (InterpolationException ex) {
        throw new EnforcerRuleException("Malformed rationale: " + trimmed, ex);
      }
      this.rationale = trimmed;
    }
  }

  /** By default, just checks children. */
  public void check() throws EnforcerRuleException {
    for (Fence childFence : getChildFences()) {
      childFence.check();
    }
  }

  /** Fences contained herein. */
  public abstract Iterable<Fence> getChildFences();

  /**
   * The API elements trusted or distrusted by the API element specified by
   * this fence.
   */
  public final Frenemies getFrenemies() {
    Frenemies.Builder b = Frenemies.builder();
    for (Namespace ns : trusts) {
      b.addFriend(ns);
    }
    for (Namespace ns : distrusts) {
      b.addEnemy(ns);
    }
    if (rationale != null) {
      b.setRationale(rationale);
    }
    return b.build();
  }

  /**
   * Modifies children in place so that no node in the fence tree has a dotted
   * name.
   * @return the split node so that parents may modify their child lists.
   */
  public abstract Fence splitDottedNames();

  void mergeTrustsFrom(Fence that) {
    this.trusts.addAll(that.trusts);
    this.distrusts.addAll(that.distrusts);
  }

  abstract void visit(FenceVisitor v, ApiElement el);

  /** Start recursively walking the fence tree. */
  public final void visit(FenceVisitor v) {
    visit(v, ApiElement.DEFAULT_PACKAGE);
  }


  private static String trimMinimalWhitespaceFromAllLines(String s) {
    // Strings that appear in XML often have a lot of leading whitespace
    // on each line.  Trim off the white-space using the minimal amount of
    // whitespace from the second-and subsequent lines as a guide.
    String[] lines = s.split("\n|\r\n?");
    int minWhitespace = Integer.MAX_VALUE;
    int nLines = lines.length;
    for (int j = 1; j < nLines; ++j) {
      int leadingWhitespace = 0;
      String line = lines[j];
      int n = line.length();
      for (int i = 0; i < n; ++i) {
        int spaceWidth = spaceWidthOf(line.charAt(i));
        if (spaceWidth == 0) { break; }
        leadingWhitespace += spaceWidth;
      }
      minWhitespace = Math.min(minWhitespace, leadingWhitespace);
    }
    if (minWhitespace == 0) { return s; }
    for (int j = nLines; --j >= 0;) {
      int nToTrim = minWhitespace;
      String line = lines[j];
      int trimPt = 0;
      int n = line.length();
      while (trimPt < n && nToTrim > 0) {
        int spaceWidth = spaceWidthOf(line.charAt(trimPt));
        if (spaceWidth == 0 || spaceWidth > nToTrim) {
          break;
        }
        nToTrim -= spaceWidth;
        ++trimPt;
      }
      lines[j] = line.substring(trimPt);
    }
    return Joiner.on('\n').join(lines);
  }

  private static int spaceWidthOf(char ch) {
    if (ch == ' ') { return 1; }
    if (ch == '\t') { return 8; }
    return 0;
  }
}