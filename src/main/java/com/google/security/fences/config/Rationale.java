package com.google.security.fences.config;

import java.util.List;

import com.google.common.base.Objects;
import com.google.common.collect.ImmutableList;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.codehaus.plexus.interpolation.InterpolationException;
import org.codehaus.plexus.interpolation.RegexBasedInterpolator;
import org.codehaus.plexus.interpolation.ValueSource;


/**
 * Human-readable text explaining the reason for a policy decision.
 */
public final class Rationale {
  /** An {@linkplain #isEmpty empty} instance. */
  public static final Rationale EMPTY = new Rationale(
      HumanReadableText.EMPTY, HumanReadableText.EMPTY);

  /**
   * Human-readable text specifying the reason for a policy decision.
   * <p>
   * These may be overridden by other rationales.  When a <tt>.pom</tt> file
   * or <tt>META-INF/fences.xml</tt> file imports another, then its
   * {@code <rationale />}s clobber any from the imported file on the same
   * API element.
   */
  public final HumanReadableText body;
  /**
   * Human-readable text specifying how to get answers about a policy decision.
   * <p>
   * These are appended to the body to come up with the whole rationale, and
   * addenda are not overridden.
   */
  public final HumanReadableText addendum;

  /** ctor */
  public Rationale(HumanReadableText body, HumanReadableText addendum) {
    this.body = body;
    this.addendum = addendum;
  }

  /** True iff there is no text in this rationale. */
  public boolean isEmpty() {
    return body.isEmpty() && addendum.isEmpty();
  }

  /**
   * The whole human readable text.
   */
  public HumanReadableText getWholeText() {
    return body.concat(addendum);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(body, addendum);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Rationale)) {
      return false;
    }
    Rationale that = (Rationale) o;
    return this.body.equals(that.body) && this.addendum.equals(that.addendum);
  }

  /**
   * Mutable builder for {@link Rationale}s.
   */
  public static final class Builder {
    /**
     * Lines of human-readable text specifying the reason for a policy decision.
     * <p>
     * These may be overridden by other rationales.  When a <tt>.pom</tt> file
     * or <tt>META-INF/fences.xml</tt> file imports another, then its
     * {@code <rationale />}s clobber any from the imported file on the same
     * API element.
     */
    private HumanReadableText body = HumanReadableText.EMPTY;
    /**
     * Lines of human-readable text specifying how to get answers about a policy
     * decision.
     * <p>
     * These are appended to the body to come up with the whole rationale, and
     * addenda are not overridden.
     */
    private HumanReadableText addendum = HumanReadableText.EMPTY;

    /**
     * Adds a rationale body parsed from an element in a plexus
     * {@code <configuration />}.
     * <p>
     * This may be called multiple times, so
     * <pre>
     *   &lt;rationale&gt;line 1&lt;/rationale&gt;
     *   &lt;rationale&gt;line 2&lt;/rationale&gt;
     * </pre>
     * is equivalent to
     * <pre>
     *   &lt;rationale&gt;
     *     line 1
     *     line 2
     *   &lt;/rationale&gt;
     * </pre>
     */
    public Builder addBody(String xmlTextNodeContent)
    throws EnforcerRuleException {
      return addBody(HumanReadableText.fromXmlTextNode(xmlTextNodeContent));
    }

    /**
     * Adds text to the body.
     * This concatenates the new body after the previous body.
     *
     * @throws EnforcerRuleException if the concatenated body contains a
     *     malformed Plexus interpolator expression.
     */
    public Builder addBody(HumanReadableText newBody)
    throws EnforcerRuleException {
      body = body.concat(checkInterpolatable(newBody));
      return this;
    }

    /**
     * Concatenates r's body after the body thus far.
     */
    public Builder addBodyFrom(Rationale r) {
      try {
        return addBody(r.body);
      } catch (EnforcerRuleException ex) {
        throw new AssertionError(null, ex);
      }
    }

    /**
     * Replaces this builder's
     */
    public Builder setBodyFrom(Rationale r) {
      this.body = r.body;
      return this;
    }

    /**
     * Adds an addendum parsed from a plexus {@code <configuration />}.
     * <p>
     * This may be called multiple times, so
     * <pre>
     *   &lt;addendum&gt;line 1&lt;/addendum&gt;
     *   &lt;addendum&gt;line 2&lt;/addendum&gt;
     * </pre>
     * is equivalent to
     * <pre>
     *   &lt;addendum&gt;
     *     line 1
     *     line 2
     *   &lt;/addendum&gt;
     * </pre>
     */
    public Builder addAddendum(String xmlTextNodeContent)
    throws EnforcerRuleException {
      return addAddendum(HumanReadableText.fromXmlTextNode(xmlTextNodeContent));
    }

    /**
     * Adds text to the addendum.
     * This concatenates the new addendum after the previous addendum.
     *
     * @throws EnforcerRuleException if the concatenated body contains a
     *     malformed Plexus interpolator expression.
     */
    public Builder addAddendum(HumanReadableText newAddendum)
    throws EnforcerRuleException {
      addendum = addendum.concat(checkInterpolatable(newAddendum));
      return this;
    }

    /**
     * Concatenates r's addendum after the addendum thus far.
     */
    public Builder addAddendumFrom(Rationale r) {
      try {
        return addAddendum(r.addendum);
      } catch (EnforcerRuleException ex) {
        throw new AssertionError(null, ex);
      }
    }

    /** The body so far. */
    public HumanReadableText getBody() {
      return body;
    }

    /** The addendum so far. */
    public HumanReadableText getAddendum() {
      return addendum;
    }

    private static HumanReadableText checkInterpolatable(HumanReadableText t)
    throws EnforcerRuleException {
      // Try to pre-validate it as a valid plexus expression?
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
        interpolator.interpolate(t.text);
      } catch (InterpolationException ex) {
        throw new EnforcerRuleException(
            "Malformed property expression in: " + t.text, ex);
      }
      return t;
    }

    /**
     * The immutable instance corresponding to the set of mutating calls thus
     * far.
     */
    public Rationale build() {
      if (body.isEmpty() && addendum.isEmpty()) {
        return Rationale.EMPTY;
      }
      return new Rationale(body, addendum);
    }
  }

  /**
   * Makes a best effort like {@link HumanReadableText#concatDedupe}.
   */
  public static Rationale merge(Rationale a, Rationale b) {
    if (b.isEmpty() || a.equals(b)) { return a; }
    if (a.isEmpty()) { return b; }
    return new Rationale(
        a.body.concatDedupe(b.body),
        a.addendum.concatDedupe(b.addendum));
  }
}

