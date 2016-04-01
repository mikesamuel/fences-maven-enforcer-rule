package com.google.security.fences;

/** Utilities relating to system properties relevant to this project. */
public final class RelevantSystemProperties {

  /**
   * When a property with this name is set, the rule will dump the
   * effective policy configuration XML to the log file.
   */
  public static final String PROPERTY_SHOW_EFFECTIVE_CONFIG =
      "fences.config.show";

  /**
   * When a property with this name is set, the rule will warn instead of
   * {@linkplain org.apache.maven.plugin.logging.Log#error erroring}
   * when a relaxing of a policy would cause the rule to pass.
   * <p>
   * This does not prevent erroring due to a missing dependency, error
   * in parsing the configuration, or exception during rule evaluation.
   * Use {@code enforcer.skip} for that.
   */
  public static final String PROPERTY_EXPERIMENTAL_MODE = "fences.experimental";

  /**
   * True to dump the effective policy configuration to the log.
   */
  public static boolean shouldShowEffectiveConfig() {
    return System.getProperty(PROPERTY_SHOW_EFFECTIVE_CONFIG) != null;
  }

  /**
   * True when we should warn instead of
   * {@linkplain org.apache.maven.plugin.logging.Log#error erroring}
   * when a relaxing of a policy would cause the rule to pass.
   */
  public static boolean inExperimentalMode() {
    return System.getProperty(PROPERTY_EXPERIMENTAL_MODE) != null;
  }
}
