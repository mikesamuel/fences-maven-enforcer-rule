package com.google.security.fences.util;

/**
 * Thrown when there is a problem with content received from a rule or plugin
 * configuration.
 */
public class MisconfigurationException extends Exception {
  private static final long serialVersionUID = 8352508127864531032L;

  /**
   * @see java.lang.Exception#Exception(String, Throwable)
   */
  public MisconfigurationException(String msg, Throwable cause) {
    super(msg, cause);
  }

  /**
   * @see java.lang.Exception#Exception(String)
   */
  public MisconfigurationException(String msg) {
    super(msg);
  }
}
