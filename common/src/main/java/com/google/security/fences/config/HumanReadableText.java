package com.google.security.fences.config;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;

/**
 * A chunk of human readable text broken up into paragraphs.
 */
public final class HumanReadableText {
  /** The text. */
  public final String text;

  /** A value with text "". */
  public static final HumanReadableText EMPTY = new HumanReadableText("");

  HumanReadableText(String text) {
    this.text = Preconditions.checkNotNull(text);
  }

  /** True if the text is empty. */
  public boolean isEmpty() {
    return text.isEmpty();
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof HumanReadableText)) { return false; }
    return this.text.equals(((HumanReadableText) o).text);
  }

  @Override
  public int hashCode() {
    return text.hashCode();
  }

  @Override
  public String toString() {
    return text;
  }

  private static final String PARAGRAPH_SEPARATOR = "\n\n";

  /**
   * Strips leading white-space for a string that is indented within a larger
   * XML document.
   *
   * @param s the content of an XML text node.
   */
  public static HumanReadableText fromXmlTextNode(String s) {
    List<String> lines = linesFromXmlTextNode(s);
    if (lines.isEmpty()) { return EMPTY; }
    return new HumanReadableText(Joiner.on('\n').join(lines));
  }


  /**
   * Split lines and trim off the white-space using the minimal amount of
   * whitespace from the second-and subsequent lines as a guide.
   * <p>
   * Strings that appear in XML often have a lot of leading whitespace
   * on each line.
   */
  static List<String> linesFromXmlTextNode(String s) {
    String[] lines = s.replaceAll("\u2029", PARAGRAPH_SEPARATOR)
        .split("[\n\u2028]|\r\n?");
    int minWhitespace = Integer.MAX_VALUE;
    int nLines = lines.length;
    for (int j = 1; j < nLines; ++j) {
      int leadingWhitespace = 0;
      String line = lines[j];
      if (line.trim().isEmpty()) { continue; }
      int n = line.length();
      for (int i = 0; i < n; ++i) {
        int spaceWidth = spaceWidthOf(line.charAt(i));
        if (spaceWidth == 0) { break; }
        leadingWhitespace += spaceWidth;
      }
      minWhitespace = Math.min(minWhitespace, leadingWhitespace);
    }
    if (minWhitespace == 0) {
      return ImmutableList.copyOf(Arrays.asList(lines));
    }
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
    ImmutableList.Builder<String> trimmedLines = ImmutableList.builder();
    boolean hasOne = false;
    for (String line : lines) {
      if (!hasOne && "".equals(line)) { continue; }
      trimmedLines.add(line);
      hasOne = true;
    }
    return trimmedLines.build();
  }


  private static int spaceWidthOf(char ch) {
    if (ch == ' ') { return 1; }
    if (ch == '\t') { return 8; }
    return 0;
  }

  /**
   * The concatenation of this and that with a paragraph separator in between.
   */
  public HumanReadableText concat(HumanReadableText that) {
    if (that.isEmpty()) { return this; }
    if (this.isEmpty()) { return that; }
    return new HumanReadableText(this.text + PARAGRAPH_SEPARATOR + that.text);
  }

  /**
   * Concatenates making a best effort to be associative so that
   * <blockquote>
   *   concatDedupe(concatDedupe("Paragraph1", "Paragraph1"), "Paragraph2")
   * </blockquote>
   * is equivalent to
   * <blockquote>
   *   concatDedupe("Paragraph1", concatDedupe("Paragraph1", "Paragraph2"))
   * </blockquote>
   * and does not contain unnecessary duplication.
   */
  public HumanReadableText concatDedupe(HumanReadableText that) {
    // Handle split edge cases first since split never produces the empty array.
    if (that.isEmpty() || this.equals(that)) { return this; }
    if (this.isEmpty()) { return that; }

    Set<String> paragraphs = Sets.newLinkedHashSet();
    paragraphs.addAll(Arrays.asList(this.text.split(PARAGRAPH_SEPARATOR)));
    paragraphs.addAll(Arrays.asList(that.text.split(PARAGRAPH_SEPARATOR)));

    return new HumanReadableText(
        Joiner.on(PARAGRAPH_SEPARATOR).join(paragraphs));
  }

}
