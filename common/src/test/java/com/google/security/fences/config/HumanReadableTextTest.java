package com.google.security.fences.config;

import java.util.List;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class HumanReadableTextTest extends TestCase {
  private static void assertTrimmedLines(
      ImmutableList<? extends String> want,
      Iterable<? extends String> input) {
    for (String sep : new String[] { "\n", "\r\n", "\r" }) {
      String inp = Joiner.on(sep).join(input);
      List<String> got = HumanReadableText.linesFromXmlTextNode(inp);
      if (!want.equals(got)) {
        // Nicer diff.
        assertEquals(
            Joiner.on('\n').join(want),
            Joiner.on('\n').join(got));
      }
      assertEquals(want, got);
    }
  }

  public static void testFromXmlTextNode() {
    assertTrimmedLines(
        ImmutableList.<String>of(),
        ImmutableList.of(""));
    assertTrimmedLines(
        ImmutableList.of("Foo"),
        ImmutableList.of("Foo"));
    assertTrimmedLines(
        ImmutableList.of("Foo"),
        ImmutableList.of("  Foo"));
    assertTrimmedLines(
        ImmutableList.of("Foo"),
        ImmutableList.of(
            "",
            "",
            "  Foo"));
    assertTrimmedLines(
        ImmutableList.of(
            "Foo",
            "",
            "Bar"),
        ImmutableList.of(
            "  Foo",
            "",
            "  Bar"));
    assertTrimmedLines(
        ImmutableList.of(
            "Foo",
            "Bar"),
        ImmutableList.of(
            "  Foo",
            "  Bar"));
    assertTrimmedLines(
        ImmutableList.of(
            "Foo",
            "  1. Bar",
            "  2. Baz",
            "Boo"),
        ImmutableList.of(
            "  Foo",
            "    1. Bar",
            "    2. Baz",
            "  Boo"));
    assertTrimmedLines(
        ImmutableList.of(
            "Foo",
            "\t1. Bar",
            "        2. Baz",
            "Boo"),
        ImmutableList.of(
            "\tFoo",  // 1 x TAB = 8 x SPC
            "\t\t1. Bar",
            "                2. Baz",
            "\tBoo"));
  }
}
