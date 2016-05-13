package com.google.security.fences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.maven.plugin.logging.Log;

import org.codehaus.plexus.interpolation.InterpolationException;
import org.codehaus.plexus.interpolation.Interpolator;
import org.codehaus.plexus.interpolation.MapBasedValueSource;
import org.codehaus.plexus.interpolation.ObjectBasedValueSource;
import org.codehaus.plexus.interpolation.RegexBasedInterpolator;
import org.codehaus.plexus.interpolation.ValueSource;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.security.fences.config.HumanReadableText;

/**
 * Groups a collection of violations so that we can provide succinct, clear
 * error messages.
 */
final class PolicyViolationReporter {
  final Log log;
  final Interpolator interpolator;

  PolicyViolationReporter(Log log) {
    this.log = log;
    this.interpolator = new RegexBasedInterpolator();
  }

  /**
   * Reports the violations to the log.
   *
   * @return non-zero iff there was a violation.
   */
  int report(ImmutableList<Violation> violations) {
    int errorCount = violations.size();
    // Probably overly paranoid given ints are always 32b.
    if (!(violations.isEmpty() ? errorCount == 0 : errorCount > 0)) {
      // Causing the error counter to overflow should not spuriously report
      // compliance.
      errorCount = Integer.MAX_VALUE;
    }
    if (errorCount == 0) {
      log.info("No access policy violations");
      return 0;
    }

    List<Violation> violationsInOrder = new ArrayList<Violation>(violations);
    // Sorting lets us group things into a nice, neat form.
    Collections.sort(violationsInOrder);
    ImmutableList<Violation> violationList = ImmutableList.copyOf(
        violationsInOrder);

    ReportTree t = groupByArtifactAndReport(violationList);
    String logMessage = t.toLogMessage();
    if (RelevantSystemProperties.inExperimentalMode()) {
      log.warn(logMessage);
    } else {
      log.error(logMessage);
    }

    Preconditions.checkState(errorCount > 0);
    return errorCount;
  }

  /**
   * Expands plexus interpolator expressions in {@code <rationale>} messages.
   */
  private Optional<String> formatRationale(Violation v) {
    HumanReadableText wholeRationale = v.rationale.getWholeText();
    if (wholeRationale.isEmpty()) {
      return Optional.absent();
    }
    ValueSource artifactValueSource = new ObjectBasedValueSource(v.artifact);
    ValueSource failedAccessValueSource = new MapBasedValueSource(
        ImmutableMap.of(
            "fences.api", v.useSiteApiElement.toDottedName(),
            "fences.distrusted", v.useSiteContainer));
    interpolator.addValueSource(artifactValueSource);
    interpolator.addValueSource(failedAccessValueSource);
    String rationaleText = wholeRationale.text;
    try {
      rationaleText = interpolator.interpolate(rationaleText);
    } catch (InterpolationException ex) {
      log.warn(ex);
    } finally {
      interpolator.removeValuesSource(failedAccessValueSource);
      interpolator.removeValuesSource(artifactValueSource);
    }
    return Optional.of(rationaleText);
  }

  private static ImmutableList<ReportTree> group(
      Function<Violation, String> getGroup,
      Function<ImmutableList<Violation>, ImmutableList<ReportTree>> descend,
      ImmutableList<Violation> violations) {
    int n = violations.size();
    if (n == 0) {
      return ImmutableList.of();
    }
    ImmutableList.Builder<ReportTree> groups = ImmutableList.builder();
    for (int i = 0, groupEnd; i < n; i = groupEnd) {
      String group = getGroup.apply(violations.get(i));
      for (groupEnd = i + 1; groupEnd < n; ++groupEnd) {
        String g = getGroup.apply(violations.get(groupEnd));
        if (!group.equals(g)) {
          break;
        }
      }
      ReportTree t = new ReportTree(group);
      t.children.addAll(descend.apply(violations.subList(i, groupEnd)));
      groups.add(t);
    }
    return groups.build();
  }

  private ReportTree groupByArtifactAndReport(
      ImmutableList<Violation> violations) {
    ReportTree root = new ReportTree("");
    root.children.addAll(group(
        new Function<Violation, String>() {
          @Override
          public String apply(Violation v) {
            return v.artifact.getId();
          }
        },
        new Function<ImmutableList<Violation>, ImmutableList<ReportTree>>() {
          @Override
          @SuppressWarnings("synthetic-access")
          public ImmutableList<ReportTree> apply(
              ImmutableList<Violation> vs) {
            return groupByUseSiteSource(vs);
          }
        },
        violations));
    return root;
  }

  private ImmutableList<ReportTree> groupByUseSiteSource(
      ImmutableList<Violation> violations) {
    return group(
        new Function<Violation, String>() {
          @Override
          public String apply(Violation v) {
            return v.useSiteSource;
          }
        },
        new Function<ImmutableList<Violation>, ImmutableList<ReportTree>>() {
          @Override
          @SuppressWarnings("synthetic-access")
          public ImmutableList<ReportTree> apply(ImmutableList<Violation> vs) {
            return groupByUseSiteLine(vs);
          }
        },
        violations);
  }

  private ImmutableList<ReportTree> groupByUseSiteLine(
      ImmutableList<Violation> violations) {
    return group(
        new Function<Violation, String>() {
          @Override
          public String apply(Violation v) {
            return v.useSiteLineNumber < 0 ? "" : "L" + v.useSiteLineNumber;
          }
        },
        new Function<ImmutableList<Violation>, ImmutableList<ReportTree>>() {
          @Override
          @SuppressWarnings("synthetic-access")
          public ImmutableList<ReportTree> apply(ImmutableList<Violation> vs) {
            return formatViolations(vs);
          }
        },
        violations);
  }

  private ImmutableList<ReportTree> formatViolations(
      ImmutableList<Violation> violations) {
    Map<String, Integer> errorMessages = Maps.newLinkedHashMap();
    Set<String> rationales = Sets.newLinkedHashSet();
    for (Violation v : violations) {
      String message =
          v.useSiteApiElement.toDottedName() + " cannot be accessed from "
          + v.useSiteContainer;
      if (!v.sensitiveApiElement.equals(v.useSiteApiElement)) {
        message += " because " + v.sensitiveApiElement.toDottedName()
            + " is restricted";
      }
      Optional<String> rationale = formatRationale(v);
      Integer priorCount = errorMessages.get(message);
      errorMessages.put(message, 1 + (priorCount != null ? priorCount : 0));
      if (rationale.isPresent()) {
        rationales.add(rationale.get());
      }
    }
    ImmutableList.Builder<ReportTree> leaves = ImmutableList.builder();
    for (Map.Entry<String, Integer> e : errorMessages.entrySet()) {
      String message = e.getKey();
      int count = e.getValue();
      if (count != 1) {
        message += " (" + count + " times)";
      }
      leaves.add(new ReportTree(message));
    }
    for (String rationale : rationales) {
      leaves.add(new ReportTree(rationale));
    }
    return leaves.build();
  }

  /**
   * A tree used to avoid having large numbers of similar policy violations
   * using a lot of boilerplate like
   *
   * <pre>
   * group:artifact:version : OneSourceFile.java : L32 : blah blah
   * group:artifact:version : OneSourceFile.java : L32 : more blah
   * group:artifact:version : AnotherSourceFile.java : L32 : blah blah
   * group:artifact:version : AnotherSourceFile.java : L33 : blah blah
   * group:artifact:version : AnotherSourceFile.java : L33 : more blah
   * </pre>
   *
   * but instead produces
   *
   * <pre>
   * group:artifact:version
   * . OneSourceFile.java : L32
   * . . blah blah
   * . . more blah
   * . AnotherSourceFile.java
   * . . L32 : blah blah
   * . . L33
   * . . . blah blah
   * . . . more blah
   * </pre>
   */
  static final class ReportTree {
    final List<ReportTree> children;
    final String text;

    ReportTree(String text) {
      this(text, Lists.<ReportTree>newArrayList());
    }

    ReportTree(String text, List<ReportTree> children) {
      this.text = text;
      this.children = children;
    }

    String toLogMessage() {
      StringBuilder sb = new StringBuilder();
      appendLogMessage(0, sb);
      return sb.toString();
    }

    private void appendLogMessage(int depth, StringBuilder sb) {
      // Don't nest unless there are multiple children.
      if (children.size() == 1) {
        ReportTree soleChild = children.get(0);
        if (!"".equals(text)) {
          String combinedText = text;
          if (!"".equals(soleChild.text)) {
            combinedText += " : " + soleChild.text;
            soleChild = new ReportTree(combinedText, soleChild.children);
          }
        }
        soleChild.appendLogMessage(depth, sb);
        return;
      }

      int childDepth = depth;
      boolean newLineBeforeChild = false;
      if (!"".equals(text)) {
        newLineBeforeChild = true;
        ++childDepth;

        int prefixStart = sb.length();
        for (int i = 0; i < depth; ++i) {
          sb.append(". ");
        }
        String indentedText = text;
        String[] lines = text.split("\r\n?|\n");
        if (lines.length != 1) {
          String prefix = sb.substring(prefixStart);
          indentedText = Joiner.on("\n" + prefix).join(lines);
        }
        sb.append(indentedText);
      }
      for (ReportTree child : children) {
        if (newLineBeforeChild) {
          sb.append('\n');
        } else {
          newLineBeforeChild = true;
        }
        child.appendLogMessage(childDepth, sb);
      }
    }
  }
}
