package com.google.security.fences;

import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.List;

import javax.annotation.Nullable;

import org.apache.maven.plugin.logging.Log;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

/**
 * Records
 */
final class RecordingLog implements Log {
  final Log backingLog;
  final List<Entry> entries = Lists.newArrayList();

  RecordingLog(Log backingLog) {
    this.backingLog = backingLog;
  }

  void reset() {
    entries.clear();
  }

  ImmutableList<Entry> getEntriesSinceLastReset() {
    return ImmutableList.copyOf(entries);
  }

  @Override
  public void debug(CharSequence s) {
    backingLog.debug(s);
    entries.add(new Entry(Level.DEBUG, s));
  }

  @Override
  public void debug(Throwable th) {
    backingLog.debug(th);
    entries.add(new Entry(Level.DEBUG, th));
  }

  @Override
  public void debug(CharSequence s, Throwable th) {
    backingLog.debug(s, th);
    entries.add(new Entry(Level.DEBUG, s, th));
  }

  @Override
  public void error(CharSequence s) {
    backingLog.error(s);
    entries.add(new Entry(Level.ERROR, s));
  }

  @Override
  public void error(Throwable th) {
    backingLog.error(th);
    entries.add(new Entry(Level.ERROR, th));
  }

  @Override
  public void error(CharSequence s, Throwable th) {
    backingLog.error(s, th);
    entries.add(new Entry(Level.ERROR, s, th));
  }

  @Override
  public void info(CharSequence s) {
    backingLog.info(s);
    entries.add(new Entry(Level.INFO, s));
  }

  @Override
  public void info(Throwable th) {
    backingLog.info(th);
    entries.add(new Entry(Level.INFO, th));
  }

  @Override
  public void info(CharSequence s, Throwable th) {
    backingLog.info(s, th);
    entries.add(new Entry(Level.INFO, s, th));
  }

  @Override
  public boolean isDebugEnabled() {
    return backingLog.isDebugEnabled();
  }

  @Override
  public boolean isErrorEnabled() {
    return true;
  }

  @Override
  public boolean isInfoEnabled() {
    return backingLog.isInfoEnabled();
  }

  @Override
  public boolean isWarnEnabled() {
    return backingLog.isWarnEnabled();
  }

  @Override
  public void warn(CharSequence s) {
    backingLog.warn(s);
    entries.add(new Entry(Level.WARN, s));
  }

  @Override
  public void warn(Throwable th) {
    backingLog.warn(th);
    entries.add(new Entry(Level.WARN, th));
  }

  @Override
  public void warn(CharSequence s, Throwable th) {
    backingLog.warn(s, th);
    entries.add(new Entry(Level.WARN, s, th));
  }


  enum Level {
    DEBUG,
    INFO,
    WARN,
    ERROR,
    ;
  }


  static final class Entry implements Externalizable {
    private Level level;
    private CharSequence s;
    private Throwable th;

    public Entry() {}

    Entry(Level level, @Nullable CharSequence s) {
      this(level, s, null);
    }

    Entry(Level level, @Nullable Throwable th) {
      this(level, null, th);
    }

    Entry(Level level, @Nullable CharSequence s, @Nullable Throwable th) {
      this.level = Preconditions.checkNotNull(level);
      this.s = s;
      this.th = th;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
      String str = s != null ? s.toString() : null;
      byte[] throwableBytes = null;
      if (th != null) {
        // Throwables are not reliably serializable.
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
          ObjectOutputStream objBytes = new ObjectOutputStream(bytes);
          try {
            objBytes.writeObject(th);
            objBytes.flush();
            throwableBytes = bytes.toByteArray();
          } finally {
            objBytes.close();
          }
        } catch (@SuppressWarnings("unused") IOException ex) {
          if (str == null) {
            str = th.getMessage();
          } else {
            str += " ; " + th.getMessage();
          }
        } finally {
          bytes.close();
        }
      }

      out.writeObject(level);
      out.writeObject(str);
      if (throwableBytes != null) {
        out.write(throwableBytes);
      } else {
        out.writeObject((Throwable) null);
      }
    }

    @Override
    public void readExternal(ObjectInput in)
    throws IOException, ClassNotFoundException {
      this.level = (Level) in.readObject();
      this.s = (CharSequence) in.readObject();
      this.th = (Throwable) in.readObject();
    }

    void apply(Log log) {
      Preconditions.checkState(level != null);
      switch (level) {
        case DEBUG:
          log.debug(s, th);
          return;
        case ERROR:
          log.error(s, th);
          return;
        case INFO:
          log.info(s, th);
          return;
        case WARN:
          log.warn(s, th);
          return;
      }
      throw new AssertionError(level);
    }
  }
}
