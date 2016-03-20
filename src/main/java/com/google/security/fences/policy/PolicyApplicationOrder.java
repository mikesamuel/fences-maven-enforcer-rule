package com.google.security.fences.policy;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.PriorityQueue;
import java.util.Set;

import org.apache.maven.plugin.logging.Log;
import org.objectweb.asm.Opcodes;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import com.google.security.fences.inheritance.ClassNode;
import com.google.security.fences.inheritance.FieldDetails;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.inheritance.MethodDetails;
import com.google.security.fences.util.LazyString;

/**
 * A series of API elements from most-specific to less-specific, honoring has-a
 * and is-a relationships, that can be used in making policy decisions.
 *
 * @see <a href="http://github.com/mikesamuel/fences-maven-enforcer-rule/blob/master/src/site/markdown/policies.md">policies docs</a>
 */
public final class PolicyApplicationOrder implements Iterable<ApiElement> {
  private final ApiElement used;
  private final String descriptor;
  private final InheritanceGraph inheritanceGraph;
  private final Log log;

  /**
   * @param used The use API element.
   * @param descriptor The descriptor for used.  When the API element is a
   *     method, then this must be a JVM method descriptor.
   * @param inheritanceGraph Used to resolve super-types, interfaces, and
   *     method and field declarations.
   * @param log Receives debug and informational messages.
   */
  public PolicyApplicationOrder(
      ApiElement used,
      String descriptor,
      InheritanceGraph inheritanceGraph,
      Log log) {
    Preconditions.checkArgument(
        used.type == ApiElementType.CONSTRUCTOR
        || used.type == ApiElementType.FIELD
        || used.type == ApiElementType.METHOD);
    this.used = used;
    this.descriptor = descriptor;
    this.inheritanceGraph = inheritanceGraph;
    this.log = log;
  }

  public Iterator<ApiElement> iterator() {
    return new ApiElementIterator();
  }

  /** An item on one of the sub lists. */
  private static final class QueueItem {
    final ApiElement el;
    /**
     * True iff we should avoid enqueuing API elements for non-abstract methods
     * because a higher priority item overrode them.
     * <p>
     * We treat methods with bodies as implementing abstract declarations,
     * and overriding other methods with bodies.  We skip overridden methods
     * but not implemented declarations.
     */
    final boolean onlyAbstract;
    /**
     * True to skip this item and use it only as a placeholder for its
     * successor queue items.
     */
    final boolean skip;

    QueueItem(ApiElement el) {
      this(el, false, false);
    }

    QueueItem(ApiElement el, boolean onlyAbstract, boolean skip) {
      this.el = el;
      this.onlyAbstract = onlyAbstract;
      this.skip = skip;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof QueueItem)) {
        return false;
      }
      QueueItem that = (QueueItem) o;
      return this.el.equals(that.el)
          && this.onlyAbstract == that.onlyAbstract
          && this.skip == that.skip;
    }

    @Override
    public int hashCode() {
      return el.hashCode()
          ^ (onlyAbstract ? 1 : 0)
          ^ (skip ? 2 : 0);
    }

    @Override
    public String toString() {
      return "[QueueItem " + el + (onlyAbstract ? " onlyAbstract" : "") + "]";
    }
  }

  @SuppressWarnings("synthetic-access")
  final class ApiElementIterator implements Iterator<ApiElement> {
    /** Non-empty sublists in order of priority. */
    private final PriorityQueue<SubList> sublists
        = new PriorityQueue<SubList>();
    /**
     * Items that have already been enqueued and so which need not be revisited.
     */
    private final Set<QueueItem> enqueued = Sets.newHashSet();
    /**
     * Items that have been produced.  This is distinct from enqueued since
     * a given element might be visited in multiple contexts
     * (like {@link QueueItem#onlyAbstract}) when a given super-type is reached
     * via multiple paths.  This frequently happens with
     * {@code java/lang/Object} which is the super-type of interfaces as well
     * as the tail of all class inheritance chains.
     */
    private final Set<ApiElement> produced = Sets.newHashSet();

    /** Null, or the next item, or when consumed the last item. */
    private QueueItem pending;
    /** The sublist from which pending was dequeued. */
    private SubList source;
    /**
     * Whether next() has advanced past pending.
     * If this is false and another next is requested we still need to query
     * source for lower priority items derived from pending.
     */
    private boolean consumed;

    /** The sub list that contains the actual use. */
    private final SubList useOnly = new SubList(0) {
      @Override
      void addLowerPrecedenceItems(QueueItem item) {
        addCorrespondingMembers(item, true);
      }
    };

    private final SubList superTypeMembers = new SubList(1) {
      @Override
      void addLowerPrecedenceItems(QueueItem item) {
        addCorrespondingMembers(item, false);
      }
    };

    private final SubList interfaceMethods = new SubList(2) {
      @Override
      void addLowerPrecedenceItems(QueueItem item) {
        addCorrespondingMembers(item, false);
      }
    };

    private final SubList classes = new SubList(3) {
      @Override
      void addLowerPrecedenceItems(QueueItem item) {
        addOuterClassesAndPackages(item);
      }
    };

    private final SubList interfaces = new SubList(4) {
      @Override
      void addLowerPrecedenceItems(QueueItem item) {
        addOuterClassesAndPackages(item);
      }
    };

    private final SubList outerClasses = new SubList(5) {
      @Override
      void addLowerPrecedenceItems(QueueItem item) {
        addOuterClassesAndPackages(item);
      }
    };

    private final SubList packages = new SubList(6) {
      @Override
      void addLowerPrecedenceItems(QueueItem item) {
        addSuperPackages(item);
      }
    };

    {
      // Initialize the lists.
      ApiElement el = PolicyApplicationOrder.this.used;
      useOnly.add(new QueueItem(el));
    }

    public boolean hasNext() {
      update();
      return pending != null;
    }

    public ApiElement next() {
      update();
      consumed = true;
      if (pending == null) {
        throw new NoSuchElementException();
      }
      return pending.el;
    }

    private void update() {
      while (true) {
        if (pending != null) {
          if (consumed) {
            source.addLowerPrecedenceItems(pending);
            consumed = false;
            source = null;
            pending = null;
          } else {
            return;
          }
        }
        source = sublists.peek();
        if (source == null) {
          break;
        }
        pending = source.removeFirst();
        if (source.isEmpty()) {
          // We keep empty elements out of the pqueue,
          // and let SubList.add put them back on as necessary.
          sublists.poll();
        }
        consumed = !produced.add(pending.el) || pending.skip;
        if (!consumed) {
          break;
        }
      }
    }

    public void remove() {
      throw new UnsupportedOperationException();
    }


    private void addCorrespondingMembers(QueueItem item, boolean isExactUse) {
      ApiElement el = item.el;
      addContainingClass(el);

      String name = el.name;
      Optional<ClassNode> cnOpt = classContaining(el);
      if (cnOpt.isPresent()) {
        ClassNode cn = cnOpt.get();
        switch (el.type) {
          case METHOD:
          {
            Optional<MethodDetails> md = cn.getMethod(name, descriptor);
            boolean onlyAbstract = item.onlyAbstract;
            boolean lookOnSuperClass = true;
            if (md.isPresent()) {
              int access = md.get().access;
              boolean isPrivate = (access & Opcodes.ACC_PRIVATE) != 0;
              boolean isAbstract = (access & Opcodes.ACC_ABSTRACT) != 0;
              if (isPrivate && isExactUse) {
                lookOnSuperClass = false;
              } else if (isAbstract) {
                Preconditions.checkState(!isPrivate);
              } else {
                onlyAbstract = !isPrivate;
              }
            }
            if (lookOnSuperClass) {
              if (cn.superType.isPresent()) {
                ApiElement correspondingApiElement =
                    ApiElement.fromInternalClassName(cn.superType.get())
                    .child(name, ApiElementType.METHOD);

                boolean skip = false;

                Optional<ClassNode> superClassNode = classContaining(
                    correspondingApiElement);
                Optional<MethodDetails> superMethod = Optional.absent();
                if (superClassNode.isPresent()) {
                   superMethod = superClassNode.get().getMethod(
                       name, descriptor);
                }
                int superMethodAccess = 0;
                if (superMethod.isPresent()) {
                  superMethodAccess = superMethod.get().access;
                }

                if ((superMethodAccess & Opcodes.ACC_PRIVATE) != 0) {
                  skip = true;
                } else if (onlyAbstract) {
                  skip = (superMethodAccess & Opcodes.ACC_ABSTRACT) == 0;
                }

                QueueItem correspondingMethod = new QueueItem(
                    correspondingApiElement,
                    onlyAbstract,
                    skip);
                superTypeMembers.add(correspondingMethod);
              }
              for (String interfaceName : cn.interfaces) {
                QueueItem correspondingMethod = new QueueItem(
                    ApiElement.fromInternalClassName(interfaceName)
                    .child(name, ApiElementType.METHOD));
                interfaceMethods.add(correspondingMethod);
              }
            }
            return;
          }
          case FIELD:
            if (cn.superType.isPresent()) {
              Optional<FieldDetails> fd = cn.getField(name);
              boolean lookOnSuperClass;
              if (fd.isPresent()) {
                int access = fd.get().access;
                boolean isPrivate = (access & Opcodes.ACC_PRIVATE) != 0;
                if (isPrivate) {
                  lookOnSuperClass = !isExactUse;
                } else {
                  lookOnSuperClass = false;
                }
              } else {
                lookOnSuperClass = true;
              }
              if (lookOnSuperClass) {
                ApiElement correspondingApiElement =
                    ApiElement.fromInternalClassName(cn.superType.get())
                    .child(name, ApiElementType.FIELD);

                // A private field of the same name does not mask a
                // field declared on a super-type of the super-type.
                Optional<ClassNode> superClassNode = classContaining(
                    correspondingApiElement);
                Optional<FieldDetails> superField = Optional.absent();
                if (superClassNode.isPresent()) {
                   superField = superClassNode.get().getField(name);
                }
                int superFieldAccess = 0;
                if (superField.isPresent()) {
                  superFieldAccess = superField.get().access;
                }
                boolean skip = (superFieldAccess & Opcodes.ACC_PRIVATE) != 0;

                if (cn.superType.isPresent()) {
                  superTypeMembers.add(
                      new QueueItem(
                          correspondingApiElement,
                          false, skip));
                }
              }
            }
            return;
          case CONSTRUCTOR:
            return;
          case CLASS:
          case PACKAGE:
            // Not a use.
            break;
        }
        throw new AssertionError(el.type);
      }
    }


    private void addContainingClass(ApiElement el) {
      ApiElement classEl = el.containingClass().get();

      Optional<ClassNode> cnOpt = classContaining(classEl);
      if (cnOpt.isPresent()) {
        ClassNode cn = cnOpt.get();
        ((cn.access & Opcodes.ACC_INTERFACE) != 0 ? interfaces : classes)
            .add(new QueueItem(classEl));
      }
    }

    private void addOuterClassesAndPackages(QueueItem item) {
      ApiElement el = item.el;
      if (el.parent.isPresent()) {
        ApiElement parent = el.parent.get();
        switch (parent.type) {
          case CLASS:
            this.outerClasses.add(new QueueItem(parent));
            return;
          case PACKAGE:
            this.packages.add(new QueueItem(parent));
            return;
          case FIELD: case METHOD: case CONSTRUCTOR:
            // Not a type.
            break;
        }
        throw new AssertionError(parent.type);
      }
    }

    private void addSuperPackages(QueueItem item) {
      Preconditions.checkArgument(item.el.type == ApiElementType.PACKAGE);
      ApiElement el = item.el;
      if (el.parent.isPresent()) {
        this.packages.add(new QueueItem(el.parent.get()));
      }
    }


    /**
     * A list that is concatenated into the ordering.
     */
    private abstract class SubList implements Comparable<SubList> {
      private final Deque<QueueItem> items = new ArrayDeque<QueueItem>();
      private final int priority;

      SubList(int priority) {
        this.priority = priority;
      }

      QueueItem removeFirst() {
        return items.removeFirst();
      }

      boolean isEmpty() {
        return items.isEmpty();
      }

      abstract void addLowerPrecedenceItems(QueueItem item);

      void add(QueueItem item) {
        if (enqueued.add(item)) {
          boolean wasEmpty = items.isEmpty();
          items.add(item);
          if (wasEmpty) {
            sublists.add(this);
          }
        }
      }

      public int compareTo(SubList ls) {
        return Integer.compare(this.priority, ls.priority);
      }
    }
  }


  private Optional<ClassNode> classContaining(ApiElement el) {
    Optional<ApiElement> elClass = el.containingClass();
    Preconditions.checkState(elClass.isPresent());
    final String elInternalName = elClass.get().toInternalName();
    Optional<ClassNode> cn = inheritanceGraph.named(elInternalName);
    if (!cn.isPresent()) {
      log.debug(new LazyString() {
        @Override
        protected String makeString() {
          return "Did not find node for class " + elInternalName;
        }
      });
    }
    return cn;
  }

  static Optional<ApiElement> apiElementFromSuper(
      ApiElement el, String superTypeName) {
    switch (el.type) {
      case CLASS:
        return Optional.of(ApiElement.fromInternalClassName(superTypeName));
      case CONSTRUCTOR:
      case FIELD:
      case METHOD:
        return Optional.of(
            apiElementFromSuper(el.parent.get(), superTypeName).get()
            .child(el.name, el.type));
      case PACKAGE:
        return Optional.absent();
    }
    throw new AssertionError(el.type);
  }

}
