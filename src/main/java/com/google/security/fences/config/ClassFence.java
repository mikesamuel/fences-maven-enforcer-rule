package com.google.security.fences.config;

import java.util.List;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.policy.ApiElementType;

/** A fence for a class. */
public final class ClassFence extends NamedFence {
  private final List<ClassFence> classes = Lists.newArrayList();
  private final List<ConstructorFence> constructors = Lists.newArrayList();
  private final List<MethodFence> methods = Lists.newArrayList();
  private final List<FieldFence> fields = Lists.newArrayList();

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) {
    classes.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setConstructor(ConstructorFence x) {
    constructors.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setMethod(MethodFence x) {
    methods.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setField(FieldFence x) {
    fields.add(Preconditions.checkNotNull(x));
  }

  @Override
  public Iterable<Fence> getChildFences() {
    return ImmutableList.<Fence>builder()
        .addAll(classes)
        .addAll(constructors)
        .addAll(methods)
        .addAll(fields)
        .build();
  }

  @Override
  void visit(FenceVisitor v, ApiElement el) {
    String name = getName();
    ApiElement classEl = el.child(name, ApiElementType.CLASS);
    v.visit(this, classEl);
    for (Fence child : getChildFences()) {
      child.visit(v, classEl);
    }
  }

  @Override
  void replaceChildFences(Iterable<? extends Fence> newChildren) {
    this.classes.clear();
    this.constructors.clear();
    this.methods.clear();
    this.fields.clear();

    for (Fence newChild : newChildren) {
      if (newChild instanceof ClassFence) {
        classes.add((ClassFence) newChild);
      } else if (newChild instanceof ConstructorFence) {
        constructors.add((ConstructorFence) newChild);
      } else if (newChild instanceof MethodFence) {
        methods.add((MethodFence) newChild);
      } else if (newChild instanceof FieldFence) {
        fields.add((FieldFence) newChild);
      } else {
        throw new IllegalArgumentException(newChild.getClass().getName());
      }
    }
  }

  @Override
  public Fence splitDottedNames(ApiElement parentEl, InheritanceGraph g)
  throws EnforcerRuleException {
    String partiallyQualifiedName = Preconditions.checkNotNull(getName());
    ClassNameDisambiguator dis = new ClassNameDisambiguator(
        g, partiallyQualifiedName);

    Optional<ApiElement> unambiguous = dis.resolve(parentEl);
    if (!unambiguous.isPresent()) {
      throw new EnforcerRuleException(
          "Cannot find a class on the class path corresponding to `"
          + partiallyQualifiedName
          + "` in `" + parentEl.toInternalName());
    }

    ApiElement el = unambiguous.get();
    Preconditions.checkState(el.type == ApiElementType.CLASS, el);

    ImmutableList.Builder<Fence> splitChildren = ImmutableList.builder();
    for (Fence unsplitChild : getChildFences()) {
      splitChildren.add(unsplitChild.splitDottedNames(el, g));
    }
    replaceChildFences(splitChildren.build());

    setName(el.name);
    Fence f = this;

    for (ApiElement anc = el.parent.get();
         !anc.equals(parentEl);
         anc = anc.parent.get()) {
      String partName = anc.name;
      switch (anc.type) {
        case CLASS:
          ClassFence classFence = new ClassFence();
          classFence.setName(partName);
          classFence.setClass((ClassFence) f);
          f = classFence;
          continue;
        case PACKAGE:
          PackageFence pkgFence = new PackageFence();
          pkgFence.setName(partName);
          if (f instanceof ClassFence) {
            pkgFence.setClass((ClassFence) f);
          } else {
            pkgFence.setPackage((PackageFence) f);
          }
          f = pkgFence;
          continue;
        case METHOD: case FIELD: case CONSTRUCTOR:
          break;
      }
      throw new AssertionError(anc.type);
    }
    return f;
  }

  @Override
  String getConfigurationElementName() {
    return "class";
  }

  @Override
  public ApiFence promoteToApi() {
    ApiFence api = new ApiFence();
    api.setClass(this);
    return api;
  }
}