package com.google.security.fences.config;

import java.util.List;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
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

    for (Fence splitChild : newChildren) {
      if (splitChild instanceof ClassFence) {
        classes.add((ClassFence) splitChild);
      } else if (splitChild instanceof ConstructorFence) {
        constructors.add((ConstructorFence) splitChild);
      } else if (splitChild instanceof MethodFence) {
        methods.add((MethodFence) splitChild);
      } else if (splitChild instanceof FieldFence) {
        fields.add((FieldFence) splitChild);
      } else {
        throw new IllegalArgumentException(splitChild.getClass().getName());
      }
    }
  }

  @Override
  public Fence splitDottedNames() {
    ImmutableList.Builder<Fence> splitChildren = ImmutableList.builder();
    for (Fence unsplitChild : getChildFences()) {
      splitChildren.add(unsplitChild.splitDottedNames());
    }
    replaceChildFences(splitChildren.build());

    String[] nameParts = this.getName().split("[.]");
    if (nameParts.length == 1) {
      return this;
    } else {
      assert nameParts.length >= 2;
      int i = nameParts.length - 1;
      setName(nameParts[i]);
      Fence f = this;
      while (--i >= 0) {
        PackageFence pkgFence = new PackageFence();
        pkgFence.setName(nameParts[i]);
        if (f instanceof ClassFence) {
          pkgFence.setClass((ClassFence) f);
        } else {
          pkgFence.setPackage((PackageFence) f);
        }
        f = pkgFence;
      }
      return f;
    }
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