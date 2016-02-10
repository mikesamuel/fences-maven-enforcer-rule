package com.google.security.fences;

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
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) {
    classes.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setConstructor(ConstructorFence x) {
    constructors.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setMethod(MethodFence x) {
    methods.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during Mojo configuration.  Actually adds
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
  public Fence splitDottedNames() {
    ImmutableList<Fence> unsplitChildren =
        ImmutableList.copyOf(getChildFences());
    this.classes.clear();
    this.constructors.clear();
    this.methods.clear();
    this.fields.clear();

    for (Fence unsplitChild : unsplitChildren) {
      Fence splitChild = unsplitChild.splitDottedNames();
      if (splitChild instanceof ClassFence) {
        classes.add((ClassFence) splitChild);
      } else if (splitChild instanceof ConstructorFence) {
        constructors.add((ConstructorFence) splitChild);
      } else if (splitChild instanceof MethodFence) {
        methods.add((MethodFence) splitChild);
      } else if (splitChild instanceof FieldFence) {
        fields.add((FieldFence) splitChild);
      } else {
        throw new AssertionError(splitChild.getClass());
      }
    }

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
}