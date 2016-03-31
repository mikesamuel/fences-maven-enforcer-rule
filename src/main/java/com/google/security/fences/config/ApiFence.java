package com.google.security.fences.config;

import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.security.fences.policy.ApiElement;

/** An unnammed collection of fences. */
public final class ApiFence extends Fence {
  private final List<PackageFence> packages = Lists.newArrayList();
  private final List<ClassFence> classes = Lists.newArrayList();

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setPackage(PackageFence x) {
    packages.add(Preconditions.checkNotNull(x));
  }

  /**
   * A setter called by reflection during rule configuration.  Actually adds
   * instead of blowing away prior value.
   */
  public void setClass(ClassFence x) {
    classes.add(Preconditions.checkNotNull(x));
  }

  ImmutableList<PackageFence> getPackages() {
    return ImmutableList.copyOf(packages);
  }

  ImmutableList<ClassFence> getClasses() {
    return ImmutableList.copyOf(classes);
  }

  @Override
  public Iterable<Fence> getChildFences() {
    return ImmutableList.<Fence>builder()
        .addAll(packages)
        .addAll(classes)
        .build();
  }

  @Override
  void visit(FenceVisitor v, ApiElement el) {
    // ApiFence should not be a child of another fence.
    Preconditions.checkArgument(el.equals(ApiElement.DEFAULT_PACKAGE));
    v.visit(this, ApiElement.DEFAULT_PACKAGE);
    for (Fence child : getChildFences()) {
      child.visit(v, ApiElement.DEFAULT_PACKAGE);
    }
  }

  @Override
  public ApiFence splitDottedNames() {
    ImmutableList.Builder<Fence> splitChildren = ImmutableList.builder();
    for (Fence unsplitChild : getChildFences()) {
      splitChildren.add(unsplitChild.splitDottedNames());
    }
    replaceChildFences(splitChildren.build());
    return this;
  }

  @Override
  void replaceChildFences(Iterable<? extends Fence> newChildren) {
    packages.clear();
    classes.clear();
    for (Fence newChild : newChildren) {
      if (newChild instanceof PackageFence) {
        packages.add((PackageFence) newChild);
      } else if (newChild instanceof ClassFence) {
        classes.add((ClassFence) newChild);
      } else if (newChild instanceof ApiFence) {
        ApiFence apiChild = (ApiFence) newChild;
        mergeFrom(apiChild);
        packages.addAll(apiChild.packages);
        classes.addAll(apiChild.classes);
      } else {
        throw new IllegalArgumentException(newChild.getClass().getName());
      }
    }
  }

  @Override
  String getKey() {
    return "";
  }

  /**
   * Creates an XML tree that should plexus-configure to an equivalent Fence.
   */
  public final Element buildEffectiveConfiguration()
  throws ParserConfigurationException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    Document doc = factory.newDocumentBuilder().newDocument();
    Element el = doc.createElement(getConfigurationElementName());
    fleshOutEffectiveConfiguration(el);
    return el;
  }

  @Override
  String getConfigurationElementName() {
    return "api";
  }

  @Override
  public ApiFence promoteToApi() {
    return this;
  }
}
