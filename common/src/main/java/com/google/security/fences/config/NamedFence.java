package com.google.security.fences.config;

import java.util.Locale;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.base.Preconditions;
import com.google.security.fences.util.MisconfigurationException;

abstract class NamedFence extends Fence {
  private String name;

  public String getName() { return name; }

  public void setName(String newName) {
    this.name = Preconditions.checkNotNull(newName);
  }

  @Override
  String getKey() {
    return name;
  }

  @Override
  public void check() throws MisconfigurationException {
    super.check();
    if (name == null) {
      throw new MisconfigurationException(
          getClass().getSimpleName().replaceFirst("Fence$", "")
          .toLowerCase(Locale.ENGLISH)
          + " is missing a name");
    }
  }

  @Override
  public String toString() {
    String type = getClass().getSimpleName().replaceFirst("Fence$", "")
        .toLowerCase(Locale.ENGLISH);
    return "{" + type + " " + name + "}";
  }

  @Override
  void fleshOutEffectiveConfiguration(Element el) {
    Document doc = el.getOwnerDocument();
    Element nameElement = doc.createElement("name");
    nameElement.appendChild(doc.createTextNode(name));
    el.appendChild(nameElement);
    super.fleshOutEffectiveConfiguration(el);
  }
}