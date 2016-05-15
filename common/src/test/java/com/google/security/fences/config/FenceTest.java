package com.google.security.fences.config;

import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.objectweb.asm.Opcodes;

import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.ApiElement;
import com.google.security.fences.util.MisconfigurationException;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class FenceTest extends TestCase {

  public static final void testStarInTrustsElement() throws Exception {
    Fence f = new ApiFence();
    f.setTrusts("*");

    boolean threw = false;
    try {
      f.setTrusts("*Test");
    } catch (MisconfigurationException ex) {
      threw = true;

      String message = ex.getMessage();
      assertTrue(message, message.startsWith("Globs not allowed"));
    }
    assertTrue(threw);
  }

  public static final void testStarInDistrustsElement() throws Exception {
    Fence f = new ApiFence();
    f.setDistrusts("*");
    f.setDistrusts(" * ");
    boolean threw = false;
    try {
      f.setDistrusts("*Test");
    } catch (MisconfigurationException ex) {
      threw = true;

      String message = ex.getMessage();
      assertTrue(message, message.startsWith("Globs not allowed"));
    }
    assertTrue(threw);
  }

  public static final void testInnerClassSplitting() throws Exception {
    ClassFence unsplit = new ClassFence();
    unsplit.setName("com.example.Foo$Bar");
    unsplit.setTrusts("com.example.Trusted");
    unsplit.setDistrusts("*");

    InheritanceGraph g = InheritanceGraph.builder()
        .declare("com/example/Foo", Opcodes.ACC_PUBLIC)
            .commit()
        .declare("com/example/Foo$Bar", Opcodes.ACC_PUBLIC)
            .outerClassName(Optional.of("com/example/Foo"))
            .commit()
        .build();

    ApiFence split = unsplit
        .splitDottedNames(ApiElement.DEFAULT_PACKAGE, g)
        .promoteToApi();
    assertEquals(
        Joiner.on('\n').join(ImmutableList.of(
            "<api>",
            "  <package>",
            "    <name>com</name>",
            "    <package>",
            "      <name>example</name>",
            "      <class>",
            "        <name>Foo</name>",
            "        <class>",
            "          <name>Bar</name>",
            "          <trusts>com.example.Trusted</trusts>",
            "          <distrusts>*</distrusts>",
            "        </class>",
            "      </class>",
            "    </package>",
            "  </package>",
            "</api>",
            ""
        )),
        toXmlString(split));

  }

  private static String toXmlString(ApiFence f) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer transformer = tf.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.setOutputProperty(OutputKeys.METHOD, "xml");
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    transformer.setOutputProperty(
        "{http://xml.apache.org/xslt}indent-amount", "2");

    StringWriter xmlOut = new StringWriter();
    transformer.transform(
        new DOMSource(f.buildEffectiveConfiguration()),
        new StreamResult(xmlOut));
    return xmlOut.toString();
  }
}
