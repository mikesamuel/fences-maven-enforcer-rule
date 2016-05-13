package com.google.security.fences.config;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.junit.Test;
import org.objectweb.asm.Opcodes;

import junit.framework.TestCase;

import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.codehaus.plexus.component.configurator.BasicComponentConfigurator;
import org.codehaus.plexus.component.configurator.ComponentConfigurationException;
import org.codehaus.plexus.component.configurator.ComponentConfigurator;
import org.codehaus.plexus.configuration.PlexusConfiguration;
import org.codehaus.plexus.configuration.xml.XmlPlexusConfiguration;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.codehaus.plexus.util.xml.Xpp3DomBuilder;
import org.codehaus.plexus.util.xml.pull.MXParser;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

import com.google.common.base.Optional;
import com.google.security.fences.inheritance.InheritanceGraph;
import com.google.security.fences.policy.ApiElement;

@SuppressWarnings("javadoc")
public final class EffectiveConfigurationTest extends TestCase {

  private static final InheritanceGraph INHERITANCE_GRAPH =
      InheritanceGraph.builder()
      .declare("com/example/Foo", Opcodes.ACC_PUBLIC)
      .commit()
      .declare("com/example/Foo$1", Opcodes.ACC_PUBLIC)
      .outerClassName(Optional.of("com/example/Foo"))
      .commit()
      .build();


  /** A resource path. */
  private static final String TEST_FILE_RESOURCE_DIR =
      "/com/google/security/fences/config/fences-xml-tests";

  private static final class TestDocumentPair {
    final int index;
    final PlexusConfiguration input;
    final Document wanted;

    TestDocumentPair(int index, PlexusConfiguration input, Document wanted) {
      this.index = index;
      this.input = input;
      this.wanted = wanted;
    }
  }

  @Test
  public static void testConfigurations() throws Exception {
    int index;
    for (index = 0; ; ++index) {
      String inputResourcePath = String.format(
          "%s/config%03d-input.xml", TEST_FILE_RESOURCE_DIR, index);
      String wantedResourcePath = String.format(
          "%s/config%03d-wanted.xml", TEST_FILE_RESOURCE_DIR, index);
      TestDocumentPair p;
      InputStream inputIn = EffectiveConfigurationTest.class.getResourceAsStream(
          inputResourcePath);
      try {
        InputStream wantedIn =
            EffectiveConfigurationTest.class.getResourceAsStream(
                wantedResourcePath);
        try {
          if ((inputIn != null) != (wantedIn != null)) {
            throw new FileNotFoundException(
                (inputIn == null) ? inputResourcePath : wantedResourcePath);
          }
          if (inputIn == null) { break; }
          assert wantedIn != null;
          Document wanted = parseXml(wantedResourcePath, wantedIn);
          stripCommentsAndWhitespace(wanted.getDocumentElement());
          p = new TestDocumentPair(
              index,
              parsePlexusConfiguration(inputResourcePath, inputIn),
              wanted);
        } finally {
          if (wantedIn != null) {
            wantedIn.close();
          }
        }
      } finally {
        if (inputIn != null) {
          inputIn.close();
        }
      }
      test(p);
    }
    assertTrue("Found " + index + " tests", index > 0);
  }

  private static Document parseXml(String path, InputStream in)
      throws TransformerException {
    StreamSource src = new StreamSource(in, path);
    DOMResult result = new DOMResult();
    try {
      TransformerFactory.newInstance().newTransformer()
      .transform(src, result);
    } catch (TransformerConfigurationException ex) {
      // We had better be able to configure an identity transformer.
      throw new AssertionError(null, ex);
    }
    return (Document) result.getNode();
  }

  private static XmlPlexusConfiguration parsePlexusConfiguration(
      String path, InputStream in)
  throws IOException, XmlPullParserException {
    MXParser p = new MXParser();
    p.setProperty("http://xmlpull.org/v1/doc/properties.html#location", path);
    p.setInput(in, "UTF-8");
    Xpp3Dom dom = Xpp3DomBuilder.build(p);
    return new XmlPlexusConfiguration(dom);
  }

  private static void test(TestDocumentPair p)
      throws ComponentConfigurationException, EnforcerRuleException,
             ParserConfigurationException, TransformerException {
    ApiFence f = new ApiFence();
    ComponentConfigurator configurator = new BasicComponentConfigurator();
    configurator.configureComponent(f, p.input, null);
    f = f.splitDottedNames(ApiElement.DEFAULT_PACKAGE, INHERITANCE_GRAPH);
    Element output = f.buildEffectiveConfiguration();
    Element configuration = output.getOwnerDocument()
        .createElement("configuration");
    if (f.getFrenemies().isEmpty()) {
      while (output.hasChildNodes()) {
        configuration.appendChild(output.getFirstChild());
      }
    } else {
      configuration.appendChild(output);
    }

    assertEquals(
        String.format("config%03d", p.index),
        formatXml(p.wanted),
        formatXml(configuration));
  }

  private static String formatXml(Node node) throws TransformerException {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer transformer;
    try {
      transformer = tf.newTransformer();
    } catch (TransformerConfigurationException ex) {
      throw new AssertionError(null, ex);
    }
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.setOutputProperty(OutputKeys.METHOD, "xml");
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    transformer.setOutputProperty(
        "{http://xml.apache.org/xslt}indent-amount", "2");

    StringWriter xmlOut = new StringWriter();
    transformer.transform(
        new DOMSource(node),
        new StreamResult(xmlOut));
    return xmlOut.toString();
  }

  private static void stripCommentsAndWhitespace(Node node) {
    for (Node next, child = node.getFirstChild(); child != null; child = next) {
      next = child.getNextSibling();
      if (child.getNodeType() == Node.COMMENT_NODE
          || (child.getNodeType() == Node.TEXT_NODE
              && node.getTextContent().trim().isEmpty())) {
        node.removeChild(child);
      } else {
        stripCommentsAndWhitespace(child);
      }
    }
  }
}
