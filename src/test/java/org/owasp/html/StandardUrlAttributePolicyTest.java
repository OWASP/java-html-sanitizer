package org.owasp.html;

import junit.framework.TestCase;
import org.junit.Test;

public class StandardUrlAttributePolicyTest extends TestCase {
  @Test
  public static final void testApply() {
    AttributePolicy attrPolicy = StandardUrlAttributePolicy.INSTANCE;

    assertEquals("http://stuff",
        attrPolicy.apply("", "", "http://stuff"));

    assertEquals("https://stuff",
        attrPolicy.apply("", "", "https://stuff"));

    assertEquals("mailto://stuff",
        attrPolicy.apply("", "", "mailto://stuff"));

    assertEquals("not-a-url",
        attrPolicy.apply("", "", "not-a-url"));

    assertNull(attrPolicy.apply("", "", "data://stuff"));
  }
}
