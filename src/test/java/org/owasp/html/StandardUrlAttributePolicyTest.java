package org.owasp.html;

import org.junit.Test;

import junit.framework.TestCase;

public class StandardUrlAttributePolicyTest extends TestCase {

  @Test
  public void testIssue213() {
    PolicyFactory policyFactory = new HtmlPolicyBuilder()
      .allowElements("a")
      .allowStandardUrlProtocols()
      .allowAttributes("href", "target")
      .onElements("a")
      .toFactory();

    assertEquals("<a href=\"#\">Hi</a>", policyFactory.sanitize("<a href=\"#\">Hi"));
    assertEquals("Hi", policyFactory.sanitize("<a href=\"jav&#97script:alert(1)\">Hi"));
    assertEquals("Hi", policyFactory.sanitize("<a href=\"jav&#97:\">Hi"));
  }
}