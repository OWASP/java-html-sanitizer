package org.owasp.html;

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class HtmlEntitiesTest extends TestCase {

	@Test
	public void testAfterAmpString() {
		String input = "<a href=\"/t?a=1&order_id=2\">order</a>";
		String output = Encoding.decodeHtml(input);
		assertEquals("<a href=\"/t?a=1&order_id=2\">order</a>", output);

		input = "<a href=\"/t?a=1&order-id=2\">order</a>";
		output = Encoding.decodeHtml(input);
		assertEquals("<a href=\"/t?a=1&order-id=2\">order</a>", output);

		input = "<a href=\"/t?a=1&order=2\">order</a>";
		output = Encoding.decodeHtml(input);
		assertEquals("<a href=\"/t?a=1&order=2\">order</a>", output);
	}
}