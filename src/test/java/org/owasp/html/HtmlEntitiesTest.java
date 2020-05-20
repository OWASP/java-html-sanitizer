package org.owasp.html;

import static org.junit.Assert.*;

import org.junit.Test;

public class HtmlEntitiesTest {

	@Test
	public void decodeTest() {
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