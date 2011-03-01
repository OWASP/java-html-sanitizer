package org.owasp.html;

import java.net.URL;
import java.util.Iterator;

import junit.framework.TestCase;

/**
 * Test that literal values for HTML attributes are honored correctly.
 *
 * @author August Detlefsen
 */
public class AntiSamyLiteralTest extends TestCase {

	/*
	private Policy policy = null;



	private URL getResource(String res) {
		URL url = this.getClass().getResource(res);
		System.out.println("Policy URL: " + url);
		return url;
	}

	public void testSAX() throws Exception {
		System.out.println("Policy: " + policy);

		// good
		String html = "<div align=\"right\">html</div>";

		CleanResults cleanResults = new AntiSamy(policy).scan(html, AntiSamy.SAX);
		System.out.println("SAX cleanResults: " + cleanResults.getCleanHTML());
		System.out.println("SAX cleanResults error messages: " + cleanResults.getErrorMessages().size());

		Iterator i = cleanResults.getErrorMessages().iterator();
		while (i.hasNext()) {
			String msg = (String)i.next();
			System.out.println("error msg: " + msg);
		}

		assertTrue(cleanResults.getErrorMessages().isEmpty());

		// AntiSamy should complain about the attribute value "foo" ... but it is not
		String badHtml = "<div align=\"foo\">badhtml</div>";

		CleanResults cleanResults2 = new AntiSamy(policy).scan(badHtml, AntiSamy.SAX);

		System.out.println("SAX cleanResults2: " + cleanResults2.getCleanHTML());
		System.out.println("SAX cleanResults2 error messages: " + cleanResults2.getErrorMessages().size());
		i = cleanResults2.getErrorMessages().iterator();
		while (i.hasNext()) {
			String msg = (String)i.next();
			System.out.println("error msg: " + msg);
		}
		assertTrue(cleanResults2.getErrorMessages().size() > 0);
	}

	public void testDOM() throws Exception {
		System.out.println("Policy: " + policy);

		// good
		String html = "<div align=\"right\">html</div>";

		CleanResults cleanResults = new AntiSamy(policy).scan(html, AntiSamy.DOM);
		System.out.println("DOM cleanResults error messages: " + cleanResults.getErrorMessages().size());
		Iterator i = cleanResults.getErrorMessages().iterator();
		while (i.hasNext()) {
			String msg = (String)i.next();
			System.out.println("error msg: " + msg);
		}

		assertTrue(cleanResults.getErrorMessages().isEmpty());

		// AntiSamy should complain about the attribute value "foo" ... but it is not
		String badHtml = "<div align=\"foo\">badhtml</div>";

		CleanResults cleanResults2 = new AntiSamy(policy).scan(badHtml, AntiSamy.DOM);

		System.out.println("DOM cleanResults2 error messages: " + cleanResults2.getErrorMessages().size());
		i = cleanResults2.getErrorMessages().iterator();
		while (i.hasNext()) {
			String msg = (String)i.next();
			System.out.println("error msg: " + msg);
		}
		assertTrue(cleanResults2.getErrorMessages().size() > 0);
	}
	*/
}
