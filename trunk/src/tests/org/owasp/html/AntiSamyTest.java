/*
 * Copyright (c) 2007-2010, Arshan Dabirsiaghi, Jason Li
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.html;

import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.ListIterator;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableSet;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * This class tests AntiSamy functionality and the basic policy file which
 * should be immune to XSS and CSS phishing attacks.
 * 
 * @author Arshan Dabirsiaghi
 * 
 */

public class AntiSamyTest extends TestCase {

	private static String sanitize(String html) throws Exception {
	    StringBuilder sb = new StringBuilder();
	    final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
	        sb,
	        new Handler<String>() {
	          @Override
	          public void handle(String errorMessage) {
	            fail(errorMessage);
	          }
	        });

	    // A VERY SIMPLE WHITELISTING POLICY
	    final ImmutableSet<String> okTags = ImmutableSet.of(
	        "a", "b", "br", "div", "i", "img", "input", "li",
	        "ol", "p", "span", "ul");
	    final ImmutableSet<String> okAttrs = ImmutableSet.of(
	        "div", "checked", "class", "href", "id", "target", "title", "type");

	    HtmlSanitizer.Policy policy = new HtmlSanitizer.Policy() {

	      int ignoreDepth = 0;

	      @Override
	      public void openDocument() {
	        renderer.openDocument();
	      }

	      @Override
	      public void closeDocument() {
	        renderer.closeDocument();
	      }

	      @Override
	      public void text(String textChunk) {
	        if (ignoreDepth == 0) { renderer.text(textChunk); }
	      }

	      @Override
	      public void openTag(String elementName, List<String> attrs) {
	        if (okTags.contains(elementName)) {
	          for (ListIterator<String> it = attrs.listIterator();
	               it.hasNext();) {
	            String attrName = it.next();
	            if (okAttrs.contains(attrName)) {
	              String value = it.next();
	              if ("id".equals(attrName) || "class".equals(attrName)) {
	                it.set(value.replaceAll("(?:^|\\s)([a-zA-Z])", " p-$1")
	                       .replaceAll("\\s+", " ")
	                       .trim());
	              }
	            } else {
	              it.remove();
	              it.next();
	              it.remove();
	            }
	          }
	          renderer.openTag(elementName, attrs);
	        } else if (ignoreContents(elementName)) {
	          ++ignoreDepth;
	        }
	      }

	      @Override
	      public void closeTag(String elementName) {
	        if (okTags.contains(elementName)) {
	          renderer.closeTag(elementName);
	        } else if (ignoreContents(elementName)) {
	          --ignoreDepth;
	        }
	      }

	      private boolean ignoreContents(String unsafeElementName) {
	        return !("body".equals(unsafeElementName)
	                 || "html".equals(unsafeElementName)
	                 || "head".equals(unsafeElementName));
	      }
	    };

	    new HtmlSanitizer().sanitize(html, policy);

	    return sb.toString();
	  }
	
	/*
	private static final String[] BASE64_BAD_XML_STRINGS = new String[] {
			// first string is
			// "<a - href=\"http://www.owasp.org\">click here</a>"
			"PGEgLSBocmVmPSJodHRwOi8vd3d3Lm93YXNwLm9yZyI+Y2xpY2sgaGVyZTwvYT4=",
			// the rest are randomly generated 300 byte sequences which generate
			// parser errors, turned into Strings
			"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",
	};
	*/

	public AntiSamyTest(String s) {
		super(s);
	}

	protected void setUp() throws Exception {


	}

	protected void tearDown() throws Exception {
	}

	public static Test suite() {

		TestSuite suite = new TestSuite(AntiSamyTest.class);
		return suite;

	}

	public void testCompareSpeeds() throws Exception {

		String urls[] = {
				"http://slashdot.org/", "http://www.fark.com/", "http://www.cnn.com/", "http://google.com/", "http://www.microsoft.com/en/us/default.aspx", "http://deadspin.com/"
		};

		double totalTime = 0;
		double averageTime = 0;
		
		int testReps = 15;

		for (int i = 0; i < urls.length; i++) {
			URL url = new URL(urls[i]);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			InputStreamReader in = new InputStreamReader(conn.getInputStream());
			StringBuilder out = new StringBuilder();
			char[] buffer = new char[5000];
			int read = 0;
			do {
				read = in.read(buffer, 0, buffer.length);
				if (read > 0) {
					out.append(buffer, 0, read);
				}
			} while (read >= 0);

			in.close();

			String html = out.toString();

			System.out.println("About to scan: " + url + " size: " + html.length());
			if (html.length() > 64000) {
				System.out.println("   -Maximum input size 64000 exceeded. SKIPPING.");
				continue;
			}

			double startTime = 0;
			double endTime = 0;

			for (int j = 0; j < testReps; j++) {
				startTime = System.currentTimeMillis();
				sanitize(html);
				endTime = System.currentTimeMillis();
				
				totalTime = totalTime + (endTime - startTime);
			}

			averageTime = totalTime / testReps;
		}

		System.out.println("Total time: " + totalTime);
		System.out.println("Average time per rep: " + averageTime);
	}

	/*
	 * Test basic XSS cases.
	 */

	public void testScriptAttacks() {

		try {

			assertTrue(sanitize("test<script>alert(document.cookie)</script>").indexOf("script") == -1);
			assertTrue(sanitize("test<script>alert(document.cookie)</script>").indexOf("script") == -1);

			assertTrue(sanitize("<<<><<script src=http://fake-evil.ru/test.js>").indexOf("<script") == -1);
			assertTrue(sanitize("<<<><<script src=http://fake-evil.ru/test.js>").indexOf("<script") == -1);

			assertTrue(sanitize("<script<script src=http://fake-evil.ru/test.js>>").indexOf("<script") == -1);
			assertTrue(sanitize("<script<script src=http://fake-evil.ru/test.js>>").indexOf("<script") == -1);

			assertTrue(sanitize("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);
			assertTrue(sanitize("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);

			assertTrue(sanitize("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>").indexOf("onload") == -1);
			assertTrue(sanitize("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>").indexOf("onload") == -1);

			assertTrue(sanitize("<BODY ONLOAD=alert('XSS')>").indexOf("alert") == -1);
			assertTrue(sanitize("<BODY ONLOAD=alert('XSS')>").indexOf("alert") == -1);

			assertTrue(sanitize("<iframe src=http://ha.ckers.org/scriptlet.html <").indexOf("<iframe") == -1);
			assertTrue(sanitize("<iframe src=http://ha.ckers.org/scriptlet.html <").indexOf("<iframe") == -1);

			assertTrue(sanitize("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">").indexOf("src") == -1);
			assertTrue(sanitize("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">").indexOf("src") == -1);

			sanitize("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>");
			sanitize("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>");

		} catch (Exception e) {
			fail("Caught exception in testScriptAttack(): " + e.getMessage());
		}

	}

	public void testImgAttacks() {

		try {

			assertTrue(sanitize("<img src=\"http://www.myspace.com/img.gif\"/>").indexOf("<img") != -1);
			assertTrue(sanitize("<img src=\"http://www.myspace.com/img.gif\"/>").indexOf("<img") != -1);

			assertTrue(sanitize("<img src=javascript:alert(document.cookie)>").indexOf("<img") == -1);
			assertTrue(sanitize("<img src=javascript:alert(document.cookie)>").indexOf("<img") == -1);

			assertTrue(sanitize("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>")
					.indexOf("<img") == -1);
			assertTrue(sanitize("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>")
					.indexOf("<img") == -1);

			assertTrue(sanitize(
							"<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>").indexOf("<img") == -1);
			assertTrue(sanitize(
							"<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>").indexOf("<img") == -1);

			assertTrue(sanitize("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">").indexOf("alert") == -1);
			assertTrue(sanitize("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">").indexOf("alert") == -1);

			String s = sanitize(
							"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>");
			assertTrue(s.length() == 0 || s.indexOf("&amp;") != -1);
			s = sanitize(
							"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>");
			assertTrue(s.length() == 0 || s.indexOf("&amp;") != -1);

			sanitize("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>");
			sanitize("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>");

			assertTrue(sanitize("<IMG SRC=\"javascript:alert('XSS')\"").indexOf("javascript") == -1);
			assertTrue(sanitize("<IMG SRC=\"javascript:alert('XSS')\"").indexOf("javascript") == -1);

			assertTrue(sanitize("<IMG LOWSRC=\"javascript:alert('XSS')\">").indexOf("javascript") == -1);
			assertTrue(sanitize("<IMG LOWSRC=\"javascript:alert('XSS')\">").indexOf("javascript") == -1);

			assertTrue(sanitize("<BGSOUND SRC=\"javascript:alert('XSS');\">").indexOf("javascript") == -1);
			assertTrue(sanitize("<BGSOUND SRC=\"javascript:alert('XSS');\">").indexOf("javascript") == -1);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Caught exception in testImgSrcAttacks(): " + e.getMessage());
		}
	}

	public void testHrefAttacks() {

		try {

			assertTrue(sanitize("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">").indexOf("href") == -1);
			assertTrue(sanitize("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">").indexOf("href") == -1);

			assertTrue(sanitize("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">").indexOf("href") == -1);
			assertTrue(sanitize("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">").indexOf("href") == -1);

			assertTrue(sanitize("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>").indexOf("ha.ckers.org") == -1);
			assertTrue(sanitize("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>").indexOf("ha.ckers.org") == -1);

			assertTrue(sanitize("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>").indexOf("ha.ckers.org") == -1);
			assertTrue(sanitize("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>").indexOf("ha.ckers.org") == -1);

			assertTrue(sanitize("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS").indexOf("javascript") == -1);
			assertTrue(sanitize("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS").indexOf("javascript") == -1);

			assertTrue(sanitize("<IMG SRC='vbscript:msgbox(\"XSS\")'>").indexOf("vbscript") == -1);
			assertTrue(sanitize("<IMG SRC='vbscript:msgbox(\"XSS\")'>").indexOf("vbscript") == -1);

			assertTrue(sanitize("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">").indexOf("<meta") == -1);
			assertTrue(sanitize("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">").indexOf("<meta") == -1);

			assertTrue(sanitize("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">").indexOf("<meta") == -1);
			assertTrue(sanitize("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">").indexOf("<meta") == -1);

			assertTrue(sanitize("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">").indexOf("<meta") == -1);
			assertTrue(sanitize("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">").indexOf("<meta") == -1);

			assertTrue(sanitize("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>").indexOf("iframe") == -1);
			assertTrue(sanitize("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>").indexOf("iframe") == -1);

			assertTrue(sanitize("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>").indexOf("javascript") == -1);
			assertTrue(sanitize("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>").indexOf("javascript") == -1);

			assertTrue(sanitize("<TABLE BACKGROUND=\"javascript:alert('XSS')\">").indexOf("background") == -1);
			assertTrue(sanitize("<TABLE BACKGROUND=\"javascript:alert('XSS')\">").indexOf("background") == -1);

			assertTrue(sanitize("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">").indexOf("background") == -1);
			assertTrue(sanitize("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">").indexOf("background") == -1);

			assertTrue(sanitize("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">").indexOf("javascript") == -1);
			assertTrue(sanitize("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">").indexOf("javascript") == -1);

			assertTrue(sanitize("<DIV STYLE=\"width: expression(alert('XSS'));\">").indexOf("alert") == -1);
			assertTrue(sanitize("<DIV STYLE=\"width: expression(alert('XSS'));\">").indexOf("alert") == -1);

			assertTrue(sanitize("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">").indexOf("alert") == -1);
			assertTrue(sanitize("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">").indexOf("alert") == -1);

			assertTrue(sanitize("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>").indexOf("ript:alert") == -1);
			assertTrue(sanitize("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>").indexOf("ript:alert") == -1);

			assertTrue(sanitize("<BASE HREF=\"javascript:alert('XSS');//\">").indexOf("javascript") == -1);
			assertTrue(sanitize("<BASE HREF=\"javascript:alert('XSS');//\">").indexOf("javascript") == -1);

			assertTrue(sanitize("<BaSe hReF=\"http://arbitrary.com/\">").indexOf("<base") == -1);
			assertTrue(sanitize("<BaSe hReF=\"http://arbitrary.com/\">").indexOf("<base") == -1);

			assertTrue(sanitize("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>").indexOf("<object") == -1);
			assertTrue(sanitize("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>").indexOf("<object") == -1);

			assertTrue(sanitize("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>").indexOf("javascript") == -1);

			String s = sanitize("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>");
			// System.out.println(cr.getErrorMessages().get(0));
			assertTrue(s.indexOf("javascript") == -1);

			assertTrue(sanitize("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>").indexOf("<embed") == -1);
			assertTrue(sanitize("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>").indexOf("<embed") == -1);

			assertTrue(
					sanitize(
							"<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>"
							).indexOf("<embed") == -1);
			assertTrue(
					sanitize(
							"<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>"
							).indexOf("<embed") == -1);

			assertTrue(sanitize("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);
			assertTrue(sanitize("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);

			assertTrue(sanitize("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);
			assertTrue(sanitize("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);

			assertTrue(sanitize("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);
			assertTrue(sanitize("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);

			assertTrue(sanitize("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);
			assertTrue(sanitize("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("<script") == -1);

			assertTrue(sanitize("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("script") == -1);
			assertTrue(sanitize("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>").indexOf("script") == -1);

			assertTrue(sanitize("<SCRIPT SRC=http://ha.ckers.org/xss.js").indexOf("<script") == -1);
			assertTrue(sanitize("<SCRIPT SRC=http://ha.ckers.org/xss.js").indexOf("<script") == -1);

			assertTrue(
					sanitize(
							"<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>"
							).indexOf("style") == -1);
			assertTrue(
					sanitize(
							"<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>"
							).indexOf("style") == -1);

			assertTrue(sanitize("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>").indexOf(
					"aim.exe") == -1);
			assertTrue(sanitize("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>")
					.indexOf("aim.exe") == -1);

			assertTrue(sanitize("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->").indexOf("javascript") == -1);
			assertTrue(sanitize("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->").indexOf("javascript") == -1);

			assertTrue(sanitize("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">").indexOf("document") == -1);
			assertTrue(sanitize("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">").indexOf(
					"document") == -1);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Caught exception in testHrefSrcAttacks(): " + e.getMessage());
		}
	}

	/*
	 * Test CSS protections.
	 */

	public void testCssAttacks() {

		try {

			assertTrue(sanitize("<div style=\"position:absolute\">").indexOf("position") == -1);
			assertTrue(sanitize("<div style=\"position:absolute\">").indexOf("position") == -1);

			assertTrue(sanitize("<style>b { position:absolute }</style>").indexOf("position") == -1);
			assertTrue(sanitize("<style>b { position:absolute }</style>").indexOf("position") == -1);

			assertTrue(sanitize("<div style=\"z-index:25\">test</div>").indexOf("z-index") == -1);
			assertTrue(sanitize("<div style=\"z-index:25\">test</div>").indexOf("z-index") == -1);

			assertTrue(sanitize("<style>z-index:25</style>").indexOf("z-index") == -1);
			assertTrue(sanitize("<style>z-index:25</style>").indexOf("z-index") == -1);

		} catch (Exception e) {
			fail("Caught exception in testCssAttacks(): " + e.getMessage());
		}
	}

	/*
	 * Test a bunch of strings that have tweaked the XML parsing capabilities of
	 * NekoHTML.
	 */
	public void testIllegalXML() {
/*TODO _ PORT THIS
		for (int i = 0; i < BASE64_BAD_XML_STRINGS.length; i++) {

			try {

				String testStr = new String(Base64.decodeBase64(BASE64_BAD_XML_STRINGS[i].getBytes()));
				sanitize(testStr);
				sanitize(testStr);

			} catch (ScanException ex) {
				// still success!

			} catch (Throwable ex) {
				ex.printStackTrace();
				fail("Caught unexpected exception in testIllegalXML(): " + ex.getMessage());
			}
		}
*/
		// This fails due to a bug in NekoHTML
		try {
		 assertTrue (
		 sanitize("<a . href=\"http://www.test.com\">").indexOf("href")
		 != -1 );
		 } catch (Exception e) {
		 e.printStackTrace();
		 fail("Couldn't parse malformed HTML: " + e.getMessage());
		 }

		//This fails due to a bug in NekoHTML
		 try {
		 assertTrue (
		 sanitize("<a - href=\"http://www.test.com\">").indexOf("href")
		 != -1 );
		 } catch (Exception e) {
		 e.printStackTrace();
		 fail("Couldn't parse malformed HTML: " + e.getMessage());
		 }

		try {
			assertTrue(sanitize("<style>") != null);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Couldn't parse malformed HTML: " + e.getMessage());
		}
	}

	public void testPreviousBugs() {

		/*
		 * issues 12 (and 36, which was similar). empty tags cause display
		 * problems/"formjacking"
		 */

		try {

			Pattern p = Pattern.compile(".*<strong(\\s*)/>.*");
			String s1 = sanitize("<br ><strong></strong><a>hello world</a><b /><i/><hr>");
			String s2 = sanitize("<br ><strong></strong><a>hello world</a><b /><i/><hr>");

			assertFalse(p.matcher(s1).matches());

			p = Pattern.compile(".*<b(\\s*)/>.*");
			assertFalse(p.matcher(s1).matches());
			assertFalse(p.matcher(s2).matches());

			p = Pattern.compile(".*<i(\\s*)/>.*");
			assertFalse(p.matcher(s1).matches());
			assertFalse(p.matcher(s2).matches());

			p = Pattern.compile(".*<hr(\\s*)/>.*");
			assertFalse(p.matcher(s1).matches());
			assertFalse(p.matcher(s2).matches());

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #20 */
		try {

			String s = sanitize("<b><i>Some Text</b></i>");
			assertTrue(s.indexOf("<i />") == -1);

			s = sanitize("<b><i>Some Text</b></i>");
			assertTrue(s.indexOf("<i />") == -1);

		} catch (Exception e) {
			e.printStackTrace();
		}

		/* issue #25 */
		try {

			String s = "<div style=\"margin: -5em\">Test</div>";
			String expected = "<div style=\"\">Test</div>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #28 */
		try {

			String s1 = sanitize("<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>");
			String s2 = sanitize("<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>");
			assertTrue(s1.indexOf("font-family") > -1);
			assertTrue(s2.indexOf("font-family") > -1);

		} catch (Exception e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		/* issue #29 - missing quotes around properties with spaces */

		try {

			String s = "<style type=\"text/css\"><![CDATA[P {\n	font-family: \"Arial Unicode MS\";\n}\n]]></style>";
			s = sanitize(s);
			//assertEquals(s, cr.getCleanHTML());

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

	
		/* issue #30 */
		/*
		try {
			String s = "<style type=\"text/css\"><![CDATA[P { margin-bottom: 0.08in; } ]]></style>";

			s= sanitize(s);

			String oldValue = policy.getDirective(Policy.USE_XHTML);

			// followup - does the patch fix multiline CSS? 
			String s2 = "<style type=\"text/css\"><![CDATA[\r\nP {\r\n margin-bottom: 0.08in;\r\n}\r\n]]></style>";
			cr = sanitize(s2);
			assertEquals("<style type=\"text/css\"><![CDATA[P {\n\tmargin-bottom: 0.08in;\n}\n]]></style>", cr.getCleanHTML());

			// next followup - does non-CDATA parsing still work? 

			policy.setDirective(Policy.USE_XHTML, "false");
			String s3 = "<style>P {\n\tmargin-bottom: 0.08in;\n}\n";
			cr = sanitize(s3);
			assertEquals("<style>P {\n\tmargin-bottom: 0.08in;\n}\n</style>\n", cr.getCleanHTML());

			policy.setDirective(Policy.USE_XHTML, oldValue); // reset this value
			// for other
			// tests

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
		*/
		/* issue 31 */
		/*
		String toDoOnBoldTags = policy.getTagByName("b").getAction();

		try {
			String test = "<b><u><g>foo";

			policy.setDirective("onUnknownTag", "encode");
			s= sanitize(test);
			String s = cr.getCleanHTML();
			assertFalse(s.indexOf("&lt;g&gt;") == -1);
			s = sanitize(test);
			assertFalse(s.indexOf("&lt;g&gt;") == -1);

			policy.getTagByName("b").setAction("encode");

			cr = sanitize(test);
			s = cr.getCleanHTML();

			assertFalse(s.indexOf("&lt;b&gt;") == -1);

			cr = sanitize(test);
			s = cr.getCleanHTML();

			assertFalse(s.indexOf("&lt;b&gt;") == -1);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		} finally {
			policy.getTagByName("b").setAction(toDoOnBoldTags);
		}
		
		*/

		/* issue #32 - nekos problem */
		try {
			String s = "<SCRIPT =\">\" SRC=\"\"></SCRIPT>";
			sanitize(s);
			sanitize(s);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #37 - OOM */

		try {
			String dirty = "<a onblur=\"try {parent.deselectBloggerImageGracefully();}" + "catch(e) {}\""
					+ "href=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\"><img" + "style=\"FLOAT: right; MARGIN: 0px 0px 10px 10px; WIDTH: 150px; CURSOR:"
					+ "hand; HEIGHT: 100px\" alt=\"\"" + "src=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\""
					+ "border=\"0\" /></a><br />Poor Bill, couldn't make it to the Museum's <span" + "class=\"blsp-spelling-corrected\" id=\"SPELLING_ERROR_0\">story time</span>"
					+ "today, he was so busy shoveling! Well, we sure missed you Bill! So since" + "ou were busy moving snow we read books about snow. We found a clue in one"
					+ "book which revealed a snowplow at the end of the story - we wish it had" + "driven to your driveway Bill. We also read a story which shared fourteen"
					+ "<em>Names For Snow. </em>We'll catch up with you next week....wonder which" + "hat Bill will wear?<br />Jane";

			String s = sanitize(dirty);
			assertNotNull(s);

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #38 - color problem/color combinations */
		try {

			String s = "<font color=\"#fff\">Test</font>";
			String expected = "<font color=\"#fff\">Test</font>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			s = "<div style=\"color: #fff\">Test 3 letter code</div>";
			expected = "<div style=\"color: rgb(255,255,255);\">Test 3 letter code</div>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			s = "<font color=\"red\">Test</font>";
			expected = "<font color=\"red\">Test</font>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			s = "<font color=\"neonpink\">Test</font>";
			expected = "<font>Test</font>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			s = "<font color=\"#0000\">Test</font>";
			expected = "<font>Test</font>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			s = "<div style=\"color: #0000\">Test</div>";
			expected = "<div style=\"\">Test</div>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			s = "<font color=\"#000000\">Test</font>";
			expected = "<font color=\"#000000\">Test</font>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			s = "<div style=\"color: #000000\">Test</div>";
			expected = "<div style=\"color: rgb(0,0,0);\">Test</div>";
			assertEquals(sanitize(s), expected);
			assertEquals(sanitize(s), expected);

			/*
			 * This test case was failing because of the following code from the
			 * batik CSS library, which throws an exception if any character
			 * other than a '!' follows a beginning token of '<'. The
			 * ParseException is now caught in the node a CssScanner.java and
			 * the outside AntiSamyDOMScanner.java.
			 * 
			 * 0398 nextChar(); 0399 if (current != '!') { 0400 throw new
			 * ParseException("character", 0401 reader.getLine(), 0402
			 * reader.getColumn());
			 */
			s = "<b><u>foo<style><script>alert(1)</script></style>@import 'x';</u>bar";
			sanitize(s);
			sanitize(s);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #40 - handling <style> media attributes right */

		try {

			String s = "<style media=\"print, projection, screen\"> P { margin: 1em; }</style>";
			
			s= sanitize(s);
			// System.out.println("here: " + cr.getCleanHTML());
			assertTrue(s.indexOf("print, projection, screen") != -1);
			// System.out.println(s);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #41 - comment handling */

		try {


			assertEquals("text ", sanitize("text <!-- comment -->"));
			assertEquals("text ", sanitize("text <!-- comment -->"));


			assertEquals("<div>text <!-- comment --></div>", sanitize("<div>text <!-- comment --></div>"));
			assertEquals("<div>text <!-- comment --></div>", sanitize("<div>text <!-- comment --></div>"));

			assertEquals("<div>text <!-- comment --></div>", sanitize("<div>text <!--[if IE]> comment <[endif]--></div>"));
			assertEquals("<div>text <!-- comment --></div>", sanitize("<div>text <!--[if IE]> comment <[endif]--></div>"));

			/*
			 * Check to see how nested conditional comments are handled. This is
			 * not very clean but the main goal is to avoid any tags. Not sure
			 * on encodings allowed in comments.
			 */
			String input = "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>";
			String expected = "<div>text <!-- <!-- comment -->&lt;[endif]--&gt;</div>";
			String output = sanitize(input);
			assertEquals(expected, output);

			input = "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>";
			expected = "<div>text <!-- <!- - comment -->&lt;[endif]--&gt;</div>";
			output = sanitize(input);

			assertEquals(expected, output);

			/*
			 * Regular comment nested inside conditional comment. Test makes
			 * sure
			 */
			assertEquals("<div>text <!-- <!-- IE specific --> comment &lt;[endif]--&gt;</div>", sanitize("<div>text <!--[if IE]> <!-- IE specific --> comment <[endif]--></div>"));

			/*
			 * These play with whitespace and have invalid comment syntax.
			 */
			assertEquals("<div>text <!-- \ncomment --></div>", sanitize("<div>text <!-- [ if lte 6 ]>\ncomment <[ endif\n]--></div>"));
			assertEquals("<div>text  comment </div>", sanitize("<div>text <![if !IE]> comment <![endif]></div>"));
			assertEquals("<div>text  comment </div>", sanitize("<div>text <![ if !IE]> comment <![endif]></div>"));

			String attack = "[if lte 8]<script>";
			String spacer = "<![if IE]>";

			StringBuffer sb = new StringBuffer();

			sb.append("<div>text<!");

			for (int i = 0; i < attack.length(); i++) {
				sb.append(attack.charAt(i));
				sb.append(spacer);
			}

			sb.append("<![endif]>");

			String s = sb.toString();

			assertTrue(sanitize(s).indexOf("<script") == -1);
			assertTrue(sanitize(s).indexOf("<script") == -1);

		} catch (Exception e) {

		}

		/*
		 * issue #44 - childless nodes of non-allowed elements won't cause an
		 * error
		 */
/*
		try {
			String s = "<iframe src='http://foo.com/'></iframe>" + "<script src=''></script>" + "<link href='/foo.css'>";

			assertEquals(cr.getNumberOfErrors(), 3);

		} catch (Exception e) {
			fail(e.getMessage());
		}
*/
/* issue #51 - offsite urls with () are found to be invalid */
/*
		try {
			String s = "<a href='http://subdomain.domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx'>test</a>";
			s= sanitize(s);

			// System.out.println(s);
			assertEquals(cr.getNumberOfErrors(), 0);

			cr = sanitize(s);
			assertEquals(cr.getNumberOfErrors(), 0);

		} catch (Exception e) {
			fail(e.getMessage());
		}
*/
		/* issue #56 - unnecessary spaces */

		try {
			String s = "<SPAN style='font-weight: bold;'>Hello World!</SPAN>";
			String expected = "<span style=\"font-weight: bold;\">Hello World!</span>";

			s= sanitize(s);
			String s2 = s;

			assertEquals(expected, s2);

			s = sanitize(s);

			assertEquals(expected, s2);

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #58 - input not in list of allowed-to-be-empty tags */
		/*
		try {
			String s = "tgdan <input/> g  h";
			s= sanitize(s);
			assertTrue(cr.getErrorMessages().size() == 0);

			cr = sanitize(s);
			assertTrue(cr.getErrorMessages().size() == 0);

		} catch (Exception e) {
			fail(e.getMessage());
		}
		*/
		
		/* issue #61 - input has newline appended if ends with an accepted tag */
		try {
			String dirtyInput = "blah <b>blah</b>.";
			String s= sanitize(dirtyInput);
			assertEquals(dirtyInput, s);

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #69 - char attribute should allow single char or entity ref */

		try {
			String s = "<td char='.'>test</td>";
			assertTrue(sanitize(s).indexOf("char") > -1);
			assertTrue(sanitize(s).indexOf("char") > -1);

			s = "<td char='..'>test</td>";
			assertTrue(sanitize(s).indexOf("char") == -1);
			assertTrue(sanitize(s).indexOf("char") == -1);

			s = "<td char='&quot;'>test</td>";
			assertTrue(sanitize(s).indexOf("char") > -1);
			assertTrue(sanitize(s).indexOf("char") > -1);

			s = "<td char='&quot;a'>test</td>";
			assertTrue(sanitize(s).indexOf("char") == -1);
			assertTrue(sanitize(s).indexOf("char") == -1);

			s = "<td char='&quot;&amp;'>test</td>";
			assertTrue(sanitize(s).indexOf("char") == -1);
			assertTrue(sanitize(s).indexOf("char") == -1);

		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		/* privately disclosed issue - cdata bypass */
		try {
			
			String malInput = "<![CDATA[]><script>alert(1)</script>]]>";
			
			String crSax = sanitize(malInput);

			//System.out.println("DOM result: " + crDom);
			//System.out.println("SAX result: " + crSax);

			assertTrue(crSax.indexOf("&lt;script") != -1);
			
		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* this test is for confirming literal-lists work as
		 * advertised. it turned out to be an invalid / non-
		 * reproducible bug report but the test seemed useful
		 * enough to keep. 
		 */
		try {
			
			String malInput = "hello<p align='invalid'>world</p>";
			String s = sanitize(malInput); 
			assertTrue(s.indexOf("invalid") == -1);
			
			String goodInput = "hello<p align='left'>world</p>";
			s = sanitize(goodInput);

			assertTrue(s.indexOf("left") != -1);

		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	/*
	 * Tests cases dealing with nofollowAnchors directive. Assumes anchor tags
	 * have an action set to "validate" (may be implicit) in the policy file.
	 */
	public void testNofollowAnchors() {

		try {

			// adds when not present

			assertTrue(sanitize("<a href=\"blah\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(sanitize("<a href=\"blah\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// adds properly even with bad attr
			assertTrue(sanitize("<a href=\"blah\" bad=\"true\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(sanitize("<a href=\"blah\" bad=\"true\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// rel with bad value gets corrected
			assertTrue(sanitize("<a href=\"blah\" rel=\"blh\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(sanitize("<a href=\"blah\" rel=\"blh\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// correct attribute doesnt get messed with
			assertTrue(sanitize("<a href=\"blah\" rel=\"nofollow\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(sanitize("<a href=\"blah\" rel=\"nofollow\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// if two correct attributes, only one remaining after scan
			assertTrue(sanitize("<a href=\"blah\" rel=\"nofollow\" rel=\"nofollow\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(sanitize("<a href=\"blah\" rel=\"nofollow\" rel=\"nofollow\">link</a>").indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// test if value is off - does it add?

			assertTrue(sanitize("a href=\"blah\">link</a>").indexOf("nofollow") == -1);
			assertTrue(sanitize("a href=\"blah\">link</a>").indexOf("nofollow") == -1);


		} catch (Exception e) {
			fail("Caught exception in testNofollowAnchors(): " + e.getMessage());
		}
	}

	public void testValidateParamAsEmbed() {
		try {

			// let's start with a YouTube embed
			String input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			String expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>";
			String s = sanitize(input);
			assertTrue(s.indexOf(expectedOutput) > -1);

			String saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			s = sanitize(input);
			// System.out.println("Expected: " + saxExpectedOutput);
			// System.out.println("Received: " + s);
			assertTrue(s.indexOf(saxExpectedOutput) > -1);

			// now what if someone sticks malicious URL in the value of the
			// value attribute in the param tag? remove that param tag
			input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://supermaliciouscode.com/badstuff.swf\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>";
			saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			s = sanitize(input);
			assertTrue(s.indexOf(expectedOutput) > -1);

			s = sanitize(input);
			// System.out.println("Expected: " + saxExpectedOutput);
			// System.out.println("Received: " + s);
			assertTrue(s.equals(saxExpectedOutput));

			// now what if someone sticks malicious URL in the value of the src
			// attribute in the embed tag? remove that embed tag
			input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://hereswhereikeepbadcode.com/ohnoscary.swf\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /></object>";
			saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"></object>";

			s = sanitize(input);
			assertTrue(s.indexOf(expectedOutput) > -1);
			s = sanitize(input);

			// System.out.println("Expected: " + saxExpectedOutput);
			// System.out.println("Received: " + s);
			assertTrue(s.indexOf(saxExpectedOutput) > -1);

		} catch (Exception e) {
			fail("Caught exception in testValidateParamAsEmbed(): " + e.getMessage());
		}
	}

}