// Copyright (c) 2011, Mike Samuel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.html;

import com.google.common.base.Function;
import com.google.common.base.Throwables;
import com.google.common.collect.Lists;

import java.io.StringReader;
import java.util.List;
import java.util.Random;

import org.w3c.dom.Attr;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import junit.framework.TestCase;

import nu.validator.htmlparser.dom.HtmlDocumentBuilder;

/**
 * Tests that the security of the policy is decoupled from that of the parser.
 */
public class HtmlPolicyBuilderFuzzerTest extends TestCase {

  long seed = System.currentTimeMillis();
  {
    String seedStr = System.getProperty("junit.seed");
    if (seedStr != null) {
      try {
        seed = Long.parseLong(seedStr);
      } catch (NumberFormatException ex) {
        ex.printStackTrace();
      }
    }
  }

  final Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy> policyFactory
      = new HtmlPolicyBuilder()
      .allowElements("a", "b", "xmp")
      .allowAttributes("href").onElements("a")
      .allowAttributes("title").globally()
      .allowStandardUrlProtocols()
      .toFactory();

  static final String[] CHUNKS = {
    "Hello, World!", "<b>", "</b>",
    "<a onclick='doEvil()' href=javascript:alert(1337)>", "</a>",
    "<script>", "</script>", "<xmp>", "</xmp>", "javascript:alert(1337)",
    "<style>", "</style>", "<plaintext>", "<!--", "-->", "<![CDATA[", "]]>",
  };

  static final String[] ELEMENT_NAMES = {
    "a", "A",
    "b", "B",
    "script", "SCRipT",
    "style", "STYLE",
    "object", "Object",
    "noscript", "noScript",
    "xmp", "XMP",
  };

  static final String[] ATTR_NAMES = {
    "href", "id", "class", "onclick", "checked", "style",
  };

  public final void testFuzzedOutput() {
    try {
      Random rnd = new Random(seed);
      for (int i = 1000; --i >= 0;) {
        StringBuilder sb = new StringBuilder();
        HtmlSanitizer.Policy policy = policyFactory.apply(
            HtmlStreamRenderer.create(sb, Handler.DO_NOTHING));
        policy.openDocument();
        List<String> attributes = Lists.newArrayList();
        for (int j = 50; --j >= 0;) {
          switch (rnd.nextInt(3)) {
            case 0:
              attributes.clear();
              if (rnd.nextBoolean()) {
                for (int k = rnd.nextInt(4); --k >= 0;) {
                  attributes.add(pick(rnd, ATTR_NAMES));
                  attributes.add(pickChunk(rnd));
                }
              }
              policy.openTag(pick(rnd, ELEMENT_NAMES), attributes);
              break;
            case 1:
              policy.closeTag(pick(rnd, ELEMENT_NAMES));
              break;
            case 2:
              policy.text(pickChunk(rnd));
              break;
          }
        }
        policy.closeDocument();

        String html = sb.toString();
        HtmlDocumentBuilder parser = new HtmlDocumentBuilder();
        Node node = parser.parseFragment(
            new InputSource(new StringReader(html)), "body");
        checkSafe(node, html);
      }
    } catch (Exception ex) {
      System.err.println("Using seed " + seed + "L");
      Throwables.propagate(ex);
    }
  }

  private static void checkSafe(Node node, String html) {
    switch (node.getNodeType()) {
      case Node.ELEMENT_NODE:
        String name = node.getNodeName();
        if (!"a".equals(name) && !"b".equals(name) && !"xmp".equals(name)) {
          fail("Illegal element name " + name + " : " + html);
        }
        NamedNodeMap attrs = node.getAttributes();
        for (int i = 0, n = attrs.getLength(); i < n; ++i) {
          Attr a = (Attr) attrs.item(i);
          if ("title".equals(a.getName())) {
            // ok
          } else if ("href".equals(a.getName())) {
            assertEquals(html, "a", name);
            assertFalse(
                html, Strings.toLowerCase(a.getValue()).contains("script:"));
          }
        }
        break;
    }
    for (Node child = node.getFirstChild(); child != null;
         child = child.getNextSibling()) {
      checkSafe(child, html);
    }
  }

  private static String pick(Random rnd, String[] choices) {
    return choices[rnd.nextInt(choices.length)];
  }

  private static String pickChunk(Random rnd) {
    String chunk = pick(rnd, CHUNKS);
    int start = 0;
    int end = chunk.length();
    if (rnd.nextBoolean()) {
      start = rnd.nextInt(end - 1);
    }
    if (end - start < 2 && rnd.nextBoolean()) {
      end = start + rnd.nextInt(end - start);
    }
    return chunk.substring(start, end);
  }
}
