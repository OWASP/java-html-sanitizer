/*
 * Copyright (c) 2018, Florent Guillaume
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.html.antisamy;

import java.net.URL;

import org.junit.Test;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import com.google.common.io.Resources;

import junit.framework.TestCase;

/**
 * Test that we can load old AntiSamy configuration files.
 */
public class LoadAntiSamyPolicyTest extends TestCase {

  @Test
  public void testAntiSamyPolicy() throws Exception {
    URL url = Resources.getResource(getClass(), "antisamy-test.xml");
    PolicyFactory policy = new HtmlPolicyBuilder().loadAntiSamyPolicy(url).toFactory();
    String html = "<div>foo</div>\n" // div unknown
        + "<p align=\"left\">bar</p>\n" // ok
        + "<p align=\"random\">moo</p>\n" // value unknown
        + "<p blorp=\"yes\">gee</p>\n" // attr unknown
        + "<p></p>\n" // no text
        + "<h1 id=\"main\">the title</h1>\n" // ok
        + "<br>\n" //
        + "<hr>\n" // not listed in allowed empty tags
        + "<dd foo=\"bar\"><p>hello</p></dd>\n" // dd policy is "truncate"
        + "<script>baz</script>\n";
    String expected = "foo\n" // element dropped, text kept
        + "<p align=\"left\">bar</p>\n" //
        + "<p>moo</p>\n" //
        + "<p>gee</p>\n" //
        + "<p></p>\n" //
        + "<h1 id=\"main\">the title</h1>\n" //
        + "<br />\n" // normalized
        + "\n" // hr dropped
        + "<dd><p>hello</p></dd>\n" // dd attrs dropped
        + "\n"; // script content dropped
    assertEquals(expected, policy.sanitize(html));
  }

}
