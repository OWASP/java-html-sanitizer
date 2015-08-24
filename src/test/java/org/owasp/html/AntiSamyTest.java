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

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;

import junit.framework.AssertionFailedError;
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
@SuppressWarnings("javadoc")
public class AntiSamyTest extends TestCase {

  static final boolean RUN_KNOWN_FAILURES = false;
  static final boolean DISABLE_INTERNETS = false;

  private static HtmlSanitizer.Policy makePolicy(Appendable buffer) {
    final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        buffer,
        new Handler<IOException>() {
          public void handle(IOException ex) {
            AssertionFailedError failure = new AssertionFailedError();
            failure.initCause(ex);
            throw failure;
          }
        },
        new Handler<String>() {
          public void handle(String errorMessage) {
            fail(errorMessage);
          }
        });

    return new HtmlPolicyBuilder()
        .allowElements(
            "a", "b", "br", "div", "font", "i", "img", "input", "li",
            "ol", "p", "span", "td", "ul")
        .allowAttributes("checked", "type").onElements("input")
        .allowAttributes("color").onElements("font")
        .allowAttributes("href").onElements("a")
        .allowAttributes("src").onElements("img")
        .allowAttributes("class", "id", "title").globally()
        .allowAttributes("char").matching(
            new AttributePolicy() {
              public String apply(
                  String elementName, String attributeName, String value) {
                return value.length() == 1 ? value : null;
              }
            }).onElements("td")
        .allowStandardUrlProtocols()
        .requireRelNofollowOnLinks()
        .allowStyling()
        .build(renderer);
  }

  private static String sanitize(String html) {
    StringBuilder sb = new StringBuilder();

    HtmlSanitizer.sanitize(html, makePolicy(sb));

    return sb.toString();
  }

  private static final String[] BASE64_BAD_XML_STRINGS = new String[] {
    // first string is
    // "<a - href=\"http://www.owasp.org\">click here</a>"
    "PGEgLSBocmVmPSJodHRwOi8vd3d3Lm93YXNwLm9yZyI+Y2xpY2sgaGVyZTwvYT4=",
    // the rest are randomly generated 300 byte sequences which generate
    // parser errors, turned into Strings
    "uz0sEy5aDiok6oufQRaYPyYOxbtlACRnfrOnUVIbOstiaoB95iw+dJYuO5sI9nudhRtSYLANlcdgO0pRb+65qKDwZ5o6GJRMWv4YajZk+7Q3W/GN295XmyWUpxuyPGVi7d5fhmtYaYNW6vxyKK1Wjn9IEhIrfvNNjtEF90vlERnz3wde4WMaKMeciqgDXuZHEApYmUcu6Wbx4Q6WcNDqohAN/qCli74tvC+Umy0ZsQGU7E+BvJJ1tLfMcSzYiz7Q15ByZOYrA2aa0wDu0no3gSatjGt6aB4h30D9xUP31LuPGZ2GdWwMfZbFcfRgDSh42JPwa1bODmt5cw0Y8ACeyrIbfk9IkX1bPpYfIgtO7TwuXjBbhh2EEixOZ2YkcsvmcOSVTvraChbxv6kP",
    "PIWjMV4y+MpuNLtcY3vBRG4ZcNaCkB9wXJr3pghmFA6rVXAik+d5lei48TtnHvfvb5rQZVceWKv9cR/9IIsLokMyN0omkd8j3TV0DOh3JyBjPHFCu1Gp4Weo96h5C6RBoB0xsE4QdS2Y1sq/yiha9IebyHThAfnGU8AMC4AvZ7DDBccD2leZy2Q617ekz5grvxEG6tEcZ3fCbJn4leQVVo9MNoerim8KFHGloT+LxdgQR6YN5y1ii3bVGreM51S4TeANujdqJXp8B7B1Gk3PKCRS2T1SNFZedut45y+/w7wp5AUQCBUpIPUj6RLp+y3byWhcbZbJ70KOzTSZuYYIKLLo8047Fej43bIaghJm0F9yIKk3C5gtBcw8T5pciJoVXrTdBAK/8fMVo29P",
    "uCk7HocubT6KzJw2eXpSUItZFGkr7U+D89mJw70rxdqXP2JaG04SNjx3dd84G4bz+UVPPhPO2gBAx2vHI0xhgJG9T4vffAYh2D1kenmr+8gIHt6WDNeD+HwJeAbJYhfVFMJsTuIGlYIw8+I+TARK0vqjACyRwMDAndhXnDrk4E5U3hyjqS14XX0kIDZYM6FGFPXe/s+ba2886Q8o1a7WosgqqAmt4u6R3IHOvVf5/PIeZrBJKrVptxjdjelP8Xwjq2ujWNtR3/HM1kjRlJi4xedvMRe4Rlxek0NDLC9hNd18RYi0EjzQ0bGSDDl0813yv6s6tcT6xHMzKvDcUcFRkX6BbxmoIcMsVeHM/ur6yRv834o/TT5IdiM9/wpkuICFOWIfM+Y8OWhiU6BK",
    "Bb6Cqy6stJ0YhtPirRAQ8OXrPFKAeYHeuZXuC1qdHJRlweEzl4F2z/ZFG7hzr5NLZtzrRG3wm5TXl6Aua5G6v0WKcjJiS2V43WB8uY1BFK1d2y68c1gTRSF0u+VTThGjz+q/R6zE8HG8uchO+KPw64RehXDbPQ4uadiL+UwfZ4BzY1OHhvM5+2lVlibG+awtH6qzzx6zOWemTih932Lt9mMnm3FzEw7uGzPEYZ3aBV5xnbQ2a2N4UXIdm7RtIUiYFzHcLe5PZM/utJF8NdHKy0SPaKYkdXHli7g3tarzAabLZqLT4k7oemKYCn/eKRreZjqTB2E8Kc9Swf3jHDkmSvzOYE8wi1vQ3X7JtPcQ2O4muvpSa70NIE+XK1CgnnsL79Qzci1/1xgkBlNq",
    "FZNVr4nOICD1cNfAvQwZvZWi+P4I2Gubzrt+wK+7gLEY144BosgKeK7snwlA/vJjPAnkFW72APTBjY6kk4EOyoUef0MxRnZEU11vby5Ru19eixZBFB/SVXDJleLK0z3zXXE8U5Zl5RzLActHakG8Psvdt8TDscQc4MPZ1K7mXDhi7FQdpjRTwVxFyCFoybQ9WNJNGPsAkkm84NtFb4KjGpwVC70oq87tM2gYCrNgMhBfdBl0bnQHoNBCp76RKdpq1UAY01t1ipfgt7BoaAr0eTw1S32DezjfkAz04WyPTzkdBKd3b44rX9dXEbm6szAz0SjgztRPDJKSMELjq16W2Ua8d1AHq2Dz8JlsvGzi2jICUjpFsIfRmQ/STSvOT8VsaCFhwL1zDLbn5jCr",
    "RuiRkvYjH2FcCjNzFPT2PJWh7Q6vUbfMadMIEnw49GvzTmhk4OUFyjY13GL52JVyqdyFrnpgEOtXiTu88Cm+TiBI7JRh0jRs3VJRP3N+5GpyjKX7cJA46w8PrH3ovJo3PES7o8CSYKRa3eUs7BnFt7kUCvMqBBqIhTIKlnQd2JkMNnhhCcYdPygLx7E1Vg+H3KybcETsYWBeUVrhRl/RAyYJkn6LddjPuWkDdgIcnKhNvpQu4MMqF3YbzHgyTh7bdWjy1liZle7xR/uRbOrRIRKTxkUinQGEWyW3bbXOvPO71E7xyKywBanwg2FtvzOoRFRVF7V9mLzPSqdvbM7VMQoLFob2UgeNLbVHkWeQtEqQWIV5RMu3+knhoqGYxP/3Srszp0ELRQy/xyyD",
    "mqBEVbNnL929CUA3sjkOmPB5dL0/a0spq8LgbIsJa22SfP580XduzUIKnCtdeC9TjPB/GEPp/LvEUFaLTUgPDQQGu3H5UCZyjVTAMHl45me/0qISEf903zFFqW5Lk3TS6iPrithqMMvhdK29Eg5OhhcoHS+ALpn0EjzUe86NywuFNb6ID4o8aF/ztZlKJegnpDAm3JuhCBauJ+0gcOB8GNdWd5a06qkokmwk1tgwWat7cQGFIH1NOvBwRMKhD51MJ7V28806a3zkOVwwhOiyyTXR+EcDA/aq5acX0yailLWB82g/2GR/DiaqNtusV+gpcMTNYemEv3c/xLkClJc29DSfTsJGKsmIDMqeBMM7RRBNinNAriY9iNX1UuHZLr/tUrRNrfuNT5CvvK1K",
    "IMcfbWZ/iCa/LDcvMlk6LEJ0gDe4ohy2Vi0pVBd9aqR5PnRj8zGit8G2rLuNUkDmQ95bMURasmaPw2Xjf6SQjRk8coIHDLtbg/YNQVMabE8pKd6EaFdsGWJkcFoonxhPR29aH0xvjC4Mp3cJX3mjqyVsOp9xdk6d0Y2hzV3W/oPCq0DV03pm7P3+jH2OzoVVIDYgG1FD12S03otJrCXuzDmE2LOQ0xwgBQ9sREBLXwQzUKfXH8ogZzjdR19pX9qe0rRKMNz8k5lqcF9R2z+XIS1QAfeV9xopXA0CeyrhtoOkXV2i8kBxyodDp7tIeOvbEfvaqZGJgaJyV8UMTDi7zjwNeVdyKa8USH7zrXSoCl+Ud5eflI9vxKS+u9Bt1ufBHJtULOCHGA2vimkU",
    "AqC2sr44HVueGzgW13zHvJkqOEBWA8XA66ZEb3EoL1ehypSnJ07cFoWZlO8kf3k57L1fuHFWJ6quEdLXQaT9SJKHlUaYQvanvjbBlqWwaH3hODNsBGoK0DatpoQ+FxcSkdVE/ki3rbEUuJiZzU0BnDxH+Q6FiNsBaJuwau29w24MlD28ELJsjCcUVwtTQkaNtUxIlFKHLj0++T+IVrQH8KZlmVLvDefJ6llWbrFNVuh674HfKr/GEUatG6KI4gWNtGKKRYh76mMl5xH5qDfBZqxyRaKylJaDIYbx5xP5I4DDm4gOnxH+h/Pu6dq6FJ/U3eDio/KQ9xwFqTuyjH0BIRBsvWWgbTNURVBheq+am92YBhkj1QmdKTxQ9fQM55O8DpyWzRhky0NevM9j",
    "qkFfS3WfLyj3QTQT9i/s57uOPQCTN1jrab8bwxaxyeYUlz2tEtYyKGGUufua8WzdBT2VvWTvH0JkK0LfUJ+vChvcnMFna+tEaCKCFMIOWMLYVZSJDcYMIqaIr8d0Bi2bpbVf5z4WNma0pbCKaXpkYgeg1Sb8HpKG0p0fAez7Q/QRASlvyM5vuIOH8/CM4fF5Ga6aWkTRG0lfxiyeZ2vi3q7uNmsZF490J79r/6tnPPXIIC4XGnijwho5NmhZG0XcQeyW5KnT7VmGACFdTHOb9oS5WxZZU29/oZ5Y23rBBoSDX/xZ1LNFiZk6Xfl4ih207jzogv+3nOro93JHQydNeKEwxOtbKqEe7WWJLDw/EzVdJTODrhBYKbjUce10XsavuiTvv+H1Qh4lo2Vx",
    "O900/Gn82AjyLYqiWZ4ILXBBv/ZaXpTpQL0p9nv7gwF2MWsS2OWEImcVDa+1ElrjUumG6CVEv/rvax53krqJJDg+4Z/XcHxv58w6hNrXiWqFNjxlu5RZHvj1oQQXnS2n8qw8e/c+8ea2TiDIVr4OmgZz1G9uSPBeOZJvySqdgNPMpgfjZwkL2ez9/x31sLuQxi/FW3DFXU6kGSUjaq8g/iGXlaaAcQ0t9Gy+y005Z9wpr2JWWzishL+1JZp9D4SY/r3NHDphN4MNdLHMNBRPSIgfsaSqfLraIt+zWIycsd+nksVxtPv9wcyXy51E1qlHr6Uygz2VZYD9q9zyxEX4wRP2VEewHYUomL9d1F6gGG5fN3z82bQ4hI9uDirWhneWazUOQBRud5otPOm9",
    "C3c+d5Q9lyTafPLdelG1TKaLFinw1TOjyI6KkrQyHKkttfnO58WFvScl1TiRcB/iHxKahskoE2+VRLUIhctuDU4sUvQh/g9Arw0LAA4QTxuLFt01XYdigurz4FT15ox2oDGGGrRb3VGjDTXK1OWVJoLMW95EVqyMc9F+Fdej85LHE+8WesIfacjUQtTG1tzYVQTfubZq0+qxXws8QrxMLFtVE38tbeXo+Ok1/U5TUa6FjWflEfvKY3XVcl8RKkXua7fVz/Blj8Gh+dWe2cOxa0lpM75ZHyz9adQrB2Pb4571E4u2xI5un0R0MFJZBQuPDc1G5rPhyk+Hb4LRG3dS0m8IASQUOskv93z978L1+Abu9CLP6d6s5p+BzWxhMUqwQXC/CCpTywrkJ0RG",
  };

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
  }

  public static Test suite() {
    TestSuite suite = new TestSuite(AntiSamyTest.class);
    return suite;
  }

  public static void testCompareSpeeds() throws Exception {
    if (DISABLE_INTERNETS) { return; }

    long totalTime = 0;
    long averageTime = 0;

    int testReps = 15;

    for (String url : new String[] {
            "http://slashdot.org/", "http://www.fark.com/",
            "http://www.cnn.com/", "http://google.com/",
            "http://www.microsoft.com/en/us/default.aspx",
            "http://deadspin.com/",
        }) {
      URLConnection conn = new URL(url).openConnection();
      String ct = guessCharsetFromContentType(conn.getContentType());
      InputStreamReader in = new InputStreamReader(conn.getInputStream(), ct);
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
      if (html.length() > 640000) {
        System.out.println("   -Maximum input size 640000 exceeded. SKIPPING.");
        continue;
      }

      long startTime = 0;
      long endTime = 0;

      for (int j = 0; j < testReps; j++) {
        startTime = System.nanoTime();
        sanitize(html);
        endTime = System.nanoTime();

        System.out.println(
            "    Took " + ((endTime - startTime) / 1000000) + " ms");
        totalTime = totalTime + (endTime - startTime);
      }

      averageTime = totalTime / testReps;
    }

    System.out.println("Total time ms: " + totalTime/1000000L);
    System.out.println("Average time per rep ms: " + averageTime/1000000L);
  }

  /*
   * Test basic XSS cases.
   */

  public static void testScriptAttacks() {
    assertSanitizedDoesNotContain("test<script>alert(document.cookie)</script>", "script");
    assertSanitizedDoesNotContain("test<script>alert(document.cookie)</script>", "script");

    assertSanitizedDoesNotContain("<<<><<script src=http://fake-evil.ru/test.js>", "<script");
    assertSanitizedDoesNotContain("<<<><<script src=http://fake-evil.ru/test.js>", "<script");

    assertSanitizedDoesNotContain("<script<script src=http://fake-evil.ru/test.js>>", "<script");
    assertSanitizedDoesNotContain("<script<script src=http://fake-evil.ru/test.js>>", "<script");

    assertSanitizedDoesNotContain("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");
    assertSanitizedDoesNotContain("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");

    assertSanitizedDoesNotContain("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", "onload");
    assertSanitizedDoesNotContain("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", "onload");

    assertSanitizedDoesNotContain("<BODY ONLOAD=alert('XSS')>", "alert");
    assertSanitizedDoesNotContain("<BODY ONLOAD=alert('XSS')>", "alert");

    assertSanitizedDoesNotContain("<iframe src=http://ha.ckers.org/scriptlet.html <", "<iframe");
    assertSanitizedDoesNotContain("<iframe src=http://ha.ckers.org/scriptlet.html <", "<iframe");

    assertSanitizedDoesNotContain("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", "src");
    assertSanitizedDoesNotContain("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", "src");

    assertSanitizedDoesNotContain("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>", "alert");
    assertSanitizedDoesNotContain("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>", "alert");
  }

  public static void testImgAttacks() {
    assertSanitizedDoesContain("<img src=\"http://www.myspace.com/img.gif\"/>", "<img");
    assertSanitizedDoesContain("<img src=\"http://www.myspace.com/img.gif\"/>", "<img");

    assertSanitizedDoesNotContain("<img src=javascript:alert(document.cookie)>", "<img");

    assertSanitizedDoesNotContain("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", "<img");
    assertSanitizedDoesNotContain("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", "<img");

    assertSanitizedDoesNotContain("<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>", "src");
    assertSanitizedDoesNotContain("<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>", "src");

    assertSanitizedDoesNotContain("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", "alert");
    assertSanitizedDoesNotContain("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", "alert");

    String s = "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>";
    if (sanitize(s).length() != 0) {
      assertSanitizedDoesContain(s, "&amp;");
    }
    s = "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>";
    if (sanitize(s).length() != 0) {
      assertSanitizedDoesContain(s, "&amp;");
    }

    sanitize("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>");
    sanitize("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>");

    assertSanitizedDoesNotContain("<IMG SRC=\"javascript:alert('XSS')\"", "javascript");
    assertSanitizedDoesNotContain("<IMG SRC=\"javascript:alert('XSS')\"", "javascript");

    assertSanitizedDoesNotContain("<IMG LOWSRC=\"javascript:alert('XSS')\">", "javascript");
    assertSanitizedDoesNotContain("<IMG LOWSRC=\"javascript:alert('XSS')\">", "javascript");

    assertSanitizedDoesNotContain("<BGSOUND SRC=\"javascript:alert('XSS');\">", "javascript");
    assertSanitizedDoesNotContain("<BGSOUND SRC=\"javascript:alert('XSS');\">", "javascript");
  }

  public static void testHrefAttacks() {
    assertSanitizedDoesNotContain("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", "href");
    assertSanitizedDoesNotContain("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", "href");

    assertSanitizedDoesNotContain("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", "href");
    assertSanitizedDoesNotContain("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", "href");

    assertSanitizedDoesNotContain("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", "ha.ckers.org");
    assertSanitizedDoesNotContain("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", "ha.ckers.org");

    assertSanitizedDoesNotContain("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", "ha.ckers.org");
    assertSanitizedDoesNotContain("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", "ha.ckers.org");

    assertSanitizedDoesNotContain("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", "javascript");
    assertSanitizedDoesNotContain("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", "javascript");

    assertSanitizedDoesNotContain("<IMG SRC='vbscript:msgbox(\"XSS\")'>", "vbscript");
    assertSanitizedDoesNotContain("<IMG SRC='vbscript:msgbox(\"XSS\")'>", "vbscript");

    assertSanitizedDoesNotContain("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", "<meta");
    assertSanitizedDoesNotContain("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", "<meta");

    assertSanitizedDoesNotContain("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", "<meta");
    assertSanitizedDoesNotContain("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", "<meta");

    assertSanitizedDoesNotContain("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", "<meta");
    assertSanitizedDoesNotContain("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", "<meta");

    assertSanitizedDoesNotContain("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", "iframe");
    assertSanitizedDoesNotContain("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", "iframe");

    assertSanitizedDoesNotContain("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", "javascript");
    assertSanitizedDoesNotContain("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", "javascript");

    assertSanitizedDoesNotContain("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", "background");
    assertSanitizedDoesNotContain("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", "background");

    assertSanitizedDoesNotContain("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", "background");
    assertSanitizedDoesNotContain("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", "background");

    assertSanitizedDoesNotContain("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", "javascript");
    assertSanitizedDoesNotContain("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", "javascript");

    assertSanitizedDoesNotContain("<DIV STYLE=\"width: expression(alert('XSS'));\">", "alert");
    assertSanitizedDoesNotContain("<DIV STYLE=\"width: expression(alert('XSS'));\">", "alert");

    assertSanitizedDoesNotContain("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", "alert");
    assertSanitizedDoesNotContain("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", "alert");

    assertSanitizedDoesNotContain("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", "ript:alert");
    assertSanitizedDoesNotContain("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", "ript:alert");

    assertSanitizedDoesNotContain("<BASE HREF=\"javascript:alert('XSS');//\">", "javascript");
    assertSanitizedDoesNotContain("<BASE HREF=\"javascript:alert('XSS');//\">", "javascript");

    assertSanitizedDoesNotContain("<BaSe hReF=\"http://arbitrary.com/\">", "<base");
    assertSanitizedDoesNotContain("<BaSe hReF=\"http://arbitrary.com/\">", "<base");

    assertSanitizedDoesNotContain("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", "<object");
    assertSanitizedDoesNotContain("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", "<object");

    assertSanitizedDoesNotContain("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", "javascript");

    assertSanitizedDoesNotContain("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", "javascript");

    assertSanitizedDoesNotContain("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", "<embed");
    assertSanitizedDoesNotContain("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", "<embed");

    assertSanitizedDoesNotContain("<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", "<embed");
    assertSanitizedDoesNotContain("<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", "<embed");

    assertSanitizedDoesNotContain("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");
    assertSanitizedDoesNotContain("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");

    assertSanitizedDoesNotContain("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");
    assertSanitizedDoesNotContain("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");

    assertSanitizedDoesNotContain("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");
    assertSanitizedDoesNotContain("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");

    assertSanitizedDoesNotContain("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");
    assertSanitizedDoesNotContain("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script");

    assertSanitizedDoesNotContain("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "script");
    assertSanitizedDoesNotContain("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "script");

    assertSanitizedDoesNotContain("<SCRIPT SRC=http://ha.ckers.org/xss.js", "<script");
    assertSanitizedDoesNotContain("<SCRIPT SRC=http://ha.ckers.org/xss.js", "<script");

    assertSanitizedDoesNotContain("<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", "style");
    assertSanitizedDoesNotContain("<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", "style");

    assertSanitizedDoesNotContain("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", "aim.exe");
    assertSanitizedDoesNotContain("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", "aim.exe");

    assertSanitizedDoesNotContain("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", "javascript");
    assertSanitizedDoesNotContain("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", "javascript");

    assertSanitizedDoesNotContain("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", "document");
    assertSanitizedDoesNotContain("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", "document");
  }

  /*
   * Test CSS protections.
   */

  public static void testCssAttacks() {

    assertSanitizedDoesNotContain("<div style=\"position:absolute\">", "position");
    assertSanitizedDoesNotContain("<div style=\"position:absolute\">", "position");

    assertSanitizedDoesNotContain("<style>b { position:absolute }</style>", "position");
    assertSanitizedDoesNotContain("<style>b { position:absolute }</style>", "position");

    assertSanitizedDoesNotContain("<div style=\"z-index:25\">test</div>", "z-index");
    assertSanitizedDoesNotContain("<div style=\"z-index:25\">test</div>", "z-index");

    assertSanitizedDoesNotContain("<style>z-index:25</style>", "z-index");
    assertSanitizedDoesNotContain("<style>z-index:25</style>", "z-index");
  }

  /*
   * Test a bunch of strings that have tweaked the XML parsing capabilities of
   * NekoHTML.
   */
  public static void testIllegalXML() throws Exception {
    for (int i = 0; i < BASE64_BAD_XML_STRINGS.length; i++) {
      String testStr = new String(
          Base64.decodeBase64(BASE64_BAD_XML_STRINGS[i]),
          "UTF-8");
      sanitize(testStr);
      sanitize(testStr);
    }

    // These fail in AntiSamy due to a bug in NekoHTML
    assertEquals(
        "<a href=\"http://www.test.com\" rel=\"nofollow\"></a>",
        sanitize("<a . href=\"http://www.test.com\">"));
    assertEquals(
        "<a href=\"http://www.test.com\" rel=\"nofollow\"></a>",
        sanitize("<a - href=\"http://www.test.com\">"));

    assertTrue(sanitize("<style>") != null);
  }

  public static void testPreviousBugs() {

    /*
     * issues 12 (and 36, which was similar). empty tags cause display
     * problems/"formjacking"
     */

    {
      Pattern p = Pattern.compile(".*<strong(\\s*)/>.*", Pattern.DOTALL);
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
    }

    /* issue #20 */
    assertSanitizedDoesNotContain("<b><i>Some Text</b></i>", "<i />");

    assertSanitizedDoesNotContain("<b><i>Some Text</b></i>", "<i />");


    /* issue #25 */
    assertEquals(
        "<div>Test</div>", sanitize("<div style=\"margin: -5em\">Test</div>"));


    /* issue #28 */
    assertSanitizedDoesContain(
        "<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>",
        "font-family:&#39;geneva&#39; , &#39;arial&#39; , &#39;courier new&#39; , sans-serif");

    /* issue #29 - missing quotes around properties with spaces */
    if (RUN_KNOWN_FAILURES) {
      String s = "<style type=\"text/css\"><![CDATA[P {\n     font-family: \"Arial Unicode MS\";\n}\n]]></style>";
      assertEquals(s, sanitize(s));
    }


    /* issue #30 */
    if (RUN_KNOWN_FAILURES) {
      String s = "<style type=\"text/css\"><![CDATA[P { margin-bottom: 0.08in; } ]]></style>";

      s = sanitize(s);

      // followup - does the patch fix multiline CSS?
      String s2 = "<style type=\"text/css\"><![CDATA[\r\nP {\r\n margin-bottom: 0.08in;\r\n}\r\n]]></style>";
      assertEquals("<style type=\"text/css\"><![CDATA[P {\n\tmargin-bottom: 0.08in;\n}\n]]></style>", sanitize(s2));

      // next followup - does non-CDATA parsing still work?

      String s3 = "<style>P {\n\tmargin-bottom: 0.08in;\n}\n";
      assertEquals("<style>P {\n\tmargin-bottom: 0.08in;\n}\n</style>\n", sanitize(s3));

      // for other
      // tests
    }

    /* issue #32 - nekos problem */
    {
      String s = "<SCRIPT =\">\" SRC=\"\"></SCRIPT>";
      sanitize(s);
      sanitize(s);
    }

    /* issue #37 - OOM */
    {
      String dirty = "<a onblur=\"try {parent.deselectBloggerImageGracefully();}" + "catch(e) {}\""
      + "href=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\"><img" + "style=\"FLOAT: right; MARGIN: 0px 0px 10px 10px; WIDTH: 150px; CURSOR:"
      + "hand; HEIGHT: 100px\" alt=\"\"" + "src=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\""
      + "border=\"0\" /></a><br />Poor Bill, couldn't make it to the Museum's <span" + "class=\"blsp-spelling-corrected\" id=\"SPELLING_ERROR_0\">story time</span>"
      + "today, he was so busy shoveling! Well, we sure missed you Bill! So since" + "ou were busy moving snow we read books about snow. We found a clue in one"
      + "book which revealed a snowplow at the end of the story - we wish it had" + "driven to your driveway Bill. We also read a story which shared fourteen"
      + "<em>Names For Snow. </em>We'll catch up with you next week....wonder which" + "hat Bill will wear?<br />Jane";

      String s = sanitize(dirty);
      assertNotNull(s);
    }

    /* issue #38 - color problem/color combinations */
    {
      String s = "<font color=\"#fff\">Test</font>";
      String expected = "<font color=\"#fff\">Test</font>";
      assertEquals(expected, sanitize(s));
      assertEquals(expected, sanitize(s));

      s = "<div style=\"color: #fff\">Test 3 letter code</div>";
      expected = "<div style=\"color:#fff\">Test 3 letter code</div>";
      assertEquals(expected, sanitize(s));
      assertEquals(expected, sanitize(s));

      s = "<font color=\"red\">Test</font>";
      expected = "<font color=\"red\">Test</font>";
      assertEquals(expected, sanitize(s));
      assertEquals(expected, sanitize(s));

      s = "<font color=\"neonpink\">Test</font>";
      expected = s;
      assertEquals(expected, sanitize(s));
      assertEquals(expected, sanitize(s));

      if (RUN_KNOWN_FAILURES) {
        s = "<font color=\"#0000\">Test</font>";
        expected = "<font>Test</font>";
        assertEquals(expected, sanitize(s));
        assertEquals(expected, sanitize(s));
      }

      if (RUN_KNOWN_FAILURES) {
        s = "<div style=\"color: #0000\">Test</div>";
        expected = "<div>Test</div>";
        assertEquals(expected, sanitize(s));
        assertEquals(expected, sanitize(s));
      }

      s = "<font color=\"#000000\">Test</font>";
      expected = "<font color=\"#000000\">Test</font>";
      assertEquals(expected, sanitize(s));
      assertEquals(expected, sanitize(s));

      s = "<div style=\"color: #000000\">Test</div>";
      expected = "<div style=\"color:#000000\">Test</div>";
      assertEquals(expected, sanitize(s));
      assertEquals(expected, sanitize(s));

      s = "<b><u>foo<style><script>alert(1)</script></style>@import 'x';</u>bar";
      sanitize(s);
    }

    /* issue #40 - handling <style> media attributes right */

    if (RUN_KNOWN_FAILURES) {
      assertSanitizedDoesContain("<style media=\"print, projection, screen\"> P { margin: 1em; }</style>", "print, projection, screen");
    }

    /* issue #41 - comment handling */

    {
      assertEquals("text ", sanitize("text <!-- comment -->"));
      assertEquals("text ", sanitize("text <!-- comment -->"));


      assertEquals("<div>text </div>", sanitize("<div>text <!-- comment --></div>"));
      assertEquals("<div>text </div>", sanitize("<div>text <!-- comment --></div>"));

      assertEquals("<div>text </div>", sanitize("<div>text <!--[if IE]> comment <[endif]--></div>"));
      assertEquals("<div>text </div>", sanitize("<div>text <!--[if IE]> comment <[endif]--></div>"));

      /*
       * Check to see how nested conditional comments are handled. This is
       * not very clean but the main goal is to avoid any tags. Not sure
       * on encodings allowed in comments.
       */
      String input = "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>";
      String expected = "<div>text &lt;[endif]--&gt;</div>";
      String output = sanitize(input);
      assertEquals(expected, output);

      input = "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>";
      expected = "<div>text &lt;[endif]--&gt;</div>";
      output = sanitize(input);
      assertEquals(expected, output);

      /*
       * Regular comment nested inside conditional comment. Test makes
       * sure
       */
      assertEquals("<div>text  comment &lt;[endif]--&gt;</div>", sanitize("<div>text <!--[if IE]> <!-- IE specific --> comment <[endif]--></div>"));

      /*
       * These play with whitespace and have invalid comment syntax.
       */
      assertEquals("<div>text </div>", sanitize("<div>text <!-- [ if lte 6 ]>\ncomment <[ endif\n]--></div>"));
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

      assertSanitizedDoesNotContain(s, "<script");
      assertSanitizedDoesNotContain(s, "<script");
    }

    /*
     * issue #44 - childless nodes of non-allowed elements won't cause an error
     */
    {
      String s = "<iframe src='http://foo.com/'></iframe>" + "<script src=''></script>" + "<link href='/foo.css'>";
      assertEquals(s, "", sanitize(s));
    }

    /* issue #51 - offsite urls with () are found to be invalid */
    assertSanitizedDoesNotContain(
        "<a href='http://subdomain.domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx'>test</a>", "(");

    /* issue #56 - unnecessary spaces */
    {
      String s = "<SPAN style='font-weight: bold;'>Hello World!</SPAN>";
      assertEquals(
          "<span style=\"font-weight:bold\">Hello World!</span>",
          sanitize(s));
    }

    /* issue #58 - input not in list of allowed-to-be-empty tags */
    {
      String s = "tgdan <input/> g  h";
      assertEquals("tgdan  g  h", sanitize(s));
    }


    /* issue #61 - input has newline appended if ends with an accepted tag */
    {
      String dirtyInput = "blah <b>blah</b>.";
      String s = sanitize(dirtyInput);
      assertEquals(dirtyInput, s);
    }

    /* issue #69 - char attribute should allow single char or entity ref */

    {
      String s = "<td char='.'>test</td>";
      assertSanitizedDoesContain(s, "char");
      assertSanitizedDoesContain(s, "char");

      s = "<td char='..'>test</td>";
      assertSanitizedDoesNotContain(s, "char");
      assertSanitizedDoesNotContain(s, "char");

      s = "<td char='&quot;'>test</td>";
      assertSanitizedDoesContain(s, "char");
      assertSanitizedDoesContain(s, "char");

      s = "<td char='&quot;a'>test</td>";
      assertSanitizedDoesNotContain(s, "char");
      assertSanitizedDoesNotContain(s, "char");

      s = "<td char='&quot;&amp;'>test</td>";
      assertSanitizedDoesNotContain(s, "char");
      assertSanitizedDoesNotContain(s, "char");
    }

    /* privately disclosed issue - cdata bypass */
    {
      String malInput = "<![CDATA[]><script>alert(1)</script>]]>";

      assertSanitizedDoesNotContain(malInput, "<script");
    }

    /* this test is for confirming literal-lists work as
     * advertised. it turned out to be an invalid / non-
     * reproducible bug report but the test seemed useful
     * enough to keep.
     */
    {
      String malInput = "hello<p align='invalid'>world</p>";
      assertSanitizedDoesNotContain(malInput, "invalid");

      String goodInput = "hello<p align='left'>world</p>";
      if (RUN_KNOWN_FAILURES) {
        assertSanitizedDoesContain(goodInput, "left");
      }
    }
  }

  /*
   * Tests cases dealing with nofollowAnchors directive. Assumes anchor tags
   * have an action set to "validate" (may be implicit) in the policy file.
   */
  public static void testNofollowAnchors() {
    // adds when not present
    assertSanitized("<a href=\"blah\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>");

    // adds properly even with bad attr
    assertSanitized("<a href=\"blah\" bad=\"true\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>");

    // rel with bad value gets corrected
    assertSanitized("<a href=\"blah\" rel=\"blh\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>");

    // correct attribute doesnt get messed with
    assertSanitized("<a href=\"blah\" rel=\"nofollow\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>");

    // if two correct attributes, only one remaining after scan
    assertSanitized("<a href=\"blah\" rel=\"nofollow\" rel=\"nofollow\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>");

    // test if value is off - does it add?
    assertSanitizedDoesNotContain("a href=\"blah\">link</a>", "nofollow");
  }

  public static void testValidateParamAsEmbed() {
    // let's start with a YouTube embed
    String input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
    String expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>";
    if (RUN_KNOWN_FAILURES) {
      assertSanitizedDoesContain(input, expectedOutput);
    } else {
      assertSanitized(input, "");
    }

    String saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
    if (RUN_KNOWN_FAILURES) {
      assertSanitizedDoesContain(input, saxExpectedOutput);
    } else {
      assertSanitized(input, "");
    }

    // now what if someone sticks malicious URL in the value of the
    // value attribute in the param tag? remove that param tag
    input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://supermaliciouscode.com/badstuff.swf\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
    expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>";
    saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
    if (RUN_KNOWN_FAILURES) {
      assertSanitizedDoesContain(input, expectedOutput);
    } else {
      assertSanitized(input, "");
    }

    if (RUN_KNOWN_FAILURES) {
      assertTrue(sanitize(input).equals(saxExpectedOutput));
    } else {
      assertSanitized(input, "");
    }

    // now what if someone sticks malicious URL in the value of the src
    // attribute in the embed tag? remove that embed tag
    input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://hereswhereikeepbadcode.com/ohnoscary.swf\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
    expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /></object>";
    saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"></object>";

    if (RUN_KNOWN_FAILURES) {
      assertSanitizedDoesContain(input, expectedOutput);
    } else {
      assertSanitized(input, "");
    }

    if (RUN_KNOWN_FAILURES) {
      assertSanitizedDoesContain(input, saxExpectedOutput);
    } else {
      assertSanitized(input, "");
    }
  }


  private static void assertSanitizedDoesNotContain(
      String html, String dangerousContent) {
    String sanitized = sanitize(html);
    int index = Strings.toLowerCase(sanitized).indexOf(
        Strings.toLowerCase(dangerousContent));
    assertEquals(
        "`" + sanitized + "` from `" + html + "` contains `" +
        dangerousContent + "`",
        -1, index);
  }

  private static void assertSanitizedDoesContain(
      String html, String dangerousContent) {
    String sanitized = sanitize(html);
    int index = Strings.toLowerCase(sanitized).indexOf(
        Strings.toLowerCase(dangerousContent));
    assertTrue(
        "`" + sanitized + "` from `" + html + "` does not contain `" +
        dangerousContent + "`",
        index >= 0);
  }

  private static void assertSanitized(String html, String sanitized) {
    assertEquals(sanitized, sanitize(html));
  }

  private static String guessCharsetFromContentType(String contentType) {
    Matcher m = Pattern.compile(";\\s*charset=(?:\"([^\"]*)\"|([^\\s;]*))")
      .matcher(contentType);
    if (m.find()) {
      String ct;
      ct = m.group(1);
      if (ct != null) { return ct; }
      ct = m.group(2);
      if (ct != null) { return ct; }
    }
    return "UTF-8";
  }
}
