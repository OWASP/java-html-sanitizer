package org.owasp.html;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class HtmlElementTablesTest extends TestCase {
  HtmlElementTables t;

  @Before @Override
  public void setUp() throws Exception {
    super.setUp();
    t = HtmlElementTables.get();
  }

  @Test
  public void testElementNames() {
    assertTrue(
        t.indexForName("a")
        != t.indexForName("b"));
    assertTrue(
        t.indexForName("p")
        != t.indexForName("q"));
    assertTrue(
        t.indexForName("customclass")
        >= 0);

    for (int ei = 0, nei = t.nElementTypes(); ei < nei; ++ei) {
      String s = t.canonNameForIndex(ei);
      assertEquals(ei, t.indexForName(s));
      ++ei;
    }
  }

  private int ix(String nm) {
    return t.indexForName(nm);
  }

  @Test
  public void testCanAppearIn() {
    assertFalse(t.canContain(ix("a"), ix("a")));
    assertFalse(t.canContain(ix("p"), ix("p")));
    assertTrue(t.canContain(ix("a"), ix("p")));
    assertTrue(t.canContain(ix("a"), ix("p")));

    assertTrue(t.canContain(ix("span"), ix("div")));
    assertTrue(t.canContain(ix("div"), ix("span")));
    assertTrue(t.canContain(ix("span"), ix("span")));

    assertTrue(t.canContain(ix("tr"), ix("td")));
    assertFalse(t.canContain(ix("span"), ix("td")));
    assertFalse(t.canContain(ix("div"), ix("td")));

    assertTrue(t.canContain(ix("html"), ix("body")));
    assertTrue(t.canContain(ix("html"), ix("head")));
    assertFalse(t.canContain(ix("body"), ix("html")));
    assertTrue(t.canContain(ix("body"), ix("p")));
  }

  @Test
  public void testCanBodyContain() {
    assertTrue(t.canContain(ix("body"), ix("a")));
    assertTrue(t.canContain(ix("body"), ix("p")));
    assertTrue(t.canContain(ix("body"), ix("table")));
    assertFalse(t.canContain(ix("body"), ix("tr")));
    assertFalse(t.canContain(ix("body"), ix("html")));
  }

  @Test
  public void testExplicitClosers() {
    int h1 = ix("h1"), h2 = ix("h2"), h3 = ix("h3"),
        h4 = ix("h4"), h5 = ix("h5"), h6 = ix("h6");
    for (int i = 0, n = t.nElementTypes(); i < n; ++i) {
      assertEquals(
          t.canonNameForIndex(i),
          i == h2 || i == h3 || i == h4 || i == h5 || i == h6,
          t.isAlternateCloserFor(i, h1));
      assertFalse(t.isAlternateCloserFor(i, ix("template")));
    }
  }

  @Test
  public void testImpliedElements() {
    assertEquals(
        Arrays.toString(new int[] { ix("table"), ix("tbody"), ix("tr") }),
        Arrays.toString(
            t.impliedElements(ix("table"), ix("td"))));
    assertEquals(
        Arrays.toString(new int[] { ix("table"), ix("tbody"), ix("tr") }),
        Arrays.toString(
            t.impliedElements(ix("table"), ix("th"))));
    assertEquals(
        Arrays.toString(new int[] { ix("table"), ix("tbody") }),
        Arrays.toString(
            t.impliedElements(ix("table"), ix("tr"))));
    assertEquals(
        Arrays.toString(new int[0]),
        Arrays.toString(
            t.impliedElements(ix("table"), ix("thead"))));
    assertEquals(
        Arrays.toString(new int[] { ix("li") }),
        Arrays.toString(
            t.impliedElements(ix("ol"), ix("span"))));
    assertEquals(
        Arrays.toString(new int[] { ix("li") }),
        Arrays.toString(
            t.impliedElements(ix("ul"), ix("span"))));
    assertEquals(
        Arrays.toString(new int[] { ix("table"), ix("tbody") }),
        Arrays.toString(
            t.impliedElements(ix("table"), ix("tr"))));
    assertEquals(
        Arrays.toString(new int[] {}),
        Arrays.toString(
            t.impliedElements(ix("td"), ix("td"))));
  }

  @Test
  public void testTextContentModel() {
    assertTrue(t.canContainComment(ix("p")));
    assertFalse(t.canContainComment(ix("script")));

    assertTrue(t.canContainCharacterReference(ix("p")));
    assertTrue(t.canContainCharacterReference(ix("textarea")));
    assertFalse(t.canContainCharacterReference(ix("script")));

    assertTrue(t.canContainText(ix("p")));
    assertTrue(t.canContainText(ix("script")));
    assertFalse(t.canContainText(ix("br")));

    assertTrue(t.isTextContentRaw(ix("script")));
    assertTrue(t.isTextContentRaw(ix("iframe")));
    assertTrue(t.isTextContentRaw(ix("textarea")));
    assertFalse(t.isTextContentRaw(ix("p")));

    assertTrue(t.isUnended(ix("plaintext")));
    assertFalse(t.isUnended(ix("script")));
  }
}
