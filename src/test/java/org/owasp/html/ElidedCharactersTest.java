package org.owasp.html;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Some characters should not appear in HTML documents, present risks for log-file injection, or are otherwise discouraged from sanitized HTML. This set of
 * unit tests verifies that the inclusion of such characters does not allow dangerous code to slip through.
 * <p>
 * There are two requirements:
 * <p>
 * 1) The Encoding.encodeRcdataOnto method should remove discouraged characters.
 * 2) Sanitized HTML should not change
 *
 * @author Simon Greatrix on 25/01/2021.
 */
public class ElidedCharactersTest extends TestCase {

  /** List of all characters that are discouraged in HTML. */
  static List<String> DISCOURAGED;


  @Test
  public static final void testRemoveDiscouragedCharacterFromTagStart() throws IOException {
    // <Xp></p> is an unrecognised tag and an unmatched end tag
    for (String d : DISCOURAGED) {
      String test = "<" + d+"h1></h1>";
      String html = Sanitizers.BLOCKS.sanitize(test);
      String m = String.format("Use in <h1> of U+%06x", d.codePointAt(0));
      assertEquals(m, "&lt;h1&gt;", html);
    }

    String html = Sanitizers.BLOCKS.sanitize("<h1></h1>");
    assertEquals("<h1></h1>",html);
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromInsideTag() throws IOException {
    // <h1X></h1> is an unrecognised tag and an unmatched end tag
    for (String d : DISCOURAGED) {
      String test = "<h"+d+"1></h1>";
      String html = Sanitizers.BLOCKS.sanitize(test);
      String m = String.format("Use in <h1> of U+%06x", d.codePointAt(0));
      assertEquals(m, "", html);
    }

    String html = Sanitizers.BLOCKS.sanitize("<h1></h1>");
    assertEquals("<h1></h1>",html);
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromTagEnd() throws IOException {
    // <h1X></h1> is an unrecognised tag and an unmatched end tag
    for (String d : DISCOURAGED) {
      String test = "<h1"+ d+"></h1>";
      String html = Sanitizers.BLOCKS.sanitize(test);
      String m = String.format("Use in <h1> of U+%06x", d.codePointAt(0));
      assertEquals(m, "", html);
    }

    String html = Sanitizers.BLOCKS.sanitize("<h1></h1>");
    assertEquals("<h1></h1>",html);
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromEndWhenEncoding() throws IOException {
    for (String d : DISCOURAGED) {
      String test = "Hello" + d;
      StringBuilder builder = new StringBuilder();
      Encoding.encodePcdataOnto(test, builder);
      String m = String.format("Elision of U+%06x", d.codePointAt(0));
      assertEquals(m, "Hello", builder.toString());
    }
  }


  @Test
  public static final void testRemoveDiscouragedCharacterFromMiddleWhenEncoding() throws IOException {
    for (String d : DISCOURAGED) {
      String test = "Hel" + d + "lo";
      StringBuilder builder = new StringBuilder();
      Encoding.encodePcdataOnto(test, builder);
      String m = String.format("Elision of U+%06x", d.codePointAt(0));
      assertEquals(m, "Hello", builder.toString());
    }
  }


  @Test
  public static final void testRemoveDiscouragedCharacterFromStartWhenEncoding() throws IOException {
    for (String d : DISCOURAGED) {
      String test = d + "Hello";
      StringBuilder builder = new StringBuilder();
      Encoding.encodePcdataOnto(test, builder);
      String m = String.format("Elision of U+%06x", d.codePointAt(0));
      assertEquals(m, "Hello", builder.toString());
    }
  }


  static {
    ArrayList<String> list = new ArrayList<String>();

    // C0 characters banned by XML, except for the three official whitespace characters
    for (char i = 0; i <= 0x1f; i++) {
      if (i != 0x9 && i != 0xa && i != 0xd && i!=0xc) {
        list.add(Character.toString(i));
      }
    }

    // Delete character and C1 escapes which are discouraged by XML and banned as HTML numeric escapes. Also discouraging the U+0085 NEL characters.
    for (char i = 0x7f; i <= 0x9f; i++) {
      list.add(Character.toString(i));
    }

    // Isolated surrogates. NB Must also test that valid non-isolated surrogates are retained.
    for (char i = 0xd800; i <= 0xdfff; i++) {
      list.add(Character.toString(i));
    }

    // Isolated surrogates. NB Must also test that valid non-isolated surrogates are retained.
    for (char i = 0xfdd0; i <= 0xfdef; i++) {
      list.add(Character.toString(i));
    }

    list.add(Character.toString((char) 0xfffe));
    list.add(Character.toString((char) 0xffff));

    // Non-characters from the supplemental planes
    for (int i = 1; i <= 16; i++) {
      list.add(new String(Character.toChars(0x10000 * i + 0xfffe)));
      list.add(new String(Character.toChars(0x10000 * i + 0xffff)));
    }

    DISCOURAGED = Collections.unmodifiableList(list);
  }

}
