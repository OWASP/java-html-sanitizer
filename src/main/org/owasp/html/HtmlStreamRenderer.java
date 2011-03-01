package org.owasp.html;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import com.google.common.annotations.VisibleForTesting;

/**
 * Given a series of HTML tokens, writes valid, normalized HTML to the output.
 * The output will have well-defined tag boundaries, but there may be orphaned
 * or missing close and open tags.
 * The result of two renderers can always be concatenated to produce a larger
 * snippet of HTML, but if the first was called with
 * {@code writeOpenTag("plaintext", ...)}, then any tags in the second will not
 * be interpreted as tags in the concatenated version.
 */
@TCB
public class HtmlStreamRenderer implements HtmlStreamEventReceiver {

  private final Appendable output;
  private final Handler<? super IOException> ioExHandler;
  private final Handler<? super String> badHtmlHandler;
  private String lastTagOpened;
  private StringBuilder pendingUnescaped;
  private boolean open;

  /**
   * @param output the buffer to which HTML is streamed.
   * @param ioExHandler called with any exception raised by output.
   */
  public static HtmlStreamRenderer create(
      Appendable output, Handler<? super IOException> ioExHandler,
      Handler<? super String> badHtmlHandler) {
    if (output instanceof Closeable) {
      return new CloseableHtmlStreamRenderer(
          output, ioExHandler, badHtmlHandler);
    } else {
      return new HtmlStreamRenderer(output, ioExHandler, badHtmlHandler);
    }
  }

  private HtmlStreamRenderer(
      Appendable output, Handler<? super IOException> ioExHandler,
      Handler<? super String> badHtmlHandler) {
    this.output = output;
    this.ioExHandler = ioExHandler;
    this.badHtmlHandler = badHtmlHandler;
  }

  public static HtmlStreamRenderer create(
      StringBuilder output, Handler<? super String> badHtmlHandler) {
    // Propagate since StringBuilder should not throw IOExceptions.
    return create(output, Handler.PROPAGATE, badHtmlHandler);
  }

  /**
   * Called when the series of calls make no sense.
   * May be overridden to throw an unchecked throwable, to log, or to take some
   * other action.
   *
   * @param message for human consumption.
   * @param identifier an HTML identifier associated with the message.
   */
  private final void error(String message, String identifier) {
    if (ioExHandler != Handler.DO_NOTHING) {   // Avoid string append.
      badHtmlHandler.handle(message + " : " + identifier);
    }
  }

  /**
   *
   */
  @Override
  public final void openDocument() throws IllegalStateException {
    if (open) { throw new IllegalStateException(); }
    open = true;
  }

  @Override
  public final void closeDocument() throws IllegalStateException {
    if (!open) { throw new IllegalStateException(); }
    if (pendingUnescaped != null) {
      closeTag(lastTagOpened);
    }
    open = false;
    if (output instanceof Flushable) {
      try {
        ((Flushable) output).flush();
      } catch (IOException ex) {
        ioExHandler.handle(ex);
      }
    }
  }

  public final boolean isDocumentOpen() {
    return open;
  }

  @Override
  public final void openTag(String elementName, List<String> attrs) {
    try {
      writeOpenTag(elementName, attrs);
    } catch (IOException ex) {
      ioExHandler.handle(ex);
    }
  }

  private void writeOpenTag(String elementName, List<? extends String> attrs)
      throws IOException {
    if (!open) { throw new IllegalStateException(); }
    elementName = HtmlLexer.canonicalName(elementName);
    if (!isValidHtmlName(elementName)) {
      error("Invalid element name", elementName);
      return;
    }
    if (pendingUnescaped != null) {
      error("Tag content cannot appear inside CDATA element", elementName);
      return;
    }

    switch (HtmlTextEscapingMode.getModeForTag(elementName)) {
      case CDATA:
      case CDATA_SOMETIMES:
      case PLAIN_TEXT:
        lastTagOpened = elementName;
        pendingUnescaped = new StringBuilder();
        break;
      default:
    }

    output.append('<').append(elementName);

    for (Iterator<? extends String> attrIt = attrs.iterator();
         attrIt.hasNext();) {
      String name = attrIt.next();
      String value = attrIt.next();
      name = HtmlLexer.canonicalName(name);
      if (!isValidHtmlName(name)) {
        error("Invalid attr name", name);
        continue;
      }
      output.append(' ').append(name).append('=').append('"');
      escapeHtmlOnto(value, output);
      output.append('"');
    }

    output.append('>');
  }

  @Override
  public final void closeTag(String elementName) {
    try {
      writeCloseTag(elementName);
    } catch (IOException ex) {
      ioExHandler.handle(ex);
    }
  }

  private final void writeCloseTag(String elementName)
      throws IOException {
    if (!open) { throw new IllegalStateException(); }
    elementName = HtmlLexer.canonicalName(elementName);
    if (!isValidHtmlName(elementName)) {
      error("Invalid element name", elementName);
      return;
    }

    if (pendingUnescaped != null) {
      if (!lastTagOpened.equals(elementName)) {
        error("Tag content cannot appear inside CDATA element", elementName);
        return;
      } else {
        String unescaped = pendingUnescaped.toString();
        pendingUnescaped = null;
        if (!containsCloseTag(unescaped, lastTagOpened)) {
          output.append(unescaped);
        } else {
          error("Unescaped text content contains close tag", elementName);
          // Still output the close tag.
        }
      }
      if ("plaintext".equals(elementName)) { return; }
    }
    output.append("</").append(elementName).append(">");
  }

  @Override
  public final void text(String text) {
    try {
      writeText(text);
    } catch (IOException ex) {
      ioExHandler.handle(ex);
    }
  }

  private final void writeText(String text) throws IOException {
    if (!open) { throw new IllegalStateException(); }
    if (pendingUnescaped != null) {
      pendingUnescaped.append(text.replaceAll("\0", ""));
    } else {
      escapeHtmlOnto(text, output);  // Works for RCDATA.
    }
  }

  private static boolean containsCloseTag(String unescaped, String tagName) {
    boolean allowEscapingTextSpan = HtmlTextEscapingMode.allowsEscapingTextSpan(
        tagName);

    int unescapedLength = unescaped.length();
    int tagNameLength = tagName.length();
    int limit = unescapedLength - tagName.length() - 2;
    for (int i = -1; (i = unescaped.indexOf('<', i + 1)) >= 0;) {
      if (i <= limit && '/' == unescaped.charAt(i + 1)
          && Strings.regionMatchesIgnoreCase(
              unescaped, i + 2, tagName, 0, tagNameLength)) {
        // Content cannot be embedded.
        return true;
      } else if (allowEscapingTextSpan && i + 4 <= unescapedLength
                 && '!' == unescaped.charAt(i + 1)
                 && '-' == unescaped.charAt(i + 2)
                 && '-' == unescaped.charAt(i + 3)) {
        // HTML 5 allows the end of an escaping text span to share dashes with
        // the open : <!--> and <!---> are both fully formed.
        if (i + 4 < unescapedLength && unescaped.charAt(i + 4) == '>') {
          i = i + 5;
        } else if (i + 5 < unescapedLength
                   && unescaped.charAt(i + 4) == '-'
                   && unescaped.charAt(i + 5) == '>') {
          i = i + 6;
        } else {
          i = unescaped.indexOf("-->", i + 4);
          if (i < 0) {
            // If the escaping text span is not closed, then final close tag
            // would be covered by the unclosed escaping text span.
            return true;
          }
        }
      }
    }
    return false;
  }


  @VisibleForTesting
  static boolean isValidHtmlName(String name) {
    int n = name.length();
    if (n == 0) { return false; }
    if (n > 128) { return false; }
    boolean isNamespaced = false;
    for (int i = 0; i < n; ++i) {
      char ch = name.charAt(i);
      switch (ch) {
        case ':':
          if (isNamespaced) { return false; }
          isNamespaced = true;
          // $FALL-THROUGH$
        case '-':
          if (i == 0 || i + 1 == n) { return false; }
          break;
        default:
          if (ch <= '9') {
            if (i == 0 || ch < '0') { return false; }
          } else if ('A' <= ch && ch <= 'z') {
            if ('Z' < ch && ch < 'a') { return false; }
          } else {
            return false;
          }
          break;
      }
    }
    return true;
  }

  static void escapeHtmlOnto(String plainText, Appendable output)
      throws IOException {
    int n = plainText.length();
    int pos = 0;
    for (int i = 0; i < n; ++i) {
      char ch = plainText.charAt(i);
      switch (ch) {
        case '<':
          output.append(plainText, pos, i).append("&lt;");
          pos = i + 1;
          break;
        case '>':
          output.append(plainText, pos, i).append("&gt;");
          pos = i + 1;
          break;
        case '&':
          output.append(plainText, pos, i).append("&amp;");
          pos = i + 1;
          break;
        case '"':
          output.append(plainText, pos, i).append("&#34;");
          pos = i + 1;
          break;
        default:
          if (0x20 <= ch && ch < 0xff00) {
            continue;
          }
          // Is a control character or possible full-width version of a
          // special character.
          // $FALL-THROUGH$
        case '+':  // UTF-7
        case '=':  // Special in attributes.
        case '@':  // Conditional compilation
        case '\'': case '`':  // Quoting character
          output.append(plainText, pos, i).append("&#")
              .append(String.valueOf((int) ch)).append(';');
          pos = i + 1;
          break;
        case 0:
          output.append(plainText, pos, i);
          pos = i + 1;
          break;
      }
    }
    output.append(plainText, pos, n);
  }


  static class CloseableHtmlStreamRenderer extends HtmlStreamRenderer
      implements Closeable {
    private final Closeable closeable;

    CloseableHtmlStreamRenderer(
        Appendable output, Handler<? super IOException> errorHandler,
        Handler<? super String> badHtmlHandler) {
      super(output, errorHandler, badHtmlHandler);
      this.closeable = (Closeable) output;
    }

    public void close() throws IOException {
      if (isDocumentOpen()) { closeDocument(); }
      closeable.close();
    }
  }
}
