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

import com.google.common.annotations.VisibleForTesting;
import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import javax.annotation.WillCloseWhenClosed;
import javax.annotation.concurrent.NotThreadSafe;

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
@NotThreadSafe
public class HtmlStreamRenderer implements HtmlStreamEventReceiver {

  private final Appendable output;
  private final Handler<? super IOException> ioExHandler;
  private final Handler<? super String> badHtmlHandler;
  private String lastTagOpened;
  private StringBuilder pendingUnescaped;
  private boolean open;

  /**
   * Factory.
   * @param output the buffer to which HTML is streamed.
   * @param ioExHandler called with any exception raised by output.
   * @param badHtmlHandler receives alerts when HTML cannot be rendered because
   *    there is not valid HTML tree that results from that series of calls.
   *    E.g. it is not possible to create an HTML {@code <style>} element whose
   *    textual content is {@code "</style>"}.
   */
  public static HtmlStreamRenderer create(
      @WillCloseWhenClosed Appendable output,
      Handler<? super IOException> ioExHandler,
      Handler<? super String> badHtmlHandler) {
    if (output instanceof Closeable) {
      return new CloseableHtmlStreamRenderer(
          output, ioExHandler, badHtmlHandler);
    } else if (output instanceof AutoCloseable) {
      return new AutoCloseableHtmlStreamRenderer(
          output, ioExHandler, badHtmlHandler);
    } else {
      return new HtmlStreamRenderer(output, ioExHandler, badHtmlHandler);
    }
  }

  /**
   * Factory.
   * @param output the buffer to which HTML is streamed.
   * @param badHtmlHandler receives alerts when HTML cannot be rendered because
   *    there is not valid HTML tree that results from that series of calls.
   *    E.g. it is not possible to create an HTML {@code <style>} element whose
   *    textual content is {@code "</style>"}.
   */
  public static HtmlStreamRenderer create(
      StringBuilder output, Handler<? super String> badHtmlHandler) {
    // Propagate since StringBuilder should not throw IOExceptions.
    return create(output, Handler.PROPAGATE, badHtmlHandler);
  }

  private HtmlStreamRenderer(
      Appendable output, Handler<? super IOException> ioExHandler,
      Handler<? super String> badHtmlHandler) {
    this.output = output;
    this.ioExHandler = ioExHandler;
    this.badHtmlHandler = badHtmlHandler;
  }

  /**
   * Called when the series of calls make no sense.
   * May be overridden to throw an unchecked throwable, to log, or to take some
   * other action.
   *
   * @param message for human consumption.
   * @param identifier an HTML identifier associated with the message.
   */
  private final void error(String message, CharSequence identifier) {
    if (badHtmlHandler != Handler.DO_NOTHING) {   // Avoid string append.
      badHtmlHandler.handle(message + " : " + identifier);
    }
  }

  public final void openDocument() throws IllegalStateException {
    if (open) { throw new IllegalStateException(); }
    open = true;
  }

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

  /**
   * True if {@link #openDocument()} has been called and
   * {@link #closeDocument()} has not subsequently been called.
   */
  public final boolean isDocumentOpen() {
    return open;
  }

  public final void openTag(String elementName, List<String> attrs) {
    try {
      writeOpenTag(elementName, attrs);
    } catch (IOException ex) {
      ioExHandler.handle(ex);
    }
  }

  private void writeOpenTag(
      String unsafeElementName, List<? extends String> attrs)
      throws IOException {
    if (!open) { throw new IllegalStateException(); }
    String elementName = safeName(unsafeElementName);
    if (!isValidHtmlName(elementName)) {
      error("Invalid element name", elementName);
      return;
    }
    if (pendingUnescaped != null) {
      error("Tag content cannot appear inside CDATA element", elementName);
      return;
    }

    switch (HtmlTextEscapingMode.getModeForTag(elementName)) {
      case CDATA_SOMETIMES:
      case CDATA:
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
      Encoding.encodeHtmlOnto(value, output);
      if (value.indexOf('`') != -1) {
        // Apparently, in quirks mode, IE8 does a poor job producing innerHTML
        // values.  Given
        //     <div attr="``foo=bar">
        // we encode &#96; but if JavaScript does:
        //    nodeA.innerHTML = nodeB.innerHTML;
        // and nodeB contains the DIV above, then IE8 will produce
        //     <div attr=``foo=bar>
        // as the value of nodeB.innerHTML and assign it to nodeA.
        // IE8's HTML parser treats `` as a blank attribute value and foo=bar
        // becomes a separate attribute.
        // Adding a space at the end of the attribute prevents this by forcing
        // IE8 to put double quotes around the attribute when computing
        // nodeB.innerHTML.
        output.append(' ');
      }
      output.append('"');
    }

    // Limit our output to the intersection of valid XML and valid HTML5 when
    // the output contains no special HTML5 elements like <title>, <script>, or
    // <textarea>.
    if (HtmlTextEscapingMode.isVoidElement(elementName)) {
      output.append(" /");
    }

    output.append('>');
  }

  public final void closeTag(String elementName) {
    try {
      writeCloseTag(safeName(elementName));
    } catch (IOException ex) {
      ioExHandler.handle(ex);
    }
  }

  private final void writeCloseTag(String uncanonElementName)
      throws IOException {
    if (!open) { throw new IllegalStateException(); }
    String elementName = HtmlLexer.canonicalName(uncanonElementName);
    if (!isValidHtmlName(elementName)) {
      error("Invalid element name", elementName);
      return;
    }

    if (pendingUnescaped != null) {
      if (!lastTagOpened.equals(elementName)) {
        error("Tag content cannot appear inside CDATA element", elementName);
        return;
      } else {
        StringBuilder cdataContent = pendingUnescaped;
        pendingUnescaped = null;
        Encoding.stripBannedCodeunits(cdataContent);
        int problemIndex = checkHtmlCdataCloseable(lastTagOpened, cdataContent);
        if (problemIndex == -1) {
          output.append(cdataContent);
        } else {
          error(
              "Invalid CDATA text content",
              cdataContent.subSequence(
                  problemIndex,
                  Math.min(problemIndex + 10, cdataContent.length())));
          // Still output the close tag.
        }
      }
      if ("plaintext".equals(elementName)) { return; }
    }
    output.append("</").append(elementName).append(">");
  }

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
      pendingUnescaped.append(text);
    } else {
      Encoding.encodeHtmlOnto(text, output);  // Works for RCDATA.
    }
  }

  private static int checkHtmlCdataCloseable(
      String localName, StringBuilder sb) {
    int escapingTextSpanStart = -1;
    for (int i = 0, n = sb.length(); i < n; ++i) {
      char ch = sb.charAt(i);
      switch (ch) {
        case '<':
          if (i + 3 < n
              && '!' == sb.charAt(i + 1)
              && '-' == sb.charAt(i + 2)
              && '-' == sb.charAt(i + 3)) {
            if (escapingTextSpanStart == -1) {
              escapingTextSpanStart = i;
            } else {
              return i;
            }
          } else if (i + 1 + localName.length() < n
                     && '/' == sb.charAt(i + 1)
                     && Strings.regionMatchesIgnoreCase(
                         sb, i + 2, localName, 0, localName.length())) {
            // A close tag contained in the content.
            if (escapingTextSpanStart < 0) {
              // We could try some recovery strategies here.
              // E.g. prepending "/<!--\n" to sb if "script".equals(localName)
              return i;
            }
            if (!"script".equals(localName)) {
              // Script tags are commonly included inside script tags.
              // <script><!--document.write('<script>f()</script>');--></script>
              // but this does not happen in other CDATA element types.
              // Actually allowing an end tag inside others is problematic.
              // Specifically,
              // <style><!--</style>-->/* foo */</style>
              // displays the text "/* foo */" on some browsers.
              return i;
            }
          }
          break;
        case '>':
          // From the HTML5 spec:
          //    The text in style, script, title, and textarea elements must not
          //    have an escaping text span start that is not followed by an
          //    escaping text span end.
          // We look left since the HTML 5 spec allows the escaping text span
          // end to share dashes with the start.
          if (i >= 2 && '-' == sb.charAt(i - 1) && '-' == sb.charAt(i - 2)) {
            if (escapingTextSpanStart < 0) { return i - 2; }
            escapingTextSpanStart = -1;
          }
          break;
        default:
          break;
      }
    }
    if (escapingTextSpanStart >= 0) {
      // We could try recovery strategies here.
      // E.g. appending "//-->" to the buffer if "script".equals(localName)
      return escapingTextSpanStart;
    }
    return -1;
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
          if (i == 0 || i + 1 == n) { return false; }
          break;
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

  /**
   * Canonicalizes the element name and possibly substitutes an alternative
   * that has more consistent semantics.
   */
  static String safeName(String unsafeElementName) {
    String elementName = HtmlLexer.canonicalName(unsafeElementName);

    // Substitute a reliably non-raw-text element for raw-text and
    // plain-text elements.
    switch (elementName.length()) {
      case 3:
        if ("xmp".equals(elementName)) { return "pre"; }
        break;
      case 7:
        if ("listing".equals(elementName)) { return "pre"; }
        break;
      case 9:
        if ("plaintext".equals(elementName)) { return "pre"; }
        break;
    }
    return elementName;
  }

  static class CloseableHtmlStreamRenderer extends HtmlStreamRenderer
      implements Closeable {
    private final Closeable closeable;

    @SuppressWarnings("synthetic-access")
    CloseableHtmlStreamRenderer(
        @WillCloseWhenClosed
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

  static class AutoCloseableHtmlStreamRenderer extends HtmlStreamRenderer
  implements AutoCloseable {
    private final AutoCloseable closeable;

    @SuppressWarnings("synthetic-access")
    AutoCloseableHtmlStreamRenderer(
        @WillCloseWhenClosed
        Appendable output, Handler<? super IOException> errorHandler,
        Handler<? super String> badHtmlHandler) {
      super(output, errorHandler, badHtmlHandler);
      this.closeable = (AutoCloseable) output;
    }

    public void close() throws Exception {
      if (isDocumentOpen()) { closeDocument(); }
      closeable.close();
    }
  }
}
