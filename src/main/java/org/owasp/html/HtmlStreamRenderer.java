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
import com.google.common.collect.ImmutableSet;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
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
  private HtmlTextEscapingMode escapingMode = HtmlTextEscapingMode.PCDATA;
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
    } else if (AutoCloseableHtmlStreamRenderer.isAutoCloseable(output)) {
      return AutoCloseableHtmlStreamRenderer.createAutoCloseableHtmlStreamRenderer(
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

  protected HtmlStreamRenderer(
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

    escapingMode = HtmlTextEscapingMode.getModeForTag(elementName);

    switch (escapingMode) {
      case CDATA_SOMETIMES:
      case CDATA:
      case PLAIN_TEXT:
        lastTagOpened = elementName;
        pendingUnescaped = new StringBuilder();
        break;
      default:
        break;
    }

    output.append('<').append(elementName);

    for (Iterator<? extends String> attrIt = attrs.iterator();
         attrIt.hasNext();) {
      String name = attrIt.next();
      String value = attrIt.next();
      name = HtmlLexer.canonicalAttributeName(name);
      if (!isValidHtmlName(name)) {
        error("Invalid attr name", name);
        continue;
      }
      output.append(' ').append(name).append('=').append('"');
      Encoding.encodeHtmlAttribOnto(value, output);
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
    String elementName = HtmlLexer.canonicalElementName(uncanonElementName);
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
          if (cdataContent.length() != 0) {
            output.append(cdataContent);
          }
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
      if (this.escapingMode == HtmlTextEscapingMode.RCDATA) {
        Encoding.encodeRcdataOnto(text, output);
      } else {
        Encoding.encodePcdataOnto(text, output);
      }
    }
  }

  private static int checkHtmlCdataCloseable(
      String localName, StringBuilder sb) {
    // www.w3.org/TR/html51/semantics-scripting.html#restrictions-for-contents-of-script-elements
    // www.w3.org/TR/html5/scripting-1.html#restrictions-for-contents-of-script-elements
    // 4.12.1.3. Restrictions for contents of script elements
    // The textContent of a script element must match the script production in the following ABNF, the character set for which is Unicode. [ABNF]
    //
    // script = outer *( comment-open inner comment-close outer )
    //
    // outer = < any string that doesn’t contain a substring that matches not-in-outer >
    // not-in-outer = comment-open
    // inner = < any string that doesn’t contain a substring that matches not-in-inner >
    // not-in-inner = comment-close / script-open
    //
    // comment-open = "<!--"
    // comment-close = "-->"
    // script-open = "<" s c r i p t tag-end

    // We apply the above restrictions to all CDATA (modulo local name).
    int innerStart = -1;
    for (int i = 0, n = sb.length(); i < n; ++i) {
      char ch = sb.charAt(i);
      switch (ch) {
        case '<':
          if (i + 3 < n && sb.charAt(i + 1) == '!') {
            if (sb.charAt(i + 2) == '-'
                && sb.charAt(i + 3) == '-') {
              if (innerStart >= 0) { return i; }  // Nesting
              innerStart = i;
            }
          } else {  // Look for embedded <script or </script
            int start = i + 1;
            if (start + 1 < n && sb.charAt(start) == '/') {
              ++start;
            } else if (innerStart < 0) {
              break;
            }
            // We don't need to do any suffix checks to preserve concatenation safety
            // since we buffer pending unescaped above.
            int end = start + localName.length();
            if (end <= n
                && Strings.regionMatchesIgnoreCase(
                    sb, start, localName, 0, end - start)
                && (end == n || isTagEnd(sb.charAt(end)))) {
              return i;
            }
          }
          break;
        case '>':
          if (i >= 2 && sb.charAt(i - 2) == '-' && sb.charAt(i - 2) == '-') {
            if (innerStart < 0) { return i - 2; }
            // Merged start and end like <!--->
            if (innerStart + 6 > i) { return innerStart; }
            innerStart = -1;
          }
          break;
        default:
          break;
      }
    }
    return innerStart;
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
        case '_':
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
    String elementName = HtmlLexer.canonicalElementName(unsafeElementName);

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

  private static final long TAG_ENDS = 0L
      | (1L << '\t')
      | (1L << '\n')
      | (1L << '\f')
      | (1L << '\r')
      | (1L << ' ')
      | (1L << '/')
      | (1L << '>');

  private static boolean isTagEnd(char ch) {
    return ch < 63 && 0 != (TAG_ENDS & (1L << ch));
  }
}
