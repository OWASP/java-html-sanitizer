// Copyright (c) 2011, Mike Samuel
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
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

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.annotation.Nullable;
import javax.annotation.WillCloseWhenClosed;
import javax.annotation.concurrent.NotThreadSafe;

import static org.owasp.shim.Java8Shim.j8;

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
  /** Told about dropped literal content; null while nobody is listening. */
  private @Nullable DropListener dropListener;
  private String lastTagOpened;
  private StringBuilder pendingUnescaped;
  private HtmlTextEscapingMode escapingMode = HtmlTextEscapingMode.PCDATA;
  private boolean open;
  /**
   * The count of {@link #FOREIGN_CONTENT_ROOT_ELEMENT_NAMES} opened and not
   * subsequently closed.
   */
  private int foreignContentDepth = 0;
  /**
   * True when the current element is one whose content the HTML lexer treats
   * as raw text, so its text arrives with character references undecoded, but
   * it is inside foreign content where browsers parse that content as markup.
   * Such text must be decoded before it is escaped, otherwise character
   * references would be encoded twice.
   */
  private boolean decodeTextBeforeEscaping = false;

  /**
   * Factory.
   * @param output the buffer to which HTML is streamed.
   * @param ioExHandler called with any exception raised by output.
   * @param badHtmlHandler receives alerts when HTML cannot be rendered because
   *    there is not valid HTML tree that results from that series of calls.
   *    E.g. it is not possible to create an HTML {@code <style>} element whose
   *    textual content is {@code "</style>"}.  What the renderer leaves out
   *    on such an alert also reaches an {@link HtmlChangeListener} when the
   *    renderer is behind an {@link HtmlChangeReporter}, as it is in
   *    {@link PolicyFactory#sanitize(String, HtmlChangeListener, Object)}.
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

  /**
   * Carries literal content discarded by the policy or renderer to
   * {@link HtmlChangeReporter}, which reports the loss to its listener.
   */
  interface DroppedTextListener {
    /**
     * @param elementName the element whose content was dropped.
     * @param text the content that was dropped.
     */
    void droppedText(String elementName, String text);
  }

  /**
   * Carries the renderer's other drops to {@link HtmlChangeReporter} as
   * well: a start tag it did not write, and an attribute it left off one it
   * did.  Each also goes to the bad-HTML handler as a message, which is all
   * there was before and which {@link PolicyFactory#sanitize} wires to
   * nobody, so without this a listener heard nothing of them.
   */
  interface DropListener extends DroppedTextListener {
    /**
     * A start tag the renderer did not write, because the element's name is
     * not one HTML allows or because it arrived inside literal content that
     * cannot hold a tag.  The matching end tag is refused for the same reason
     * when it comes, and is not reported: it is the same loss.
     *
     * @param elementName the element's name as the renderer received it.
     */
    void droppedTag(String elementName);

    /**
     * An attribute left off a start tag the renderer wrote, because its name
     * is not one HTML allows.
     *
     * @param elementName the element the tag opened.
     * @param name the attribute's name, as the renderer received it.
     * @param value the attribute's value, as the renderer received it.
     */
    void droppedAttribute(String elementName, String name, String value);
  }

  /**
   * Sends what the renderer drops to {@code listener}, or to nobody, until
   * the next {@link #openDocument}, which starts a document with nobody
   * listening.
   */
  final void reportDropsTo(@Nullable DropListener listener) {
    this.dropListener = listener;
  }

  public final void openDocument() throws IllegalStateException {
    if (open) { throw new IllegalStateException(); }
    open = true;
    // A listener is for one document; whoever wants this one's drops
    // registers after this, so an earlier document's cannot linger.
    dropListener = null;
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
      if (dropListener != null) { dropListener.droppedTag(elementName); }
      return;
    }
    if (pendingUnescaped != null) {
      error("Tag content cannot appear inside CDATA element", elementName);
      if (dropListener != null) { dropListener.droppedTag(elementName); }
      return;
    }

    if (FOREIGN_CONTENT_ROOT_ELEMENT_NAMES.contains(elementName)) {
      foreignContentDepth += 1;
    }

    boolean inForeignContent = foreignContentDepth != 0;
    HtmlTextEscapingMode tentativeEscapingMode =
        HtmlTextEscapingMode.getModeForTag(elementName);
    // The lexer delivers the content of a raw-text element without decoding
    // character references, but browsers parse that content as markup inside
    // foreign content, so decode it there before re-encoding.
    decodeTextBeforeEscaping
        = inForeignContent && emitsContentLiterally(elementName, false);
    if (!inForeignContent
        || tentativeEscapingMode == HtmlTextEscapingMode.PCDATA
        || tentativeEscapingMode == HtmlTextEscapingMode.VOID) {
      escapingMode = tentativeEscapingMode;
    } else {
      // Escape special characters but do not allow tags.
      escapingMode = HtmlTextEscapingMode.RCDATA;
    }

    if (emitsContentLiterally(elementName, inForeignContent)) {
      lastTagOpened = elementName;
      pendingUnescaped = new StringBuilder();
    }

    output.append('<').append(elementName);

    for (Iterator<? extends String> attrIt = attrs.iterator();
         attrIt.hasNext();) {
      String name = attrIt.next();
      String value = attrIt.next();
      name = HtmlLexer.canonicalAttributeName(name);
      if (!isValidHtmlName(name)) {
        error("Invalid attr name", name);
        if (dropListener != null) {
          dropListener.droppedAttribute(elementName, name, value);
        }
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

    if (foreignContentDepth != 0
        && FOREIGN_CONTENT_ROOT_ELEMENT_NAMES.contains(elementName)) {
      foreignContentDepth -= 1;
    }
    decodeTextBeforeEscaping = false;

    if (pendingUnescaped != null) {
      if (!lastTagOpened.equals(elementName)) {
        error("Tag content cannot appear inside CDATA element", elementName);
        return;
      }
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
        if (dropListener != null) {
          dropListener.droppedText(elementName, cdataContent.toString());
        }
        // Still output the close tag.
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
        Encoding.encodeRcdataOnto(
            decodeTextBeforeEscaping ? Encoding.decodeHtml(text, false) : text,
            output);
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
    // The textContent of a script element must match the script production
    // in the following ABNF, the character set for which is Unicode. [ABNF]
    //
    // script = outer *( comment-open inner comment-close outer )
    //
    // outer = < any string that doesn’t contain a substring that matches
    //           not-in-outer >
    // not-in-outer = comment-open
    // inner = < any string that doesn’t contain a substring that matches
    //           not-in-inner >
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
              // The end tag of an element that a browser reads as raw text
              // while the sanitizer treats it as a container would end that
              // element for the browser, wherever this content sits, and
              // hand it whatever follows as markup (CVE-2025-66021).  The
              // policy strips such tags; this catches what reaches the
              // renderer by any other route.
              for (String container : CONTAINERS_RAW_TEXT_TO_BROWSERS) {
                if (isTagNameAt(sb, start, container)) { return i; }
              }
            } else if (innerStart < 0) {
              break;
            }
            // We don't need to do any suffix checks to preserve concatenation
            // safety since we buffer pending unescaped above.
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
          if (i >= 2 && sb.charAt(i - 2) == '-' && sb.charAt(i - 1) == '-') {
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

  // only visible for testing
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
        case '_':
          if (i + 1 == n) { return false; }
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
   * True if the content of an element named {@code canonElementName}, written
   * where {@code inForeignContent} says, is emitted as it is instead of being
   * escaped, so that a tag in that content would reach the browser as
   * written.
   * <p>
   * This is the one place that decides it.  The renderer asks under the name
   * it emits, which {@link #safeName} may have substituted, and
   * {@link ElementAndAttributePolicyBasedSanitizerPolicy}, whose filter has to
   * run exactly where nothing escapes a tag for it, asks the same question
   * about the receiver it writes to.
   */
  static boolean emitsContentLiterally(
      String canonElementName, boolean inForeignContent) {
    if (inForeignContent) { return false; }
    switch (HtmlTextEscapingMode.getModeForTag(canonElementName)) {
      case CDATA:
      case CDATA_SOMETIMES:
      case PLAIN_TEXT:
        return true;
      default:
        return false;
    }
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

  private static final long TAG_ENDS = 0L
      | (1L << '\t')
      | (1L << '\n')
      | (1L << '\f')
      | (1L << '\r')
      | (1L << ' ')
      | (1L << '/')
      | (1L << '>');

  /**
   * Elements the sanitizer treats as ordinary containers but that browsers
   * read as raw text: {@code noscript} with scripting on, and
   * {@code noframes} and {@code noembed} always.
   */
  private static final String[] CONTAINERS_RAW_TEXT_TO_BROWSERS = {
    "noscript", "noframes", "noembed",
  };

  /** True if {@code name} sits at {@code start} in {@code sb} as a tag name. */
  private static boolean isTagNameAt(
      StringBuilder sb, int start, String name) {
    int end = start + name.length();
    return end <= sb.length()
        && Strings.regionMatchesIgnoreCase(sb, start, name, 0, name.length())
        && (end == sb.length() || isTagEnd(sb.charAt(end)));
  }

  private static boolean isTagEnd(char ch) {
    return ch < 63 && 0 != (TAG_ENDS & (1L << ch));
  }

  /**
   * The elements that root foreign content, inside which a browser parses the
   * content of every element as markup, so that nothing there is literal.
   */
  static final Set<String> FOREIGN_CONTENT_ROOT_ELEMENT_NAMES =
      j8().setOf("svg", "math");
}
