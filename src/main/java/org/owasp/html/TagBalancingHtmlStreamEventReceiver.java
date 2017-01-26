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

import java.util.BitSet;
import java.util.List;

import org.owasp.html.HtmlElementTables.HtmlElementNames;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;

/**
 * Wraps an HTML stream event receiver to fill in missing close tags.
 * If the balancer is given the HTML {@code <p>1<p>2}, the wrapped receiver will
 * see events equivalent to {@code <p>1</p><p>2</p>}.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
@TCB
public class TagBalancingHtmlStreamEventReceiver
    implements HtmlStreamEventReceiver {
  private final HtmlStreamEventReceiver underlying;
  private int nestingLimit = Integer.MAX_VALUE;
  private final IntVector openElements = new IntVector();
  private final IntVector toResumeInReverse = new IntVector();
  private static final HtmlElementTables METADATA = HtmlElementTables.get();
  private static final int UNRECOGNIZED_TAG =
      METADATA.indexForName(HtmlElementNames.CUSTOM_ELEMENT_NAME);
  private static final int A_TAG = METADATA.indexForName("a");
  private static final int BODY_TAG = METADATA.indexForName("body");

  private static final boolean DEBUG = false;

  /**
   * @param underlying An event receiver that should receive a stream of
   *     balanced events that is as close as possible to the stream of events
   *     received by this.
   */
  public TagBalancingHtmlStreamEventReceiver(
      HtmlStreamEventReceiver underlying) {
    this.underlying = underlying;
  }

  /**
   * Set the maximum element nesting depth.
   */
  public void setNestingLimit(int limit) {
    if (openElements.size() > limit) {
      throw new IllegalStateException();
    }
    this.nestingLimit = limit;
  }

  public void openDocument() {
    underlying.openDocument();
  }

  public void closeDocument() {
    for (int i = Math.min(nestingLimit, openElements.size()); --i >= 0;) {
      int elIndex = openElements.get(i);
      String elname = METADATA.canonNameForIndex(elIndex);
      underlying.closeTag(elname);
    }
    openElements.clear();
    toResumeInReverse.clear();
    underlying.closeDocument();
  }

  public void openTag(String elementName, List<String> attrs) {
    if (DEBUG) {
      dumpState("open " + elementName);
    }
    String canonElementName = HtmlLexer.canonicalName(elementName);

    int elIndex = METADATA.indexForName(canonElementName);
    // Treat unrecognized tags as void, but emit closing tags in closeTag().
    if (elIndex == UNRECOGNIZED_TAG) {
      if (openElements.size() < nestingLimit) {
        underlying.openTag(elementName, attrs);
      }
      return;
    }

    prepareForContent(elIndex);

    if (openElements.size() < nestingLimit) {
      underlying.openTag(METADATA.canonNameForIndex(elIndex), attrs);
    }
    if (!HtmlTextEscapingMode.isVoidElement(canonElementName)) {
      openElements.add(elIndex);
    }
  }

  private void prepareForContent(int elIndex) {
    int nOpen = openElements.size();
    {
      int top = nOpen != 0 ? openElements.get(nOpen - 1) : BODY_TAG;
      // Open implied elements, such as list-items and table cells & rows.
      int[] impliedElIndices = METADATA.impliedElements(top, elIndex);
      if (impliedElIndices.length != 0) {
        List<String> attrs = Lists.<String>newArrayList();

        int startPos = 0;
        for (int i = 0, n = impliedElIndices.length; i < n; ++i) {
          int impliedElIndex = impliedElIndices[i];
          if (impliedElIndex == top) {
            startPos = i + 1;
            break;
          }
        }

        for (int i = startPos, n = impliedElIndices.length; i < n; ++i) {
          int impliedElIndex = impliedElIndices[i];
          String impliedElName = METADATA.canonNameForIndex(
              impliedElIndex);
          attrs.clear();
          underlying.openTag(impliedElName, attrs);
          openElements.add(impliedElIndex);
          top = impliedElIndex;
          ++nOpen;
        }
      }
    }

    if (nOpen != 0) {
      int top = openElements.get(nOpen - 1);
      // Close all the elements that cannot contain the content to open.
      while (true) {
        boolean canContain = canContain(elIndex, top, nOpen - 1)
            && !(elIndex == A_TAG
                 && openElements.lastIndexOf(A_TAG) >= 0);
        if (canContain) {
          break;
        }
        if (openElements.size() < nestingLimit) {
          underlying.closeTag(METADATA.canonNameForIndex(top));
        }
        openElements.remove(--nOpen);
        if (METADATA.resumable(top) && top != elIndex) {
          toResumeInReverse.add(top);
        }
        if (nOpen == 0) { break; }
        top = openElements.get(nOpen - 1);
      }
    }

    while (!toResumeInReverse.isEmpty()) {
      int toResume = toResumeInReverse.getLast();
      // If toResume can contain elInfo AND the top of the stack can contain
      // toResume, then we push toResume.
      nOpen = openElements.size();
      if ((nOpen == 0
          || canContain(toResume, openElements.get(nOpen - 1), nOpen))
          && canContain(elIndex, toResume, nOpen)) {
        toResumeInReverse.removeLast();
        if (openElements.size() < nestingLimit) {
          underlying.openTag(
              METADATA.canonNameForIndex(toResume),
              Lists.<String>newArrayList());
        }
        openElements.add(toResume);
      } else {
        break;
      }
    }
  }

  private static final BitSet TRANSPARENT = new BitSet();
  static {
    for (String transparentElement
        : new String[] {
            "a",
            "audio",
            "canvas",
            "del",
            "ins",
            "map",
            "object",
            "video",
        }) {
      TRANSPARENT.set(METADATA.indexForName(
          transparentElement));
    }
  }

  /**
   * Takes into account transparency when figuring out what
   * can be contained.
   */
  private boolean canContain(
      int child, int container, int containerIndexOnStack) {
    Preconditions.checkArgument(containerIndexOnStack >= 0);
    int anc = container;
    int ancIndexOnStack = containerIndexOnStack;
    while (true) {
      if (METADATA.canContain(anc, child)) {
        return true;
      }
      if (!TRANSPARENT.get(anc)) {
        return false;
      }
      if (ancIndexOnStack == 0) {
        return METADATA.canContain(BODY_TAG, child);
      }
      --ancIndexOnStack;
      anc = openElements.get(ancIndexOnStack);
    }
  }

  public void closeTag(String elementName) {
    if (DEBUG) {
      dumpState("close " + elementName);
    }
    String canonElementName = HtmlLexer.canonicalName(elementName);

    int elIndex = METADATA.indexForName(canonElementName);
    if (elIndex == UNRECOGNIZED_TAG) {  // Allow unrecognized end tags through.
      if (openElements.size() < nestingLimit) {
        underlying.closeTag(elementName);
      }
      return;
    }

    // Ensure that index is in the scope of closeable elements.
    // This approximates the "has an element in *** scope" predicates defined at
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/syntax.html
    // #has-an-element-in-the-specific-scope
    int blockingScopes = ALL_SCOPES & ~SCOPES_BY_ELEMENT[elIndex];

    int index = -1;
    {
      if (isHeaderElementName(canonElementName)) {
        // Let any of </h1>, </h2>, ... close other header tags.
        for (int i = openElements.size(); -- i >= 0;) {
          int openElementIndex = openElements.get(i);
          if (isHeaderElement(openElementIndex)) {
            elIndex = openElementIndex;
            index = i;
            canonElementName = METADATA.canonNameForIndex(openElementIndex);
            break;
          }
          int openElementScope = SCOPES_BY_ELEMENT[openElementIndex];
          if (openElementScope == ALL_SCOPES
              || (openElementScope & blockingScopes) != 0) {
            break;
          }
        }
      } else {
        for (int i = openElements.size(); -- i >= 0;) {
          int openElementIndex = openElements.get(i);
          if (openElementIndex == elIndex) {
            index = i;
            break;
          }
          int openElementScope = SCOPES_BY_ELEMENT[openElementIndex];
          if (openElementScope == ALL_SCOPES
              || (openElementScope & blockingScopes) != 0) {
            break;
          }
        }
      }
    }
    if (index < 0) {
      return;  // Don't close unopened tags.
    }

    int last = openElements.size();
    // Close all the elements that cannot contain the element to open.
    while (--last > index) {
      int unclosed = openElements.remove(last);
      if (last + 1 < nestingLimit) {
        underlying.closeTag(METADATA.canonNameForIndex(unclosed));
      }
      if (METADATA.resumable(unclosed)) {
        toResumeInReverse.add(unclosed);
      }
    }
    if (openElements.size() < nestingLimit) {
      underlying.closeTag(METADATA.canonNameForIndex(elIndex));
    }
    openElements.remove(index);
  }

  /**
   * True if text is the value of an inter-element whitespace text node as
   * defined by HTML5.
   * <p>
   * This is the kind of text that is often inserted by
   * HTML authors to nicely indent their HTML documents and which
   * (modulo unconventional use of {@code white-space:pre}) are not apparent
   * to the end-user.
   */
  public static boolean isInterElementWhitespace(String text) {
    int n = text.length();
    for (int i = 0; i < n; ++i) {
      if (!Strings.isHtmlSpace(text.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  public void text(String text) {
    if (DEBUG) {
      dumpState("text `" + text.replace("\n", "\\n") + "`");
    }
    boolean isInterElementWhitespace = isInterElementWhitespace(text);
    if (isInterElementWhitespace) {
      int nOpenElements = openElements.size();
      if (nOpenElements != 0) {
        int top = openElements.get(nOpenElements - 1);
        if (!METADATA.canContainText(top)
            // Use this as a proxy for whether or not a manufactured node is
            // needed.  If it is, then skip the inter-element space and don't
            // manufacture a node.
            || METADATA.impliedElements(top, A_TAG).length != 0) {
          return;
        }
      }
    } else {
      prepareForContent(HtmlElementTables.TEXT_NODE);
    }

    if (openElements.size() < nestingLimit) {
      underlying.text(text);
    }
  }

  private static boolean isHeaderElement(int elIndex) {
    String canonElementName = METADATA.canonNameForIndex(elIndex);
    return isHeaderElementName(canonElementName);
  }

  private static boolean isHeaderElementName(String canonElementName) {
    return canonElementName.length() == 2
        && (canonElementName.charAt(0) | 32) == 'h'
        && canonElementName.charAt(1) <= '9';
  }

  private static final byte ALL_SCOPES;
  private static final byte[] SCOPES_BY_ELEMENT;

  static {
    // w3c.github.io/html/single-page.html#as-that-element-in-the-specific-scope
    final byte IN = 1;
    final byte BUTTON = 2;
    final byte LIST_ITEM = 4;
    final byte TABLE = 8;
    final byte SELECT = 16;

    ALL_SCOPES = IN | BUTTON | LIST_ITEM | TABLE | SELECT;

    SCOPES_BY_ELEMENT = new byte[METADATA.nElementTypes()];
    String[] inScopeElements = {
        "applet",
        "caption",
        "html",
        "table",
        "td",
        "th",
        "marquee",
        "object",
        "template",
        // TODO: mathml and svg
    };
    for (String tn : inScopeElements) {
      SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= IN;
    }

    String[] listItemScopeExtras = {
        "ol",
        "ul",
    };
    for (String[] tns
         : new String[][] { listItemScopeExtras, inScopeElements }) {
      for (String tn : tns) {
        SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= LIST_ITEM;
      }
    }
    String[] buttonScopeExtras = {
        "button",
    };
    for (String[] tns
        : new String[][] { buttonScopeExtras, inScopeElements }) {
     for (String tn : tns) {
       SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= BUTTON;
     }
   }

    String[] tableScopeElements = {
        "html",
        "table",
        "template",
    };
    for (String tn : tableScopeElements) {
      SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= TABLE;
    }

    String[] selectScopeExceptions = {
        "optgroup",
        "option",
    };
    for (int i = 0, n = SCOPES_BY_ELEMENT.length; i < n; ++i) {
      SCOPES_BY_ELEMENT[i] |= SELECT;
    }
    for (String tn : selectScopeExceptions) {
      SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] &= ~SELECT;
    }

    // The <nofeature> elements are weird.
    //     <table><noscript></table></noscript>...
    // is equivalent to
    //     <table>...
    // when scripts are enabled and is equivalent to
    //     <table></table>...
    // when not.
    //
    // We scope <noscript> so that, even when we parse and filter the content
    // as if it were tag content, we don't treat that content as escaping
    // which is consistent with the view that that content is ignored by the
    // browser as is usually the case.
    String[] nofeatureScopeHack = new String[] {
      "noscript",
      "noframes",
      "noembed",
    };
    for (String tn : nofeatureScopeHack) {
      SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= ALL_SCOPES;
    }

  }

  private void dumpState(String msg) {
    System.err.println(msg);
    System.err.println("\tstack");
    for (int i = 0, n = openElements.size(); i < n; ++i) {
      int idx = openElements.get(i);
      System.err.println("\t\t" + METADATA.canonNameForIndex(idx));
    }
    System.err.println("\tresumable");
    for (int i = 0, n = toResumeInReverse.size(); i < n; ++i) {
      int idx = toResumeInReverse.get(i);
      System.err.println("\t\t" + METADATA.canonNameForIndex(idx));
    }
  }
}
