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

import java.util.List;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

import com.google.common.collect.ImmutableMap;
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
  private final List<ElementContainmentInfo> openElements
      = Lists.newArrayList();

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
      underlying.closeTag(openElements.get(i).elementName);
    }
    openElements.clear();
    underlying.closeDocument();
  }

  public void openTag(String elementName, List<String> attrs) {
    String canonElementName = HtmlLexer.canonicalName(elementName);
    ElementContainmentInfo elInfo = ELEMENT_CONTAINMENT_RELATIONSHIPS.get(
        canonElementName);
    // Treat unrecognized tags as void, but emit closing tags in closeTag().
    if (elInfo == null) {
      if (openElements.size() < nestingLimit) {
        underlying.openTag(elementName, attrs);
      }
      return;
    }

    prepareForContent(elInfo);

    if (openElements.size() < nestingLimit) {
      underlying.openTag(elInfo.elementName, attrs);
    }
    if (!elInfo.isVoid) {
      openElements.add(elInfo);
    }
  }

  private void prepareForContent(ElementContainmentInfo elInfo) {
    int nOpen = openElements.size();
    if (nOpen != 0) {
      ElementContainmentInfo top = openElements.get(nOpen - 1);
      if ((top.contents & elInfo.types) == 0) {
        ElementContainmentInfo blockContainerChild = top.blockContainerChild;
        // Open implied elements, such as list-items and table cells & rows.
        if (blockContainerChild != null
            && (blockContainerChild.contents & elInfo.types) != 0) {
          underlying.openTag(
              blockContainerChild.elementName, Lists.<String>newArrayList());
          openElements.add(blockContainerChild);
          top = blockContainerChild;
          ++nOpen;
        }
      }

      // Close all the elements that cannot contain the element to open.
      List<ElementContainmentInfo> toResumeInReverse = null;
      while (true) {
        if ((top.contents & elInfo.types) != 0) { break; }
        if (openElements.size() < nestingLimit) {
          underlying.closeTag(top.elementName);
        }
        openElements.remove(--nOpen);
        if (top.resumable) {
          if (toResumeInReverse == null) {
            toResumeInReverse = Lists.newArrayList();
          }
          toResumeInReverse.add(top);
        }
        if (nOpen == 0) { break; }
        top = openElements.get(nOpen - 1);
      }

      if (toResumeInReverse != null) {
        resume(toResumeInReverse);
      }
    }
  }

  public void closeTag(String elementName) {
    String canonElementName = HtmlLexer.canonicalName(elementName);
    ElementContainmentInfo elInfo = ELEMENT_CONTAINMENT_RELATIONSHIPS.get(
        canonElementName);
    if (elInfo == null) {  // Allow unrecognized end tags through.
      if (openElements.size() < nestingLimit) {
        underlying.closeTag(elementName);
      }
      return;
    }
    int index = openElements.lastIndexOf(elInfo);
    // Let any of </h1>, </h2>, ... close other header tags.
    if (isHeaderElementName(canonElementName)) {
      for (int i = openElements.size(), limit = index + 1; -- i >= limit;) {
        ElementContainmentInfo openEl = openElements.get(i);
        if (isHeaderElementName(openEl.elementName)) {
          elInfo = openEl;
          index = i;
          canonElementName = openEl.elementName;
          break;
        }
      }
    }
    if (index < 0) {
      return;  // Don't close unopened tags.
    }

    // Ensure that index is in the scope of closeable elements.
    // This approximates the "has an element in *** scope" predicates defined at
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/parsing.html
    // #has-an-element-in-the-specific-scope
    int blockingScopes = elInfo.blockedByScopes;
    for (int i = openElements.size(); --i > index;) {
      if ((openElements.get(i).inScopes & blockingScopes) != 0) {
        return;
      }
    }

    int last = openElements.size();
    // Close all the elements that cannot contain the element to open.
    List<ElementContainmentInfo> toResumeInReverse = null;
    while (--last > index) {
      ElementContainmentInfo unclosed = openElements.remove(last);
      if (last + 1 < nestingLimit) {
        underlying.closeTag(unclosed.elementName);
      }
      if (unclosed.resumable) {
        if (toResumeInReverse == null) {
          toResumeInReverse = Lists.newArrayList();
        }
        toResumeInReverse.add(unclosed);
      }
    }
    if (openElements.size() < nestingLimit) {
      underlying.closeTag(elInfo.elementName);
    }
    openElements.remove(index);
    if (toResumeInReverse != null) {
      resume(toResumeInReverse);
    }
  }

  private void resume(List<ElementContainmentInfo> toResumeInReverse) {
    for (ElementContainmentInfo toResume : toResumeInReverse) {
      // TODO: If resuming of things other than plain formatting tags like <b>
      // and <i>, then we need to store the attributes for resumable tags so
      // that we can resume with the appropriate attributes.
      if (openElements.size() < nestingLimit) {
        underlying.openTag(toResume.elementName, Lists.<String>newArrayList());
      }
      openElements.add(toResume);
    }
  }

  private static final long HTML_SPACE_CHAR_BITMASK =
      (1L << ' ')
    | (1L << '\t')
    | (1L << '\n')
    | (1L << '\u000c')
    | (1L << '\r');

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
      int ch = text.charAt(i);
      if (ch > 0x20 || (HTML_SPACE_CHAR_BITMASK & (1L << ch)) == 0) {
        return false;
      }
    }
    return true;
  }

  public void text(String text) {
    if (!isInterElementWhitespace(text)) {
      prepareForContent(ElementContainmentRelationships.CHARACTER_DATA_ONLY);
    }

    if (openElements.size() < nestingLimit) {
      underlying.text(text);
    }
  }

  private static boolean isHeaderElementName(String canonElementName) {
    return canonElementName.length() == 2 && canonElementName.charAt(0) == 'h'
        && canonElementName.charAt(1) <= '9';
  }


  @Immutable
  private static final class ElementContainmentInfo {
    final String elementName;
    /**
     * True if the adoption agency algorithm allows an element to be resumed
     * after a mis-nested end tag closes it.
     * E.g. in {@code <b>Foo<i>Bar</b>Baz</i>} the {@code <i>} element is
     * resumed after the {@code <b>} element is closed.
     */
    final boolean resumable;
    /** A set of bits of element groups into which the element falls. */
    final int types;
    /** The type of elements that an element can contain. */
    final int contents;
    /** True if the element has no content -- not even text content. */
    final boolean isVoid;
    /** A legal child of this node that can contain block content. */
    final @Nullable ElementContainmentInfo blockContainerChild;
    /** A bit set of close tag scopes that block this element's close tags. */
    final int blockedByScopes;
    /** A bit set of scopes groups into which this element falls. */
    final int inScopes;

    ElementContainmentInfo(
        String elementName, boolean resumable, int types, int contents,
        @Nullable ElementContainmentInfo blockContainerChild,
        int inScopes) {
      this.elementName = elementName;
      this.resumable = resumable;
      this.types = types;
      this.contents = contents;
      this.isVoid = contents == 0
          && HtmlTextEscapingMode.isVoidElement(elementName);
      this.blockContainerChild = blockContainerChild;
      this.blockedByScopes =
          ElementContainmentRelationships.CloseTagScope.ALL & ~inScopes;
      this.inScopes = inScopes;
    }

    @Override public String toString() {
      return "<" + elementName + ">";
    }
  }

  static final ImmutableMap<String, ElementContainmentInfo>
      ELEMENT_CONTAINMENT_RELATIONSHIPS
      = ElementContainmentRelationships.make().toMap();

  private static final class ElementContainmentRelationships {
    private enum ElementGroup {
      BLOCK,
      INLINE,
      INLINE_MINUS_A,
      MIXED,
      TABLE_CONTENT,
      HEAD_CONTENT,
      TOP_CONTENT,
      AREA_ELEMENT,
      FORM_ELEMENT,
      LEGEND_ELEMENT,
      LI_ELEMENT,
      DL_PART,
      P_ELEMENT,
      OPTIONS_ELEMENT,
      OPTION_ELEMENT,
      PARAM_ELEMENT,
      TABLE_ELEMENT,
      TR_ELEMENT,
      TD_ELEMENT,
      COL_ELEMENT,
      CHARACTER_DATA,
      ;
    }

    /**
     * An identifier for one of the "has a *** element in scope" predicates
     * used by HTML5 to decide when a close tag implicitly closes tags above
     * the target element on the open element stack.
     */
    private enum CloseTagScope {
      COMMON,
      BUTTON,
      LIST_ITEM,
      TABLE,
      ;

      static final int ALL = (1 << values().length) - 1;
    }

    static ElementContainmentRelationships make() {
      return new ElementContainmentRelationships();
    }

    private static int elementGroupBits(ElementGroup a) {
      return 1 << a.ordinal();
    }

    private static int elementGroupBits(
        ElementGroup a, ElementGroup b) {
      return (1 << a.ordinal()) | (1 << b.ordinal());
    }

    private static int elementGroupBits(
        ElementGroup a, ElementGroup b, ElementGroup c) {
      return (1 << a.ordinal()) | (1 << b.ordinal()) | (1 << c.ordinal());
    }

    private static int elementGroupBits(
        ElementGroup... bits) {
      int bitField = 0;
      for (ElementGroup bit : bits) {
        bitField |= (1 << bit.ordinal());
      }
      return bitField;
    }

    private static int scopeBits(CloseTagScope a) {
      return 1 << a.ordinal();
    }

    private static int scopeBits(
        CloseTagScope a, CloseTagScope b, CloseTagScope c) {
      return (1 << a.ordinal()) | (1 << b.ordinal()) | (1 << c.ordinal());
    }

    private ImmutableMap.Builder<String, ElementContainmentInfo> definitions
        = ImmutableMap.builder();

    private ElementContainmentInfo defineElement(
        String elementName, boolean resumable, int types, int contentTypes) {
      return defineElement(elementName, resumable, types, contentTypes, null);
    }

    private ElementContainmentInfo defineElement(
        String elementName, boolean resumable, int types, int contentTypes,
        int inScopes) {
      return defineElement(
          elementName, resumable, types, contentTypes, null, inScopes);
    }

    private ElementContainmentInfo defineElement(
        String elementName, boolean resumable, int types, int contentTypes,
        @Nullable ElementContainmentInfo blockContainer) {
      return defineElement(
          elementName, resumable, types, contentTypes, blockContainer, 0);
    }

    private ElementContainmentInfo defineElement(
        String elementName, boolean resumable, int types, int contentTypes,
        @Nullable ElementContainmentInfo blockContainer, int inScopes) {
      ElementContainmentInfo info = new ElementContainmentInfo(
          elementName, resumable, types, contentTypes, blockContainer,
          inScopes);
      definitions.put(elementName, info);
      return info;
    }

    ImmutableMap<String, ElementContainmentInfo> toMap() {
      return definitions.build();
    }

    {
      defineElement(
          "a", false, elementGroupBits(
              ElementGroup.INLINE
          ), elementGroupBits(
              ElementGroup.INLINE_MINUS_A
          ));
      defineElement(
          "abbr", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "acronym", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "address", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE, ElementGroup.P_ELEMENT
          ));
      defineElement(
          "applet", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE,
              ElementGroup.PARAM_ELEMENT
          ), scopeBits(
              CloseTagScope.COMMON, CloseTagScope.BUTTON,
              CloseTagScope.LIST_ITEM
          ));
      defineElement(
          "area", false, elementGroupBits(ElementGroup.AREA_ELEMENT), 0);
      defineElement(
          "audio", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), 0);
      defineElement(
          "b", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "base", false, elementGroupBits(ElementGroup.HEAD_CONTENT), 0);
      defineElement(
          "basefont", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), 0);
      defineElement(
          "bdi", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "bdo", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "big", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "blink", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "blockquote", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "body", false, elementGroupBits(
              ElementGroup.TOP_CONTENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "br", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), 0);
      defineElement(
          "button", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ), scopeBits(CloseTagScope.BUTTON));
      defineElement(
          "canvas", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "caption", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT
          ), elementGroupBits(
              ElementGroup.INLINE
          ), scopeBits(
              CloseTagScope.COMMON, CloseTagScope.BUTTON,
              CloseTagScope.LIST_ITEM
          ));
      defineElement(
          "center", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "cite", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "code", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "col", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT, ElementGroup.COL_ELEMENT
          ), 0);
      defineElement(
          "colgroup", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT
          ), elementGroupBits(
              ElementGroup.COL_ELEMENT
          ));
      ElementContainmentInfo DD = defineElement(
          "dd", false, elementGroupBits(
              ElementGroup.DL_PART
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "del", true, elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE,
              ElementGroup.MIXED
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "dfn", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "dir", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.LI_ELEMENT
          ));
      defineElement(
          "div", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "dl", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.DL_PART
          ),
          DD);
      defineElement(
          "dt", false, elementGroupBits(
              ElementGroup.DL_PART
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "em", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "fieldset", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE,
              ElementGroup.LEGEND_ELEMENT
          ));
      defineElement(
          "font", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "form", false, elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.FORM_ELEMENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE,
              ElementGroup.INLINE_MINUS_A, ElementGroup.TR_ELEMENT,
              ElementGroup.TD_ELEMENT
          ));
      defineElement(
          "h1", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "h2", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "h3", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "h4", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "h5", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "h6", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "head", false, elementGroupBits(
              ElementGroup.TOP_CONTENT
          ), elementGroupBits(
              ElementGroup.HEAD_CONTENT
          ));
      defineElement(
          "hr", false, elementGroupBits(ElementGroup.BLOCK), 0);
      defineElement(
          "html", false, 0, elementGroupBits(ElementGroup.TOP_CONTENT),
          CloseTagScope.ALL);
      defineElement(
          "i", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "iframe", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "img", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), 0);
      defineElement(
          "input", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), 0);
      defineElement(
          "ins", true, elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "isindex", false, elementGroupBits(ElementGroup.INLINE), 0);
      defineElement(
          "kbd", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "label", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "legend", false, elementGroupBits(
              ElementGroup.LEGEND_ELEMENT
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      ElementContainmentInfo LI = defineElement(
          "li", false, elementGroupBits(
              ElementGroup.LI_ELEMENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "link", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.HEAD_CONTENT
          ), 0);
      defineElement(
          "listing", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "map", false, elementGroupBits(
              ElementGroup.INLINE
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.AREA_ELEMENT
          ));
      defineElement(
          "meta", false, elementGroupBits(ElementGroup.HEAD_CONTENT), 0);
      defineElement(
          "nobr", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "noframes", false, elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.TOP_CONTENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE,
              ElementGroup.TOP_CONTENT
          ));
      defineElement(
          "noscript", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "object", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A,
              ElementGroup.HEAD_CONTENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE,
              ElementGroup.PARAM_ELEMENT
          ), scopeBits(
              CloseTagScope.COMMON, CloseTagScope.BUTTON,
              CloseTagScope.LIST_ITEM
          ));
      defineElement(
          "ol", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.LI_ELEMENT
          ),
          LI,
          scopeBits(CloseTagScope.LIST_ITEM));
      defineElement(
          "optgroup", false, elementGroupBits(
              ElementGroup.OPTIONS_ELEMENT
          ), elementGroupBits(
              ElementGroup.OPTIONS_ELEMENT
          ));
      defineElement(
          "option", false, elementGroupBits(
              ElementGroup.OPTIONS_ELEMENT, ElementGroup.OPTION_ELEMENT
          ), elementGroupBits(
              ElementGroup.CHARACTER_DATA
          ));
      defineElement(
          "p", false, elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.P_ELEMENT
          ), elementGroupBits(
              ElementGroup.INLINE, ElementGroup.TABLE_ELEMENT
          ));
      defineElement(
          "param", false, elementGroupBits(ElementGroup.PARAM_ELEMENT), 0);
      defineElement(
          "pre", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "q", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "s", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "samp", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "script", false, elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE,
              ElementGroup.INLINE_MINUS_A, ElementGroup.MIXED,
              ElementGroup.TABLE_CONTENT, ElementGroup.HEAD_CONTENT,
              ElementGroup.TOP_CONTENT, ElementGroup.AREA_ELEMENT,
              ElementGroup.FORM_ELEMENT, ElementGroup.LEGEND_ELEMENT,
              ElementGroup.LI_ELEMENT, ElementGroup.DL_PART,
              ElementGroup.P_ELEMENT, ElementGroup.OPTIONS_ELEMENT,
              ElementGroup.OPTION_ELEMENT, ElementGroup.PARAM_ELEMENT,
              ElementGroup.TABLE_ELEMENT, ElementGroup.TR_ELEMENT,
              ElementGroup.TD_ELEMENT, ElementGroup.COL_ELEMENT
          ), elementGroupBits(
              ElementGroup.CHARACTER_DATA));
      defineElement(
          "select", false, elementGroupBits(
              ElementGroup.INLINE
          ), elementGroupBits(
              ElementGroup.OPTIONS_ELEMENT
          ));
      defineElement(
          "small", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "span", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "strike", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "strong", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "style", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.HEAD_CONTENT
          ), elementGroupBits(
              ElementGroup.CHARACTER_DATA
          ));
      defineElement(
          "sub", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "sup", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "table", false, elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.TABLE_ELEMENT
          ), elementGroupBits(
              ElementGroup.TABLE_CONTENT, ElementGroup.FORM_ELEMENT
          ), CloseTagScope.ALL);
      defineElement(
          "tbody", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT
          ), elementGroupBits(
              ElementGroup.TR_ELEMENT
          ));
      ElementContainmentInfo TD = defineElement(
          "td", false, elementGroupBits(
              ElementGroup.TD_ELEMENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ), scopeBits(
              CloseTagScope.COMMON, CloseTagScope.BUTTON,
              CloseTagScope.LIST_ITEM
          ));
      defineElement(
          "textarea", false,
          // No, a textarea cannot be inside a link.
          elementGroupBits(ElementGroup.INLINE),
          elementGroupBits(ElementGroup.CHARACTER_DATA));
      defineElement(
          "tfoot", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT
          ), elementGroupBits(
              ElementGroup.FORM_ELEMENT, ElementGroup.TR_ELEMENT,
              ElementGroup.TD_ELEMENT
          ));
      defineElement(
          "th", false, elementGroupBits(
              ElementGroup.TD_ELEMENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ), scopeBits(
              CloseTagScope.COMMON, CloseTagScope.BUTTON,
              CloseTagScope.LIST_ITEM
          ));
      defineElement(
          "thead", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT
          ), elementGroupBits(
              ElementGroup.FORM_ELEMENT, ElementGroup.TR_ELEMENT,
              ElementGroup.TD_ELEMENT
          ));
      defineElement(
          "title", false, elementGroupBits(ElementGroup.HEAD_CONTENT),
          elementGroupBits(ElementGroup.CHARACTER_DATA));
      defineElement(
          "tr", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT, ElementGroup.TR_ELEMENT
          ), elementGroupBits(
              ElementGroup.FORM_ELEMENT, ElementGroup.TD_ELEMENT
          ),
          TD);
      defineElement(
          "tt", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "u", true, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "ul", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.LI_ELEMENT
          ),
          LI,
          scopeBits(CloseTagScope.LIST_ITEM));
      defineElement(
          "var", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), elementGroupBits(
              ElementGroup.INLINE
          ));
      defineElement(
          "video", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), 0);
      defineElement(
          "wbr", false, elementGroupBits(
              ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A
          ), 0);
      defineElement(
          "xmp", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.INLINE
          ));

    }

    static final ElementContainmentInfo CHARACTER_DATA_ONLY
        = new ElementContainmentInfo(
            "#text", false,
            elementGroupBits(
                ElementGroup.INLINE, ElementGroup.INLINE_MINUS_A,
                ElementGroup.BLOCK, ElementGroup.CHARACTER_DATA),
            0, null, 0);
  }

  static boolean allowsPlainTextualContent(String canonElementName) {
    ElementContainmentInfo info =
       ELEMENT_CONTAINMENT_RELATIONSHIPS.get(canonElementName);
    if (info == null
        || ((info.contents
             & ElementContainmentRelationships.CHARACTER_DATA_ONLY.types)
            != 0)) {
      switch (HtmlTextEscapingMode.getModeForTag(canonElementName)) {
        case PCDATA:     return true;
        case RCDATA:     return true;
        case PLAIN_TEXT: return true;
        case VOID:       return false;
        case CDATA:
        case CDATA_SOMETIMES:
          return "xmp".equals(canonElementName)
              || "listing".equals(canonElementName);
      }
    }
    return false;
  }
}
