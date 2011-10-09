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

import javax.annotation.concurrent.Immutable;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;

/**
 * Wraps an HTML stream event receiver to fill in missing close tags.
 * If the balancer is given the HTML {@code <p>1<p>2}, the wrapped receiver will
 * see events equivalent to {@code <p>1</p><p>2</p>}.
 *
 * @author Mike Samuel <mikesamuel@gmail.com>
 */
@TCB
public class TagBalancingHtmlStreamEventReceiver
    implements HtmlStreamEventReceiver {
  private final HtmlStreamEventReceiver underlying;
  private final List<ElementContainmentInfo> openElements
      = Lists.newArrayList();

  public TagBalancingHtmlStreamEventReceiver(
      HtmlStreamEventReceiver underlying) {
    this.underlying = underlying;
  }

  public void openDocument() {
    underlying.openDocument();
  }

  public void closeDocument() {
    while (!openElements.isEmpty()) {
      underlying.closeTag(
          openElements.remove(openElements.size() - 1).elementName);
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
      underlying.openTag(elementName, attrs);
      return;
    }

    // Close all the elements that cannot contain the element to open.
    List<ElementContainmentInfo> toResumeInReverse = null;
    for (int i = openElements.size(); --i >= 0;) {
      ElementContainmentInfo top = openElements.get(i);
      if ((top.contents & elInfo.types) != 0) { break; }
      underlying.closeTag(top.elementName);
      openElements.remove(i);
      if (top.resumable) {
        if (toResumeInReverse == null) {
          toResumeInReverse = Lists.newArrayList();
        }
        toResumeInReverse.add(top);
      }
    }

    if (toResumeInReverse != null) {
      for (ElementContainmentInfo toResume : toResumeInReverse) {
        openElements.add(toResume);
        // TODO: If resuming of things other than plain formatting tags like <b>
        // and <i>, then we need to store the attributes for resumable tags so
        // that we can resume with the appropriate attributes.
        underlying.openTag(toResume.elementName, Lists.<String>newArrayList());
      }
    }
    if (!elInfo.isVoid) {
      openElements.add(elInfo);
    }
    underlying.openTag(elementName, attrs);
  }

  public void closeTag(String elementName) {
    String canonElementName = HtmlLexer.canonicalName(elementName);
    ElementContainmentInfo elInfo = ELEMENT_CONTAINMENT_RELATIONSHIPS.get(
        canonElementName);
    if (elInfo == null) {  // Allow unrecognized end tags through.
      underlying.closeTag(elementName);
      return;
    }
    int index = openElements.lastIndexOf(elInfo);
    if (index < 0) { return; }  // Don't close unopened tags.
    int last = openElements.size();
    // Close all the elements that cannot contain the element to open.
    List<ElementContainmentInfo> toResumeInReverse = null;
    while (--last > index) {
      ElementContainmentInfo unclosed = openElements.remove(last);
      underlying.closeTag(unclosed.elementName);
      if (unclosed.resumable) {
        if (toResumeInReverse == null) {
          toResumeInReverse = Lists.newArrayList();
        }
        toResumeInReverse.add(unclosed);
      }
    }
    openElements.remove(index);
    underlying.closeTag(elementName);

    if (toResumeInReverse != null) {
      for (ElementContainmentInfo toResume : toResumeInReverse) {
        openElements.add(toResume);
        // TODO: If resuming of things other than plain formatting tags like <b>
        // and <i>, then we need to store the attributes for resumable tags so
        // that we can resume with the appropriate attributes.
        underlying.openTag(toResume.elementName, Lists.<String>newArrayList());
      }
    }
  }

  public void text(String text) {
    underlying.text(text);
  }


  @Immutable
  static final class ElementContainmentInfo {
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

    ElementContainmentInfo(
        String elementName, boolean resumable, int types, int contents) {
      this.elementName = elementName;
      this.resumable = resumable;
      this.types = types;
      this.contents = contents;
      this.isVoid = contents == 0
          && HtmlTextEscapingMode.isVoidElement(elementName);
    }

    @Override public String toString() {
      return "<" + elementName + ">";
    }
  }

  ImmutableMap<String, ElementContainmentInfo> ELEMENT_CONTAINMENT_RELATIONSHIPS
      = new ElementContainmentRelationships().toMap();

  private static class ElementContainmentRelationships {
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
      ;
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

    private ImmutableMap.Builder<String, ElementContainmentInfo> definitions
        = ImmutableMap.builder();

    private void defineElement(
        String elementName, boolean resumable, int types, int contentTypes) {
      definitions.put(elementName, new ElementContainmentInfo(
          elementName, resumable, types, contentTypes));
    }

    private ImmutableMap<String, ElementContainmentInfo> toMap() {
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
          ));
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
      defineElement(
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
          ));
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
          "html", false, 0, elementGroupBits(ElementGroup.TOP_CONTENT));
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
      defineElement(
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
          ));
      defineElement(
          "ol", false, elementGroupBits(
              ElementGroup.BLOCK
          ), elementGroupBits(
              ElementGroup.LI_ELEMENT
          ));
      defineElement(
          "optgroup", false, elementGroupBits(
              ElementGroup.OPTIONS_ELEMENT
          ), elementGroupBits(
              ElementGroup.OPTIONS_ELEMENT
          ));
      defineElement(
          "option", false, elementGroupBits(
              ElementGroup.OPTIONS_ELEMENT, ElementGroup.OPTION_ELEMENT
          ), 0);
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
          ), 0);
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
          ), 0);
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
          ));
      defineElement(
          "tbody", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT
          ), elementGroupBits(
              ElementGroup.TR_ELEMENT
          ));
      defineElement(
          "td", false, elementGroupBits(
              ElementGroup.TD_ELEMENT
          ), elementGroupBits(
              ElementGroup.BLOCK, ElementGroup.INLINE
          ));
      defineElement(
          "textarea", false,
          // No, a textarea cannot be inside a link.
          elementGroupBits(ElementGroup.INLINE), 0);
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
          ));
      defineElement(
          "thead", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT
          ), elementGroupBits(
              ElementGroup.FORM_ELEMENT, ElementGroup.TR_ELEMENT,
              ElementGroup.TD_ELEMENT
          ));
      defineElement(
          "title", false, elementGroupBits(ElementGroup.HEAD_CONTENT), 0);
      defineElement(
          "tr", false, elementGroupBits(
              ElementGroup.TABLE_CONTENT, ElementGroup.TR_ELEMENT
          ), elementGroupBits(
              ElementGroup.FORM_ELEMENT, ElementGroup.TD_ELEMENT
          ));
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
          ));
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
  }
}