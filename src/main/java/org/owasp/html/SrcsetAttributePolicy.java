// Copyright (c) 2019, Mike Samuel
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

/**
 * Applies a URL policy to all URLs in a srcset attribute value.
 * <p>
 * https://html.spec.whatwg.org/multipage/images.html#srcset-attributes
 * explains srcset for images and other media content.
 * <p>
 * There is a pending draft to use it on <script> to allow loading
 * scripts compatible with different versions of JS.
 * <p>
 * The general form of srcset is
 * <pre>
 * srcset ::== space* srcplus ([,] space* srcplus)*
 * # Additionally, the URL may not start or end with a comma
 * srcplus ::== URL (space+ metadata)?
 * metadata ::== FLOAT [a-z]?
 * </pre>
 * <p>
 * This policy applies the given attribute policy to URLs and emits metadata
 * as given, but normalizing spaces.
 */
final class SrcsetAttributePolicy implements AttributePolicy {

  private final AttributePolicy srcPolicy;

  SrcsetAttributePolicy(AttributePolicy srcPolicy) {
    this.srcPolicy = srcPolicy;
  }

  public String apply(String elementName, String attributeName, String value) {
    StringBuilder sb = new StringBuilder();

    int i = 0, n = value.length();
    // Skip spaces.
    while (i < n && Strings.isHtmlSpace(value.charAt(i))) {
      ++i;
    }

    while (i < n) {
      // Find URL end.
      int urlStart = i;
      while (i < n && !Strings.isHtmlSpace(value.charAt(i))) {
        ++i;
      }
      int urlEnd = i;
      // Find metadata end.
      while (i < n && Strings.isHtmlSpace(value.charAt(i))) {
        ++i;
      }
      int metadataStart = i;
      if (urlEnd < i) {  // Space required before metadata.
        int floatEnd = Strings.skipValidFloatingPointNumber(value, i);
        if (floatEnd >= 0) {
          i = floatEnd;
          if (i < n) {
            // Skip over width specifier 'w', or pixel density specifier 'x'.
            // We make this optional to support the <script srcset> proposal.
            int ch = value.charAt(i) | 32;
            if ('a' <= ch && ch <= 'z') {
              ++i;
            }
          }
        }
      }
      int metadataEnd = i;

      if (urlStart < urlEnd) {
        if (value.charAt(urlStart) == ',' || value.charAt(urlEnd - 1) == ',') {
          // These introduce lexical ambiguity and are called out in the spec.
          return null;
        }
        String okUrl = srcPolicy.apply(
            elementName, "src", value.substring(urlStart, urlEnd));
        if (okUrl != null && !okUrl.isEmpty()) {
          if (sb.length() != 0) {
            sb.append(" , ");
          }
          sb.append(okUrl.replace(",", "%2c"));
          if (metadataStart < metadataEnd) {
            sb.append(' ');
            sb.append(value, metadataStart, metadataEnd);
          }
        }
      }
      // Skip space before comma
      while (i < n && Strings.isHtmlSpace(value.charAt(i))) {
        ++i;
      }
      if (i == n || value.charAt(i) != ',') {
        break;
      }
      ++i;
      while (i < n && Strings.isHtmlSpace(value.charAt(i))) {
        ++i;
      }
    }

    if (i < n  // Unexpected trailing content.
        || sb.length() == 0) {  // No URLs found.
      return null;
    }
    return sb.toString();
  }

}
