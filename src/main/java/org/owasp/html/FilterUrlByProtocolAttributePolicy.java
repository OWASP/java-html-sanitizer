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

import javax.annotation.Nullable;

import com.google.common.collect.ImmutableSet;

/**
 * An attribute policy for attributes whose values are URLs that requires that
 * the value have no protocol or have an allowed protocol.
 *
 * <p>
 * URLs with protocols must match the protocol set passed to the constructor.
 * URLs without protocols but which specify an origin different from the
 * containing page (e.g. {@code //example.org}) are only allowed if the
 * {@link FilterUrlByProtocolAttributePolicy#allowProtocolRelativeUrls policy}
 * allows both {@code http} and {@code https} which are normally used to serve
 * HTML.
 * Same-origin URLs, URLs without any protocol or authority part are always
 * allowed.
 * </p>
 *
 * <p>
 * This class assumes that URLs are either hierarchical, or are opaque, but
 * do not look like they contain an authority portion.
 * </p>
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
@TCB
public class FilterUrlByProtocolAttributePolicy implements AttributePolicy {
  private final ImmutableSet<String> protocols;

  /**
   * @param protocols lower-case protocol names without any trailing colon (":")
   */
  public FilterUrlByProtocolAttributePolicy(
      Iterable<? extends String> protocols) {
    this.protocols = ImmutableSet.copyOf(protocols);
  }

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    String url = Strings.stripHtmlSpaces(value);
    protocol_loop:
    for (int i = 0, n = url.length(); i < n; ++i) {
      switch (url.charAt(i)) {
        case '/': case '#': case '?':  // No protocol.
          // Check for domain relative URLs like //www.evil.org/
          if (url.startsWith("//")
              // or the protocols by which HTML is normally served are OK.
              && !allowProtocolRelativeUrls()) {
            return null;
          }
          break protocol_loop;
        case ':':
          String protocol = Strings.toLowerCase(url.substring(0, i));
          if (!protocols.contains(protocol)) { return null; }
          break protocol_loop;
      }
    }
    return normalizeUri(url);
  }

  protected boolean allowProtocolRelativeUrls() {
    return protocols.contains("http") && protocols.contains("https");
  }

  /** Percent encodes anything that looks like a colon, or a parenthesis. */
  static String normalizeUri(String s) {
    int n = s.length();
    boolean colonsIrrelevant = false;
    for (int i = 0; i < n; ++i) {
      char ch = s.charAt(i);
      switch (ch) {
        case '/': case '#': case '?': case ':':
          colonsIrrelevant = true;
          break;
        case '(': case ')':
        case '{': case '}':
          return normalizeUriFrom(s, i, colonsIrrelevant);
        case '\u0589':
        case '\u05c3':
        case '\u2236':
        case '\uff1a':
          if (!colonsIrrelevant) {
            return normalizeUriFrom(s, i, false);
          }
          break;
        default:
          if (ch <= 0x20) {
            return normalizeUriFrom(s, i, false);
          }
          break;
      }
    }
    return s;
  }

  private static String normalizeUriFrom(
      String s, int start, boolean colonsIrrelevant) {
    int n = s.length();
    StringBuilder sb = new StringBuilder(n + 16);
    int pos = 0;
    for (int i = start; i < n; ++i) {
      char ch = s.charAt(i);
      String repl = null;
      switch (ch) {
        case '(': repl = "%28"; break;
        case ')': repl = "%29"; break;
        case '{': repl = "%7b"; break;
        case '}': repl = "%7d"; break;
        default:
          if (ch >= 0x100 && !colonsIrrelevant) {
            // Other colon like characters.
            // TODO: do we need to encode non-colon characters if we're
            // not dealing with URLs that haven't been copy/pasted into
            // the URL bar?
            // Is it safe to assume UTF-8 here?
            switch (ch) {
              case '\u0589': repl = "%d6%89";    break;
              case '\u05c3': repl = "%d7%83";    break;
              case '\u2236': repl = "%e2%88%b6"; break;
              case '\uff1a': repl = "%ef%bc%9a"; break;
            }
          } else if (ch <= 0x20) {
            repl = CONTROL_REPL[ch];
          }
          break;
      }
      if (repl != null) {
        sb.append(s, pos, i).append(repl);
        pos = i + 1;
      }
    }
    return sb.append(s, pos, n).toString();
  }

  @Override
  public boolean equals(Object o) {
    return o != null && this.getClass() == o.getClass()
        && protocols.equals(((FilterUrlByProtocolAttributePolicy) o).protocols);
  }

  @Override
  public int hashCode() {
    return protocols.hashCode();
  }

  /** Replacements for control characters. */
  private static String[] CONTROL_REPL = {
      "",    "%01", "%02", "%03", "%04", "%05", "%06", "%07",
      "%08", "%09", "%0a", "%0b", "%0c", "%0d", "%0e", "%0f",
      "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17",
      "%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f",
      "%20",
  };
}
