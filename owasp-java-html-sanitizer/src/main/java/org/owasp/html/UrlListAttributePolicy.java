// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package org.owasp.html;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

import org.owasp.html.AttributePolicy.JoinableAttributePolicy;

/**
 * Applies a URL policy to each URL in an attribute whose value is a list of
 * URLs separated by spaces, such as {@code ping} on {@code <a>} and
 * {@code <area>}, whose URLs the browser sends a request to when the link is
 * followed.
 * <p>
 * https://html.spec.whatwg.org/multipage/links.html#ping explains
 * {@code ping}.
 * <p>
 * The browser splits the value on ASCII whitespace, so this policy does too,
 * keeps each URL that the URL policy allows, as that policy rewrites it,
 * drops the others, and joins what is left with single spaces.  If the list
 * had URLs and none is left, the attribute is dropped.  A list with no URL at
 * all comes out empty, since an empty {@code attributionsrc} has a meaning of
 * its own: register attribution with the element's own {@code src} or
 * {@code href}, which its own guard has vetted.
 */
@TCB
final class UrlListAttributePolicy implements JoinableAttributePolicy {

  private final AttributePolicy urlPolicy;

  UrlListAttributePolicy(AttributePolicy urlPolicy) {
    this.urlPolicy = urlPolicy;
  }

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    StringBuilder sb = new StringBuilder();
    boolean sawUrl = false;
    int i = 0, n = value.length();
    while (i < n) {
      while (i < n && Strings.isHtmlSpace(value.charAt(i))) {
        ++i;
      }
      int urlStart = i;
      while (i < n && !Strings.isHtmlSpace(value.charAt(i))) {
        ++i;
      }
      if (urlStart < i) {
        sawUrl = true;
        String okUrl = urlPolicy.apply(
            elementName, attributeName, value.substring(urlStart, i));
        if (okUrl != null && !okUrl.isEmpty()) {
          if (sb.length() != 0) {
            sb.append(' ');
          }
          sb.append(okUrl);
        }
      }
    }
    return sb.length() != 0 || !sawUrl ? sb.toString() : null;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof UrlListAttributePolicy
        && urlPolicy.equals(((UrlListAttributePolicy) o).urlPolicy);
  }

  @Override
  public int hashCode() {
    return urlPolicy.hashCode();
  }

  public Joinable.JoinStrategy<JoinableAttributePolicy> getJoinStrategy() {
    return UrlListJoinStrategy.INSTANCE;
  }

  /**
   * Joins URL list policies by joining the policies they apply to each URL,
   * so that the URL protocol guards inside them meet and join as they do on
   * {@code href}: a builder that allowed no protocol yields to one that did,
   * and two allowlists intersect.
   */
  static final class UrlListJoinStrategy
  implements Joinable.JoinStrategy<JoinableAttributePolicy> {
    static final UrlListJoinStrategy INSTANCE = new UrlListJoinStrategy();

    public JoinableAttributePolicy join(
        Iterable<? extends JoinableAttributePolicy> toJoin) {
      List<AttributePolicy> urlPolicies = new ArrayList<>();
      for (JoinableAttributePolicy p : toJoin) {
        urlPolicies.add(((UrlListAttributePolicy) p).urlPolicy);
      }
      return new UrlListAttributePolicy(
          AttributePolicy.Util.join(
              urlPolicies.toArray(new AttributePolicy[0])));
    }
  }

}
