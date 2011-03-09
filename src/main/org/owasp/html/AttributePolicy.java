package org.owasp.html;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * A policy that can be applied to an HTML attribute to decide whether or not to
 * allow it in the output, possibly after transforming its value.
 *
 * @author Mike Samuel
 * @see HtmlPolicyBuilder#allowAttributesGlobally(AttributePolicy, String...)
 */
@TCB public interface AttributePolicy {

  /**
   * @param elementName the lower-case element name.
   * @param attributeName the lower-case attribute name.
   * @param value the attribute value without quotes and with HTML entities
   *     decoded.
   *
   * @return {@code null} to disallow the attribute or the adjusted value if
   *     allowed.
   */
  public @Nullable String apply(
      String elementName, String attributeName, String value);


  /** Utilities for working with attribute policies. */
  public static final class Util {

    /**
     * An attribute policy equivalent to applying all the given policies in
     * order, failing early if any of them fails.
     */
    public static final AttributePolicy join(AttributePolicy... policies) {

      class PolicyJoiner {
        AttributePolicy last = null;
        AttributePolicy out = null;

        void join(AttributePolicy p) {
          if (REJECT_ALL_ATTRIBUTE_POLICY.equals(p)) {
            out = p;
          } else if (!REJECT_ALL_ATTRIBUTE_POLICY.equals(out)) {
            if (p instanceof JoinedAttributePolicy) {
              JoinedAttributePolicy jap = (JoinedAttributePolicy) p;
              join(jap.first);
              join(jap.second);
            } else if (p != last) {
              last = p;
              if (out == null || IDENTITY_ATTRIBUTE_POLICY.equals(out)) {
                out = p;
              } else if (!IDENTITY_ATTRIBUTE_POLICY.equals(p)) {
                out = new JoinedAttributePolicy(out, p);
              }
            }
          }
        }
      }

      PolicyJoiner pu = new PolicyJoiner();
      for (AttributePolicy policy : policies) {
        if (policy == null) { continue; }
        pu.join(policy);
      }
      return pu.out != null ? pu.out : IDENTITY_ATTRIBUTE_POLICY;
    }
  }


  public static final AttributePolicy IDENTITY_ATTRIBUTE_POLICY
      = new AttributePolicy() {
        public String apply(
            String elementName, String attributeName, String value) {
          return value;
        }
      };

  public static final AttributePolicy REJECT_ALL_ATTRIBUTE_POLICY
      = new AttributePolicy() {
        public @Nullable String apply(
            String elementName, String attributeName, String value) {
          return null;
        }
      };

}

@Immutable
final class JoinedAttributePolicy implements AttributePolicy {
  final AttributePolicy first, second;

  JoinedAttributePolicy(AttributePolicy first, AttributePolicy second) {
    this.first = first;
    this.second = second;
  }

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    value = first.apply(elementName, attributeName, value);
    return value != null
        ? second.apply(elementName, attributeName, value) : null;
  }
}
