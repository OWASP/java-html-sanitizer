package org.owasp.html;

import java.util.List;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * A policy that can be applied to an element to decide whether or not to
 * allow it in the output, possibly after transforming attributes.
 * <p>
 * Element policies are applied <strong>after</strong>
 * {@link AttributePolicy attribute policies} so
 * they can be used to add extra attributes.
 *
 * @author Mike Samuel
 * @see HtmlPolicyBuilder#allowElements(ElementPolicy, String...)
 */
@TCB public interface ElementPolicy {
  /**
   * @param elementName the lower-case element name.
   * @param attrs a list of alternating attribute names and values.
   *    The list may be added to or removed from.  When removing, be
   *    careful to remove both the name and its associated value.
   *
   * @return {@code null} to disallow the element, or the adjusted element name.
   */
  public @Nullable String apply(String elementName, List<String> attrs);


  /** Utilities for working with element policies. */
  public static final class Util {
    private Util() { /* uninstantiable */ }

    /**
     * Given zero or more element policies, returns an element policy equivalent
     * to applying them in order failing early if any of them fails.
     */
    public static final ElementPolicy join(ElementPolicy... policies) {

      class PolicyJoiner {
        ElementPolicy last = null;
        ElementPolicy out = null;

        void join(ElementPolicy p) {
          if (p == REJECT_ALL_ELEMENT_POLICY) {
            out = p;
          } else if (out != REJECT_ALL_ELEMENT_POLICY) {
            if (p instanceof JoinedElementPolicy) {
              JoinedElementPolicy jep = (JoinedElementPolicy) p;
              join(jep.first);
              join(jep.second);
            } else if (p != last) {
              last = p;
              if (out == null || out == IDENTITY_ELEMENT_POLICY) {
                out = p;
              } else if (p != IDENTITY_ELEMENT_POLICY) {
                out = new JoinedElementPolicy(out, p);
              }
            }
          }
        }
      }

      PolicyJoiner pu = new PolicyJoiner();
      for (ElementPolicy policy : policies) {
        if (policy == null) { continue; }
        pu.join(policy);
      }
      return pu.out != null ? pu.out : IDENTITY_ELEMENT_POLICY;
    }

  }

  public static final ElementPolicy IDENTITY_ELEMENT_POLICY
      = new ElementPolicy() {
    public String apply(String elementName, List<String> attrs) {
      return elementName;
    }
  };

  public static final ElementPolicy REJECT_ALL_ELEMENT_POLICY
      = new ElementPolicy() {
    public @Nullable String apply(String elementName, List<String> attrs) {
      return null;
    }
  };

}

@Immutable
final class JoinedElementPolicy implements ElementPolicy {
  final ElementPolicy first, second;

  JoinedElementPolicy(ElementPolicy first, ElementPolicy second) {
    this.first = first;
    this.second = second;
  }

  public @Nullable String apply(String elementName, List<String> attrs) {
    elementName = first.apply(elementName, attrs);
    return elementName != null ? second.apply(elementName, attrs) : null;
  }
}
