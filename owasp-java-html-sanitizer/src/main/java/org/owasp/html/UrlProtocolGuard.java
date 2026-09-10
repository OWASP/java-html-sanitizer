// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package org.owasp.html;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

import org.owasp.html.AttributePolicy.JoinableAttributePolicy;

import static org.owasp.shim.Java8Shim.j8;

/**
 * The guard {@link HtmlPolicyBuilder} puts on every URL attribute it allows,
 * which lets a value through only if it names no protocol or names one the
 * builder allowed via {@link HtmlPolicyBuilder#allowUrlProtocols}.
 *
 * <p>A builder that allowed no protocol installs {@link #NONE}, which rejects
 * every URL that names a protocol.  That is a default, not an allowlist, and
 * the difference shows when two factories are combined by
 * {@link PolicyFactory#and}: the default yields to the other factory's
 * allowlist, whereas two allowlists intersect, as policies on the same
 * attribute always do.  So a factory that never mentioned protocols leaves
 * the links of one that did alone, while two factories that each allowed
 * some protocols together allow only those both allowed.  The default yields
 * only to another guard.  It never yields to a policy an author attached with
 * {@code matching}, so a builder that allowed no protocol rejects every
 * absolute URL on its own, however its author-supplied policies are written.
 *
 * <p>{@link HtmlPolicyBuilder#allowOnlyRelativeUrls} installs
 * {@link #RELATIVE_ONLY}, whose explicit empty allowlist does not yield.
 * Two nonempty allowlists with nothing in common also join to an explicit
 * empty allowlist.  On its own either behaves like the default, but neither
 * is one, so the same factories combined in any grouping allow the same URLs.
 */
@TCB
@Immutable
final class UrlProtocolGuard implements JoinableAttributePolicy {

  private static final Set<String> STANDARD_PROTOCOLS
      = j8().setOf("http", "https", "mailto");

  /** The guard for a builder that allowed no protocol. */
  static final UrlProtocolGuard NONE = new UrlProtocolGuard(null);

  /** The explicit empty allowlist for a relative-only builder. */
  static final UrlProtocolGuard RELATIVE_ONLY =
      new UrlProtocolGuard(j8().setOf());

  /** The protocols allowed, or null for the default guard. */
  private final @Nullable Set<String> allowlist;
  private final AttributePolicy delegate;

  /**
   * The guard that enforces the given allowlist, or {@link #NONE} if it is
   * empty.
   */
  static UrlProtocolGuard forProtocols(Set<? extends String> protocols) {
    return protocols.isEmpty() ? NONE : new UrlProtocolGuard(protocols);
  }

  private UrlProtocolGuard(@Nullable Set<? extends String> allowlist) {
    if (allowlist == null) {
      this.allowlist = null;
      this.delegate = new FilterUrlByProtocolAttributePolicy(j8().setOf());
    } else {
      this.allowlist = j8().setCopyOf(allowlist);
      // The standard set has a checker that allocates nothing per URL.
      this.delegate = STANDARD_PROTOCOLS.equals(this.allowlist)
          ? StandardUrlAttributePolicy.INSTANCE
          : new FilterUrlByProtocolAttributePolicy(this.allowlist);
    }
  }

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    return delegate.apply(elementName, attributeName, value);
  }

  public Joinable.JoinStrategy<JoinableAttributePolicy> getJoinStrategy() {
    return UrlProtocolGuardJoinStrategy.INSTANCE;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof UrlProtocolGuard
        && Objects.equals(allowlist, ((UrlProtocolGuard) o).allowlist);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(allowlist);
  }

  /** Intersects the allowlists being joined; the default guard yields. */
  static final class UrlProtocolGuardJoinStrategy
  implements Joinable.JoinStrategy<JoinableAttributePolicy> {
    static final UrlProtocolGuardJoinStrategy INSTANCE =
        new UrlProtocolGuardJoinStrategy();

    public JoinableAttributePolicy join(
        Iterable<? extends JoinableAttributePolicy> toJoin) {
      Set<String> allowed = null;
      for (JoinableAttributePolicy p : toJoin) {
        Set<String> allowlist = ((UrlProtocolGuard) p).allowlist;
        if (allowlist == null) { continue; }
        if (allowed == null) {
          allowed = new HashSet<>(allowlist);
        } else {
          allowed.retainAll(allowlist);
        }
      }
      return allowed == null ? NONE : new UrlProtocolGuard(allowed);
    }
  }
}
