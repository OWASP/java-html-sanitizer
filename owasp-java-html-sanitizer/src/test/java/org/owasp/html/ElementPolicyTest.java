package org.owasp.html;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;

import org.junit.Test;

import junit.framework.TestCase;

import static org.owasp.html.ElementPolicy.REJECT_ALL_ELEMENT_POLICY;
import static org.owasp.html.ElementPolicy.IDENTITY_ELEMENT_POLICY;
import static org.owasp.html.ElementPolicy.Util.join;
import static org.owasp.shim.Java8Shim.j8;

@SuppressWarnings("javadoc")
public final class ElementPolicyTest extends TestCase {

  static class HasCharElementPolicy implements ElementPolicy {
    final char ch;

    HasCharElementPolicy(char ch) {
      this.ch = ch;
    }

    public @Nullable
    String apply(String elementName, List<String> attrs) {
      attrs.clear();
      return elementName.indexOf(ch) >= 0 ? elementName : null;
    }

    @Override
    public String toString() {
      return "(has '" + ch + "')";
    }
  }

  private static void assertPassed(ElementPolicy p, String... expected) {
    List<String> attrs = new ArrayList<>();
    List<String> actual = new ArrayList<>();
    for (String elName : TEST_EL_NAMES) {
      if (p.apply(elName, attrs) != null) {
        actual.add(elName);
      }
    }
    assertEquals(p.toString(), Arrays.asList(expected), actual);
  }

  private static List<String> TEST_EL_NAMES = j8().listOf(
      "abacus", "abracadabra", "bar", "foo", "far", "cadr", "cdr");

  @Test
  public final void testJoin() {
    ElementPolicy a = new HasCharElementPolicy('a');
    ElementPolicy b = new HasCharElementPolicy('b');
    ElementPolicy c = new HasCharElementPolicy('c');
    ElementPolicy d = new HasCharElementPolicy('d');
    assertPassed(REJECT_ALL_ELEMENT_POLICY);
    assertPassed(IDENTITY_ELEMENT_POLICY,
                 TEST_EL_NAMES.toArray(new String[0]));
    assertPassed(a, "abacus", "abracadabra", "bar", "far", "cadr");
    assertPassed(c, "abacus", "abracadabra", "cadr", "cdr");
    assertPassed(d, "abracadabra", "cadr", "cdr");
    ElementPolicy a_b = join(a, b);
    ElementPolicy b_a = join(b, a);
    assertPassed(a_b, "abacus", "abracadabra", "bar");
    assertPassed(b_a, "abacus", "abracadabra", "bar");
    assertPassed(join(b_a, b_a), "abacus", "abracadabra", "bar");
    assertPassed(join(a_b, c), "abacus", "abracadabra");
    assertPassed(join(c, REJECT_ALL_ELEMENT_POLICY));
    assertPassed(join(REJECT_ALL_ELEMENT_POLICY, a_b));
  }

}
