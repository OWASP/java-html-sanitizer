package org.owasp.html;

import java.util.LinkedList;
import java.util.Random;

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class IntVectorTest extends TestCase {

  @Test
  public static void testIntVector() {
    Random r = new Random(0xA03B79241106C82FL);

    IntVector iv = new IntVector();
    LinkedList<Integer> ad = new LinkedList<Integer>();

    for (int i = 0; i < 200000; ++i) {
      switch (r.nextInt(4)) {
        case 0: {
          int el = r.nextInt();
          iv.add(el);
          ad.add(el);
          break;
        }
        case 1:
          if (ad.isEmpty()) {
            assertTrue(iv.isEmpty());
          } else {
            int ix = r.nextInt(ad.size());
            int el0 = iv.remove(ix);
            int el1 = ad.remove(ix);
            assertEquals(el0, el1);
          }
          break;
        case 2: case 3:
          if (ad.isEmpty()) {
            assertTrue(iv.isEmpty());
          } else {
            int ix = r.nextInt(ad.size());
            int el0 = iv.get(ix);
            int el1 = ad.get(ix);
            assertEquals(el0, el1);
          }
          break;
      }
    }
    assertEquals(ad.toString(), iv.toString());
  }

  @Test
  public static void testLastIndexOf() {
    IntVector v = new IntVector();
    for (int i = 0; i < 30; ++i) {
      v.add(i);
    }
    for (int i = 0; i < 10; ++i) {
      v.remove(0);
    }
    for (int i = 0; i < 11; ++i) {
      v.add(i);
    }

    // State should now be [10 .. 29, 0 .. 10]
    // for indices         [0 .. 19, 20 .. 30]
    assertEquals(31, v.size());
    int[] contentsLastOrNeg1 = new int[] {
        -1,  // 10 appears at end too
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 0,
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    };
    for (int i = 0; i < contentsLastOrNeg1.length; ++i) {
      int val = contentsLastOrNeg1[i];
      if (val == -1) { continue; }
      assertEquals(i, v.lastIndexOf(val));
    }
  }
}
