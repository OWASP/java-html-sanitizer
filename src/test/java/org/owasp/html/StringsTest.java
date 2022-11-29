package org.owasp.html;

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings({ "javadoc" })
public final class StringsTest extends TestCase {

  @Test
  public static void testValidFloatingPointNumber() {
    assertEquals(
        -1,
        Strings.skipValidFloatingPointNumber("", 0));
    assertEquals(
        3,
        Strings.skipValidFloatingPointNumber("123", 0));
    assertEquals(
        7,
        Strings.skipValidFloatingPointNumber("123.456", 0));
    assertEquals(
        7,
        Strings.skipValidFloatingPointNumber("123.456f", 0));
    assertEquals(
        8,
        Strings.skipValidFloatingPointNumber(" 123.456 ", 1));
    assertEquals(
        -1,
        Strings.skipValidFloatingPointNumber("1e", 0));
    assertEquals(
        -1,
        Strings.skipValidFloatingPointNumber("1.", 0));
    assertEquals(
        -1,
        Strings.skipValidFloatingPointNumber("1e+", 0));
    assertEquals(
        -1,
        Strings.skipValidFloatingPointNumber("1e+e", 0));
    assertEquals(
        5,
        Strings.skipValidFloatingPointNumber(" 1E-1", 1));
    assertEquals(
        5,
        Strings.skipValidFloatingPointNumber(" 1E+2 ", 1));
    assertEquals(
        5,
        Strings.skipValidFloatingPointNumber(" 1E+2,", 1));
  }

}
