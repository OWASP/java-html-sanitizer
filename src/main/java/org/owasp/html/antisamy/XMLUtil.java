/*
 * Copyright (c) 2007-2011, Arshan Dabirsiaghi, Jason Li
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.html.antisamy;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XMLUtil {

    private static final Pattern encgt = Pattern.compile("&gt;");
    private static final Pattern enclt = Pattern.compile("&lt;");
    private static final Pattern encQuot = Pattern.compile("&quot;");
    private static final Pattern encAmp = Pattern.compile("&amp;");

    private static final Pattern gt = Pattern.compile(">");
    private static final Pattern lt = Pattern.compile("<");
    private static final Pattern quot = Pattern.compile("\"");
    private static final Pattern amp = Pattern.compile("&");

    /**
   * Helper function for quickly retrieving an attribute from a given
   * element.
   * @param ele The document element from which to pull the attribute value.
   * @param attrName The name of the attribute.
   * @return The value of the attribute contained within the element
   */
  public static String getAttributeValue (Element ele, String attrName) {
    return decode(ele.getAttribute(attrName));
  }

  /**
   * Helper function for quickly retrieving an integer value of a given
   * XML element.
   * @param ele The document element from which to pull the integer value.
   * @param tagName The name of the node.
   * @return The integer value of the given node in the element passed in.
   */

  public static int getIntValue(Element ele, String tagName, int defaultValue) {

    int toReturn = defaultValue;

    try {
      toReturn = Integer.parseInt(getTextValue(ele,tagName));
    } catch (Throwable t) { }

    return toReturn;
  }


  /**
   * Helper function for quickly retrieving a String value of a given
   * XML element.
   * @param ele The document element from which to pull the String value.
   * @param tagName The name of the node.
   * @return The String value of the given node in the element passed in.
   */
  public static String getTextValue(Element ele, String tagName) {
    String textVal = null;
    NodeList nl = ele.getElementsByTagName(tagName);
    if(nl != null && nl.getLength() > 0) {
      Element el = (Element)nl.item(0);
      if ( el.getFirstChild() != null ) {
        textVal = el.getFirstChild().getNodeValue();
      } else {
        textVal = "";
      }
    }
    return decode(textVal);
  }


  /**
   * Helper function for quickly retrieving an boolean value of a given
   * XML element.
   * @param ele The document element from which to pull the boolean value.
   * @param tagName The name of the node.
   * @return The boolean value of the given node in the element passed in.
   */
  public static boolean getBooleanValue(Element ele, String tagName) {

    boolean boolVal = false;
    NodeList nl = ele.getElementsByTagName(tagName);

    if ( nl != null && nl.getLength() > 0 ) {
      Element el = (Element)nl.item(0);
      boolVal = el.getFirstChild().getNodeValue().equals("true");
    }

    return boolVal;
  }

  /**
   * Helper function for quickly retrieving an boolean value of a given
   * XML element, with a default initialization value passed in a parameter.
   * @param ele The document element from which to pull the boolean value.
   * @param tagName The name of the node.
   * @param defaultValue The default value of the node if it's value can't be processed.
   * @return The boolean value of the given node in the element passed in.
   */
  public static boolean getBooleanValue(Element ele, String tagName, boolean defaultValue) {

    boolean boolVal = defaultValue;
    NodeList nl = ele.getElementsByTagName(tagName);

    if ( nl != null && nl.getLength() > 0 ) {

      Element el = (Element)nl.item(0);

      if ( el.getFirstChild().getNodeValue() != null ) {

        boolVal = "true".equals(el.getFirstChild().getNodeValue());

      } else {

        boolVal = defaultValue;

      }
    }

    return boolVal;
  }


    /**
     * Helper function for decode XML entities.
     *
     * @param str The XML-encoded String to decode.
     * @return An XML-decoded String.
     */
    public static String decode(String str) {

        if (str == null) {
            return null;
        }

        Matcher gtmatcher = encgt.matcher(str);
        if (gtmatcher.matches()) {
            str = gtmatcher.replaceAll(">");
        }
        Matcher ltmatcher = enclt.matcher(str);
        if (ltmatcher.matches()) {
            str = ltmatcher.replaceAll("<");
        }
        Matcher quotMatcher = encQuot.matcher(str);
        if (quotMatcher.matches()) {
            str = quotMatcher.replaceAll("\"");
        }
        Matcher ampMatcher = encAmp.matcher(str);
        if (ampMatcher.matches()) {
            str = ampMatcher.replaceAll("&");
        }

        return str;
    }

    public static String encode(String str) {

        if (str == null) {
            return null;
        }

        Matcher gtMatcher = gt.matcher(str);
        if (gtMatcher.matches()) {
            str = gtMatcher.replaceAll("&gt;");
        }
        Matcher ltMatcher = lt.matcher(str);
        if (ltMatcher.matches()) {
            str = ltMatcher.replaceAll("&lt;");
        }
        Matcher quotMatcher = quot.matcher(str);
        if (quotMatcher.matches()) {
            str = quotMatcher.replaceAll("&quot;");
        }
        Matcher ampMatcher = amp.matcher(str);
        if (ampMatcher.matches()) {
            str = ampMatcher.replaceAll("&amp;");
        }

        return str;
    }
}
