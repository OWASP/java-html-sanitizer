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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.owasp.html.antisamy.Attribute;
import org.owasp.html.antisamy.Policy;
import org.owasp.html.antisamy.Tag;

public class Constants {

    public static final String DEFAULT_ENCODING_ALGORITHM = "UTF-8";
    public static final Tag BASIC_PARAM_TAG_RULE;
    public static List<String> defaultAllowedEmptyTags;
    public static List<String> defaultRequiresClosingTags;

    private static final String[] allowedEmptyTags = {
         "br", "hr", "a", "img", "link", "iframe", "script", "object", "applet",
         "frame", "base", "param", "meta", "input", "textarea", "embed",
         "basefont", "col"
        };

    private static final String[] requiresClosingTags = {
      "iframe", "script", "link"
    };

    static {
        Attribute paramNameAttr = new Attribute("name", Arrays.asList(Policy.ANYTHING_REGEXP), Collections.<String>emptyList(), null, null );
        Attribute paramValueAttr = new Attribute("value", Arrays.asList(Policy.ANYTHING_REGEXP), Collections.<String>emptyList(), null, null );

        Map<String, Attribute> attrs = new HashMap<String, Attribute>();
        attrs.put(paramNameAttr.getName().toLowerCase(), paramNameAttr);
        attrs.put(paramValueAttr.getName().toLowerCase(), paramValueAttr);
        BASIC_PARAM_TAG_RULE = new Tag("param", attrs, Policy.ACTION_VALIDATE);

        defaultAllowedEmptyTags = new ArrayList<String>();
        defaultAllowedEmptyTags.addAll(Arrays.asList(allowedEmptyTags));

        defaultRequiresClosingTags = new ArrayList<String>();
        defaultRequiresClosingTags.addAll(Arrays.asList(requiresClosingTags));
    }

    public static final String DEFAULT_LOCALE_LANG = "en";
    public static final String DEFAULT_LOCALE_LOC = "US";

    public static final String big5CharsToEncode = "<>\"'&";
    public static final Set<Integer> big5CharsToEncodeSet = new HashSet<Integer>(){
        {
            for (int i = 0; i <big5CharsToEncode.length(); i++){
                add((int) big5CharsToEncode.charAt(i));
            }
        }
    };

}
