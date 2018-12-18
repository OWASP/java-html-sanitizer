/*
 * Copyright (c) 2007-2013, Arshan Dabirsiaghi, Jason Li, Kristian Rosenvold
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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static org.owasp.html.antisamy.Tag.ANY_NORMAL_WHITESPACES;
import static org.owasp.html.antisamy.Tag.ATTRIBUTE_DIVIDER;
import static org.owasp.html.antisamy.Tag.CLOSE_ATTRIBUTE;

/**
 * A model for HTML attributes and the "rules" they must follow (either literals or regular expressions) in
 * order to be considered valid.
 *
 * @author Arshan Dabirsiaghi
 * @author Kristian Rosenvold
 *
 */

public class Attribute  {

  private final String name;
  private final String description;
  private final String onInvalid;
    private final List<String> allowedValues;
    private final Pattern[] allowedRegExps;
    private final Set<String> allowedValuesLower;

    public Attribute(String name, List<Pattern> allowedRegexps, List<String> allowedValues, String onInvalidStr, String description) {
        this.name = name;
        this.allowedRegExps = allowedRegexps.toArray(new Pattern[ allowedRegexps.size()]);
        this.allowedValues = Collections.unmodifiableList( allowedValues);
        Set<String> allowedValuesLower = new HashSet<String>();
        for (String allowedValue : allowedValues) {
            allowedValuesLower.add( allowedValue.toLowerCase());
        }

        this.allowedValuesLower = allowedValuesLower;
        this.onInvalid = onInvalidStr;
        this.description = description;
    }

    public boolean matchesAllowedExpression(String value){
        String input = value.toLowerCase();
        for (Pattern pattern : allowedRegExps) {
            if (pattern != null && pattern.matcher(input).matches()) {
                return true;
            }
        }
        return false;
    }

    public boolean containsAllowedValue(String valueInLowerCase){
        return allowedValuesLower.contains(valueInLowerCase);
    }

  public String getName() {
    return name;
  }

    /**
   *
   * @return The <code>onInvalid</code> value a tag could have, from the list of "filterTag", "removeTag" and "removeAttribute"
   */
  public String getOnInvalid() {
    return onInvalid;
  }


    public Attribute mutate(String onInvalid, String description)  {
        return new Attribute(name, Arrays.asList(allowedRegExps), allowedValues, onInvalid != null && onInvalid.length() != 0 ? onInvalid : this.onInvalid,
                description != null && description.length() != 0 ? description : this.description);
    }

    public String matcherRegEx(boolean hasNext){
        // <p (id=#([0-9.*{6})|sdf).*>

        StringBuilder regExp = new StringBuilder();
        regExp.append(this.getName()).append(ANY_NORMAL_WHITESPACES).append("=").append(ANY_NORMAL_WHITESPACES).append("\"").append(Tag.OPEN_ATTRIBUTE);

        boolean hasRegExps = allowedRegExps.length > 0;

        if (allowedRegExps.length + allowedValues.size() > 0) {

            /*
            * Go through and add static values to the regular expression.
            */
            Iterator<String> allowedValues = this.allowedValues.iterator();
            while (allowedValues.hasNext()) {
                String allowedValue = (String) allowedValues.next();

                regExp.append(Tag.escapeRegularExpressionCharacters(allowedValue));

                if (allowedValues.hasNext() || hasRegExps) {
                    regExp.append(ATTRIBUTE_DIVIDER);
                }
            }

            /*
            * Add the regular expressions for this attribute value to the mother regular expression.
            */
            Iterator<Pattern> allowedRegExps = Arrays.asList((Pattern[]) this.allowedRegExps).iterator();
            while (allowedRegExps.hasNext()) {
                Pattern allowedRegExp = (Pattern) allowedRegExps.next();
                regExp.append(allowedRegExp.pattern());

                if (allowedRegExps.hasNext()) {
                    regExp.append(ATTRIBUTE_DIVIDER);
                }
            }

            if (this.allowedRegExps.length + this.allowedValues.size() > 0) {
                regExp.append(CLOSE_ATTRIBUTE);
            }

            regExp.append("\"" + ANY_NORMAL_WHITESPACES);

            if (hasNext) {
                regExp.append(ATTRIBUTE_DIVIDER);
            }
        }
        return regExp.toString();

    }
}
