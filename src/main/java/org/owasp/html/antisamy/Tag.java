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
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * A model for HTML "tags" and the rules dictating their validation/filtration. Also contains information
 * about their allowed attributes.
 * <p/>
 * There is also some experimental (unused) code in here for generating a valid regular expression according to a policy
 * file on a per-tag basis.
 *
 * @author Arshan Dabirsiaghi
 */
public class Tag {

    /*
      * These are the fields pulled from the policy XML.
      */
    private final Map<String, Attribute> allowedAttributes;
    private final String name;
    private final String action;


    public Tag(String name, Map<String, Attribute> tagAttributes, String action) {
        this.name = name;
        this.allowedAttributes = Collections.unmodifiableMap(tagAttributes);
        this.action = action;
    }

    /**
     * @return The action for this tag which is one of <code>filter</code>, <code>validate</code> or <code>remove</code>.
     */
    public String getAction() {
        return action;
    }

    /** Indicates if the action for this tag matches the supplied action
     * @param action The action to match against
     * @return True if it matches
     */
    public boolean isAction(String action){
        return action.equals( this.action);
    }

    public Tag mutateAction(String action) {
        return new Tag(this.name, this.allowedAttributes, action);
    }


    /* --------------------------------------------------------------------------------------------------*/


    /**
     * Returns a regular expression for validating individual tags. Not used by the AntiSamy scanner, but you might find some use for this.
     *
     * @return A regular expression for the tag, i.e., "^<b>$", or "<hr(\s)*(width='((\w){2,3}(\%)*)'>"
     */

    public String getRegularExpression() {

        /*
           * For such tags as <b>, <i>, <u>
           */
        if (allowedAttributes.size() == 0) {
            return "^<" + name + ">$";
        }

        StringBuilder regExp = new StringBuilder("<" + ANY_NORMAL_WHITESPACES + name + OPEN_TAG_ATTRIBUTES);

        List<Attribute> values = new ArrayList<Attribute>(allowedAttributes.values());
        Collections.sort(values, new Comparator<Attribute>() {
            public int compare(Attribute o1, Attribute o2) {
                return o1.getName().compareTo(o2.getName());
            }
        } );
        Iterator<Attribute> attributes = values.iterator();
        while (attributes.hasNext()) {
            Attribute attr = attributes.next();
            regExp.append( attr.matcherRegEx(attributes.hasNext()));
        }

        regExp.append(CLOSE_TAG_ATTRIBUTES + ANY_NORMAL_WHITESPACES + ">");

        return regExp.toString();
    }

    static String escapeRegularExpressionCharacters(String allowedValue) {

        String toReturn = allowedValue;

        if (toReturn == null) {
            return null;
        }

        for (int i = 0; i < REGEXP_CHARACTERS.length(); i++) {
            toReturn = toReturn.replaceAll("\\" + String.valueOf(REGEXP_CHARACTERS.charAt(i)), "\\" + REGEXP_CHARACTERS.charAt(i));
        }

        return toReturn;
    }

    /**
     * Begin Variables Needed For Generating Regular Expressions *
     */
    final static String ANY_NORMAL_WHITESPACES = "(\\s)*";
    final static String OPEN_ATTRIBUTE = "(";
    final static String ATTRIBUTE_DIVIDER = "|";
    final static String CLOSE_ATTRIBUTE = ")";
    private final static String OPEN_TAG_ATTRIBUTES = ANY_NORMAL_WHITESPACES + OPEN_ATTRIBUTE;
    private final static String CLOSE_TAG_ATTRIBUTES = ")*";
    private final static String REGEXP_CHARACTERS = "\\(){}.*?$^-+";

    /**
     * @return The String name of the tag.
     */
    public String getName() {
        return name;
    }


    /**
     * Returns an <code>Attribute</code> associated with a lookup name.
     *
     * @param name The name of the allowed attribute by name.
     * @return The <code>Attribute</code> object associated with the name, or
     */
    public Attribute getAttributeByName(String name) {
        return allowedAttributes.get(name);
    }


    /**
     * Returns the allowed attributes.
     */
    public Collection<Attribute> getAllowedAttributes() {
        return allowedAttributes.values();
    }
}
