package org.owasp.html;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OptgroupBugTest {
    
    /**
     * Test that optgroup elements inside select are not corrupted with extra select tags.
     * 
     * Before fix: <select><optgroup><select><option></option></select></optgroup></select>
     * After fix:  <select><optgroup><option></option></optgroup></select>
     */
    @Test
    void testOptgroupInsideSelectDoesNotAddExtraSelectTags() {
        PolicyFactory factory = new HtmlPolicyBuilder()
            .allowElements("select", "optgroup", "option")
            .allowAttributes("label").globally()
            .toFactory();
        
        String input = "<select><optgroup label=\"mygroup\"><option>My option</option></optgroup></select>";
        String result = factory.sanitize(input);
        
        // The key assertion: no extra select tags should be inserted
        assertEquals(input, result);
    }
}