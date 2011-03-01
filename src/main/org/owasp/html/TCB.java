package org.owasp.html;

import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

/**
 * Indicates that a program element is in the trusted computing base --
 * there exists a security property that could be violated if this code is not
 * correct.
 */
@Target({
    ElementType.CONSTRUCTOR,
    ElementType.METHOD,
    ElementType.PACKAGE,
    ElementType.TYPE
})
public @interface TCB {
  // No members.
}
