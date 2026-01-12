package org.owasp.shim;

import java.util.*;

/**
 * Static adapters for Java 9 APIs that we need to support on Java 8.
 */
@SuppressWarnings("JavadocReference")
public abstract class Java8Shim {
    /** Statically import this and do `j8.listOf(...)`. */
    public static Java8Shim j8() { return instance; }

    Java8Shim() {} // Not public so there can only be one instance loaded below.

    private static final Java8Shim instance;
    static {
        Object _instance;
        try {
            try {
                // This is compiled with -release 1.10 in a separate project.
                _instance = Class.forName("org.owasp.shim.ForJava10AndLater").newInstance();
            } catch (Error e) {
                // This is co-located with this project and is a fall-back.
                _instance = Class.forName("org.owasp.shim.ForJava8").newInstance();
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new Error(e);
        }
        instance = (Java8Shim) _instance;
    }

    /**
     * {@link java.util.List.of}
     */
    public abstract <T> List<T> listOf();

    /**
     * {@link java.util.List.of}
     */
    public abstract <T> List<T> listOf(T a);

    /**
     * {@link java.util.List.of}
     */
    public abstract <T> List<T> listOf(T a, T b);

    /**
     * {@link java.util.List.of}
     */
    public abstract <T> List<T> listOf(T a, T b, T c);

    /**
     * {@link java.util.List.of}
     */
    public abstract <T> List<T> listOf(T... els);

    /**
     * {@link java.util.List.copyOf}
     */
    public abstract <T> List<T> listCopyOf(Collection<? extends T> c);

    /**
     * {@link java.util.Map.copyOf}
     */
    public abstract <K, V> Map<K, V> mapCopyOf(Map<? extends K, ? extends V> m);

    /**
     * {@link java.util.Map.entry}
     */
    public abstract <K, V> Map.Entry<K, V> mapEntry(K key, V value);

    /**
     * {@link java.util.Map.ofEntries}
     */
    public abstract <K, V> Map<K, V> mapOfEntries(Map.Entry<K, V>... entries);

    /**
     * {@link java.util.Set.of}
     */
    public abstract <T> Set<T> setOf();

    /**
     * {@link java.util.Set.of}
     */
    public abstract <T> Set<T> setOf(T a);

    /**
     * {@link java.util.Set.of}
     */
    public abstract <T> Set<T> setOf(T a, T b);

    /**
     * {@link java.util.Set.of}
     */
    public abstract <T> Set<T> setOf(T a, T b, T c);

    /**
     * {@link java.util.Set.of}
     */
    public abstract <T> Set<T> setOf(T... els);

    /**
     * {@link java.util.Set.copyOf}
     */
    public abstract <T> Set<T> setCopyOf(Collection<? extends T> c);
}
