package org.owasp.shim;

import java.util.*;

@SuppressWarnings("Since15") // We're compiling two versions to handle @since problems.
final class ForJava9AndLater extends Java8Shim {

    @Override public <T> List<T> listOf() {
        return List.of();
    }

    @Override public <T> List<T> listOf(T a) {
        return List.of(a);
    }

    @Override public <T> List<T> listOf(T a, T b) {
        return List.of(a, b);
    }

    @Override public <T> List<T> listOf(T a, T b, T c) {
        return List.of(a, b, c);
    }

    @Override public <T> List<T> listOf(T... els) {
        return List.of(els);
    }

    @Override public <T> List<T> listCopyOf(Collection<? extends T> c) {
        return List.copyOf(c);
    }

    @Override public <K, V> Map<K, V> mapCopyOf(Map<? extends K, ? extends V> m) {
        return Map.copyOf(m);
    }

    @Override public <K, V> Map.Entry<K, V> mapEntry(K key, V value) {
        return Map.entry(key, value);
    }

    @Override public <K, V> Map<K, V> mapOfEntries(Map.Entry<K, V>... entries) {
        return Map.ofEntries(entries);
    }

    @Override public <T> Set<T> setOf() {
        return Set.of();
    }

    @Override public <T> Set<T> setOf(T a) {
        return Set.of(a);
    }

    @Override public <T> Set<T> setOf(T a, T b) {
        return Set.of(a, b);
    }

    @Override public <T> Set<T> setOf(T a, T b, T c) {
        return Set.of(a, b, c);
    }

    @Override public <T> Set<T> setOf(T... els) {
        return Set.of(els);
    }

    @Override public <T> Set<T> setCopyOf(Collection<? extends T> c) {
        return Set.copyOf(c);
    }
}
