package org.owasp.shim;

import java.util.*;

class ForJava8 extends Java8Shim {
    @Override public <T> List<T> listOf() {
        return ImmutableListShim.empty();
    }

    @Override public <T> List<T> listOf(T a) {
        return new ImmutableListShim<>(Collections.singletonList(a));
    }

    @Override public <T> List<T> listOf(T a, T b) {
        ArrayList<T> ls = new ArrayList<>(2);
        ls.add(a);
        ls.add(b);
        return new ImmutableListShim<>(ls);
    }

    @Override public <T> List<T> listOf(T a, T b, T c) {
        ArrayList<T> ls = new ArrayList<>(3);
        ls.add(a);
        ls.add(b);
        ls.add(c);
        return new ImmutableListShim<>(ls);
    }

    @Override public <T> List<T> listOf(T... els) {
        return new ImmutableListShim<>(Arrays.asList(els));
    }

    @SuppressWarnings("unchecked") // Immutable collections aren't invariant
    @Override public <T> List<T> listCopyOf(Collection<? extends T> c) {
        if (c instanceof ImmutableListShim) {
            return (ImmutableListShim<T>) c;
        }
        return new ImmutableListShim<>(new ArrayList<>(c));
    }

    @SuppressWarnings("unchecked") // Immutable collections aren't invariant
    @Override public <K, V> Map<K, V> mapCopyOf(Map<? extends K, ? extends V> m) {
        if (m instanceof ImmutableMapShim) {
            return (ImmutableMapShim<K, V>) m;
        }
        return new ImmutableMapShim<>(new LinkedHashMap<>(m));
    }

    @Override public <K, V> Map.Entry<K, V> mapEntry(K key, V value) {
        return new ImmutableEntryShim<>(key, value);
    }

    @Override public <K, V> Map<K, V> mapOfEntries(Map.Entry<K, V>... entries) {
        Map<K, V> m = new LinkedHashMap<>(entries.length);
        for (Map.Entry<K, V> e : entries) {
            m.put(e.getKey(), e.getValue());
        }
        return new ImmutableMapShim<>(m);
    }

    @Override public <T> Set<T> setOf() {
        return new ImmutableSetShim<>(Collections.emptySet());
    }

    @Override public <T> Set<T> setOf(T a) {
        return new ImmutableSetShim<>(Collections.singleton(a));
    }

    @Override public <T> Set<T> setOf(T a, T b) {
        LinkedHashSet<T> ls = new LinkedHashSet<>(2);
        ls.add(a);
        ls.add(b);
        return new ImmutableSetShim<>(ls);
    }

    @Override public <T> Set<T> setOf(T a, T b, T c) {
        LinkedHashSet<T> ls = new LinkedHashSet<>(3);
        ls.add(a);
        ls.add(b);
        ls.add(c);
        return new ImmutableSetShim<>(ls);
    }

    @Override public <T> Set<T> setOf(T... els) {
        return new ImmutableSetShim<>(new LinkedHashSet<>(Arrays.asList(els)));
    }

    @SuppressWarnings("unchecked") // Immutable collections aren't invariant
    @Override public <T> Set<T> setCopyOf(Collection<? extends T> c) {
        if (c instanceof ImmutableSetShim) {

            return (ImmutableSetShim<T>) c;
        }
        return new ImmutableSetShim<>(new LinkedHashSet<>(c));
    }

    private static final class ImmutableListShim<T> extends AbstractList<T> {
        private final List<T> underlying;

        ImmutableListShim(List<T> underlying) {
            this.underlying = underlying;
        }

        @Override
        public T get(int index) {
            return underlying.get(index);
        }

        @Override
        public int size() {
            return underlying.size();
        }

        private static final ImmutableListShim<Object> empty = new ImmutableListShim<>(Collections.emptyList());

        @SuppressWarnings("unchecked") // contains no elements of any specific T
        static <T> ImmutableListShim<T> empty() {
            return (ImmutableListShim<T>) empty;
        }
    }

    private static final class ImmutableMapShim<K, V> extends AbstractMap<K, V> {
        private final Map<K, V> underlying;

        ImmutableMapShim(Map<K, V> underlying) {
            this.underlying = underlying;
        }

        @Override
        public V get(Object k) {
            return underlying.get(k);
        }

        @Override
        public boolean containsKey(Object k) {
            return underlying.containsKey(k);
        }

        @Override
        public Set<Entry<K, V>> entrySet() {
            return new ImmutableEntrySetShim<>(underlying.entrySet());
        }
    }

    private static final class ImmutableEntrySetShim<K, V> extends AbstractSet<Map.Entry<K, V>> {
        private final Set<Map.Entry<K, V>> underlying;
        ImmutableEntrySetShim(Set<Map.Entry<K, V>> underlying) {
            this.underlying = underlying;
        }


        @Override
        public Iterator<Map.Entry<K, V>> iterator() {
            class IteratorImpl implements Iterator<Map.Entry<K, V>> {
                private final Iterator<Map.Entry<K, V>> underlying;
                private ImmutableEntryShim<K, V> pending;

                IteratorImpl(Iterator<Map.Entry<K, V>> underlying) {
                    this.underlying = underlying;
                }

                @Override
                public boolean hasNext() {
                    if (pending == null && underlying.hasNext()) {
                        Map.Entry<K, V> e = underlying.next();
                        pending = new ImmutableEntryShim<>(e.getKey(), e.getValue());
                    }
                    return pending != null;
                }

                @Override
                public Map.Entry<K, V> next() {
                    ImmutableEntryShim<K, V> next = pending;
                    pending = null;
                    if (next == null) { throw new NoSuchElementException(); }
                    return next;
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException();
                }
            }
            return new IteratorImpl(underlying.iterator());
        }

        @Override
        public int size() {
            return underlying.size();
        }
    }

    private static final class ImmutableEntryShim<K, V> implements Map.Entry<K, V> {
        private final K key;
        private final V value;
        ImmutableEntryShim(K key, V value) {
            this.key = key;
            this.value = value;
        }

        @Override
        public K getKey() { return key; }

        @Override
        public V getValue() { return value; }

        @Override
        public V setValue(V value) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class ImmutableSetShim<T> extends AbstractSet<T> {
        private final Set<T> underlying;

        ImmutableSetShim(Set<T> underlying) {
            this.underlying = underlying;
        }

        @Override
        public Iterator<T> iterator() {
            class IteratorImpl implements Iterator<T> {
                private final Iterator<T> underlying;
                IteratorImpl(Iterator<T> underlying) {
                    this.underlying = underlying;
                }

                @Override
                public boolean hasNext() {
                    return underlying.hasNext();
                }

                @Override
                public T next() {
                    return underlying.next();
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException();
                }
            }
            return new IteratorImpl(underlying.iterator());
        }

        @Override
        public int size() {
            return underlying.size();
        }

        @Override
        public boolean contains(Object o) {
            return underlying.contains(o);
        }
    }
}
