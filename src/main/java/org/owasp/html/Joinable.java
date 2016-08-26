package org.owasp.html;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

/**
 * Something that can request special joining.
 * If two or more things have the same (per equals/hashCode) joinStrategy
 * then they will be grouped together for joining according to that strategy.
 */
interface Joinable<T> {
  Joinable.JoinStrategy<T> getJoinStrategy();

  /**
   * An n-ary function from T to a joined T.
   */
  interface JoinStrategy<T> {
    /** Joins toJoin into a single T. */
    T join(Iterable<? extends T> toJoin);

    /**
     * Must be hashable so that special joinables can be grouped by strategy.
     */
    boolean equals(Object o);

    /**
     * Must be hashable so that special joinables can be grouped by strategy.
     */
    int hashCode();
  }



  static abstract class JoinHelper<T, SJ extends Joinable<SJ>> {

    final Class<T> baseType;
    final Class<SJ> specialJoinableType;
    final T zeroValue;
    final T identityValue;
    private Map<JoinStrategy<SJ>, Set<SJ>> requireSpecialJoining;
    private Set<T> uniq = new LinkedHashSet<T>();

    JoinHelper(
        Class<T> baseType,
        Class<SJ> specialJoinableType,
        T zeroValue,
        T identityValue) {
      this.baseType = baseType;
      this.specialJoinableType = specialJoinableType;
      this.zeroValue = Preconditions.checkNotNull(zeroValue);
      this.identityValue = Preconditions.checkNotNull(identityValue);
    }

    abstract Optional<? extends Iterable<? extends T>> split(T x);

    abstract T rejoin(Set<? extends T> xs);

    void unroll(T x) {
      Optional<? extends Iterable<? extends T>> splitX = split(x);
      if (splitX.isPresent()) {
        for (T part : splitX.get()) {
          unroll(part);
        }
      } else if (specialJoinableType.isInstance(x)) {
        // We shouldn't implement special joinable for AttributePolicies
        // without implementing the properly parameterized variant.
        SJ sj = specialJoinableType.cast(x);

        JoinStrategy<SJ> strategy = sj.getJoinStrategy();

        if (requireSpecialJoining == null) {
          requireSpecialJoining = Maps.newLinkedHashMap();
        }
        Set<SJ> toJoinTogether = requireSpecialJoining.get(strategy);
        if (toJoinTogether == null) {
          toJoinTogether = Sets.newLinkedHashSet();
          requireSpecialJoining.put(strategy, toJoinTogether);
        }

        toJoinTogether.add(sj);
      } else {
        uniq.add(Preconditions.checkNotNull(x));
      }
    }

    T join() {
      if (uniq.contains(zeroValue)) {
        return zeroValue;
      }

      if (requireSpecialJoining != null) {
        Iterator<Map.Entry<JoinStrategy<SJ>, Set<SJ>>> entryIterator
            = requireSpecialJoining.entrySet().iterator();
        while (entryIterator.hasNext()) {
          Map.Entry<JoinStrategy<SJ>, Set<SJ>> e
              = entryIterator.next();

          JoinStrategy<SJ> strategy = e.getKey();
          Set<SJ> toJoin = e.getValue();

          entryIterator.remove();

          SJ joined = toJoin.size() == 1
              ? toJoin.iterator().next()
              : strategy.join(toJoin);

          uniq.add(Preconditions.checkNotNull(baseType.cast(joined)));
        }
      }

      uniq.remove(identityValue);

      switch (uniq.size()) {
        case 0:  return identityValue;
        case 1:  return uniq.iterator().next();
        default: return rejoin(uniq);
      }
    }
  }

}