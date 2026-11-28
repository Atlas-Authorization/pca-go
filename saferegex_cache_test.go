package pca

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"unicode/utf16"
)

// Ports of the reference's regex-cache tests: weights, the 1/16 admission bound, the inclusive weight cap with LRU eviction,
// the anonymous source, per-source admission and the injective key. Each test builds its own cache instance.

func rcU(s string) []uint16 { return utf16.Encode([]rune(s)) }

const rcHeavy = RegexCacheMaxWeight / 16

func rcGet(c *regexCacheT, s string, value any, weight float64) any {
	return c.get(rcU(s), nil, func() any { return value }, func(any) float64 { return weight })
}

func TestRegexCacheWeightsAreCeilMinOneAndSummed(t *testing.T) {
	c := newRegexCache(RegexCacheMaxEntries)
	rcGet(c, "a", 1, 100)
	rcGet(c, "b", 2, 2.5)
	rcGet(c, "c", 3, 0)
	rcGet(c, "d", 4, math.NaN())
	st := c.stats()
	if st.Weight != 100+3+1+1 || st.Entries != 4 || st.MaxWeight != 131072 || len(st.Keys) != 4 || st.BySource[""] != 4 || len(st.BySource) != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestRegexCacheAProgramOfExactlyOneSixteenthIsCachedOneHeavierIsNot(t *testing.T) {
	c := newRegexCache(RegexCacheMaxEntries)
	if rcGet(c, "edge", "v", rcHeavy) != "v" || !c.has(rcU("edge")) {
		t.Fatal("edge not cached")
	}
	if rcGet(c, "over", "w", rcHeavy+1) != "w" || c.has(rcU("over")) {
		t.Fatal("over was cached")
	}
	if c.stats().Weight != rcHeavy {
		t.Fatalf("weight %d", c.stats().Weight)
	}
}

func TestRegexCacheWeightCapIsInclusiveAndEvictsLeastRecentlyUsed(t *testing.T) {
	c := newRegexCache(RegexCacheMaxEntries)
	for i := 0; i < 16; i++ {
		rcGet(c, fmt.Sprintf("x%d", i), i, rcHeavy)
	}
	if c.stats().Weight != 16*rcHeavy {
		t.Fatal("not exactly at the cap")
	}
	for i := 0; i < 16; i++ {
		if !c.has(rcU(fmt.Sprintf("x%d", i))) {
			t.Fatalf("x%d evicted at the cap", i)
		}
	}
	if rcGet(c, "x0", "recomputed", rcHeavy) != 0 { // a hit returns the cached value
		t.Fatal("hit recomputed")
	}
	rcGet(c, "x16", 16, rcHeavy)
	if !c.has(rcU("x0")) || c.has(rcU("x1")) || c.stats().Weight != 16*rcHeavy || c.stats().Entries != 16 {
		t.Fatalf("recency not honoured: %+v", c.stats())
	}
}

func TestRegexCacheProviderNullOrPanickingMeansTheAnonymousSource(t *testing.T) {
	c := newRegexCache(RegexCacheMaxEntries)
	c.provider.Store(nil)
	set := func(fn func() (string, bool)) { c.provider.Store(&fn) }
	set(func() (string, bool) { return "", false })
	rcGet(c, "n", 1, 1)
	set(func() (string, bool) { panic("boom") })
	rcGet(c, "t", 1, 1)
	set(func() (string, bool) { return "src-a", true })
	rcGet(c, "s", 1, 1)
	st := c.stats()
	if len(st.BySource) != 2 || st.BySource[""] != 2 || st.BySource["src-a"] != 1 {
		t.Fatalf("bySource %v", st.BySource)
	}
}

func TestRegexCacheASourceWhoseLastEntryIsEvictedDisappears(t *testing.T) {
	c := newRegexCache(RegexCacheMaxEntries)
	set := func(s string) { fn := func() (string, bool) { return s, true }; c.provider.Store(&fn) }
	set("a")
	rcGet(c, "a0", 1, 1)
	set("b")
	for i := 0; i < 16; i++ {
		rcGet(c, fmt.Sprintf("b%d", i), i, rcHeavy)
	}
	st := c.stats()
	if c.has(rcU("a0")) || len(st.BySource) != 1 || st.BySource["b"] != 16 {
		t.Fatalf("bySource %v", st.BySource)
	}
}

func TestRegexCacheAFloodFromOneSourceNeverEvictsAnotherSourcesPattern(t *testing.T) {
	c := newRegexCache(RegexCacheMaxEntries)
	srcOf := func(s string) func() (string, bool) { return func() (string, bool) { return s, true } }
	fn := srcOf("10.0.0.1")
	c.provider.Store(&fn)
	rcGet(c, "victim-[a-z]{1,8}", "hot", 1)
	flood := srcOf("6.6.6.6")
	c.provider.Store(&flood)
	for i := 0; i < 5000; i++ {
		rcGet(c, fmt.Sprintf("abc%dx[0-9]+", i), i, 1)
	}
	if !c.has(rcU("victim-[a-z]{1,8}")) {
		t.Fatal("the other source's hot pattern was evicted")
	}
	if n := c.stats().BySource["6.6.6.6"]; n > RegexCacheMaxPerSource {
		t.Fatalf("flooding source holds %d", n)
	}
}

func TestRegexCacheIsNeverClearedWholesaleAndKeepsRecentlyUsed(t *testing.T) {
	c := newRegexCache(RegexCacheMaxEntries)
	i := 0
	next := func() string { i++; return fmt.Sprintf("abc%dx[0-9]+", i) }
	asSource := func(s string) { fn := func() (string, bool) { return s, true }; c.provider.Store(&fn) }
	for s := 0; s < 40; s++ {
		asSource(fmt.Sprintf("198.51.100.%d", s))
		for j := 0; j < RegexCacheMaxPerSource; j++ {
			rcGet(c, next(), 1, 1)
		}
	}
	if n := c.stats().Entries; n <= RegexCacheMaxEntries/2 || n > RegexCacheMaxEntries {
		t.Fatalf("entries %d", n)
	}
	asSource("203.0.113.1")
	rcGet(c, "keep-me-[0-9]", 1, 1)
	for j := 0; j < 100; j++ {
		asSource(fmt.Sprintf("192.0.2.%d", j))
		rcGet(c, next(), 1, 1)
		asSource("203.0.113.1")
		rcGet(c, "keep-me-[0-9]", 1, 1)
	}
	if !c.has(rcU("keep-me-[0-9]")) {
		t.Fatal("a recently used pattern was evicted")
	}
	for _, k := range c.stats().Keys {
		if len(k) != 64 || strings.Trim(k, "0123456789abcdef") != "" {
			t.Fatalf("key %q is not a sha-256 hex", k)
		}
	}
}

func TestRegexCacheBudgetLookupAndFullMatchUseTheProcessWideCache(t *testing.T) {
	b := NewRequestRegexBudgetFor("10.9.9.9")
	if !b.Charge("budget-[a-z]+", 10) || !RegexCacheHas(rcU("budget-[a-z]+")) {
		t.Fatal("the budget lookup did not use the shared cache")
	}
	if n := RegexCacheStats().BySource["10.9.9.9"]; n < 1 {
		t.Fatalf("the program was not owned by the request's source: %v", RegexCacheStats().BySource)
	}
	if m, ok := safeRegexFullMatch(rcU("lib-[0-9]{2}"), rcU("lib-42")); !ok || !m || !RegexCacheHas(rcU("lib-[0-9]{2}")) {
		t.Fatal("library use is not cached under the anonymous source")
	}
	if _, ok := safeRegexFullMatch(rcU("(a"), rcU("a")); ok {
		t.Fatal("an unsupported pattern must still fail closed")
	}
}

func TestRegexCacheKeyIsInjectiveOverLoneSurrogates(t *testing.T) {
	a, b, c := []uint16{'x', 0xd800}, []uint16{'x', 0xdc00}, []uint16{'x', 0xfffd}
	if regexCacheKey(a) == regexCacheKey(b) || regexCacheKey(a) == regexCacheKey(c) || regexCacheKey(b) == regexCacheKey(c) {
		t.Fatal("distinct sources share a key")
	}
	if m, ok := safeRegexFullMatch(a, a); !ok || !m {
		t.Fatal("lone surrogate source does not match itself")
	}
	if m, ok := safeRegexFullMatch(a, c); !ok || m {
		t.Fatal("lone surrogate source matched U+FFFD")
	}
}
