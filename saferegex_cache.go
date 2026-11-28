package pca

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sync"
	"sync/atomic"
)

// The ONE bounded cache of compiled regex programs (used by the full-match entry point and by the regex budget's program-length
// lookup).
//
//   - keys are the SHA-256 of the pattern source (its UTF-16 code units, 2 bytes each, big-endian: injective over strings; the raw
//     source is not retained as a key);
//   - eviction is least-recently-used, one entry at a time; nothing on any request path clears the cache;
//   - PER-SOURCE ADMISSION: each entry is owned by the source that inserted it (the server supplies the source, its trusted client
//     address, through SetRegexCacheSourceProvider or NewRequestRegexBudgetFor); once a source owns RegexCacheMaxPerSource entries, a
//     new pattern from it evicts that source's OWN least-recently-used entry, so one source cannot flush the cache. (Many sources can
//     still churn the global LRU, but a pattern in use stays most-recently-used.)
//   - a total WEIGHT cap (instructions + character-class ranges) bounds memory, and a single program heavier than 1/16 of it is
//     compiled and used but never cached.
//
// Library use outside any request is the anonymous source "" under the same rules.
const (
	// RegexCacheMaxPerSource is the number of entries one source may own.
	RegexCacheMaxPerSource = 64
	// RegexCacheMaxWeight is the total weight cap of the cache.
	RegexCacheMaxWeight = 131_072
)

type regexCacheEntry struct {
	key, source string
	weight      int
	tick        uint64
	value       any
}

type regexCacheT struct {
	mu         sync.Mutex
	lru        *list.List // front = most recently used
	idx        map[string]*list.Element
	bySource   map[string]map[string]*list.Element
	weight     int
	tick       uint64
	maxEntries int
	provider   atomic.Pointer[func() (string, bool)]
}

func newRegexCache(maxEntries int) *regexCacheT {
	return &regexCacheT{lru: list.New(), idx: map[string]*list.Element{}, bySource: map[string]map[string]*list.Element{}, maxEntries: maxEntries}
}

// regexCache is the process-wide cache.
var regexCache = newRegexCache(RegexCacheMaxEntries)

// SetRegexCacheSourceProvider installs the provider of the CURRENT source (the server's per-request client key); it reports
// ok=false for no source, which is the anonymous source "". A provider that panics also means the anonymous source. nil
// uninstalls it, and the source is then read from the regex budget the lookup is made under (NewRequestRegexBudgetFor).
func SetRegexCacheSourceProvider(fn func() (source string, ok bool)) {
	if fn == nil {
		regexCache.provider.Store(nil)
		return
	}
	regexCache.provider.Store(&fn)
}

// sourceFor is the source a lookup under budget b is charged to.
func (c *regexCacheT) sourceFor(b *regexBudget) (source string) {
	if p := c.provider.Load(); p != nil {
		defer func() {
			if recover() != nil {
				source = ""
			}
		}()
		s, ok := (*p)()
		if !ok {
			return ""
		}
		return s
	}
	for _, start := range []*regexBudget{b, ambientRegexBudget()} { // the budget in hand, then the ambient request budget
		for x := start; x != nil; x = x.parent {
			if x.hasSource {
				return x.source
			}
		}
	}
	return ""
}

func regexCacheKey(src []uint16) string {
	b := make([]byte, 0, 2*len(src))
	for _, u := range src {
		b = append(b, byte(u>>8), byte(u))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (c *regexCacheT) touch(el *list.Element) {
	c.lru.MoveToFront(el)
	c.tick++
	el.Value.(*regexCacheEntry).tick = c.tick
}

func (c *regexCacheT) remove(el *list.Element) {
	e := el.Value.(*regexCacheEntry)
	c.lru.Remove(el)
	delete(c.idx, e.key)
	c.weight -= e.weight
	if owned := c.bySource[e.source]; owned != nil {
		delete(owned, e.key)
		if len(owned) == 0 {
			delete(c.bySource, e.source)
		}
	}
}

// get returns the cached value for the pattern src, computing (and admitting) it on a miss. weigh gives the memory weight of a
// value (>= 1). The compute runs outside the lock.
func (c *regexCacheT) get(src []uint16, b *regexBudget, compute func() any, weigh func(any) float64) any {
	key := regexCacheKey(src)
	c.mu.Lock()
	if el, ok := c.idx[key]; ok {
		c.touch(el)
		v := el.Value.(*regexCacheEntry).value
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()
	source := c.sourceFor(b)
	value := compute()
	wf := math.Ceil(weigh(value))
	if math.IsNaN(wf) || wf < 1 {
		wf = 1
	}
	if wf > RegexCacheMaxWeight/16 {
		return value // too heavy to cache: never evict others for it
	}
	w := int(wf)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[key]; ok { // another caller admitted it meanwhile
		c.touch(el)
		return el.Value.(*regexCacheEntry).value
	}
	// per-source admission: a source at its share replaces its OWN least-recently-used entry
	for owned := c.bySource[source]; len(owned) >= RegexCacheMaxPerSource; owned = c.bySource[source] {
		var oldest *list.Element
		for _, el := range owned {
			if oldest == nil || el.Value.(*regexCacheEntry).tick < oldest.Value.(*regexCacheEntry).tick {
				oldest = el
			}
		}
		c.remove(oldest)
	}
	for c.lru.Len() >= c.maxEntries || c.weight+w > RegexCacheMaxWeight {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.remove(back)
	}
	c.tick++
	el := c.lru.PushFront(&regexCacheEntry{key: key, source: source, weight: w, tick: c.tick, value: value})
	c.idx[key] = el
	c.weight += w
	owned := c.bySource[source]
	if owned == nil {
		owned = map[string]*list.Element{}
		c.bySource[source] = owned
	}
	owned[key] = el
	return value
}

func (c *regexCacheT) has(src []uint16) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.idx[regexCacheKey(src)]
	return ok
}

// RegexCacheOccupancy is the cache occupancy (tests and diagnostics).
type RegexCacheOccupancy struct {
	Entries   int
	Weight    int
	MaxWeight int
	// Keys are the entry keys, least recently used first.
	Keys []string
	// BySource is the number of entries each source owns.
	BySource map[string]int
}

func (c *regexCacheT) stats() RegexCacheOccupancy {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := RegexCacheOccupancy{Entries: c.lru.Len(), Weight: c.weight, MaxWeight: RegexCacheMaxWeight, BySource: map[string]int{}}
	for el := c.lru.Back(); el != nil; el = el.Prev() {
		st.Keys = append(st.Keys, el.Value.(*regexCacheEntry).key)
	}
	for s, owned := range c.bySource {
		st.BySource[s] = len(owned)
	}
	return st
}

// RegexCacheHas reports whether the pattern src is currently cached.
func RegexCacheHas(src []uint16) bool { return regexCache.has(src) }

// RegexCacheStats is the occupancy of the process-wide cache.
func RegexCacheStats() RegexCacheOccupancy { return regexCache.stats() }

// regexProgramWeight is the memory weight of a compiled program: its instructions plus its character-class ranges.
func regexProgramWeight(prog []reInst) float64 {
	if prog == nil {
		return 1
	}
	w := len(prog)
	for _, ins := range prog {
		if ins.set != nil {
			w += len(ins.set.ranges)
		}
	}
	return float64(w)
}

// cachedProgram is compileSafeRegex through the bounded cache, charged to the source of budget b (nil: the provider or the ambient
// request budget). A pattern outside the subset is cached too (nil). The program is shared and must not be modified.
func cachedProgram(src []uint16, b *regexBudget) []reInst {
	v := regexCache.get(src, b, func() any { return compileSafeRegex(src) }, func(v any) float64 { p, _ := v.([]reInst); return regexProgramWeight(p) })
	prog, _ := v.([]reInst)
	return prog
}

// CompileSafeRegexCached is CompileSafeRegex through the bounded, per-source-admitted LRU, never cleared wholesale. A pattern
// outside the subset is cached too (nil). The program is shared between callers and must not be modified.
func CompileSafeRegexCached(src []uint16) []ReInst { return cachedProgram(src, nil) }
