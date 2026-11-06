package pca

import (
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

// Key order of parsed JSON objects. A Go map has no insertion order, but the reference (JavaScript) reports the FIRST of several
// simultaneous violations of an object in `Object.keys` order. The package's own parsers (StrictParse, ParseJSON,
// ParseJSONLenient) therefore record the text order of every object with two or more members in a side table keyed by the map's
// identity; an entry lives exactly as long as its map (runtime.AddCleanup, with a generation id so a recycled address can never
// delete a newer entry). A map that did not come from these parsers (or was changed afterwards) has no usable entry and its keys
// are taken in sorted order. jsKeys applies JavaScript's rule on top: canonical array-index keys first, ascending.

type keyOrderEntry struct {
	id   uint64
	keys []string
}

var (
	keyOrders   sync.Map // uintptr (the map's identity) -> *keyOrderEntry
	keyOrderSeq atomic.Uint64
)

type keyOrderCleanup struct {
	addr uintptr
	id   uint64
}

// recordKeyOrder remembers the text order of m's members. Best effort: any failure only loses the order.
func recordKeyOrder(m map[string]any, keys []string) {
	if len(keys) < 2 {
		return
	}
	defer func() { _ = recover() }()
	p := reflect.ValueOf(m).UnsafePointer()
	if p == nil {
		return
	}
	addr := uintptr(p)
	id := keyOrderSeq.Add(1)
	keyOrders.Store(addr, &keyOrderEntry{id: id, keys: keys})
	runtime.AddCleanup((*byte)(p), keyOrderForget, keyOrderCleanup{addr: addr, id: id})
}

// keyOrderForget drops the entry of a collected map, unless a newer map already took over the address.
func keyOrderForget(c keyOrderCleanup) {
	if v, ok := keyOrders.Load(c.addr); ok && v.(*keyOrderEntry).id == c.id {
		keyOrders.CompareAndDelete(c.addr, v)
	}
}

// jsArrayIndex reports whether k is a canonical array index (JavaScript orders such keys first, ascending).
func jsArrayIndex(k string) (uint64, bool) {
	if k == "0" {
		return 0, true
	}
	if k == "" || len(k) > 10 || k[0] == '0' {
		return 0, false
	}
	// base 10 ParseUint accepts digits only (no sign, no '_'): any other byte is ErrSyntax with n = 0, i.e. (0, false)
	n, err := strconv.ParseUint(k, 10, 64)
	return n, err == nil && n < 4294967295
}

// jsKeys is `Object.keys(m)` of the JSON value m was parsed from (see the note above).
func jsKeys(m map[string]any) []string {
	var keys []string
	if v, ok := keyOrders.Load(uintptr(reflect.ValueOf(m).UnsafePointer())); ok {
		e := v.(*keyOrderEntry)
		same := len(e.keys) == len(m)
		for _, k := range e.keys {
			if _, has := m[k]; !has {
				same = false
				break
			}
		}
		if same {
			keys = e.keys
		}
	}
	if keys == nil {
		keys = make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	idx := []string{}
	rest := []string{}
	for _, k := range keys {
		if _, ok := jsArrayIndex(k); ok {
			idx = append(idx, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.Slice(idx, func(i, j int) bool {
		a, _ := jsArrayIndex(idx[i])
		b, _ := jsArrayIndex(idx[j])
		return a < b
	})
	return append(idx, rest...)
}
