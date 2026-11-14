package pca

// Mutants that only crash on the inputs the rest of the suite happens to reach first (a one-leaf tree, a regex with a prefix, a
// JSON escape), yet terminate with a wrong answer on the inputs below. The test binary runs tests in file-name order and a
// runtime fatal ends it, so these must sort before every other test file: that is what the a0_ name is for.
// The inputs and their order are deliberate: each mutant has to meet an input it terminates on before any it hangs on.

import (
	"bytes"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestRE0KeyOrderForget(t *testing.T) {
	const addr = uintptr(1) // never the address of a map
	defer keyOrders.Delete(addr)
	keyOrders.Store(addr, &keyOrderEntry{id: 7})
	keyOrderForget(keyOrderCleanup{addr: addr, id: 6}) // an older map's cleanup keeps the newer entry
	if _, ok := keyOrders.Load(addr); !ok {
		t.Fatal("an older generation deleted the newer entry")
	}
	keyOrderForget(keyOrderCleanup{addr: addr, id: 7})
	if _, ok := keyOrders.Load(addr); ok {
		t.Fatal("the entry outlived its map")
	}
	keyOrderForget(keyOrderCleanup{addr: addr, id: 7}) // nothing left to delete: a no-op
}

// RFC 6962: the largest power of two below n, as merkle.ts split.
func TestRE0Split(t *testing.T) {
	for _, c := range []struct{ n, want int }{{2, 1}, {3, 2}, {4, 2}, {5, 4}, {8, 4}, {9, 8}} {
		if got := split(c.n); got != c.want {
			t.Fatalf("split(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}

func TestRE0BuildTwoLeaves(t *testing.T) {
	a, b := sha([]byte{1}), sha([]byte{2})
	if got := build([][]byte{a, b}); !bytes.Equal(got, nodeHash(a, b)) {
		t.Fatalf("root of two leaves: %x", got)
	}
}

func TestRE0ProveTwoLeaves(t *testing.T) {
	a, b := sha([]byte{1}), sha([]byte{2})
	var out []any
	prove([][]byte{a, b}, 0, &out)
	if len(out) != 1 {
		t.Fatalf("path of a two-leaf tree: %v", out)
	}
	step := out[0].(map[string]any)
	if step["side"] != "R" || step["hash"] != b64.EncodeToString(b) {
		t.Fatalf("step: %v", step)
	}
}

func reKillMapRoot(hs [][]byte) []byte {
	if len(hs) == 1 {
		return hs[0]
	}
	k := 1
	for k<<1 < len(hs) {
		k <<= 1
	}
	return mapNodeHash(reKillMapRoot(hs[:k]), reKillMapRoot(hs[k:]))
}

// 22 leaves split 16+4+2, so a base case at two leaves never meets a lone leaf; and k overshoots the slice (a panic on this
// goroutine, not endless recursion) both when k doubles on k*1 < n and when k triples.
func TestRE0MapTreeRoot22Leaves(t *testing.T) {
	hs := make([][]byte, 22)
	for i := range hs {
		hs[i] = sha([]byte{byte(i)})
	}
	if got := mapTreeRoot(hs); !bytes.Equal(got, reKillMapRoot(hs)) {
		t.Fatalf("root: %x", got)
	}
}

// revocation.ts expectedSides, leaf to root. Before the one-leaf test: a loop that stops at once on these inputs never ends on that one.
func TestRE0PathShapeFromTheLeaf(t *testing.T) {
	for _, c := range []struct {
		idx, n int
		want   []string
	}{
		{0, 2, []string{"R"}},
		{1, 2, []string{"L"}},
		{0, 3, []string{"R", "R"}},
		{1, 3, []string{"L", "R"}},
		{2, 3, []string{"L"}},
	} {
		if got := pathShape(c.idx, c.n); !slices.Equal(got, c.want) {
			t.Fatalf("pathShape(%d, %d) = %v, want %v", c.idx, c.n, got, c.want)
		}
	}
}

// A one-leaf tree has no siblings whatever the index (revocation.ts expectedSides stops at n === 1).
func TestRE0PathShapeOneLeaf(t *testing.T) {
	if got := pathShape(1, 1); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

// One source per parser branch, with nothing before the branch: a position that moves backwards goes out of range (compile
// refuses) or re-reads a closing bracket, where a longer source would loop for ever. Fatal on the first wrong answer: the later
// sources can hang on the mutants the earlier ones exist for.
func TestRE0RegexParserBranches(t *testing.T) {
	for _, c := range []struct{ src, subject string }{
		{`a`, "a"},
		{`(a)`, "a"},
		{`(?:a)`, "a"},
		{`(a)*`, "aa"},
		{`(a)+`, "a"},
		{`(a)?`, ""},
		{`a{2}`, "aa"},
		{`|a`, "a"},
		{`.`, "a"},
		{`^a`, "a"},
		{`$`, ""},
		{`\x41`, "A"},
		{`\u0041`, "A"},
		{`[a]`, "a"},
	} {
		prog := compileSafeRegex(utf16Units(c.src))
		if prog == nil {
			t.Fatalf("%s did not compile", c.src)
		}
		if m, ok := runSafeRegex(prog, utf16Units(c.subject)); !ok || !m {
			t.Fatalf("%s on %q: matched %v, ok %v", c.src, c.subject, m, ok)
		}
	}
}

// Sixteen empty-string paths lead to x. The visited mark keeps one; without it they overflow the thread list.
func TestRE0RegexVisitedMark(t *testing.T) {
	prog := compileSafeRegex(utf16Units(`(?:|)(?:|)(?:|)(?:|)x`))
	if prog == nil {
		t.Fatal("did not compile")
	}
	if m, ok := runSafeRegex(prog, utf16Units("x")); !ok || !m {
		t.Fatalf("matched %v, ok %v", m, ok)
	}
}

// The letter before the escape makes a wrong re-read an unknown escape instead of an endless loop, and \u leaves the
// position inside the digits instead of on the backslash.
func TestRE0StrictJSONEscape(t *testing.T) {
	v, err := parseJSON(`"a\u0041"`, true)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := v.(string); !ok || s != "aA" {
		t.Fatalf("got %#v", v)
	}
}

// The child at offset 2 is unreadable; offset 0 holds a readable parent, so a kid list that restarts from 0 ends instead of looping.
func TestRE0OcspKidsChildError(t *testing.T) {
	b := []byte{0x30, 0x02, 0xFF, 0x00}
	kids, err := ocspKids(b, ocspNode{tag: 0x30, hdr: 0, start: 2, end: 4})
	if err == nil || err.Error() != "multi-byte tags are not supported" || kids != nil {
		t.Fatalf("kids %v, err %v", kids, err)
	}
}

// re0NeedsLock: call must wait while someone else holds mu. A call that lost its Lock runs through instead, and its own Unlock
// releases the lock taken here, so there is no unlock of an unlocked mutex and the test fails normally.
func re0NeedsLock(t *testing.T, mu *sync.Mutex, call func()) {
	t.Helper()
	mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		call()
	}()
	select {
	case <-done:
		t.Fatal("the call finished while another holder had the lock")
	case <-time.After(200 * time.Millisecond):
	}
	mu.Unlock()
	<-done
}

// These run before every other caller of the same code: with the Lock gone, a call on a free mutex is an unrecoverable fatal.
func TestRE0AtomicKVTakesItsLock(t *testing.T) {
	kv := NewMemoryAtomicKV()
	re0NeedsLock(t, &kv.mu, func() { _, _, _ = kv.Get("k") })
	re0NeedsLock(t, &kv.mu, func() { _ = kv.Update("k", func([]byte) []byte { return nil }) })
}

func TestRE0LeaseRegistryTakesItsLock(t *testing.T) {
	k := newKey(t)
	reg := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}}, MemoryLeaseKv())
	lease := g04SignLease(t, k, g04Lease())
	rev := g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})
	re0NeedsLock(t, &reg.mu, func() { reg.Accept(lease, nil) })
	re0NeedsLock(t, &reg.mu, func() { reg.Revoke(rev) })
	re0NeedsLock(t, &reg.mu, func() { _, _, _ = reg.lookup("L1") })
	re0NeedsLock(t, &reg.mu, func() { reg.Get("L1") })
}

// OnCounter ends the call before signing: the agent needs no key, and the lock it would still hold belongs to this test alone.
func TestRE0AgentCounterTakesItsLock(t *testing.T) {
	a := &Agent{OnCounter: func(int64) { runtime.Goexit() }}
	re0NeedsLock(t, &a.mu, func() { _, _ = a.Act("v", "/r", nil, nil) })
}

func TestRELeaseGetUnknownIsNil(t *testing.T) {
	if got := NewLeaseRegistry(LeasePolicy{}, MemoryLeaseKv()).Get("never-accepted"); got != nil {
		t.Fatalf("got %v", got)
	}
}
