package pca

// Conformance cases for a RevocationStore. Run them against your own store:
//
//	for _, c := range pca.RevocationStoreCases(func() (pca.RevocationStore, error) { return open() }, nil) {
//		t.Run(c.Name, func(t *testing.T) { if err := c.Run(); err != nil { t.Fatal(err) } })
//	}
//
// Each case returns an error when the store breaks the contract. A store that passes keeps (kind, value) keys apart, replaces rather
// than duplicates, hands out snapshots, and loses nothing under interleaved writes. Durability across a restart is checked with
// reopen.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RevocationStoreCase is one named check.
type RevocationStoreCase struct {
	Name string
	Run  func() error
}

func rsEntry(kind, value string, extra map[string]any) RevocationEntry {
	e := RevocationEntry{"kind": kind, "value": value, "reason": "r-" + kind + "-" + value, "revokedAt": float64(1000)}
	if kind == "prefix" {
		p := []any{}
		for _, s := range strings.Split(value, ",") {
			p = append(p, s)
		}
		e["prefix"] = p
	}
	for k, v := range extra {
		e[k] = v
	}
	return e
}

func rsJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func rsSortedJSON(es []RevocationEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = rsJSON(e)
	}
	sort.Strings(out)
	return out
}

func rsValues(es []RevocationEntry) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, fmt.Sprint(e["value"]))
	}
	sort.Strings(out)
	return out
}

func rsCheck(cond bool, format string, args ...any) error {
	if cond {
		return nil
	}
	return fmt.Errorf(format, args...)
}

// RevocationStoreCases returns the cases. newStore returns a fresh, empty store each call. For a store that persists, reopen returns a
// store over the same backing location as previous; nil skips the durability case.
func RevocationStoreCases(newStore func() (RevocationStore, error), reopen func(previous RevocationStore) (RevocationStore, error)) []RevocationStoreCase {
	all := func(s RevocationStore) []RevocationEntry { es, _ := s.All(); return es }
	cases := []RevocationStoreCase{
		{"starts empty", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			if n := len(all(s)); n != 0 {
				return fmt.Errorf("a new store holds %d entries", n)
			}
			e, err := s.Get("cap", "x")
			return rsCheck(e == nil && err == nil, "a new store returned an entry or an error: %v %v", e, err)
		}},
		{"add then get returns the whole entry, including notBefore", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			e := rsEntry("cap", "c1", map[string]any{"notBefore": float64(5000)})
			if err := s.Add(e); err != nil {
				return err
			}
			got, err := s.Get("cap", "c1")
			return rsCheck(err == nil && rsJSON(got) == rsJSON(e), "got %s want %s (%v)", rsJSON(got), rsJSON(e), err)
		}},
		{"the same value under different kinds is kept apart", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			for _, k := range []string{"cap", "holder", "issuer"} {
				if err := s.Add(rsEntry(k, "k", nil)); err != nil {
					return err
				}
			}
			if n := len(all(s)); n != 3 {
				return fmt.Errorf("%d entries for 3 kinds", n)
			}
			if ok, err := s.Remove("holder", "k"); err != nil || !ok {
				return fmt.Errorf("remove holder/k: %v %v", ok, err)
			}
			c, _ := s.Get("cap", "k")
			i, _ := s.Get("issuer", "k")
			h, _ := s.Get("holder", "k")
			return rsCheck(c != nil && c["kind"] == "cap" && i != nil && i["kind"] == "issuer" && h == nil, "a removal crossed kinds")
		}},
		{"add at an existing key replaces, it does not duplicate", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			_ = s.Add(rsEntry("cap", "c", map[string]any{"reason": "first"}))
			_ = s.Add(rsEntry("cap", "c", map[string]any{"reason": "second"}))
			g, _ := s.Get("cap", "c")
			return rsCheck(len(all(s)) == 1 && g != nil && g["reason"] == "second", "%d entries, reason %v", len(all(s)), g["reason"])
		}},
		{"remove reports whether something was removed, and only once", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			_ = s.Add(rsEntry("cap", "c", nil))
			a, _ := s.Remove("cap", "c")
			b, _ := s.Remove("cap", "c")
			c, _ := s.Remove("cap", "never-added")
			return rsCheck(a && !b && !c, "remove results %v %v %v (want true false false)", a, b, c)
		}},
		{"prefix paths that differ stay distinct", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			for _, v := range []string{"a,b", "a", "b,a"} {
				_ = s.Add(rsEntry("prefix", v, nil))
			}
			if n := len(all(s)); n != 3 {
				return fmt.Errorf("%d entries for 3 distinct paths", n)
			}
			if ok, _ := s.Remove("prefix", "a"); !ok {
				return fmt.Errorf("remove prefix a failed")
			}
			return rsCheck(strings.Join(rsValues(all(s)), "|") == "a,b|b,a", "left %v", rsValues(all(s)))
		}},
		{"All() is a snapshot: changing it does not change the store", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			_ = s.Add(rsEntry("cap", "c", nil))
			snap := all(s)
			snap = append(snap[:0], rsEntry("cap", "forged", nil))
			_ = snap
			g, _ := s.Get("cap", "forged")
			return rsCheck(len(all(s)) == 1 && g == nil, "the snapshot is the live list")
		}},
		{"clear drops everything", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			_ = s.Add(rsEntry("cap", "c", nil))
			_ = s.Add(rsEntry("prefix", "a,b", nil))
			if err := s.Clear(); err != nil {
				return err
			}
			g, _ := s.Get("cap", "c")
			return rsCheck(len(all(s)) == 0 && g == nil, "clear left entries behind")
		}},
		{"interleaved adds and removes from many goroutines lose nothing", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			const n = 200
			var wg sync.WaitGroup
			errs := make(chan error, n)
			added := make([]chan struct{}, n/2) // an odd goroutine removes its even neighbour only once that one is added
			for i := range added {
				added[i] = make(chan struct{})
			}
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					if err := s.Add(rsEntry("cap", fmt.Sprintf("c%d", i), nil)); err != nil {
						errs <- err
						if i%2 == 0 {
							close(added[i/2])
						}
						return
					}
					if i%2 == 0 {
						close(added[i/2])
					}
					if i%2 == 1 {
						<-added[i/2]
						if _, err := s.Remove("cap", fmt.Sprintf("c%d", i-1)); err != nil {
							errs <- err
						}
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			if err := <-errs; err != nil {
				return err
			}
			left := map[string]bool{}
			for _, e := range all(s) {
				left[fmt.Sprint(e["value"])] = true
			}
			if len(left) != n/2 {
				return fmt.Errorf("%d entries left, want %d", len(left), n/2)
			}
			for i := 0; i < n; i++ {
				if left[fmt.Sprintf("c%d", i)] != (i%2 == 1) {
					return fmt.Errorf("c%d: present=%v, want %v", i, left[fmt.Sprintf("c%d", i)], i%2 == 1)
				}
			}
			return nil
		}},
	}
	if reopen != nil {
		cases = append(cases, RevocationStoreCase{"entries survive reopening the store", func() error {
			s, err := newStore()
			if err != nil {
				return err
			}
			a := rsEntry("cap", "durable", map[string]any{"notBefore": float64(9000)})
			b := rsEntry("prefix", "r,m", nil)
			_ = s.Add(a)
			_ = s.Add(b)
			_ = s.Add(rsEntry("holder", "gone", nil))
			_, _ = s.Remove("holder", "gone")
			again, err := reopen(s)
			if err != nil {
				return err
			}
			got, want := rsSortedJSON(all(again)), rsSortedJSON([]RevocationEntry{a, b})
			return rsCheck(strings.Join(got, "\n") == strings.Join(want, "\n"), "after reopen: %v want %v", got, want)
		}})
	}
	return cases
}
