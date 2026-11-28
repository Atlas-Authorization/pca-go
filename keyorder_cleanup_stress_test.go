package pca

import (
	"reflect"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

// The key-order table under GC pressure: concurrent parses, a ring of maps kept alive, forced collections in between. A cleanup
// that ran for a still-reachable map (or a corrupted table) shows up as a live map losing its text order or as a fault here; a
// cleanup that never runs shows up as entries of dropped maps that outlive the final collections.
func TestKeyOrderCleanupStress(t *testing.T) {
	const workers, rounds, ring = 4, 3000, 64
	text := `{"z":1,"a":{"q":1,"b":2,"c":[{"y":1,"x":2}]},"m":3}`
	type rec struct {
		addr uintptr
		id   uint64
	}
	var mu sync.Mutex
	var dropped []rec
	check := func(m map[string]any) bool {
		inner := m["a"].(map[string]any)
		leaf := inner["c"].([]any)[0].(map[string]any)
		return slices.Equal(jsKeys(m), []string{"z", "a", "m"}) && slices.Equal(jsKeys(inner), []string{"q", "b", "c"}) &&
			slices.Equal(jsKeys(leaf), []string{"y", "x"})
	}
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			live := make([]map[string]any, ring)
			for i := 0; i < rounds; i++ {
				v, err := StrictParse(text)
				if err != nil {
					errs <- err.Error()
					return
				}
				m := v.(map[string]any)
				if old := live[i%ring]; old != nil && i%50 == 0 {
					if e, ok := g14koEntry(old); ok {
						mu.Lock()
						dropped = append(dropped, rec{uintptr(reflect.ValueOf(old).UnsafePointer()), e.id})
						mu.Unlock()
					}
				}
				live[i%ring] = m
				if i%200 == 0 {
					runtime.GC()
				}
				if i%10 == 0 {
					for _, l := range live {
						if l != nil && !check(l) {
							errs <- "a live map lost its key order"
							return
						}
					}
				}
			}
			for _, l := range live {
				if l != nil && !check(l) {
					errs <- "a live map lost its key order after the run"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if len(dropped) == 0 {
		t.Fatal("no entries were sampled")
	}
	pending := func() int {
		n := 0
		for _, r := range dropped {
			if v, ok := keyOrders.Load(r.addr); ok && v.(*keyOrderEntry).id == r.id {
				n++
			}
		}
		return n
	}
	for deadline := time.Now().Add(20 * time.Second); pending() > 0 && time.Now().Before(deadline); {
		runtime.GC()
		for i := 0; i < 100 && pending() > 0; i++ {
			runtime.Gosched()
		}
	}
	if n := pending(); n > 0 {
		t.Fatalf("%d of %d entries of collected maps were never removed", n, len(dropped))
	}
}
