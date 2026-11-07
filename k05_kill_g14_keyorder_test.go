package pca

import (
	"reflect"
	"runtime"
	"testing"
	"time"
)

// g14: canonical array-index keys, the key-order side table (what is recorded, generation ids, cleanup) and jsKeys' sorted
// fallback.

func TestK05KillG14ArrayIndex(t *testing.T) {
	cases := []struct {
		k  string
		n  uint64
		ok bool
	}{
		{"0", 0, true}, {"", 0, false}, {"00", 0, false}, {"01", 0, false}, {"1", 1, true}, {"10", 10, true}, {"9", 9, true},
		{"1a", 0, false}, {"a1", 0, false}, {"-1", 0, false}, {"+1", 0, false}, {"1_0", 0, false}, {"1 ", 0, false},
		{"1234567890", 1234567890, true}, {"12345678901", 0, false},
		{"4294967294", 4294967294, true}, {"4294967295", 4294967295, false}, {"4294967296", 4294967296, false},
		{"9999999999", 9999999999, false},
	}
	for _, c := range cases {
		if n, ok := jsArrayIndex(c.k); n != c.n || ok != c.ok {
			t.Errorf("jsArrayIndex(%q) = %d %v, want %d %v", c.k, n, ok, c.n, c.ok)
		}
	}
}

func g14koEntry(m map[string]any) (*keyOrderEntry, bool) {
	v, ok := keyOrders.Load(uintptr(reflect.ValueOf(m).UnsafePointer()))
	if !ok {
		return nil, false
	}
	return v.(*keyOrderEntry), true
}

func TestK05KillG14RecordKeyOrder(t *testing.T) {
	// one member: nothing to order, nothing recorded
	one := map[string]any{"a": 1}
	oneKeys := []string{"a"}
	recordKeyOrder(one, oneKeys)
	if e, ok := g14koEntry(one); ok && len(e.keys) == 1 && &e.keys[0] == &oneKeys[0] {
		t.Error("a one-member object was recorded")
	}
	// a nil map has no identity: nothing recorded at address 0
	recordKeyOrder(nil, []string{"a", "b"})
	if _, ok := keyOrders.Load(uintptr(0)); ok {
		keyOrders.Delete(uintptr(0))
		t.Error("a nil map was recorded")
	}
	// two maps get consecutive generation ids, and their text order is used by jsKeys
	m1 := map[string]any{"a": 1, "b": 2}
	m2 := map[string]any{"c": 1, "d": 2}
	recordKeyOrder(m1, []string{"b", "a"})
	recordKeyOrder(m2, []string{"d", "c"})
	e1, ok1 := g14koEntry(m1)
	e2, ok2 := g14koEntry(m2)
	if !ok1 || !ok2 || e1.id == 0 || e2.id != e1.id+1 {
		t.Fatalf("entries: %v %v %+v %+v", ok1, ok2, e1, e2)
	}
	if got := jsKeys(m1); !reflect.DeepEqual(got, []string{"b", "a"}) {
		t.Errorf("jsKeys(recorded) = %v", got)
	}
	runtime.KeepAlive(m1)
	runtime.KeepAlive(m2)
	runtime.KeepAlive(one)
}

func TestK05KillG14KeyOrderCleanup(t *testing.T) {
	var addr uintptr
	var id uint64
	func() {
		m := map[string]any{"x": 1, "y": 2}
		recordKeyOrder(m, []string{"y", "x"})
		addr = uintptr(reflect.ValueOf(m).UnsafePointer())
		e, ok := g14koEntry(m)
		if !ok {
			t.Fatal("not recorded")
		}
		id = e.id
	}()
	ours := func() bool {
		v, ok := keyOrders.Load(addr)
		return ok && v.(*keyOrderEntry).id == id
	}
	// the map is unreachable: a GC queues its cleanup, which removes exactly its own entry
	for deadline := time.Now().Add(10 * time.Second); ours() && time.Now().Before(deadline); {
		runtime.GC()
		for i := 0; i < 100 && ours(); i++ {
			runtime.Gosched()
		}
	}
	if ours() {
		t.Fatal("the entry of a collected map was never removed")
	}
}

func TestK05KillG14JsKeysSorted(t *testing.T) {
	m := map[string]any{"h": 1, "c": 1, "f": 1, "a": 1, "g": 1, "b": 1, "e": 1, "d": 1, "10": 1, "2": 1, "01": 1}
	want := []string{"2", "10", "01", "a", "b", "c", "d", "e", "f", "g", "h"}
	if got := jsKeys(m); !reflect.DeepEqual(got, want) {
		t.Errorf("jsKeys = %v, want %v", got, want)
	}
}
