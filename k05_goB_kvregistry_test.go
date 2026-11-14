package pca

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type goBTxnKv struct {
	AtomicKV
	updErr   error
	updPanic bool
	getFn    func(key string) ([]byte, bool, error)
	getPanic bool
}

func (k goBTxnKv) Update(key string, fn func([]byte) []byte) error {
	if k.updPanic {
		panic("kv")
	}
	if k.updErr != nil {
		return k.updErr
	}
	return k.AtomicKV.Update(key, fn)
}

func (k goBTxnKv) Get(key string) ([]byte, bool, error) {
	if k.getPanic {
		panic("kv")
	}
	if k.getFn != nil {
		return k.getFn(key)
	}
	return k.AtomicKV.Get(key)
}

func TestGoB_KvEncode(t *testing.T) {
	if got := string(kvEncode(map[string]any{"a": 1})); got != `{"a":1}` {
		t.Errorf("encode: %q", got)
	}
	defer func() {
		if r := recover(); r != "pca: the registry state cannot be encoded" {
			t.Errorf("an unencodable state must panic with its message, got %v", r)
		}
	}()
	kvEncode(make(chan int))
	t.Error("kvEncode returned for a state it cannot encode")
}

func TestGoB_KvTxn(t *testing.T) {
	loadOK := func([]byte) error { return nil }
	dump := func() []byte { return []byte(`"written"`) }
	yes := func() bool { return true }

	// fn true: the document is written; fn false: nothing is
	mem := NewMemoryAtomicKV()
	if err := kvTxn(mem, "k", loadOK, yes, dump); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := mem.Get("k"); !ok || string(v) != `"written"` {
		t.Errorf("written: %q %v", v, ok)
	}
	dumped := false
	mem2 := NewMemoryAtomicKV()
	err := kvTxn(mem2, "k", loadOK, func() bool { return false }, func() []byte { dumped = true; return []byte(`"x"`) })
	if err != nil || dumped {
		t.Errorf("fn false must not dump: %v dumped=%v", err, dumped)
	}
	if _, ok, _ := mem2.Get("k"); ok {
		t.Error("fn false must leave the key unwritten")
	}

	// load sees the previous document (nil when there is none), and its error wins: fn does not run, nothing is written
	var seen []byte
	var seenNil bool
	_ = kvTxn(mem, "k", func(prev []byte) error { seen, seenNil = prev, prev == nil; return nil }, func() bool { return false }, dump)
	if string(seen) != `"written"` || seenNil {
		t.Errorf("load saw %q", seen)
	}
	mem3 := NewMemoryAtomicKV()
	_ = kvTxn(mem3, "k", func(prev []byte) error { seenNil = prev == nil; return nil }, func() bool { return false }, dump)
	if !seenNil {
		t.Error("load saw a document for a fresh key")
	}
	loadErr := errors.New("load")
	ran := false
	err = kvTxn(mem3, "k", func([]byte) error { return loadErr }, func() bool { ran = true; return true }, dump)
	if err != loadErr || ran {
		t.Errorf("load error: %v ran=%v", err, ran)
	}
	if _, ok, _ := mem3.Get("k"); ok {
		t.Error("a load error must not write")
	}

	// a store error is returned as it is; the load error is not mistaken for it
	storeErr := errors.New("store")
	if err := kvTxn(goBTxnKv{AtomicKV: mem3, updErr: storeErr}, "k", loadOK, yes, dump); err != storeErr {
		t.Errorf("store error: %v", err)
	}
	if err := kvTxn(mem3, "k", loadOK, yes, dump); err != nil {
		t.Errorf("a clean transaction: %v", err)
	}

	// a store that panics is an error, never a crash
	err = kvTxn(goBTxnKv{AtomicKV: mem3, updPanic: true}, "k", loadOK, yes, dump)
	if err == nil || err.Error() != "pca: the registry store panicked" {
		t.Errorf("panicking store: %v", err)
	}
}

func TestGoB_KvRead(t *testing.T) {
	mem := NewMemoryAtomicKV()
	_ = mem.Update("k", func([]byte) []byte { return []byte(`1`) })
	var got []byte
	capture := func(prev []byte) error { got = prev; return nil }
	if err := kvRead(mem, "k", capture); err != nil || string(got) != `1` {
		t.Errorf("present: %q %v", got, err)
	}
	if err := kvRead(mem, "none", capture); err != nil || got != nil {
		t.Errorf("absent: %q %v", got, err)
	}
	// a store that reports "not found" next to a value still hands load nothing
	junk := goBTxnKv{AtomicKV: mem, getFn: func(string) ([]byte, bool, error) { return []byte("junk"), false, nil }}
	if err := kvRead(junk, "k", capture); err != nil || got != nil {
		t.Errorf("not found beside a value: %q %v", got, err)
	}
	down := errors.New("down")
	if err := kvRead(goBTxnKv{AtomicKV: mem, getFn: func(string) ([]byte, bool, error) { return []byte(`1`), true, down }}, "k", capture); err != down {
		t.Errorf("read error: %v", err)
	}
	loadErr := errors.New("load")
	if err := kvRead(mem, "k", func([]byte) error { return loadErr }); err != loadErr {
		t.Errorf("load error: %v", err)
	}
	if err := kvRead(goBTxnKv{AtomicKV: mem, getPanic: true}, "k", capture); err == nil || err.Error() != "pca: the registry store panicked" {
		t.Errorf("panicking store: %v", err)
	}
}

// RequirePCA in authorize mode with no AuthorizeOptions behaves as a guard with the empty options: it builds, and refuses a
// request that carries no PCActn.
func TestGoB_AuthorizeHandlerWithoutOptions(t *testing.T) {
	called := false
	h := authorizeHandler(RequirePCAOptions{}, func() int64 { return 1 }, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusUnauthorized || called {
		t.Errorf("code %d called=%v", rec.Code, called)
	}
}
