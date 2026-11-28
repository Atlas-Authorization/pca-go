package pca

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Durable state of the lease, break-glass and blueprint registries. Each registry keeps its state as JSON documents in an AtomicKV
// (the same atomic key/value seam the operation records use), so a restart or a second instance sees the same revocations,
// uses and epochs. The constructors REQUIRE a kv: a process-local default would forget a revocation on restart. A kv that is
// local to the process exists only under an explicit name (MemoryLeaseKv, MemoryBreakGlassKv, MemoryBlueprintKv).
// Every mutation runs inside one kv.Update, so it is atomic across goroutines, processes and nodes; a kv error is reported as
// `store_unreachable` (never as an allow).

// MemoryLeaseKv is the process-local kv for tests and single-process use (the reference memoryLeaseKv()).
func MemoryLeaseKv() AtomicKV { return NewMemoryAtomicKV() }

// MemoryBreakGlassKv is the process-local kv for tests and single-process use.
func MemoryBreakGlassKv() AtomicKV { return NewMemoryAtomicKV() }

// MemoryBlueprintKv is the process-local kv for tests and single-process use.
func MemoryBlueprintKv() AtomicKV { return NewMemoryAtomicKV() }

// errStoreState is a stored document that does not decode: the store is treated as unreachable (fail closed).
var errStoreState = errors.New("pca: stored registry state is unreadable")

// kvDecode reads one JSON document with numbers kept as json.Number (the form records are verified in).
func kvDecode(b []byte, into any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(into); err != nil {
		return errStoreState
	}
	return nil
}

func kvEncode(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("pca: the registry state cannot be encoded") // kvTxn turns it into store_unreachable: never an allow on state that was not written
	}
	return b
}

// kvTxn runs fn on the document under key inside one kv.Update. load decodes the previous document (nil: none) into the
// working state; fn mutates it and returns whether to persist; dump encodes it. A document that does not decode, or a panic of
// the kv, is an error.
func kvTxn(kv AtomicKV, key string, load func(prev []byte) error, fn func() bool, dump func() []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("pca: the registry store panicked")
		}
	}()
	var loadErr error
	if uerr := kv.Update(key, func(prev []byte) []byte {
		if loadErr = load(prev); loadErr != nil {
			return nil
		}
		if !fn() {
			return nil
		}
		return dump()
	}); uerr != nil {
		return uerr
	}
	return loadErr
}

// kvRead loads the document under key into the working state.
func kvRead(kv AtomicKV, key string, load func(prev []byte) error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("pca: the registry store panicked")
		}
	}()
	v, ok, gerr := kv.Get(key)
	if gerr != nil {
		return gerr
	}
	if !ok {
		v = nil
	}
	return load(v)
}
