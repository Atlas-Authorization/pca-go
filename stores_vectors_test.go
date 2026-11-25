package pca

import (
	"encoding/json"
	"errors"
	"testing"
)

// Replay of the durable ledger store and the checkpoint-verified stored ledger against the reference (the ledgerStore and
// storedLedger sections of ref-core-stores-java). Every op answers its value or {"$err": code}.

func stScript(ops any, f func(op []any) (any, error)) []any {
	out := []any{}
	for _, o := range ops.([]any) {
		op := o.([]any)
		v, err := func() (v any, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("panic")
				}
			}()
			return f(op)
		}()
		if err != nil {
			out = append(out, map[string]any{"$err": StoreErrorCode(err)})
		} else {
			out = append(out, v)
		}
	}
	return out
}

func stKvSet(kv *MemoryAtomicKV, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return kv.Update(key, func([]byte) []byte { return b })
}

func stKvGet(kv *MemoryAtomicKV, key string) (any, error) {
	raw, ok, err := kv.Get(key)
	if err != nil || !ok {
		return nil, err
	}
	return ParseJSONLenient(raw)
}

// stNegZeroSize restores the reference's -0 checkpoint size: its script sends {size: -0} (refused) right before the identical
// {size: 0} (accepted), and JSON carries both as 0. The first of two identical size-0 checkpoint appends is the -0 one.
func stNegZeroSize(ops any) []any {
	l, _ := ops.([]any)
	out := append([]any{}, l...)
	zero := func(op any) (map[string]any, bool) {
		o, _ := op.([]any)
		if len(o) != 3 || o[0] != "appendCp" {
			return nil, false
		}
		cp, _ := o[2].(map[string]any)
		sth, _ := cp["sth"].(map[string]any)
		n, ok := sth["size"].(json.Number)
		return sth, ok && n == "0" && len(sth) == 2 // the -0 script's checkpoints carry only {size, root}
	}
	for i := 0; i+1 < len(out); i++ {
		a, okA := zero(out[i])
		b, okB := zero(out[i+1])
		ra, _ := a["root"].(string)
		rb, _ := b["root"].(string)
		if okA && okB && ra == rb {
			cp := map[string]any{"sth": map[string]any{"size": json.Number("-0"), "root": a["root"]}}
			out[i] = []any{"appendCp", out[i].([]any)[1], cp}
		}
	}
	return out
}

func TestLedgerStoreMatchesTheReference(t *testing.T) {
	rsReplaySubset(t, "ref-core-stores-java.json.gz", map[string]vecFn{"ledgerStore": func(a []any) (any, error) {
		kv := NewMemoryAtomicKV()
		s, err := NewKvLedgerStore(kv)
		if err != nil {
			return nil, err
		}
		return stScript(stNegZeroSize(a[0]), func(op []any) (any, error) {
			switch op[0] {
			case "size":
				return s.Size()
			case "read":
				return s.readAny(op[1], op[2])
			case "append":
				return s.appendAny(op[1], op[2])
			case "cpCount":
				return s.CheckpointCount()
			case "cps":
				return s.checkpointsAny(op[1])
			case "appendCp":
				return s.appendCheckpointAny(op[1], op[2])
			case "kvSet":
				return nil, stKvSet(kv, LedgerDocKey, op[1])
			}
			return nil, errors.New("op")
		}), nil
	}})
}

func stStoredLedgerOps(t *testing.T, a []any, suite *SuiteOpts, pin map[string]string, gkey *KeyPair) []any {
	kv := NewMemoryAtomicKV()
	store, _ := NewKvLedgerStore(kv)
	handles := map[string]*StoredLedger{}
	calls := 0
	return stScript(a[0], func(op []any) (any, error) {
		head, _ := op[0].(string)
		switch head {
		case "open":
			o := StoredLedgerOptions{Store: store, Guardian: gkey, InstanceID: "inst", Principal: "pr", Suite: suite, Pin: pin}
			if len(op) > 2 && op[2] == "other-key" {
				o.Guardian = mwKey(t, "other")
			}
			if len(op) > 3 && op[3] != nil {
				o.InstanceID = op[3].(string)
			}
			o.Clock = func() float64 { calls++; return 1_800_000_000_000 + 1000*float64(calls-1) }
			h, err := OpenStoredLedger(o)
			if err != nil {
				return nil, err
			}
			handles[op[1].(string)] = h
			return map[string]any{"size": h.Size(), "guardian": h.Guardian()}, nil
		case "kvSet":
			return nil, stKvSet(kv, LedgerDocKey, op[1])
		case "kvGet":
			return stKvGet(kv, LedgerDocKey)
		}
		h := handles[head]
		switch op[1] {
		case "append":
			i, err := h.Append(op[2].(string))
			if err != nil {
				return nil, err
			}
			return map[string]any{"index": i, "commit": op[2]}, nil
		case "checkpoint":
			return h.Checkpoint()
		case "catchUp":
			return nil, h.CatchUp()
		case "head":
			return h.Head(), nil
		case "size":
			return h.Size(), nil
		case "incl":
			return h.inclusionAny(op[2])
		case "consFrom":
			return h.consistencyAny(op[2])
		case "commits":
			return h.Commits(), nil
		case "latest":
			return h.LatestCheckpoint(), nil
		case "chain":
			return h.CheckpointChain(), nil
		case "guardian":
			return h.Guardian(), nil
		}
		return nil, errors.New("op")
	})
}

func TestStoredLedgerMatchesTheReference(t *testing.T) {
	rsReplaySubset(t, "ref-core-stores-java.json.gz", map[string]vecFn{"storedLedger": func(a []any) (any, error) {
		return stStoredLedgerOps(t, a, nil, nil, mwKey(t, "stored-ledger-guardian")), nil
	}})
}

// TestStoredLedgerPqMatchesTheReference reopens documents the reference signed under hybrid and pure ML-DSA-65 checkpoint suites with
// and without the pin, and continues them under each suite (ref-core-stored-ledger-pq-java).
func TestStoredLedgerPqMatchesTheReference(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", seed)
	if err != nil {
		t.Fatal(err)
	}
	g := mwKey(t, "stored-ledger-guardian")
	replayVectors(t, "ref-core-stored-ledger-pq-java.json.gz", map[string]vecFn{"storedLedgerPq": func(a []any) (any, error) {
		pins := vecObj(a[0])
		kv := NewMemoryAtomicKV()
		store, _ := NewKvLedgerStore(kv)
		hs := map[string]*StoredLedger{}
		calls := 0
		return stScript(a[1], func(op []any) (any, error) {
			head, _ := op[0].(string)
			switch head {
			case "kvSet":
				return nil, stKvSet(kv, LedgerDocKey, op[1])
			case "open":
				c := vecObj(vecArg(op, 2))
				o := StoredLedgerOptions{Store: store, Guardian: g, InstanceID: "inst", Principal: "pr"}
				o.Clock = func() float64 { calls++; return 1_800_000_000_000 + 1000*float64(calls-1) }
				switch c["suite"] {
				case "hybrid":
					o.Suite = &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq}
				case "ml":
					o.Suite = &SuiteOpts{Alg: "ml-dsa-65", Pq: pq}
				}
				if name, ok := c["pin"].(string); ok {
					o.Pin = rsStrMap(pins[name])
				}
				h, err := OpenStoredLedger(o)
				if err != nil {
					return nil, err
				}
				hs[op[1].(string)] = h
				return map[string]any{"size": h.Size(), "guardian": h.Guardian()}, nil
			}
			h := hs[head]
			switch op[1] {
			case "append":
				i, err := h.Append(op[2].(string))
				if err != nil {
					return nil, err
				}
				return map[string]any{"index": i, "commit": op[2]}, nil
			case "checkpoint":
				s, err := h.Checkpoint()
				if err != nil {
					return nil, err
				}
				_, hasPq := s["pq_sig"]
				return map[string]any{"size": s["size"], "alg": s["alg"], "pq": hasPq, "root": s["root"], "prev_root": s["prev_root"]}, nil
			case "latest":
				return h.LatestCheckpoint(), nil
			case "chain":
				return h.CheckpointChain(), nil
			case "head":
				return h.Head(), nil
			case "size":
				return h.Size(), nil
			}
			return nil, errors.New("op")
		}), nil
	}})
}
