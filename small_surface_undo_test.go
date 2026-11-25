package pca

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// The undo ledger half of the shared small-surface corpus: the record lifecycle (transitions plus signed receipts) and the
// reference stores. The other functions of the corpus are replayed by the sibling small-surface tests.

func smallUndoKey(t *testing.T) *KeyPair {
	t.Helper()
	h := sha256.Sum256([]byte("atlas-pca-conformance/small/undo/service"))
	k, err := KeyPairFromSeed(h[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func smallUndoLifecycle(t *testing.T, a []any) (any, error) {
	key := smallUndoKey(t)
	rec := vecObj(a[0])
	cur, err := WithReceipt(rec, "opened", "", int64(undoInt(rec["opened_at"])), key)
	if err != nil {
		return nil, err
	}
	out := []any{cur}
	for _, st := range a[1].([]any) {
		pair := st.([]any)
		now := undoInt(pair[1])
		tr := UndoTransition(cur, pair[0], float64(now))
		step := map[string]any{}
		if tr.Outcome == "applied" {
			cur, err = WithReceipt(tr.Record, tr.Event, tr.Note, now, key)
			if err != nil {
				return nil, err
			}
			step["applied"] = vecObj(pair[0])["kind"]
			step["record"] = cur
		} else if tr.Outcome == "replayed" {
			step["replayed"] = nil
		} else {
			step[tr.Outcome] = tr.Code
		}
		out = append(out, step)
	}
	chain := map[string]any{"chain": nil}
	if e := UndoReceiptChainError(UndoChainRecord{ID: undoStr(cur, "id"), CompensationDigest: undoStr(cur, "compensation_digest"), State: undoStr(cur, "state"),
		Receipts: cur["receipts"].([]any)}, key.Public); e != "" {
		chain["chain"] = e
	}
	return append(out, chain), nil
}

func smallUndoStore(a []any) (any, error) {
	var st UndoStore
	if a[0] == "memory" {
		st = NewMemoryUndoStore()
	} else {
		s, err := NewKvUndoStore(NewMemoryAtomicKV(), true)
		if err != nil {
			return nil, err
		}
		st = s
	}
	out := []any{}
	for _, op0 := range a[1].([]any) {
		op := op0.([]any)
		var res any
		var err error
		switch op[0] {
		case "create":
			created, existing, e := st.Create(vecObj(op[1]))
			err = e
			r := map[string]any{"created": created}
			if !created {
				r["record"] = existing
			}
			res = r
		case "get":
			var r map[string]any
			r, err = st.Get(op[1].(string))
			if r != nil {
				res = r
			}
		case "replace":
			res, err = st.Replace(op[1].(string), undoInt(op[2]), vecObj(op[3]))
		default:
			q := vecObj(op[1])
			uq := UndoQuery{State: vecStr(q, "state"), GrantRef: vecStr(q, "grantRef"), BondRef: vecStr(q, "bondRef")}
			if q["windowEndedBy"] != nil {
				w := undoInt(q["windowEndedBy"])
				uq.WindowEndedBy = &w
			}
			if q["limit"] != nil {
				uq.Limit = int(undoInt(q["limit"]))
			}
			var l []map[string]any
			l, err = st.List(uq)
			arr := make([]any, len(l))
			for i, r := range l {
				arr[i] = r
			}
			res = arr
		}
		var ue *UndoError
		if errors.As(err, &ue) {
			out = append(out, map[string]any{"error": ue.Code})
		} else if err != nil {
			return nil, err
		} else {
			out = append(out, res)
		}
	}
	return out, nil
}

// smallDetector replays the detector-receipt policy check and the tighten-only signal.
func smallDetectorSignal(a []any) (any, error) {
	o := DetectorSignal(vecObj(a[0]))
	rej := make([]any, len(o.Rejected))
	for i, r := range o.Rejected {
		rej[i] = map[string]any{"index": jsNumber(float64(r.Index)), "reason": r.Reason}
	}
	fl := make([]any, len(o.Flagged))
	for i, f := range o.Flagged {
		fl[i] = f
	}
	return map[string]any{"signal": o.Signal, "env": map[string]any{"detect": o.Detect}, "flagged": fl, "rejected": rej}, nil
}

// smallGuardSeq replays the replay guard over a shared in-memory store: each step is one PCActn presented at a clock.
func smallGuardSeq(a []any) (any, error) {
	o := vecObj(a[0])
	var skew *float64
	if f, ok := jsNum(o["clockSkewMs"]); ok {
		skew = &f
	}
	requireNonce := o["requireNonce"] != false
	store := NewInMemoryPcactnReplayStore(0)
	var counters PcactnCounterStore
	if o["counters"] == true {
		counters = store
	}
	out := []any{}
	for _, st := range a[1].([]any) {
		s := vecObj(st)
		now, _ := jsNum(s["now"])
		v := GuardPcactnReplay(store, vecObj(s["p"]), vecStr(o, "aud"), now, skew, requireNonce, counters)
		r := map[string]any{"ok": v.OK}
		if !v.OK {
			r["code"], r["reason"] = v.Code, v.Reason
		}
		out = append(out, r)
	}
	return out, nil
}

func TestSmallSurfaceUndoLedger(t *testing.T) {
	rsReplaySubset(t, "ref-core-small-surface.json.gz", map[string]vecFn{
		"undoLifecycle":       func(a []any) (any, error) { return smallUndoLifecycle(t, a) },
		"undoStore":           smallUndoStore,
		"detectorPolicyError": func(a []any) (any, error) { return ccNilIfEmpty(DetectorPolicyError(a[0])), nil },
		"detectorSignal":      smallDetectorSignal,
		"guardSeq":            smallGuardSeq,
		"createLink": func(a []any) (any, error) {
			ref, err := CreateLink(a[0], a[1], vecArg(a, 2) == true)
			if err != nil {
				return map[string]any{"ok": false}, nil
			}
			return map[string]any{"ok": true, "ref": ref}, nil
		},
		"slotsDigest": func(a []any) (any, error) { return SlotsDigest(a[0]) },
		"linkDigest":  func(a []any) (any, error) { return LinkDigest(a[0]) },
		"limits": func(a []any) (any, error) {
			return map[string]any{"MAX_SLOTS": jsNumber(MaxSlots), "MAX_SLOT_STRING": jsNumber(MaxSlotString), "MAX_SLOT_SET": jsNumber(MaxSlotSet),
				"TEMPLATE_KIND": TemplateKind, "TIGHTEN_KIND": TightenKind}, nil
		},
	})
	if NewMemoryUndoStore().Durable() {
		t.Fatal("the in-memory store must not claim durability")
	}
	if s, _ := NewKvUndoStore(NewMemoryAtomicKV(), true); !s.Durable() || !IsUndoStore(s) || IsUndoStore(struct{}{}) {
		t.Fatal("kv store durability / IsUndoStore")
	}
}

// The pure parity corpus, every function of it: an unhandled function fails the replay.
func TestParityPureMatchesTheReference(t *testing.T) {
	fns := map[string]vecFn{
		"enforceRequired": func(a []any) (any, error) {
			v := vecObj(a[0])
			checks := map[string]string{}
			for k, x := range vecObj(v["checks"]) {
				checks[k], _ = x.(string)
			}
			out := EnforceRequired(v["allow"] == true, checks, vecStrs(v, "reasons"), func() []string {
				var r []string
				for _, x := range a[1].([]any) {
					s, _ := x.(string)
					r = append(r, s)
				}
				return r
			}())
			cs := map[string]any{}
			for k, x := range out.Checks {
				cs[k] = x
			}
			rs := make([]any, len(out.Reasons))
			for i, r := range out.Reasons {
				rs[i] = r
			}
			return map[string]any{"allow": out.Allow, "checks": cs, "reasons": rs}, nil
		},
	}
	for k, f := range ppFns() {
		fns[k] = f
	}
	count := 0
	for k, f := range fns {
		f := f
		fns[k] = func(a []any) (any, error) { count++; return f(a) }
	}
	replayVectors(t, "ref-core-parity-pure.json.gz", fns)
	if count != 405 {
		t.Fatalf("replayed %d cases, the corpus has 405", count)
	}
}
