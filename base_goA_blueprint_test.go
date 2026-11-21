package pca

import (
	"errors"
	"testing"
)

// goABpKV wraps the in-memory store with per-key failure injection.
type goABpKV struct {
	mem       *MemoryAtomicKV
	updateErr map[string]error // returned AFTER the update function ran
	panics    map[string]bool
}

func goANewBpKV() *goABpKV {
	return &goABpKV{mem: NewMemoryAtomicKV(), updateErr: map[string]error{}, panics: map[string]bool{}}
}

func (k *goABpKV) Get(key string) ([]byte, bool, error) { return k.mem.Get(key) }

func (k *goABpKV) Update(key string, fn func(prev []byte) []byte) error {
	if k.panics[key] {
		panic("store down")
	}
	err := k.mem.Update(key, fn)
	if e := k.updateErr[key]; e != nil {
		return e
	}
	return err
}

func (k *goABpKV) put(key, val string) {
	_ = k.mem.Update(key, func([]byte) []byte { return []byte(val) })
}

func (k *goABpKV) del(key string) {
	k.mem.mu.Lock()
	delete(k.mem.m, key)
	k.mem.mu.Unlock()
}

func (k *goABpKV) raw(key string) string {
	v, _, _ := k.mem.Get(key)
	return string(v)
}

func goABp(t *testing.T, op fxKey, key string, epoch int64, mut func(b map[string]any)) map[string]any {
	return parityBlueprint(t, op, key, "active", func(b map[string]any) {
		b["epoch"] = jnum(epoch)
		if mut != nil {
			mut(b)
		}
	})
}

func TestGoABlueprintAcceptEpochDocument(t *testing.T) {
	op := newKey(t)
	kv := goANewBpKV()
	reg := NewBlueprintRegistry([]string{op.id}, kv)
	if reg.Epoch() != 0 {
		t.Fatalf("empty registry epoch %d", reg.Epoch())
	}
	if code, rep := reg.Accept(goABp(t, op, "K", 12, nil)); code != "" || !rep {
		t.Fatalf("accept: %q %v", code, rep)
	}
	if got := kv.raw(blueprintMaxEpochKey); got != "12" || reg.Epoch() != 12 {
		t.Fatalf("max epoch doc %q epoch %d", got, reg.Epoch())
	}
	if code, rep := reg.Accept(goABp(t, op, "K2", 3, nil)); code != "" || !rep {
		t.Fatalf("accept lower epoch under another key: %q %v", code, rep)
	}
	if got := kv.raw(blueprintMaxEpochKey); got != "12" {
		t.Fatalf("a lower epoch must not lower the maximum: %q", got)
	}

	kv2 := goANewBpKV()
	kv2.put(blueprintMaxEpochKey, "20")
	reg2 := NewBlueprintRegistry([]string{op.id}, kv2)
	if code, rep := reg2.Accept(goABp(t, op, "K", 12, nil)); code != "" || !rep {
		t.Fatalf("accept: %q %v", code, rep)
	}
	if got := kv2.raw(blueprintMaxEpochKey); got != "20" || reg2.Epoch() != 20 {
		t.Fatalf("an existing higher maximum must stay: %q %d", got, reg2.Epoch())
	}

	if code, rep := reg.Accept(map[string]any{}); code != "bad_record" || rep {
		t.Errorf("bad record: %q %v", code, rep)
	}
	other := newKey(t)
	if code, rep := reg.Accept(goABp(t, other, "K3", 1, nil)); code != "unknown_operator" || rep {
		t.Errorf("unknown operator: %q %v", code, rep)
	}
}

func TestGoABlueprintRefusalsWriteNothing(t *testing.T) {
	op, op2 := newKey(t), newKey(t)
	kv := goANewBpKV()
	reg := NewBlueprintRegistry([]string{op.id, op2.id}, kv)
	if code, rep := reg.Accept(goABp(t, op, "K", 5, nil)); code != "" || !rep {
		t.Fatalf("seed: %q %v", code, rep)
	}
	doc := blueprintKeyDoc("K")
	// a stored document the registry did not format itself is rewritten only by an accepted record
	kv.put(doc, " "+kv.raw(doc))
	marked := kv.raw(doc)
	same := goABp(t, op, "K", 5, nil)
	rows := []struct {
		name, code string
		rep        bool
		rec        map[string]any
	}{
		{"identical record", "", false, same},
		{"stale epoch", "stale_epoch", false, goABp(t, op, "K", 4, nil)},
		{"fork", "epoch_fork", false, goABp(t, op, "K", 5, func(b map[string]any) { b["id"] = "other" })},
		{"operator changed", "operator_changed", false, goABp(t, op2, "K", 9, nil)},
	}
	for _, r := range rows {
		if code, rep := reg.Accept(r.rec); code != r.code || rep != r.rep {
			t.Errorf("%s: got %q %v want %q %v", r.name, code, rep, r.code, r.rep)
		}
		if kv.raw(doc) != marked {
			t.Errorf("%s: the stored document must not be rewritten: %q", r.name, kv.raw(doc))
		}
		if reg.Epoch() != 5 {
			t.Errorf("%s: a refused record must not raise the epoch: %d", r.name, reg.Epoch())
		}
	}
	if code, rep := reg.Accept(goABp(t, op, "K", 6, nil)); code != "" || !rep || kv.raw(doc) == marked || reg.Epoch() != 6 {
		t.Errorf("a higher epoch replaces: %q %v epoch %d", code, rep, reg.Epoch())
	}
}

func TestGoABlueprintStoreFailures(t *testing.T) {
	op := newKey(t)
	rec := func() map[string]any { return goABp(t, op, "K", 5, nil) }

	kv := goANewBpKV()
	kv.updateErr[blueprintKeyDoc("K")] = errors.New("commit failed")
	if code, rep := NewBlueprintRegistry([]string{op.id}, kv).Accept(rec()); code != "store_unreachable" || rep {
		t.Errorf("commit failure after the update ran: %q %v", code, rep)
	}

	kv = goANewBpKV()
	kv.updateErr[blueprintMaxEpochKey] = errors.New("down")
	if code, rep := NewBlueprintRegistry([]string{op.id}, kv).Accept(rec()); code != "store_unreachable" || rep {
		t.Errorf("max epoch update failure: %q %v", code, rep)
	}

	kv = goANewBpKV()
	kv.panics[blueprintMaxEpochKey] = true
	if code, rep := NewBlueprintRegistry([]string{op.id}, kv).Accept(rec()); code != "store_unreachable" || rep {
		t.Errorf("max epoch update panic: %q %v", code, rep)
	}

	kv = goANewBpKV()
	kv.put(blueprintKeyDoc("K"), "not json")
	if code, rep := NewBlueprintRegistry([]string{op.id}, kv).Accept(rec()); code != "store_unreachable" || rep {
		t.Errorf("unreadable record: %q %v", code, rep)
	}
}

func TestGoABlueprintEpochGate(t *testing.T) {
	chain := []any{map[string]any{"issuer": "a", "holder": "b"}}
	zero, one := int64(0), int64(1)
	check := func(kv *goABpKV, min *int64) BlueprintDecision {
		return CheckBlueprints(chain, NewBlueprintRegistry(nil, kv), jnum(2), "any", min)
	}
	if d := check(goANewBpKV(), &zero); d.Decision != "allow" || len(d.Governed) != 0 {
		t.Errorf("empty store, need 0: %+v", d)
	}
	if d := check(goANewBpKV(), &one); d.Decision != "escalate" || d.Code != "stale_blueprint_state" || d.Have != 0 || d.Need != 1 {
		t.Errorf("empty store, need 1: %+v", d)
	}
	kv := goANewBpKV()
	kv.put(blueprintMaxEpochKey, "0")
	if d := check(kv, &zero); d.Decision != "allow" {
		t.Errorf("stored zero is a valid epoch: %+v", d)
	}
	kv.put(blueprintMaxEpochKey, "7")
	if d := check(kv, &one); d.Decision != "allow" {
		t.Errorf("stored 7, need 1: %+v", d)
	}
	for name, doc := range map[string]string{"garbage": "not json", "negative": "-5", "unsafe": "99999999999999999999", "fraction": "1.5"} {
		kv.put(blueprintMaxEpochKey, doc)
		if d := check(kv, &zero); d.Decision != "deny" || d.Code != "store_unreachable" {
			t.Errorf("%s epoch document: %+v", name, d)
		}
	}
}

func TestGoABlueprintLookupReloadsFromStore(t *testing.T) {
	op := newKey(t)
	kv := goANewBpKV()
	reg := NewBlueprintRegistry([]string{op.id}, kv)
	if code, _ := reg.Accept(goABp(t, op, "K", 1, nil)); code != "" {
		t.Fatalf("accept: %q", code)
	}
	chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
	if d := CheckBlueprints(chain, reg, jnum(2), "require", nil); d.Code != "admission_required" {
		t.Fatalf("seeded: %+v", d)
	}
	kv.del(blueprintKeyDoc("K"))
	if d := CheckBlueprints(chain, reg, jnum(2), "require", nil); d.Decision != "deny" || d.Code != "no_blueprint" {
		t.Errorf("a record gone from the store must not be served from the working copy: %+v", d)
	}
}
