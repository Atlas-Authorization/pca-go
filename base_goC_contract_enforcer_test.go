package pca

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

var goCSeed = bytes.Repeat([]byte{7}, 32)

func goCContract(t *testing.T) (map[string]any, string) {
	t.Helper()
	kp, err := KeyPairFromSeed(goCSeed)
	if err != nil {
		t.Fatal(err)
	}
	c, err := SignContract(map[string]any{"version": pInt(1), "principal": kp.Public, "clauses": []any{
		map[string]any{"id": "no-delete", "kind": "never", "p": map[string]any{"verb": "delete"}},
		map[string]any{"id": "review-first", "kind": "precedes", "p": map[string]any{"verb": "review"}, "q": map[string]any{"verb": "deploy"}},
	}}, goCSeed)
	if err != nil {
		t.Fatal(err)
	}
	return c, kp.Public
}

func goCAct(verb string) map[string]any {
	return map[string]any{"action": map[string]any{"verb": verb, "resource": "/r"}}
}

func goCEnforcer(t *testing.T, kv AtomicKV, wall *float64) (*ContractEnforcer, string) {
	t.Helper()
	c, pub := goCContract(t)
	e, err := OpenContractEnforcer(kv, c, pub, ContractEnforcerOptions{Now: func() float64 { return *wall }})
	if err != nil {
		t.Fatal(err)
	}
	return e, c["id"].(string)
}

func goCWant(allow bool, reason string, violated, reasons []any, seq int) map[string]any {
	if violated == nil {
		violated = []any{}
	}
	if reasons == nil {
		reasons = []any{}
	}
	return map[string]any{"allow": allow, "reason": reason, "violated": violated, "reasons": reasons, "seq": pInt(seq)}
}

func goCDocBytes(t *testing.T, id string, mut func(d map[string]any)) []byte {
	t.Helper()
	d := map[string]any{"v": pInt(1), "contract_id": id, "state": EmptyMonitorState(pInt(1700000000000))}
	if mut != nil {
		mut(d)
	}
	s, err := Canonicalize(d)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func TestGoCContractResetMsgAndSign(t *testing.T) {
	want := append([]byte(ContractResetDomain), sha([]byte("c:10"))...)
	if got := contractResetMsg("c", 10); !bytes.Equal(got, want) {
		t.Errorf("reset message: %x", got)
	}
	if s, err := SignContractReset([]byte("short"), "c", 1); err == nil || s != "" {
		t.Errorf("a bad seed must not sign: %q %v", s, err)
	}
	if s, err := SignContractReset(goCSeed, "c", 1); err != nil || s == "" {
		t.Errorf("sign: %q %v", s, err)
	}
	if got := (&ContractEnforcerError{"x"}).Error(); got != "ContractEnforcer: x" {
		t.Errorf("error text: %q", got)
	}
}

func TestGoCContractDoc(t *testing.T) {
	const id = "cid"
	ok := func(name string, b []byte, want bool) {
		t.Helper()
		d, got := contractDoc(b, id)
		if got != want || (!want && d != nil) || (want && d == nil) {
			t.Errorf("%s: ok=%v d=%v want %v", name, got, d, want)
		}
	}
	ok("garbage", []byte("{"), false)
	ok("empty", nil, false)
	ok("not an object", []byte("[]"), false)
	ok("base", goCDocBytes(t, id, nil), true)
	ok("wrong version", goCDocBytes(t, id, func(d map[string]any) { d["v"] = pInt(2) }), false)
	ok("other contract", goCDocBytes(t, id, func(d map[string]any) { d["contract_id"] = "other" }), false)
	ok("bad state", goCDocBytes(t, id, func(d map[string]any) { d["state"] = map[string]any{} }), false)
	lat := func(l any) []byte {
		return goCDocBytes(t, id, func(d map[string]any) { d["latched"] = l })
	}
	ok("latched ok", lat(map[string]any{"seq": pInt(0), "violated": []any{"a"}}), true)
	ok("latched empty list", lat(map[string]any{"seq": pInt(3), "violated": []any{}}), true)
	ok("latched not an object", lat("x"), false)
	ok("violated not a list", lat(map[string]any{"seq": pInt(0), "violated": "x"}), false)
	ok("violated missing", lat(map[string]any{"seq": pInt(0)}), false)
	ok("seq fractional", lat(map[string]any{"seq": json.Number("1.5"), "violated": []any{}}), false)
	ok("seq missing", lat(map[string]any{"violated": []any{}}), false)
	ok("violated entry not a string", lat(map[string]any{"seq": pInt(0), "violated": []any{pInt(1)}}), false)
	ok("second violated entry not a string", lat(map[string]any{"seq": pInt(0), "violated": []any{"a", pInt(1)}}), false)
}

func TestGoCContractEnforcerOpen(t *testing.T) {
	c, pub := goCContract(t)
	kv := NewMemoryAtomicKV()
	if e, err := OpenContractEnforcer(kv, c, "", ContractEnforcerOptions{}); e != nil || err == nil || err.Error() != "ContractEnforcer: a pinned principal is required" {
		t.Errorf("principal: %v %v", e, err)
	}
	if e, err := OpenContractEnforcer(nil, c, pub, ContractEnforcerOptions{}); e != nil || err == nil || err.Error() != "ContractEnforcer: a store is required" {
		t.Errorf("store: %v %v", e, err)
	}
	other, _ := NewKeyPair()
	v := VerifyContract(c, other.Public)
	if v["ok"] == true {
		t.Fatal("a contract must not verify under another principal")
	}
	if e, err := OpenContractEnforcer(kv, c, other.Public, ContractEnforcerOptions{}); e != nil || err == nil || err.Error() != "ContractEnforcer: contract refused: "+v["reason"].(string) {
		t.Errorf("refused: %v %v", e, err)
	}
	// default key and clock
	e, err := OpenContractEnforcer(kv, c, pub, ContractEnforcerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Check(goCAct("review"), true); r["allow"] != true || r["reason"] != "ok" {
		t.Errorf("default clock: %v", r)
	}
	if _, found, _ := kv.Get("contract/" + c["id"].(string)); !found {
		t.Error("default key")
	}
	// custom key
	kv2 := NewMemoryAtomicKV()
	e2, _ := OpenContractEnforcer(kv2, c, pub, ContractEnforcerOptions{Key: "k1", Now: func() float64 { return 1700000000000 }})
	e2.Check(goCAct("review"), true)
	if _, found, _ := kv2.Get("k1"); !found {
		t.Error("custom key")
	}
	if _, found, _ := kv2.Get("contract/" + c["id"].(string)); found {
		t.Error("custom key must replace the default")
	}
}

func TestGoCContractEnforcerCheckFlow(t *testing.T) {
	wall := 1700000000000.0
	kv := NewMemoryAtomicKV()
	e, _ := goCEnforcer(t, kv, &wall)
	vecSame(t, "admit", e.Check(goCAct("review"), true), goCWant(true, "ok", nil, nil, 1))
	vecSame(t, "deny by permission", e.Check(goCAct("review"), false), goCWant(false, "permission", nil, []any{"<permission>: not permitted"}, 1))
	vecSame(t, "peek", e.Peek(goCAct("deploy")), goCWant(true, "ok", nil, nil, 1))
	if r := e.Peek(goCAct("delete")); r["allow"] != false || r["reason"] != "violated" || len(r["violated"].([]any)) != 1 || r["violated"].([]any)[0] != "no-delete" || r["seq"] != pInt(1) {
		t.Errorf("peek violation: %v", r)
	}
	st, err := e.State()
	if err != nil || st["latched"] != false || st["state"].(map[string]any)["seq"] != pInt(1) {
		t.Errorf("state: %v %v", st, err)
	}

	kv2 := NewMemoryAtomicKV()
	e2, id := goCEnforcer(t, kv2, &wall)
	vecSame(t, "violation", e2.Check(goCAct("deploy"), true), goCWant(false, "violated", []any{"review-first"},
		[]any{"review-first: precedence violated (prerequisite p not yet admitted before q)"}, 0))
	latched := goCWant(false, "latched", []any{"review-first"}, []any{"<latched>: contract violated at seq 0"}, 0)
	vecSame(t, "latched", e2.Check(goCAct("review"), true), latched)
	vecSame(t, "latched peek", e2.Peek(goCAct("review")), latched)
	st2, err := e2.State()
	if err != nil || st2["latched"] != true {
		t.Errorf("latched state: %v %v", st2, err)
	}

	// a corrupt stored document
	bad := NewMemoryAtomicKV()
	e3, _ := goCEnforcer(t, bad, &wall)
	_ = bad.Update("contract/"+id, func([]byte) []byte { return []byte("{") })
	corrupt := goCWant(false, "state-error", nil, []any{contractCorrupt}, 0)
	vecSame(t, "corrupt check", e3.Check(goCAct("review"), true), corrupt)
	vecSame(t, "corrupt peek", e3.Peek(goCAct("review")), corrupt)
	if s, err := e3.State(); s != nil || err == nil || err.Error() != "ContractEnforcer: stored state is corrupt or belongs to another contract" {
		t.Errorf("corrupt state: %v %v", s, err)
	}
	// a document of another contract
	_ = bad.Update("contract/"+id, func([]byte) []byte { return goCDocBytes(t, "someone-else", nil) })
	vecSame(t, "foreign check", e3.Check(goCAct("review"), true), corrupt)

	// nothing stored yet
	e4, _ := goCEnforcer(t, NewMemoryAtomicKV(), &wall)
	if s, err := e4.State(); s != nil || err != nil {
		t.Errorf("empty state: %v %v", s, err)
	}
	vecSame(t, "fresh peek", e4.Peek(goCAct("review")), goCWant(true, "ok", nil, nil, 0))
}

func TestGoCContractEnforcerClock(t *testing.T) {
	wall := 1700000000000.0
	kv := NewMemoryAtomicKV()
	e, _ := goCEnforcer(t, kv, &wall)
	vecSame(t, "first", e.Check(goCAct("review"), true), goCWant(true, "ok", nil, nil, 1))
	for _, w := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		wall = w
		vecSame(t, "non-finite clock over a stored state", e.Check(goCAct("review"), true),
			goCWant(false, "state-error", nil, []any{"<state>: clock is not finite"}, 1))
	}
	// no stored state, non-finite clock
	for _, w := range []float64{math.NaN(), math.Inf(1)} {
		wall = w
		e2, _ := goCEnforcer(t, NewMemoryAtomicKV(), &wall)
		vecSame(t, "non-finite clock, fresh", e2.Check(goCAct("review"), true),
			goCWant(false, "state-error", nil, []any{"<state>: advance failed: clock regression"}, 0))
	}
	wall = math.Inf(-1)
	e3, _ := goCEnforcer(t, NewMemoryAtomicKV(), &wall)
	if r := e3.Check(goCAct("review"), true); r["allow"] != true {
		t.Errorf("-Inf clock, fresh: %v", r)
	}
	// Peek on a fresh store with a non-finite clock still evaluates against a valid genesis
	for _, w := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		wall = w
		e4, _ := goCEnforcer(t, NewMemoryAtomicKV(), &wall)
		vecSame(t, "peek non-finite", e4.Peek(goCAct("review")), goCWant(true, "ok", nil, nil, 0))
	}
}

func TestGoCContractEnforcerStoreFaults(t *testing.T) {
	wall := 1700000000000.0
	fail := goCWant(false, "store-error", nil, []any{"store error (fail closed)"}, 0)

	// the store never runs the callback: the default verdict stands
	skip := goCNewKV()
	skip.skip = func(string) bool { return true }
	e, _ := goCEnforcer(t, skip, &wall)
	vecSame(t, "skipped", e.Check(goCAct("review"), true), goCWant(false, "store-error", nil, []any{"store unavailable"}, 0))

	// the store errors
	bad := goCNewKV()
	bad.failUpdate = func(string) bool { return true }
	e2, _ := goCEnforcer(t, bad, &wall)
	vecSame(t, "update error", e2.Check(goCAct("review"), true), fail)

	// a panicking store or clock never escapes
	e3, _ := goCEnforcer(t, goCBeaconKV{func(string, func([]byte) []byte) error { panic("down") }}, &wall)
	vecSame(t, "update panic", e3.Check(goCAct("review"), true), fail)
	c, pub := goCContract(t)
	e4, _ := OpenContractEnforcer(NewMemoryAtomicKV(), c, pub, ContractEnforcerOptions{Now: func() float64 { panic("clock") }})
	vecSame(t, "clock panic", e4.Check(goCAct("review"), true), fail)

	// Peek: read error and read panic
	e5, _ := goCEnforcer(t, brokenKv{}, &wall)
	vecSame(t, "peek read error", e5.Peek(goCAct("review")), fail)
	e6, _ := goCEnforcer(t, brokenKv{panics: true}, &wall)
	vecSame(t, "peek read panic", e6.Peek(goCAct("review")), fail)
	if s, err := e5.State(); s != nil || err == nil {
		t.Errorf("state read error: %v %v", s, err)
	}
	// the store error constant
	if r := storeErr(); r["seq"] != pInt(0) {
		t.Errorf("storeErr seq: %v", r["seq"])
	}
	// save of a document that cannot be canonicalised
	if b := e.save(map[string]any{"x": make(chan int)}); b != nil {
		t.Errorf("save: %q", b)
	}
	if b := e.save(map[string]any{"x": pInt(1)}); string(b) != `{"x":1}` {
		t.Errorf("save: %q", b)
	}
}

func TestGoCContractEnforcerReset(t *testing.T) {
	wall := 1700000000000.0
	kv := NewMemoryAtomicKV()
	e, id := goCEnforcer(t, kv, &wall)
	if e.Reset("anything") {
		t.Error("nothing stored: nothing to reset")
	}
	e.Check(goCAct("deploy"), true) // latches at seq 0
	good, _ := SignContractReset(goCSeed, id, 0)
	wrongSeq, _ := SignContractReset(goCSeed, id, 1)
	for name, sig := range map[string]any{"wrong seq": wrongSeq, "not a string": 5, "nil": nil, "empty": ""} {
		if e.Reset(sig) {
			t.Errorf("%s must not reset", name)
		}
	}
	if st, _ := e.State(); st["latched"] != true {
		t.Fatal("still latched")
	}
	if !e.Reset(good) {
		t.Fatal("the principal's reset must clear")
	}
	if st, _ := e.State(); st["latched"] != false {
		t.Error("cleared")
	}
	if e.Reset(good) {
		t.Error("a second reset has nothing to clear")
	}
	// a corrupt document is not reset
	_ = kv.Update("contract/"+id, func([]byte) []byte { return []byte("{") })
	if e.Reset(good) {
		t.Error("corrupt document")
	}
	// a store that never runs the callback cleared nothing
	skip := goCNewKV()
	skip.skip = func(string) bool { return true }
	e2, _ := goCEnforcer(t, skip, &wall)
	if e2.Reset(good) {
		t.Error("skipped callback")
	}
	// a store error is not a clear
	bad := goCNewKV()
	bad.failUpdate = func(string) bool { return true }
	e3, _ := goCEnforcer(t, bad, &wall)
	if e3.Reset(good) {
		t.Error("store error")
	}
	// a retried callback does not keep a stale "cleared"
	kv4 := NewMemoryAtomicKV()
	e4, _ := goCEnforcer(t, kv4, &wall)
	e4.Check(goCAct("deploy"), true)
	latchedDoc, _, _ := kv4.Get("contract/" + id)
	retry := goCBeaconKV{func(_ string, fn func([]byte) []byte) error {
		fn(latchedDoc)
		fn(nil)
		return nil
	}}
	c, pub := goCContract(t)
	e5, _ := OpenContractEnforcer(retry, c, pub, ContractEnforcerOptions{Now: func() float64 { return wall }})
	if e5.Reset(good) {
		t.Error("cleared flag leaked across a retry")
	}
}
