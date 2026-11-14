package pca

import (
	"fmt"
	"testing"
)

type goAEvFx struct {
	act  map[string]any
	c    any
	st   map[string]any
	kp   *KeyPair
	seed []byte
}

func goAFx(t *testing.T) goAEvFx {
	t.Helper()
	seed := make([]byte, 32)
	seed[0] = 9
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return goAEvFx{act: goAAct("pay", ""), c: goAC(`{"id":"n","kind":"never","when":{"verb":"zzz"}}`), st: goAGenesis("{}", "{}"), kp: kp, seed: seed}
}

func (f goAEvFx) evidence() map[string]any { return ProveSafety(f.act, f.c, f.st) }

func (f goAEvFx) sign(t *testing.T, ev map[string]any) map[string]any {
	t.Helper()
	s, err := SignSafetyEvidence(ev, f.seed, f.kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f goAEvFx) full() map[string]any {
	return map[string]any{"signer": f.kp.Public, "action": f.act, "constitution": f.c, "state": f.st}
}

func goAClone(v any) any {
	n, err := NormalizeJSON(v)
	if err != nil {
		panic(err)
	}
	return n
}

func goAMut(v map[string]any, f func(m map[string]any)) map[string]any {
	m := goAClone(v).(map[string]any)
	f(m)
	return m
}

func TestGoAProveSafety(t *testing.T) {
	f := goAFx(t)
	ev := f.evidence()
	cid, _ := ConstitutionID(f.c)
	ad, _ := HashCanonical(f.act)
	sd, _ := StateDigest(f.st)
	if ev["v"] != goAN("1") || ev["constitution"] != cid || ev["action_digest"] != ad || ev["state_digest"] != sd || ev["now"] != goAN("1000000") || ev["ok"] != true {
		t.Errorf("evidence: %v", ev)
	}
	if got := fmt.Sprint(ev["violated"]); got != "[]" {
		t.Errorf("violated: %s", got)
	}
	rows := ev["evaluated"].([]any)
	if len(rows) != 1 || fmt.Sprint(rows[0]) != "map[id:n kind:never result:pass]" {
		t.Errorf("rows: %v", rows)
	}
	if d, err := EvidenceDigest(ev); err != nil {
		t.Error(err)
	} else if want, _ := HashCanonical(ev); d != want {
		t.Error("EvidenceDigest")
	}
	bad := ProveSafety(goAAct("pay", ""), goAC(goANever), f.st)
	if bad["ok"] != false || fmt.Sprint(bad["violated"]) != "[n]" {
		t.Errorf("violating evidence: %v", bad)
	}
	// a malformed state is unhashable and fails the evidence once, with the time defaulting to 0
	ms := ProveSafety(f.act, f.c, goAJ(`{"now":"x"}`))
	if ms["state_digest"] != Unhashable || ms["now"] != goAN("0") || ms["ok"] != false || fmt.Sprint(ms["violated"]) != "[<state>]" {
		t.Errorf("malformed state: %v", ms)
	}
	if got := ProveSafety(f.act, f.c, "x"); got["now"] != goAN("0") {
		t.Errorf("state not an object: %v", got)
	}
	if got := ProveSafety(f.act, f.c, goAStateJ("5", "0", "null", "{}", "{}")); got["now"] != goAN("5") {
		t.Errorf("now follows the state: %v", got["now"])
	}
	mc := ProveSafety(f.act, "x", f.st)
	if mc["constitution"] != Unhashable || fmt.Sprint(mc["violated"]) != "[<constitution>]" || mc["ok"] != false {
		t.Errorf("malformed constitution: %v", mc)
	}
}

func TestGoAEvidenceFromAppendsUnhashable(t *testing.T) {
	f := goAFx(t)
	pass := map[string]any{"ok": true, "violated": []any{}, "evaluated": []any{}}
	// each of the three digests that cannot be computed is reported, once, and fails the evidence
	e := evidenceFrom(pass, f.act, "x", f.st)
	if e["ok"] != false || fmt.Sprint(e["violated"]) != "[<constitution>]" || e["constitution"] != Unhashable {
		t.Errorf("constitution: %v", e)
	}
	e = evidenceFrom(pass, map[string]any{"x": 1.5}, f.c, f.st)
	if e["ok"] != false || fmt.Sprint(e["violated"]) != "[<action>]" || e["action_digest"] != Unhashable {
		t.Errorf("action: %v", e)
	}
	e = evidenceFrom(pass, f.act, f.c, goAJ(`{}`))
	if e["ok"] != false || fmt.Sprint(e["violated"]) != "[<state>]" || e["state_digest"] != Unhashable {
		t.Errorf("state: %v", e)
	}
	e = evidenceFrom(pass, map[string]any{"x": 1.5}, "x", goAJ(`{}`))
	if fmt.Sprint(e["violated"]) != "[<constitution> <action> <state>]" {
		t.Errorf("all three: %v", e["violated"])
	}
	// already named by the monitor: not repeated
	named := map[string]any{"ok": false, "violated": []any{"<state>"}, "evaluated": []any{}}
	e = evidenceFrom(named, f.act, f.c, goAJ(`{}`))
	if fmt.Sprint(e["violated"]) != "[<state>]" {
		t.Errorf("not repeated: %v", e["violated"])
	}
	// a failed monitor result stays failed even when every digest is fine
	failed := map[string]any{"ok": false, "violated": []any{"n"}, "evaluated": []any{}}
	if e = evidenceFrom(failed, f.act, f.c, f.st); e["ok"] != false || fmt.Sprint(e["violated"]) != "[n]" {
		t.Errorf("failed monitor: %v", e)
	}
}

func TestGoAVerifySafetyEvidence(t *testing.T) {
	f := goAFx(t)
	ev := f.evidence()
	run := func(e any) map[string]any { return VerifySafetyEvidence(e, f.act, f.c, f.st) }
	if r := run(ev); r["ok"] != true {
		t.Errorf("fresh evidence: %v", r)
	}
	rows := []struct {
		name string
		e    any
		want string
	}{
		{"not an object", "x", "unsupported evidence version"},
		{"version 2", goAMut(ev, func(m map[string]any) { m["v"] = 2 }), "unsupported evidence version"},
		{"no version", goAMut(ev, func(m map[string]any) { delete(m, "v") }), "unsupported evidence version"},
		{"constitution", goAMut(ev, func(m map[string]any) { m["constitution"] = "x" }), "constitution mismatch"},
		{"action", goAMut(ev, func(m map[string]any) { m["action_digest"] = "x" }), "action digest mismatch"},
		{"state", goAMut(ev, func(m map[string]any) { m["state_digest"] = "x" }), "state digest mismatch"},
		{"time", goAMut(ev, func(m map[string]any) { m["now"] = 5 }), "evidence does not reproduce"},
		{"rows", goAMut(ev, func(m map[string]any) { m["evaluated"] = []any{} }), "evidence does not reproduce"},
	}
	for _, r := range rows {
		if got := run(r.e); got["ok"] != false || got["reason"] != r.want {
			t.Errorf("%s: %v", r.name, got)
		}
	}
	// a violation reproduces but is reported, all violated ids joined
	two := goAC(goANever, `{"id":"m","kind":"never","when":{"verb":"pay"}}`)
	e2 := ProveSafety(f.act, two, f.st)
	if r := VerifySafetyEvidence(e2, f.act, two, f.st); r["ok"] != false || r["reason"] != "prohibition violated: n,m" {
		t.Errorf("violation: %v", r)
	}
}

func TestGoASafetyBindingID(t *testing.T) {
	f := goAFx(t)
	ev := f.evidence()
	id, err := SafetyBindingID(ev, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	eh, _ := HashCanonical(ev)
	want, _ := HashCanonical(map[string]any{"d": SafetyEvidenceSigDomain, "signer": "signer-1", "evidence": eh, "constitution": ev["constitution"],
		"action_digest": ev["action_digest"], "state_digest": ev["state_digest"]})
	if id != want {
		t.Errorf("binding id %s want %s", id, want)
	}
	if other, _ := SafetyBindingID(ev, "signer-2"); other == id {
		t.Error("the signer is bound")
	}
	if got, err := SafetyBindingID(map[string]any{"x": 1.5}, "s"); got != "" || err == nil {
		t.Errorf("unhashable evidence: %q %v", got, err)
	}
	// all three bound members present, one other member unhashable: the canonicalizer error is returned, not an id
	bad := map[string]any{"x": 1.5, "constitution": "c", "action_digest": "a", "state_digest": "s"}
	if got, err := SafetyBindingID(bad, "s"); got != "" || err == nil {
		t.Errorf("unhashable evidence with bound members: %q %v", got, err)
	}
}

func TestGoASignSafetyEvidence(t *testing.T) {
	f := goAFx(t)
	ev := f.evidence()
	unsupported := "signSafetyEvidence: unsupported evidence"
	unbound := "signSafetyEvidence: unbound evidence"
	rows := []struct {
		name   string
		ev     any
		signer string
		seed   []byte
		want   string
	}{
		{"not an object", "x", f.kp.Public, f.seed, unsupported},
		{"version 2", goAMut(ev, func(m map[string]any) { m["v"] = 2 }), f.kp.Public, f.seed, unsupported},
		{"no version", goAMut(ev, func(m map[string]any) { delete(m, "v") }), f.kp.Public, f.seed, unsupported},
		{"version before digests", goAMut(ev, func(m map[string]any) { m["v"] = 2; delete(m, "constitution") }), f.kp.Public, f.seed, unsupported},
		{"no constitution", goAMut(ev, func(m map[string]any) { delete(m, "constitution") }), f.kp.Public, f.seed, unbound},
		{"no action digest", goAMut(ev, func(m map[string]any) { delete(m, "action_digest") }), f.kp.Public, f.seed, unbound},
		{"no state digest", goAMut(ev, func(m map[string]any) { delete(m, "state_digest") }), f.kp.Public, f.seed, unbound},
		{"empty digest", goAMut(ev, func(m map[string]any) { m["state_digest"] = "" }), f.kp.Public, f.seed, unbound},
		{"numeric digest", goAMut(ev, func(m map[string]any) { m["action_digest"] = 5 }), f.kp.Public, f.seed, unbound},
		{"unhashable constitution", goAMut(ev, func(m map[string]any) { m["constitution"] = Unhashable }), f.kp.Public, f.seed, unbound},
		{"unhashable action", goAMut(ev, func(m map[string]any) { m["action_digest"] = Unhashable }), f.kp.Public, f.seed, unbound},
		{"unhashable state", goAMut(ev, func(m map[string]any) { m["state_digest"] = Unhashable }), f.kp.Public, f.seed, unbound},
		{"digests before signer", goAMut(ev, func(m map[string]any) { delete(m, "constitution") }), "", f.seed, unbound},
		{"signer missing", ev, "", f.seed, "signSafetyEvidence: signer missing"},
	}
	for _, r := range rows {
		out, err := SignSafetyEvidence(r.ev, r.seed, r.signer)
		if err == nil || out != nil || err.Error() != r.want {
			t.Errorf("%s: %v %v", r.name, out, err)
		}
	}
	if out, err := SignSafetyEvidence(ev, []byte("short"), f.kp.Public); err == nil || out != nil {
		t.Errorf("a bad seed must not sign: %v %v", out, err)
	}
	s, err := SignSafetyEvidence(ev, f.seed, f.kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := SafetyBindingID(s["evidence"].(map[string]any), f.kp.Public)
	if s["signer"] != f.kp.Public || s["id"] != id || len(s) != 4 {
		t.Errorf("signed: %v", s)
	}
	if sig, _ := s["sig"].(string); !verifyB64u(f.kp.Public, pDomainMessage(SafetyEvidenceSigDomain, id), sig) {
		t.Error("the signature covers the binding id")
	}
}

func TestGoAPropOf(t *testing.T) {
	if propOf("x", "k") != nil || propOf(map[string]any{"k": "v"}, "k") != "v" || propOf(map[string]any{}, "k") != nil {
		t.Error("propOf")
	}
	defer func() {
		if recover() == nil {
			t.Error("reading a member of null must fail")
		}
	}()
	propOf(nil, "k")
}

func TestGoAVerifySignedSafetyEvidence(t *testing.T) {
	f := goAFx(t)
	ev := f.evidence()
	signed := f.sign(t, ev)
	full := f.full()
	check := func(s, e any) map[string]any { return VerifySignedSafetyEvidence(s, e) }
	if r := check(signed, full); r["ok"] != true {
		t.Fatalf("fresh: %v", r)
	}
	reason := func(name string, r map[string]any, want string) {
		t.Helper()
		if r["ok"] != false || r["reason"] != want {
			t.Errorf("%s: got %v want %q", name, r, want)
		}
	}
	reason("signed not an object", check("x", full), "malformed input")
	reason("expected not an object", check(signed, "x"), "malformed input")
	reason("both not objects", check("x", "y"), "malformed input")
	reason("no evidence", check(goAMut(signed, func(m map[string]any) { delete(m, "evidence") }), full), "malformed input")
	reason("evidence not an object", check(goAMut(signed, func(m map[string]any) { m["evidence"] = 5 }), full), "malformed input")
	reason("version", check(goAMut(signed, func(m map[string]any) { m["evidence"].(map[string]any)["v"] = 2 }), full), "unsupported evidence version")

	// pinned signers
	with := func(f2 func(m map[string]any)) map[string]any { return goAMut(full, f2) }
	reason("signer missing", check(signed, with(func(m map[string]any) { delete(m, "signer") })), "no pinned signer")
	reason("signer list empty", check(signed, with(func(m map[string]any) { m["signer"] = []any{} })), "no pinned signer")
	reason("signer empty string", check(signed, with(func(m map[string]any) { m["signer"] = "" })), "no pinned signer")
	reason("signer list with an empty", check(signed, with(func(m map[string]any) { m["signer"] = []any{f.kp.Public, ""} })), "no pinned signer")
	reason("signer list with a number", check(signed, with(func(m map[string]any) { m["signer"] = []any{5, f.kp.Public} })), "no pinned signer")
	reason("signer not listed", check(signed, with(func(m map[string]any) { m["signer"] = "someone-else" })), "signer not trusted")
	reason("signer list without it", check(signed, with(func(m map[string]any) { m["signer"] = []any{"a", "b"} })), "signer not trusted")
	reason("signed without a signer", check(goAMut(signed, func(m map[string]any) { delete(m, "signer") }), full), "signer not trusted")
	reason("signed with a numeric signer", check(goAMut(signed, func(m map[string]any) { m["signer"] = 5 }), full), "signer not trusted")
	if r := check(signed, with(func(m map[string]any) { m["signer"] = []any{"a", f.kp.Public} })); r["ok"] != true {
		t.Errorf("signer list: %v", r)
	}

	// the three bindings must each be stated, either as the object or as its digest
	ad, _ := HashCanonical(f.act)
	cid, _ := ConstitutionID(f.c)
	sd, _ := StateDigest(f.st)
	digests := map[string]any{"signer": f.kp.Public, "actionDigest": ad, "constitutionId": cid, "stateDigest": sd}
	if r := check(signed, digests); r["ok"] != true {
		t.Errorf("digests only: %v", r)
	}
	reason("no action", check(signed, goAMut(digests, func(m map[string]any) { delete(m, "actionDigest") })), "unbound: action not specified")
	reason("no constitution", check(signed, goAMut(digests, func(m map[string]any) { delete(m, "constitutionId") })), "unbound: constitution not specified")
	reason("no state", check(signed, goAMut(digests, func(m map[string]any) { delete(m, "stateDigest") })), "unbound: state not specified")
	for _, key := range []string{"actionDigest", "constitutionId", "stateDigest"} {
		obj := map[string]string{"actionDigest": "action", "constitutionId": "constitution", "stateDigest": "state"}[key]
		mixed := goAMut(digests, func(m map[string]any) { delete(m, key); m[obj] = full[obj] })
		if r := check(signed, mixed); r["ok"] != true {
			t.Errorf("%s given as the object only: %v", key, r)
		}
	}

	// the signature and its binding
	reason("binding id", check(goAMut(signed, func(m map[string]any) { m["id"] = "x" }), full), "binding id mismatch")
	reason("no binding id", check(goAMut(signed, func(m map[string]any) { delete(m, "id") }), full), "binding id mismatch")
	reason("numeric binding id", check(goAMut(signed, func(m map[string]any) { m["id"] = 5 }), full), "binding id mismatch")
	reason("evidence changed after signing", check(goAMut(signed, func(m map[string]any) { m["evidence"].(map[string]any)["now"] = 7 }), full), "binding id mismatch")
	reason("bad signature", check(goAMut(signed, func(m map[string]any) { m["sig"] = "AAAA" }), full), "bad signature")
	reason("no signature", check(goAMut(signed, func(m map[string]any) { delete(m, "sig") }), full), "bad signature")
	reason("numeric signature", check(goAMut(signed, func(m map[string]any) { m["sig"] = 5 }), full), "bad signature")

	// action binding
	reason("action and digest disagree", check(signed, with(func(m map[string]any) { m["actionDigest"] = "x" })), "expected action and digest disagree")
	if r := check(signed, with(func(m map[string]any) { m["actionDigest"] = ad })); r["ok"] != true {
		t.Errorf("action with its own digest: %v", r)
	}
	other := goAAct("read", "")
	reason("another action", check(signed, with(func(m map[string]any) { m["action"] = other })), "action digest mismatch (evidence bound to another action)")
	reason("another action digest", check(signed, goAMut(digests, func(m map[string]any) { m["actionDigest"] = "x" })), "action digest mismatch (evidence bound to another action)")

	// constitution binding
	reason("constitution and id disagree", check(signed, with(func(m map[string]any) { m["constitutionId"] = "x" })), "expected constitution and id disagree")
	if r := check(signed, with(func(m map[string]any) { m["constitutionId"] = cid })); r["ok"] != true {
		t.Errorf("constitution with its own id: %v", r)
	}
	reason("another constitution", check(signed, with(func(m map[string]any) { m["constitution"] = goAC(goANever) })), "constitution mismatch (evidence bound to another constitution)")
	reason("another constitution id", check(signed, goAMut(digests, func(m map[string]any) { m["constitutionId"] = "x" })), "constitution mismatch (evidence bound to another constitution)")
	reason("constitution not hashable", check(signed, with(func(m map[string]any) { m["constitution"] = "x" })), failClosedVerifyError)

	// state binding
	reason("state and digest disagree", check(signed, with(func(m map[string]any) { m["stateDigest"] = "x" })), "expected state and digest disagree")
	if r := check(signed, with(func(m map[string]any) { m["stateDigest"] = sd })); r["ok"] != true {
		t.Errorf("state with its own digest: %v", r)
	}
	reason("another state", check(signed, with(func(m map[string]any) { m["state"] = goAStateJ("2000000", "0", "null", "{}", "{}") })), "state digest mismatch (evidence bound to another state)")
	reason("another state digest", check(signed, goAMut(digests, func(m map[string]any) { m["stateDigest"] = "x" })), "state digest mismatch (evidence bound to another state)")
	reason("state not hashable", check(signed, with(func(m map[string]any) { m["state"] = goAJ(`{}`) })), failClosedVerifyError)
}

func TestGoAVerifySignedSafetyEvidenceRows(t *testing.T) {
	f := goAFx(t)
	base := f.evidence()
	digests := func() map[string]any {
		ad, _ := HashCanonical(f.act)
		cid, _ := ConstitutionID(f.c)
		sd, _ := StateDigest(f.st)
		return map[string]any{"signer": f.kp.Public, "actionDigest": ad, "constitutionId": cid, "stateDigest": sd}
	}
	reason := func(name string, r map[string]any, want string) {
		t.Helper()
		if r["ok"] != false || r["reason"] != want {
			t.Errorf("%s: got %v want %q", name, r, want)
		}
	}
	sign := func(f2 func(m map[string]any)) map[string]any { return f.sign(t, goAMut(base, f2)) }
	exp := digests()
	reason("evaluated not a list", VerifySignedSafetyEvidence(sign(func(m map[string]any) { m["evaluated"] = "x" }), exp), "malformed evidence")
	reason("violated not a list", VerifySignedSafetyEvidence(sign(func(m map[string]any) { m["violated"] = "x" }), exp), "malformed evidence")
	reason("evaluated missing", VerifySignedSafetyEvidence(sign(func(m map[string]any) { delete(m, "evaluated") }), exp), "malformed evidence")
	reason("violated missing", VerifySignedSafetyEvidence(sign(func(m map[string]any) { delete(m, "violated") }), exp), "malformed evidence")
	reason("row id not a string", VerifySignedSafetyEvidence(sign(func(m map[string]any) {
		m["evaluated"] = []any{map[string]any{"id": 5, "result": "pass"}}
	}), exp), "malformed evidence")
	// a row without an id is not malformed by itself
	if r := VerifySignedSafetyEvidence(sign(func(m map[string]any) { m["evaluated"] = []any{map[string]any{"result": "pass"}} }), exp); r["ok"] != true {
		t.Errorf("row without an id: %v", r)
	}
	// the verdict must follow the rows
	pass := map[string]any{"id": "n", "kind": "never", "result": "pass"}
	viol := map[string]any{"id": "n", "kind": "never", "result": "violated"}
	for name, mut := range map[string]func(m map[string]any){
		"ok but a violated row":     func(m map[string]any) { m["evaluated"] = []any{viol}; m["violated"] = []any{}; m["ok"] = true },
		"ok but a violated id":      func(m map[string]any) { m["evaluated"] = []any{pass}; m["violated"] = []any{"n"}; m["ok"] = true },
		"ok but a row that is null": func(m map[string]any) { m["evaluated"] = []any{nil}; m["violated"] = []any{}; m["ok"] = true },
		"ok but a number row":       func(m map[string]any) { m["evaluated"] = []any{5}; m["violated"] = []any{}; m["ok"] = true },
		"ok but a row without result": func(m map[string]any) {
			m["evaluated"] = []any{map[string]any{"id": "n"}}
			m["violated"] = []any{}
			m["ok"] = true
		},
		"not ok but clean rows":  func(m map[string]any) { m["evaluated"] = []any{pass}; m["violated"] = []any{}; m["ok"] = false },
		"ok is not a boolean":    func(m map[string]any) { m["ok"] = "true" },
		"ok is missing":          func(m map[string]any) { delete(m, "ok") },
		"ok false and no rows":   func(m map[string]any) { m["evaluated"] = []any{}; m["violated"] = []any{}; m["ok"] = false },
		"ok false only violated": func(m map[string]any) { m["evaluated"] = []any{pass}; m["violated"] = []any{"x"}; m["ok"] = true },
	} {
		reason(name, VerifySignedSafetyEvidence(sign(mut), exp), "evidence verdict inconsistent with rows")
	}
	// a violated verdict is refused unless the caller opts out of requiring ok
	violEv := func(m map[string]any) { m["evaluated"] = []any{viol}; m["violated"] = []any{"n"}; m["ok"] = false }
	reason("violation refused", VerifySignedSafetyEvidence(sign(violEv), exp), "prohibition violated: n")
	if r := VerifySignedSafetyEvidence(sign(violEv), goAMut(exp, func(m map[string]any) { m["requireOk"] = false })); r["ok"] != true {
		t.Errorf("requireOk false: %v", r)
	}
	reason("requireOk true", VerifySignedSafetyEvidence(sign(violEv), goAMut(exp, func(m map[string]any) { m["requireOk"] = true })), "prohibition violated: n")
	reason("requireOk a string", VerifySignedSafetyEvidence(sign(violEv), goAMut(exp, func(m map[string]any) { m["requireOk"] = "no" })), "prohibition violated: n")
}

func TestGoAVerifySignedSafetyEvidenceRecompute(t *testing.T) {
	f := goAFx(t)
	full := f.full()
	reason := func(name string, r map[string]any, want string) {
		t.Helper()
		if r["ok"] != false || r["reason"] != want {
			t.Errorf("%s: got %v want %q", name, r, want)
		}
	}
	// claims ok but the monitor disagrees: the row set differs from the recomputation
	lying := goAMut(f.evidence(), func(m map[string]any) { m["now"] = 5 })
	reason("ok evidence that does not reproduce", VerifySignedSafetyEvidence(f.sign(t, lying), full), "evidence does not reproduce")
	// a violated verdict that is also tampered reports the mismatch, not the violation
	vc := goAC(goANever)
	vev := ProveSafety(f.act, vc, f.st)
	vfull := map[string]any{"signer": f.kp.Public, "action": f.act, "constitution": vc, "state": f.st}
	reason("honest violation", VerifySignedSafetyEvidence(f.sign(t, vev), vfull), "prohibition violated: n")
	tampered := goAMut(vev, func(m map[string]any) { m["now"] = 5 })
	reason("tampered violation", VerifySignedSafetyEvidence(f.sign(t, tampered), vfull), "evidence does not reproduce")
	if r := VerifySignedSafetyEvidence(f.sign(t, vev), goAMut(vfull, func(m map[string]any) { m["requireOk"] = false })); r["ok"] != true {
		t.Errorf("an honest violation with requireOk false: %v", r)
	}
	if r := VerifySignedSafetyEvidence(f.sign(t, tampered), goAMut(vfull, func(m map[string]any) { m["requireOk"] = false })); r["ok"] != false {
		t.Errorf("a tampered violation is refused even with requireOk false: %v", r)
	}
	// ok evidence for a state the monitor would refuse
	st2 := goAStateJ("1000000", "0", "null", `{"c":[{"t":999999,"amount":9}]}`, "{}")
	capC := goAC(`{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.n","max":10}`)
	act2 := goAAct("pay", `"n":5`)
	okEv := ProveSafety(act2, capC, goAGenesis("{}", "{}"))
	forged := map[string]any{"signer": f.kp.Public, "action": act2, "constitution": capC, "state": st2}
	okDig, _ := StateDigest(st2)
	bound := goAMut(okEv, func(m map[string]any) { m["state_digest"] = okDig })
	reason("ok evidence for a worse state", VerifySignedSafetyEvidence(f.sign(t, bound), forged), "evidence does not reproduce")
}

func TestGoAVerifySignedSafetyEvidenceCoverage(t *testing.T) {
	f := goAFx(t)
	two := goAC(`{"id":"a","kind":"never","when":{"verb":"zzz"}}`, `{"id":"b","kind":"never","when":{"verb":"zzz"}}`)
	ev := ProveSafety(f.act, two, f.st)
	ad, _ := HashCanonical(f.act)
	sd, _ := StateDigest(f.st)
	exp := func(c any) map[string]any {
		return map[string]any{"signer": f.kp.Public, "actionDigest": ad, "constitution": c, "stateDigest": sd}
	}
	if r := VerifySignedSafetyEvidence(f.sign(t, ev), exp(two)); r["ok"] != true {
		t.Errorf("covered: %v", r)
	}
	// evidence bound to the constitution but listing fewer rows
	fewer := goAMut(ev, func(m map[string]any) { m["evaluated"] = m["evaluated"].([]any)[:1] })
	r := VerifySignedSafetyEvidence(f.sign(t, fewer), exp(two))
	if r["ok"] != false || r["reason"] != "evidence does not cover every invariant" {
		t.Errorf("fewer rows: %v", r)
	}
	// the same count with a different id
	swapped := goAMut(ev, func(m map[string]any) {
		rows := m["evaluated"].([]any)
		rows[1].(map[string]any)["id"] = "zz"
	})
	r = VerifySignedSafetyEvidence(f.sign(t, swapped), exp(two))
	if r["ok"] != false || r["reason"] != "evidence does not cover every invariant" {
		t.Errorf("swapped id: %v", r)
	}
	// a null row does not cover anything
	nulled := goAMut(ev, func(m map[string]any) {
		rows := m["evaluated"].([]any)
		rows[1] = map[string]any{"result": "pass"}
	})
	r = VerifySignedSafetyEvidence(f.sign(t, nulled), exp(two))
	if r["ok"] != false || r["reason"] != "evidence does not cover every invariant" {
		t.Errorf("row without id: %v", r)
	}
	// the coverage check is only for evidence that claims ok: a violated one is judged by the verdict
	viol := goAMut(ev, func(m map[string]any) {
		m["evaluated"] = []any{map[string]any{"id": "a", "kind": "never", "result": "violated"}}
		m["violated"] = []any{"a"}
		m["ok"] = false
	})
	r = VerifySignedSafetyEvidence(f.sign(t, viol), exp(two))
	if r["ok"] != false || r["reason"] != "prohibition violated: a" {
		t.Errorf("violated evidence: %v", r)
	}
	// a constitution that is itself malformed never verifies
	badC := goAJ(`{"version":2,"principal":"P","invariants":[]}`)
	bev := ProveSafety(f.act, badC, f.st)
	r = VerifySignedSafetyEvidence(f.sign(t, bev), exp(badC))
	if r["ok"] != false || r["reason"] != "constitution malformed: unsupported version 2" {
		t.Errorf("malformed constitution: %v", r)
	}
}

func TestGoAVerifySignedSafetyEvidencePrincipal(t *testing.T) {
	f := goAFx(t)
	pseed := make([]byte, 32)
	pseed[0] = 33
	pkp, _ := KeyPairFromSeed(pseed)
	c := goAJ(`{"version":1,"principal":"` + pkp.Public + `","invariants":[{"id":"n","kind":"never","when":{"verb":"zzz"}}]}`)
	sc, err := SignConstitution(c, pseed)
	if err != nil {
		t.Fatal(err)
	}
	ev := ProveSafety(f.act, sc, f.st)
	signed := f.sign(t, ev)
	ad, _ := HashCanonical(f.act)
	sd, _ := StateDigest(f.st)
	exp := func(mut func(m map[string]any)) map[string]any {
		m := map[string]any{"signer": f.kp.Public, "actionDigest": ad, "constitution": sc, "stateDigest": sd, "principal": pkp.Public}
		if mut != nil {
			mut(m)
		}
		return m
	}
	reason := func(name string, r map[string]any, want string) {
		t.Helper()
		if r["ok"] != false || r["reason"] != want {
			t.Errorf("%s: got %v want %q", name, r, want)
		}
	}
	if r := VerifySignedSafetyEvidence(signed, exp(nil)); r["ok"] != true {
		t.Fatalf("pinned principal: %v", r)
	}
	if r := VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) { delete(m, "principal") })); r["ok"] != true {
		t.Errorf("no pin: %v", r)
	}
	reason("another principal", VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) { m["principal"] = "someone-else" })), "constitution not authentic: principal mismatch")
	reason("empty principal", VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) { m["principal"] = "" })), "constitution not authentic: principal mismatch")
	reason("numeric principal", VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) { m["principal"] = 5 })), "constitution not authentic: principal mismatch")
	reason("no constitution object", VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) { delete(m, "constitution"); m["constitutionId"] = ev["constitution"] })), "principal pin requires a signed constitution")
	reason("unsigned constitution", VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) { m["constitution"] = c })), "principal pin requires a signed constitution")
	reason("numeric signature on the constitution", VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) {
		m["constitution"] = goAMut(sc, func(x map[string]any) { x["sig"] = 5 })
	})), "principal pin requires a signed constitution")
	reason("forged constitution signature", VerifySignedSafetyEvidence(signed, exp(func(m map[string]any) {
		m["constitution"] = goAMut(sc, func(x map[string]any) { x["sig"] = "AAAA" })
	})), "constitution not authentic: bad signature")
}

func TestGoAComposeAuthority(t *testing.T) {
	f := goAFx(t)
	okC, badC := f.c, goAC(goANever)
	rows := []struct {
		name      string
		permitted any
		c         any
		allow     bool
		by        string
		permit    bool
	}{
		{"permitted and clean", true, okC, true, "none", true},
		{"permitted and violating", true, badC, false, "prohibition", true},
		{"not permitted and clean", false, okC, false, "permission", false},
		{"not permitted and violating", false, badC, false, "prohibition", false},
		{"permitted is exactly true", "true", okC, false, "permission", false},
		{"permitted missing", nil, okC, false, "permission", false},
	}
	for _, r := range rows {
		got := ComposeAuthority(r.permitted, f.act, r.c, f.st)
		if got["allow"] != r.allow || got["decidedBy"] != r.by || got["permitted"] != r.permit || got["prohibition"] == nil {
			t.Errorf("%s: %v", r.name, got)
		}
	}
}

func TestGoACheckAndAdvance(t *testing.T) {
	f := goAFx(t)
	out := CheckAndAdvance(true, f.act, f.c, f.st, nil)
	next, _ := out["next"].(map[string]any)
	if out["allow"] != true || out["decidedBy"] != "none" || out["evidence"] == nil || out["prohibition"] == nil || next["seq"] != goAN("1") || len(out) != 5 {
		t.Fatalf("allow: %v", out)
	}
	if _, has := out["reason"]; has {
		t.Error("an allow carries no reason")
	}
	if ev := out["evidence"].(map[string]any); ev["ok"] != true {
		t.Errorf("evidence: %v", ev)
	}

	// refusals keep the pre-state and carry no reason unless there is one
	ref := CheckAndAdvance(false, f.act, f.c, f.st, nil)
	if ref["allow"] != false || ref["decidedBy"] != "permission" || goACanon(ref["next"]) != goACanon(f.st) {
		t.Errorf("not permitted: %v", ref)
	}
	if _, has := ref["reason"]; has {
		t.Errorf("a plain refusal has no reason: %v", ref)
	}
	if ref := CheckAndAdvance(true, f.act, goAC(goANever), f.st, nil); ref["allow"] != false || ref["decidedBy"] != "prohibition" {
		t.Errorf("violating: %v", ref)
	}
	if ref := CheckAndAdvance(false, f.act, goAC(goANever), f.st, nil); ref["allow"] != false || ref["decidedBy"] != "prohibition" {
		t.Errorf("violating and not permitted: %v", ref)
	}

	// compare-and-set guards
	stale := func(opts map[string]any) map[string]any { return CheckAndAdvance(true, f.act, f.c, f.st, opts) }
	if r := stale(map[string]any{"expectedSeq": goAN("0")}); r["allow"] != true {
		t.Errorf("matching seq: %v", r)
	}
	if r := stale(map[string]any{"expectedSeq": 0}); r["allow"] != true {
		t.Errorf("matching seq (int): %v", r)
	}
	for _, v := range []any{goAN("1"), "0", nil} {
		if r := stale(map[string]any{"expectedSeq": v}); r["allow"] != false || r["decidedBy"] != "state" || r["reason"] != "stale state head (seq)" {
			t.Errorf("seq %v: %v", v, r)
		}
	}
	if r := CheckAndAdvance(true, f.act, f.c, "x", map[string]any{"expectedSeq": goAN("0")}); r["allow"] != false || r["reason"] != "stale state head (seq)" {
		t.Errorf("seq with a state that is not an object: %v", r)
	}
	sd, _ := StateDigest(f.st)
	if r := stale(map[string]any{"expectedStateDigest": sd}); r["allow"] != true {
		t.Errorf("matching digest: %v", r)
	}
	for _, v := range []any{"x", []any{sd}, goAN("5"), nil} {
		if r := stale(map[string]any{"expectedStateDigest": v}); r["allow"] != false || r["decidedBy"] != "state" || r["reason"] != "stale state head (digest)" {
			t.Errorf("digest %v: %v", v, r)
		}
	}
	// the guards run before the decision
	if r := CheckAndAdvance(false, f.act, f.c, f.st, map[string]any{"expectedSeq": goAN("9")}); r["decidedBy"] != "state" {
		t.Errorf("guard first: %v", r)
	}
	if r := CheckAndAdvance(false, f.act, f.c, f.st, map[string]any{"expectedStateDigest": "x"}); r["decidedBy"] != "state" {
		t.Errorf("digest guard first: %v", r)
	}
}

func TestGoACheckAndAdvanceAdvanceFailure(t *testing.T) {
	// the monitor admits it, but the next state would carry more entries than a state may
	// 1024 ledger keys is a valid state (<= maxStateKeys); the rate's own new key makes the next one 1025. (100000 entries cannot be
	// built: the strict parser caps a state at 1 MiB of JSON, so the entry-total bound is covered by TestGoAStateEntryTotal.)
	st := goAState(func(m map[string]any) { m["ledger"] = goAKeys(1024, goAEntries(1)) })
	r := CheckAndAdvance(true, goAAct("pay", ""), goAC(goARate), st, nil)
	if r["allow"] != false || r["decidedBy"] != "state" || r["reason"] != "advance failed: resulting state invalid" {
		t.Errorf("advance failure: %v", r)
	}
	if ev := r["evidence"].(map[string]any); ev["ok"] != true {
		t.Errorf("the evidence is still the pre-state's: %v", ev["ok"])
	}
}
