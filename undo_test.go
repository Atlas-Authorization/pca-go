package pca

import (
	"crypto/sha256"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Undo windows: the shared vectors (conformance/undo-vectors.json, produced by the TypeScript reference; a missing file FAILS),
// exact-outcome kill tests, and the undo admission hook in Authorize and RequirePCA.

func undoVectors(t *testing.T) map[string]any {
	t.Helper()
	d := load(t, "undo-vectors.json")
	if d["format"] != "pca-undo-vectors" || num(d["ver"]) != 1 {
		t.Fatalf("format %v ver %v", d["format"], d["ver"])
	}
	return d
}

func undoSigner(t *testing.T) *KeyPair {
	t.Helper()
	seed := sha256.Sum256([]byte("atlas-pca/undo-vectors/signer"))
	k, err := KeyPairFromSeed(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func undoTokenRecordOf(m map[string]any) UndoTokenRecord {
	rd, _ := m["render_digest"].(string) // absent = the record carries no render (binds "")
	return UndoTokenRecord{ID: m["id"].(string), Aud: m["aud"].(string), Principal: m["principal"].(string),
		CompensationDigest: m["compensation_digest"].(string), RenderDigest: rd, WindowEnd: num(m["window_end"])}
}

func optF(v any) *float64 {
	if v == nil {
		return nil
	}
	f := jsF(v)
	return &f
}

// ---- vectors ------------------------------------------------------------------------------------------------------------

func TestUndoVectorsSignerAndCompensation(t *testing.T) {
	d := undoVectors(t)
	s := d["signer"].(map[string]any)
	if k := undoSigner(t); k.Public != s["public"] {
		t.Fatalf("signer %s, want %v", k.Public, s["public"])
	}
	for _, x := range d["compensation"].([]any) {
		c := x.(map[string]any)
		m := c["compensation"].(map[string]any)
		tp, _ := m["target_param"].(string)
		got, err := CompensationDigest(UndoCompensation{Verb: m["verb"].(string), Resource: m["resource"].(string), Params: m["params"].(map[string]any),
			UndoOf: m["undo_of"].(string), DefDigest: m["def_digest"].(string), TargetParam: tp})
		if err != nil || got != c["digest"] {
			t.Errorf("%v: %s %v, want %v", c["name"], got, err, c["digest"])
		}
	}
}

func TestUndoVectorsToken(t *testing.T) {
	d := undoVectors(t)
	v := d["token"].(map[string]any)
	tok, err := SignUndoToken(undoTokenRecordOf(v["record"].(map[string]any)), undoSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	sameCanonJSON(t, "token", tok, v["token"])
	if enc, err := EncodeUndoToken(tok); err != nil || enc != v["encoded"] {
		t.Fatalf("encoded %s %v", enc, err)
	}
	sameCanonJSON(t, "decoded", DecodeUndoToken(v["encoded"].(string)), v["token"])
	if dg, err := UndoTokenDigest(v["token"].(map[string]any)); err != nil || dg != v["digest"] {
		t.Fatalf("digest %s %v, want %v", dg, err, v["digest"])
	}
	codes := map[string]bool{}
	for _, x := range v["checks"].([]any) {
		c := x.(map[string]any)
		got := UndoTokenCheck(c["token"], c["signer"].(string), undoTokenRecordOf(c["record"].(map[string]any)), num(c["now"]))
		if got != c["expect"] {
			t.Errorf("%v: %s, want %v", c["name"], got, c["expect"])
		}
		codes[got] = true
	}
	for _, c := range []string{"ok", "malformed", "signer", "signature", "record", "binding", "expired"} {
		if !codes[c] {
			t.Errorf("no token vector yields %s", c)
		}
	}
}

func TestUndoVectorsReceiptsAndChains(t *testing.T) {
	d := undoVectors(t)
	key := undoSigner(t)
	r := d["receipts"].(map[string]any)
	for i, x := range r["list"].([]any) {
		item := x.(map[string]any)
		want := item["receipt"].(map[string]any)
		got, err := SignUndoReceipt(UndoReceiptBody{Record: want["record"].(string), Event: want["event"].(string), State: want["state"].(string),
			At: num(want["at"]), CompensationDigest: want["compensation_digest"].(string), Prev: want["prev"].(string), Note: want["note"].(string)}, key)
		if err != nil {
			t.Fatal(err)
		}
		sameCanonJSON(t, "receipt", got, want)
		if dg, err := UndoReceiptDigest(want); err != nil || dg != item["digest"] {
			t.Fatalf("receipt %d digest %s %v", i, dg, err)
		}
		if !VerifyUndoReceipt(want, key.Public) || VerifyUndoReceipt(want, d["signer"].(map[string]any)["other_public"].(string)) {
			t.Fatalf("receipt %d verification", i)
		}
	}
	for _, x := range r["chains"].([]any) {
		c := x.(map[string]any)
		rec := c["record"].(map[string]any)
		e := UndoReceiptChainError(UndoChainRecord{ID: rec["id"].(string), CompensationDigest: rec["compensation_digest"].(string), State: rec["state"].(string),
			Receipts: c["receipts"].([]any)}, c["signer"].(string))
		if ok := c["expect"].(map[string]any)["ok"] == true; (e == "") != ok {
			t.Errorf("%v: %q, want ok=%v", c["name"], e, ok)
		}
	}
}

func TestUndoVectorsTransitions(t *testing.T) {
	d := undoVectors(t)
	for _, x := range d["transitions"].([]any) {
		c := x.(map[string]any)
		e := c["expect"].(map[string]any)
		got := UndoTransition(c["record"], c["event"], jsF(c["now"]))
		if got.Outcome != e["outcome"] {
			t.Errorf("%v: %+v, want %v", c["name"], got, e)
			continue
		}
		switch got.Outcome {
		case "refused":
			if got.Code != e["code"] || got.Reason == "" {
				t.Errorf("%v: code %s (%s), want %v", c["name"], got.Code, got.Reason, e["code"])
			}
		case "applied":
			if got.Record["state"] != e["state"] || jsF(got.Record["ver"]) != jsF(e["ver"]) || got.Event == "" {
				t.Errorf("%v: %+v, want %v", c["name"], got, e)
			}
			if a, has := e["attempt"]; has && jsF(got.Record["attempt"]) != jsF(a) {
				t.Errorf("%v: attempt %v, want %v", c["name"], got.Record["attempt"], a)
			}
		case "replayed":
			sameCanonJSON(t, c["name"].(string), got.Record, c["record"])
		}
	}
}

func TestUndoVectorsWindowAndObligation(t *testing.T) {
	d := undoVectors(t)
	for _, x := range d["window"].([]any) {
		c := x.(map[string]any)
		p := c["policy"].(map[string]any)
		got := ResolveUndoWindow(optF(c["requested"]), UndoWindowPolicy{MinMs: optF(p["minMs"]), MaxMs: optF(p["maxMs"]), DefaultMs: optF(p["defaultMs"])})
		if got != num(c["expect"]) {
			t.Errorf("%v: %d, want %v", c["name"], got, c["expect"])
		}
	}
	for _, x := range d["obligation"].([]any) {
		c := x.(map[string]any)
		if ok := ObligationError(c["obligation"]) == ""; ok != (c["expect"].(map[string]any)["ok"] == true) {
			t.Errorf("%v: ok=%v (%s)", c["name"], ok, ObligationError(c["obligation"]))
		}
	}
}

// ---- kill tests -------------------------------------------------------------------------------------------------------------

func TestUndoKillTokenCheckOrder(t *testing.T) {
	key := undoSigner(t)
	other, _ := NewKeyPair()
	rec := UndoTokenRecord{ID: "op_9", Aud: "rs", Principal: "pr", CompensationDigest: "cd", RenderDigest: "", WindowEnd: 5000}
	tok, err := SignUndoToken(rec, key)
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(m map[string]any)) map[string]any {
		m := copyMap(tok)
		f(m)
		return m
	}
	with := func(f func(r *UndoTokenRecord)) UndoTokenRecord {
		r := rec
		f(&r)
		return r
	}
	for name, c := range map[string]struct {
		tok    any
		signer string
		rec    UndoTokenRecord
		now    int64
		want   string
	}{
		"ok-before":         {tok, key.Public, rec, 0, "ok"},
		"ok-at-exp":         {tok, key.Public, rec, 5000, "ok"},
		"expired-after-exp": {tok, key.Public, rec, 5001, "expired"},
		"nil":               {nil, key.Public, rec, 0, "malformed"},
		"missing-member":    {mut(func(m map[string]any) { delete(m, "render_digest") }), key.Public, rec, 0, "malformed"},
		"extra-member":      {mut(func(m map[string]any) { m["x"] = 1 }), key.Public, rec, 0, "malformed"},
		"v2":                {mut(func(m map[string]any) { m["v"] = 2 }), key.Public, rec, 0, "malformed"},
		"exp-fraction":      {mut(func(m map[string]any) { m["exp"] = 1.5 }), key.Public, rec, 0, "malformed"},
		"short-sig":         {mut(func(m map[string]any) { m["sig"] = "AAAA" }), key.Public, rec, 0, "malformed"},
		"control-in-id":     {mut(func(m map[string]any) { m["record"] = "a\nb" }), key.Public, rec, 0, "malformed"},
		// each later check only once every earlier one holds: a wrong signer wins over a tampered body and a wrong record
		"signer-first":      {mut(func(m map[string]any) { m["aud"] = "x" }), other.Public, with(func(r *UndoTokenRecord) { r.ID = "y" }), 9999, "signer"},
		"signature-next":    {mut(func(m map[string]any) { m["aud"] = "x" }), key.Public, with(func(r *UndoTokenRecord) { r.ID = "y" }), 9999, "signature"},
		"record-next":       {tok, key.Public, with(func(r *UndoTokenRecord) { r.ID = "y"; r.Aud = "z" }), 9999, "record"},
		"binding-aud":       {tok, key.Public, with(func(r *UndoTokenRecord) { r.Aud = "z" }), 9999, "binding"},
		"binding-principal": {tok, key.Public, with(func(r *UndoTokenRecord) { r.Principal = "z" }), 0, "binding"},
		"binding-comp":      {tok, key.Public, with(func(r *UndoTokenRecord) { r.CompensationDigest = "z" }), 0, "binding"},
		"binding-render":    {tok, key.Public, with(func(r *UndoTokenRecord) { r.RenderDigest = "z" }), 0, "binding"},
		"binding-window":    {tok, key.Public, with(func(r *UndoTokenRecord) { r.WindowEnd = 5001 }), 0, "binding"},
		"now-unsafe":        {tok, key.Public, rec, math.MinInt64, "expired"},
	} {
		if got := UndoTokenCheck(c.tok, c.signer, c.rec, c.now); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	// the URL form round-trips and refuses anything that is not strict base64url JSON of an object
	enc, _ := EncodeUndoToken(tok)
	if UndoTokenCheck(DecodeUndoToken(enc), key.Public, rec, 0) != "ok" {
		t.Fatal("round trip")
	}
	for _, s := range []string{"", enc + "=", "!!", b64.EncodeToString([]byte("[1]")), b64.EncodeToString([]byte("{")), strings.Repeat("A", 4097)} {
		if DecodeUndoToken(s) != nil {
			t.Errorf("decoded %q", s)
		}
	}
	if _, err := SignUndoToken(rec, nil); err == nil {
		t.Fatal("signed without a key")
	}
}

func undoChain(t *testing.T, key *KeyPair, steps [][3]any) []any {
	t.Helper()
	out := []any{}
	prev := ""
	for _, s := range steps {
		r, err := SignUndoReceipt(UndoReceiptBody{Record: "op_1", Event: s[0].(string), State: s[1].(string), At: s[2].(int64), CompensationDigest: "cd", Prev: prev}, key)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
		prev, _ = UndoReceiptDigest(r)
	}
	return out
}

func TestUndoKillReceiptsAndChain(t *testing.T) {
	key := undoSigner(t)
	r, _ := SignUndoReceipt(UndoReceiptBody{Record: "op_1", Event: "opened", State: "open", At: 10, CompensationDigest: "cd"}, key)
	if !VerifyUndoReceipt(r, key.Public) || len(r) != 11 {
		t.Fatalf("baseline %v", r)
	}
	extra := copyMap(r)
	extra["x"] = "y"
	short := withoutKeys(r, "note")
	badEv := copyMap(r)
	badEv["event"] = "vetoed_twice"
	if VerifyUndoReceipt(extra, key.Public) || VerifyUndoReceipt(short, key.Public) || VerifyUndoReceipt(badEv, key.Public) || VerifyUndoReceipt("x", key.Public) {
		t.Fatal("a receipt with the wrong member set verified")
	}
	ok := func(rs []any, state string) string {
		return UndoReceiptChainError(UndoChainRecord{ID: "op_1", CompensationDigest: "cd", State: state, Receipts: rs}, key.Public)
	}
	// equal `at` is fine; the last receipt states the record state
	if e := ok(undoChain(t, key, [][3]any{{"opened", "open", int64(10)}, {"effect", "open", int64(10)}, {"vetoed", "vetoed", int64(11)}}), "vetoed"); e != "" {
		t.Fatal(e)
	}
	if e := ok(undoChain(t, key, [][3]any{{"opened", "open", int64(10)}, {"vetoed", "vetoed", int64(11)}}), "open"); e != "the last receipt does not state the record state" {
		t.Fatal(e)
	}
	if e := ok(undoChain(t, key, [][3]any{{"opened", "open", int64(10)}, {"effect", "open", int64(9)}}), "open"); e != "receipt 1 goes back in time" {
		t.Fatal(e)
	}
	if e := ok(undoChain(t, key, [][3]any{{"effect", "open", int64(10)}}), "open"); e != "the first receipt is not opened" {
		t.Fatal(e)
	}
	// prev: the first must be "", every later one the previous digest
	first, _ := SignUndoReceipt(UndoReceiptBody{Record: "op_1", Event: "opened", State: "open", At: 10, CompensationDigest: "cd", Prev: "x"}, key)
	if e := ok([]any{first}, "open"); e != "receipt 0 does not link to the previous one" {
		t.Fatal(e)
	}
	c := undoChain(t, key, [][3]any{{"opened", "open", int64(10)}, {"effect", "open", int64(11)}, {"vetoed", "vetoed", int64(12)}})
	if e := ok([]any{c[0], c[2]}, "vetoed"); e != "receipt 1 does not link to the previous one" {
		t.Fatal(e)
	}
	if e := UndoReceiptChainError(UndoChainRecord{ID: "op_2", CompensationDigest: "cd", State: "vetoed", Receipts: c}, key.Public); e != "receipt 0 is for another record" {
		t.Fatal(e)
	}
	if e := ok(nil, "open"); e != "no receipts" {
		t.Fatal(e)
	}
}

func TestUndoKillTransitions(t *testing.T) {
	open := map[string]any{"state": "open", "window_end": 1000, "ver": 3, "attempt": 0}
	veto := map[string]any{"kind": "veto", "veto": map[string]any{"at": 1, "via": "operator", "by": "p"}}
	// the window is inclusive: a veto at window_end applies, a finalize at window_end is refused
	if r := UndoTransition(open, veto, 1000); r.Outcome != "applied" || r.Event != "vetoed" || r.Note != "operator" || r.Record["state"] != "vetoed" || jsF(r.Record["ver"]) != 4 {
		t.Fatalf("veto at end: %+v", r)
	}
	if open["state"] != "open" {
		t.Fatal("the input record was modified")
	}
	if r := UndoTransition(open, veto, 1001); r.Code != "window_closed" {
		t.Fatalf("veto after end: %+v", r)
	}
	if r := UndoTransition(open, map[string]any{"kind": "finalize"}, 1000); r.Code != "window_open" {
		t.Fatalf("finalize at end: %+v", r)
	}
	if r := UndoTransition(open, map[string]any{"kind": "finalize"}, 1001); r.Outcome != "applied" || r.Event != "finalized" {
		t.Fatalf("finalize after end: %+v", r)
	}
	// abort keeps its reason (note clipped to 128, outcome reason to 512 code units); absent is "undefined"
	long := strings.Repeat("r", 600)
	r := UndoTransition(open, map[string]any{"kind": "abort", "reason": long}, 5)
	if r.Event != "aborted" || r.Note != long[:128] || r.Record["outcome"].(map[string]any)["reason"] != long[:512] {
		t.Fatalf("abort: %+v", r)
	}
	if r := UndoTransition(open, map[string]any{"kind": "abort"}, 5); r.Note != "undefined" {
		t.Fatalf("abort without reason: %+v", r)
	}
	// the result of an effect / compensation is kept; a retry counts the attempt
	if r := UndoTransition(open, map[string]any{"kind": "effect", "result": map[string]any{"id": "d"}}, 5); r.Record["effect"].(map[string]any)["result"].(map[string]any)["id"] != "d" {
		t.Fatalf("effect: %+v", r)
	}
	failed := map[string]any{"state": "compensation_failed", "window_end": 1000, "ver": 3, "attempt": 7}
	if r := UndoTransition(failed, map[string]any{"kind": "retry"}, 5); r.Event != "retried" || jsF(r.Record["attempt"]) != 8 || r.Record["state"] != "vetoed" {
		t.Fatalf("retry: %+v", r)
	}
	if r := UndoTransition(map[string]any{"state": "compensation_failed", "window_end": 1000, "ver": 3}, map[string]any{"kind": "retry"}, 5); r.Code != "invalid" {
		t.Fatalf("retry without attempt: %+v", r)
	}
	// malformed inputs are refused, never a panic
	for name, c := range map[string][2]any{
		"nil-record": {nil, veto}, "bad-ver": {map[string]any{"state": "open", "window_end": 1, "ver": "3"}, veto}, "nil-event": {open, nil},
		"veto-no-by": {open, map[string]any{"kind": "veto", "veto": map[string]any{"at": 1, "via": "token"}}},
		"veto-at":    {open, map[string]any{"kind": "veto", "veto": map[string]any{"at": 1.5, "via": "token", "by": "p"}}},
	} {
		if r := UndoTransition(c[0], c[1], 5); r.Outcome != "refused" || r.Code != "invalid" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	for _, now := range []float64{math.NaN(), math.Inf(1), 9007199254740992, 0.5} {
		if r := UndoTransition(open, veto, now); r.Code != "invalid" {
			t.Errorf("now %v: %+v", now, r)
		}
	}
}

func TestUndoKillWindowAndObligation(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for name, c := range map[string]struct {
		req  *float64
		p    UndoWindowPolicy
		want int64
	}{
		"nan":          {f(math.NaN()), UndoWindowPolicy{}, 900000},
		"inf":          {f(math.Inf(1)), UndoWindowPolicy{}, 900000},
		"floor-frac":   {f(120000.9), UndoWindowPolicy{}, 120000},
		"below-min-1":  {f(29999), UndoWindowPolicy{}, 30000},
		"at-max":       {f(86400000), UndoWindowPolicy{}, 86400000},
		"above-max-1":  {f(86400001), UndoWindowPolicy{}, 86400000},
		"host-max-at":  {f(300000), UndoWindowPolicy{MaxMs: f(300000)}, 300000},
		"host-max-up":  {f(300001), UndoWindowPolicy{MaxMs: f(300000)}, 300000},
		"host-max-big": {f(90000000), UndoWindowPolicy{MaxMs: f(100000000)}, 86400000},
		"host-min":     {f(40000), UndoWindowPolicy{MinMs: f(50000)}, 50000},
		"negative":     {f(-5), UndoWindowPolicy{}, 30000},
	} {
		if got := ResolveUndoWindow(c.req, c.p); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	ob := func(params map[string]any) string {
		return ObligationError(map[string]any{"kind": "undo_window", "params": params})
	}
	id128 := strings.Repeat("i", 128)
	if e := ob(map[string]any{"id": id128, "window_end": 0}); e != "" {
		t.Fatalf("128-char id, window_end 0: %s", e)
	}
	for name, p := range map[string]map[string]any{
		"extra":      {"id": "a", "window_end": 1, "x": 1},
		"id-129":     {"id": id128 + "i", "window_end": 1},
		"id-empty":   {"id": "", "window_end": 1},
		"negative":   {"id": "a", "window_end": -1},
		"fraction":   {"id": "a", "window_end": 1.5},
		"unsafe":     {"id": "a", "window_end": 9007199254740992.0},
		"string-end": {"id": "a", "window_end": "1"},
	} {
		if ob(p) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	// the admission's obligation: an id over 128 characters or a negative window_end is no admission
	for name, a := range map[string]UndoAdmission{"long-id": {ID: id128 + "x", WindowEnd: 1}, "negative": {ID: "a", WindowEnd: -1}, "empty-id": {WindowEnd: 1}} {
		hook := func(UndoAdmitInput) (*UndoAdmission, error) { c := a; return &c, nil }
		if adm, o := callUndoAdmit(hook, UndoAdmitInput{}); adm != nil || o != nil {
			t.Errorf("%s: admitted", name)
		}
	}
}

// ---- the admission hook in Authorize ----------------------------------------------------------------------------------------

type undoProbe struct {
	calls int
	got   UndoAdmitInput
	err   error
	panic bool
}

func (u *undoProbe) hook(a UndoAdmitInput) (*UndoAdmission, error) {
	u.calls++
	u.got = a
	if u.panic {
		panic("coordinator down")
	}
	if u.err != nil {
		return nil, u.err
	}
	return &UndoAdmission{ID: "op_1", WindowEnd: 1792930500000, Compensation: UndoCompensation{Verb: "payments.refund", Resource: "payments/acme"}}, nil
}

// (a) an escalate-class failure (not provenance) with an admitting hook: allow under a veto window.
func TestUndoHookAdmitsAnEscalation(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	defer escalateHookReasons([]string{"facts"}, []string{"facts: intent_required: q"})()
	u := &undoProbe{}
	i := in(NewMemoryStateStore(), nil, nil)
	i.Undo = u.hook
	r := Authorize(pcactn, i)
	if !r.Allow || r.Decision != "allow" || r.Status != 200 || r.Escalation != nil || u.calls != 1 {
		t.Fatalf("got %+v (calls %d)", r, u.calls)
	}
	if r.Checks["undo_window"] != "pass" || r.Checks["facts"] != "pass" || r.Checks["provenance_flow"] != "pass" {
		t.Fatalf("checks %v", r.Checks)
	}
	for n, st := range r.Checks {
		if st == "fail" {
			t.Fatalf("check %s still fails", n)
		}
	}
	if last := r.Reasons[len(r.Reasons)-1]; last != "undo_window: runs now under a veto window until 1792930500000 (compensation payments.refund)" {
		t.Fatalf("reason %q", last)
	}
	if r.Undo == nil || r.Undo.ID != "op_1" || len(r.Obligations) != 1 {
		t.Fatalf("undo %+v obligations %v", r.Undo, r.Obligations)
	}
	sameCanonJSON(t, "obligation", r.Obligations[0], map[string]any{"kind": "undo_window", "params": map[string]any{"id": "op_1", "window_end": 1792930500000}, "due": 1792930500000})
	if u.got.PCActn["grant_ref"] != pcactn["grant_ref"] || u.got.Grant["id"] != grant["id"] || u.got.Operation.Verb != "payments.send" {
		t.Fatalf("hook input %+v", u.got)
	}
	// without a hook the same request escalates
	if r := Authorize(pcactn, in(NewMemoryStateStore(), nil, nil)); r.Allow || r.Decision != "escalate" || r.Undo != nil {
		t.Fatalf("no hook: %+v", r)
	}
}

// (b) a provenance_flow escalation is never converted, even by a hook that would admit.
func TestUndoHookNotCalledForAProvenanceFlowEscalation(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	u := &undoProbe{}
	i := in(NewMemoryStateStore(), nil, nil)
	i.ArgProvenance = &ArgProvenanceOptions{Mediators: harnessPins()} // no bundle: an unlabelled sensitive call
	i.Undo = u.hook
	r := Authorize(pcactn, i)
	if r.Allow || r.Decision != "escalate" || r.Checks["provenance_flow"] != "fail" || u.calls != 0 || r.Undo != nil {
		t.Fatalf("got %+v (calls %d)", r, u.calls)
	}
}

// (c) an Intent v2 rule 17 `provenance` failure is never converted either.
func TestUndoHookNotCalledForARule17ProvenanceFailure(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	defer escalateHook("provenance")()
	u := &undoProbe{}
	i := in(NewMemoryStateStore(), nil, nil)
	i.Undo = u.hook
	r := Authorize(pcactn, i)
	if r.Allow || r.Decision != "escalate" || r.Checks["provenance"] != "fail" || r.Checks["provenance_flow"] != "pass" || u.calls != 0 {
		t.Fatalf("got %+v (calls %d)", r, u.calls)
	}
}

// (d) an escalation answer presented: the answer decides, the hook is not consulted (valid or not).
func TestUndoHookNotCalledWhenAnAnswerIsPresented(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHookReasons([]string{"facts"}, []string{"facts: intent_required: q"})()
	u := &undoProbe{}
	i := in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub})
	i.Undo = u.hook
	if r := Authorize(pcactn, i); !r.Allow || r.Escalation["answered_by"] != pub || r.Undo != nil || u.calls != 0 {
		t.Fatalf("valid answer: %+v (calls %d)", r, u.calls)
	}
	i = in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, map[string]any{"decision": "deny"}), []string{pub})
	i.Undo = u.hook
	if r := Authorize(pcactn, i); r.Allow || r.Decision != "escalate" || u.calls != 0 {
		t.Fatalf("deny answer: %+v (calls %d)", r, u.calls)
	}
}

// (e) a hook that errors or panics is no admission: the escalation stands.
func TestUndoHookErrorOrPanicLeavesTheEscalation(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	defer escalateHookReasons([]string{"facts"}, []string{"facts: intent_required: q"})()
	for name, u := range map[string]*undoProbe{"error": {err: errors.New("ledger unavailable")}, "panic": {panic: true}} {
		i := in(NewMemoryStateStore(), nil, nil)
		i.Undo = u.hook
		r := Authorize(pcactn, i)
		if r.Allow || r.Decision != "escalate" || r.Escalation == nil || r.Undo != nil || u.calls != 1 {
			t.Fatalf("%s: %+v (calls %d)", name, r, u.calls)
		}
		if _, has := r.Checks["undo_window"]; has {
			t.Fatalf("%s: undo_window reported", name)
		}
	}
}

// (f) a deny (one hard failure) never reaches the hook.
func TestUndoHookNotCalledForADeny(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	defer escalateHookReasons([]string{"facts", "leaf_signature"}, []string{"facts: intent_required: q", "leaf_signature: bad signature"})()
	u := &undoProbe{}
	i := in(NewMemoryStateStore(), nil, nil)
	i.Undo = u.hook
	if r := Authorize(pcactn, i); r.Allow || r.Decision != "deny" || u.calls != 0 {
		t.Fatalf("got %+v (calls %d)", r, u.calls)
	}
}

// RequirePCA passes the request to its Undo hook; the handler reads the admission from the context.
func TestUndoHookInRequirePCA(t *testing.T) {
	_, c, s := firstFixtureStep(t)
	defer escalateHookReasons([]string{"facts"}, []string{"facts: intent_required: q"})()
	d := authorizeFixtures(t)
	op := fixOp(s["operation"].(map[string]any))
	grant := c["grant"].(map[string]any)
	u := &undoProbe{}
	var seen *http.Request
	var got *AuthorizeResult
	h := RequirePCA(RequirePCAOptions{Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
		Authorize: &AuthorizeOptions{StateStore: NewMemoryStateStore(), IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil },
			Operation: func(*http.Request, []byte) (*Operation, error) { return op, nil }, ArgProvenance: harnessProv(),
			Undo: func(r *http.Request, a UndoAdmitInput) (*UndoAdmission, error) { seen = r; return u.hook(a) }}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = AuthorizationFromContext(r.Context())
		w.WriteHeader(204)
	}))
	req := httptest.NewRequest(http.MethodPost, "/pay", strings.NewReader(`{}`))
	req.Header.Set(PCAHeader, headerFor(t, s["pcactn"].(map[string]any)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 || u.calls != 1 || seen == nil || seen.URL.Path != "/pay" || got == nil || got.Undo == nil || len(got.Obligations) != 1 {
		t.Fatalf("code %d calls %d result %+v", rec.Code, u.calls, got)
	}
}
