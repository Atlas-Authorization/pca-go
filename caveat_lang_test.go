package pca

import (
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Caveat language v2 (track K1): the shared vectors (packages/pca/conformance/caveat-lang-vectors.json) replayed against the
// port, plus exact-outcome tests for what the vectors cannot show. A missing file or primitive FAILS, it is never skipped.

func clVectors(t *testing.T, name string, min int) []map[string]any {
	t.Helper()
	list, ok := load(t, "caveat-lang-vectors.json")["primitives"].(map[string]any)[name].([]any)
	if !ok || len(list) < min {
		t.Fatalf("primitive %s: %d vectors, want at least %d", name, len(list), min)
	}
	out := make([]map[string]any, len(list))
	for i, x := range list {
		out[i] = x.(map[string]any)
	}
	return out
}

func clPins(v any) []DischargePin {
	var pins []DischargePin
	list, _ := v.([]any)
	for _, x := range list {
		p := x.(map[string]any)
		pin := DischargePin{PinnedSigner: PinnedSigner{PK: p["pk"].(string)}, Label: p["label"].(string), Class: p["class"].(string)}
		if s, ok := p["pq_pk"].(string); ok {
			pin.PQPK = s
		}
		if s, ok := p["spiffe_id"].(string); ok {
			pin.SpiffeID = s
		}
		pins = append(pins, pin)
	}
	return pins
}

func clNum(t *testing.T, v any) float64 {
	t.Helper()
	f, ok := jsNum(v)
	if !ok {
		t.Fatalf("%v is not a number", v)
	}
	return f
}

func clCanonEq(t *testing.T, got, want any) bool {
	t.Helper()
	a, err1 := Canonicalize(normalizeJSON(got))
	b, err2 := Canonicalize(normalizeJSON(want))
	if err1 != nil || err2 != nil {
		t.Fatalf("canonicalize: %v %v", err1, err2)
	}
	return a == b
}

func TestCaveatLangDischargeVectors(t *testing.T) {
	ran := 0
	for _, v := range clVectors(t, "discharge_verify", 50) {
		t.Run(v["name"].(string), func(t *testing.T) {
			in := v["input"].(map[string]any)
			b := in["binding"].(map[string]any)
			bind := DischargeBinding{Pins: clPins(b["pins"]), Now: clNum(t, b["now"])}
			bind.CapHash, _ = b["cap_hash"].(string)
			bind.ActionDigest, _ = b["action_digest"].(string)
			if rv, ok := b["revoked"].([]any); ok {
				bind.Revoked = clStrings(rv)
			}
			r := VerifyDischarge(in["discharge"], in["caveat"], bind)
			e := v["expect"].(map[string]any)
			if need, has := v["requires_suite"].(string); has && !supportedSuites[need] {
				// a suite this build cannot run is refused, never accepted and never mistaken for a bad signature
				if r.OK || !strings.Contains(r.Reason, UnsupportedSuite) {
					t.Fatalf("suite %s is not built: want %s, got %+v", need, UnsupportedSuite, r)
				}
				return
			}
			ran++
			if r.OK != e["ok"].(bool) {
				t.Fatalf("ok = %v (%s), want %v", r.OK, r.Reason, e["ok"])
			}
			if r.OK {
				if r.Digest != e["digest"] || !clCanonEq(t, r.Claims, e["claims"]) {
					t.Fatalf("got digest %s claims %v, want %v", r.Digest, r.Claims, e)
				}
			} else if !strings.Contains(r.Reason, e["reason_contains"].(string)) {
				t.Fatalf("reason %q lacks %q", r.Reason, e["reason_contains"])
			}
		})
	}
	if ran < 40 {
		t.Fatalf("only %d discharge vectors ran", ran)
	}
}

// clK1Input is nil for a k1 that is not an object (the verifier has no K1 input).
func clK1Input(t *testing.T, raw any) *K1Input {
	t.Helper()
	k, isObj := raw.(map[string]any)
	if !isObj {
		return nil
	}
	var in K1Input
	in.Pins = clPins(k["pins"])
	in.Discharges, _ = k["discharges"].([]any)
	in.Narrow, in.HasNarrow = k["narrow"]
	in.ActionDigest, _ = k["action_digest"].(string)
	if rv, ok := k["revoked_discharges"].([]any); ok {
		in.RevokedDischarges = clStrings(rv)
	}
	in.SpiffeID, _ = k["spiffe_id"].(string)
	if h, ok := k["history"].([]any); ok {
		in.History = h
	}
	return &in
}

func TestCaveatLangK1EvalVectors(t *testing.T) {
	sawAllow, sawDeny := false, false
	for _, v := range clVectors(t, "k1_eval", 100) {
		t.Run(v["name"].(string), func(t *testing.T) {
			in := v["input"].(map[string]any)
			allow, failed := EvaluateCaveatsK1(in["grant"], in["chain"], clK1Input(t, in["k1"]), in["context"].(map[string]any))
			e := v["expect"].(map[string]any)
			want := []string{}
			for _, x := range e["failed"].([]any) {
				want = append(want, x.(string))
			}
			if allow != e["allow"].(bool) || !reflect.DeepEqual(failed, want) {
				t.Fatalf("got allow=%v failed=%v, want allow=%v failed=%v", allow, failed, e["allow"], want)
			}
			if allow {
				sawAllow = true
			} else {
				sawDeny = true
			}
		})
	}
	if !sawAllow || !sawDeny {
		t.Fatal("the k1_eval vectors must contain both allows and denies")
	}
}

func TestCaveatLangShapeVectors(t *testing.T) {
	for _, v := range clVectors(t, "caveat_shape", 50) {
		t.Run(v["name"].(string), func(t *testing.T) {
			c := v["input"].(map[string]any)["caveat"].(map[string]any)
			var err string
			switch c["type"] {
			case CaveatNeedsDischarge:
				err = NeedsDischargeError(c)
			case CaveatMaxUses:
				err = MaxUsesError(c)
			case CaveatDerive:
				err = DeriveError(c)
			case CaveatSpiffeBound:
				err = SpiffeBoundError(c)
			default:
				t.Fatalf("unexpected caveat type %v", c["type"])
			}
			if (err == "") != v["expect"].(map[string]any)["valid"].(bool) {
				t.Fatalf("error %q, want valid=%v", err, v["expect"])
			}
		})
	}
}

func TestCaveatLangUsesKeyVectors(t *testing.T) {
	for _, v := range clVectors(t, "uses_key", 5) {
		t.Run(v["name"].(string), func(t *testing.T) {
			in := v["input"].(map[string]any)
			got := MaxUsesSlotKey(in["cap_hash"].(string), in["id"].(string), int(clNum(t, in["i"])))
			if got != v["expect"].(map[string]any)["key"] {
				t.Fatalf("key %s, want %v", got, v["expect"])
			}
		})
	}
}

func TestCaveatLangUsesReserveVectors(t *testing.T) {
	for _, v := range clVectors(t, "uses_reserve", 10) {
		t.Run(v["name"].(string), func(t *testing.T) {
			in := v["input"].(map[string]any)
			var bound []BoundCaveat
			for _, x := range in["bound"].([]any) {
				b := x.(map[string]any)
				bound = append(bound, BoundCaveat{Caveat: b["caveat"], CapHash: b["cap_hash"].(string)})
			}
			store := NewMemoryStateStore()
			calls := in["calls"].([]any)
			want := v["expect"].(map[string]any)["results"].([]any)
			if len(calls) != len(want) {
				t.Fatalf("%d calls, %d results", len(calls), len(want))
			}
			for i, c := range calls {
				r := ReserveMaxUses(store, bound, clNum(t, c.(map[string]any)["now"]))
				w := want[i].(map[string]any)
				if r.OK != w["ok"].(bool) {
					t.Fatalf("call %d: ok = %v (%s), want %v", i, r.OK, r.Reason, w["ok"])
				}
				if r.OK && float64(r.Spent) != clNum(t, w["spent"]) {
					t.Fatalf("call %d: spent %d, want %v", i, r.Spent, w["spent"])
				}
				if !r.OK && !strings.Contains(r.Reason, w["reason_contains"].(string)) {
					t.Fatalf("call %d: reason %q lacks %q", i, r.Reason, w["reason_contains"])
				}
			}
		})
	}
}

func TestCaveatLangSpiffeIDVectors(t *testing.T) {
	for _, v := range clVectors(t, "spiffe_id", 20) {
		t.Run(v["name"].(string), func(t *testing.T) {
			got := SpiffeIDError(v["input"].(map[string]any)["id"]) == ""
			if got != v["expect"].(map[string]any)["valid"].(bool) {
				t.Fatalf("valid = %v, want %v", got, v["expect"])
			}
		})
	}
}

// ---- exact outcomes the vectors cannot show -------------------------------------------------------------------------

type clFailStore struct{}

func (clFailStore) Claim(string, int64) (ClaimResult, error) {
	return ClaimResult{}, errors.New("db down")
}

func TestCaveatLangHostileInputsDoNotPanic(t *testing.T) {
	hostile := []any{nil, 5, "x", true, []any{}, []any{nil}, map[string]any{}, map[string]any{"caveats": 5}, map[string]any{"caveats": []any{5, nil, "x"}}}
	for _, h := range hostile {
		if r := VerifyDischarge(h, h, DischargeBinding{Now: 1}); r.OK || r.Reason == "" {
			t.Fatalf("VerifyDischarge(%v) = %+v", h, r)
		}
		if r := VerifyNarrow(h, h, h, NarrowBinding{Now: 1}); r.OK || r.Reason == "" {
			t.Fatalf("VerifyNarrow(%v) = %+v", h, r)
		}
		for _, e := range []string{DischargeShapeError(h), NarrowShapeError(h), NeedsDischargeError(h), MaxUsesError(h), DeriveError(h), SpiffeBoundError(h), SpiffeIDError(h)} {
			if e == "" {
				t.Fatalf("a hostile value %v was judged valid", h)
			}
		}
		BoundCaveats(h, h)
		r := EvaluateK1(h, h, &K1Input{Narrow: h, HasNarrow: true, Discharges: []any{h}, History: []any{h}}, K1Context{Now: 1})
		if r.OK || len(r.Failed) == 0 || len(r.Failed) != len(r.Reasons) {
			t.Fatalf("EvaluateK1(%v) = %+v", h, r)
		}
		if ok, failed := EvaluateCaveatsK1(h, h, &K1Input{}, map[string]any{"now": h}); ok || len(failed) == 0 {
			t.Fatalf("EvaluateCaveatsK1(%v) = %v %v", h, ok, failed)
		}
		ReserveMaxUses(nil, []BoundCaveat{{Caveat: h}}, 1)
	}
}

func TestCaveatLangMalformedChainIsOneMalformedFailure(t *testing.T) {
	g := map[string]any{"caveats": 5}
	r := EvaluateK1(g, []any{g}, &K1Input{}, K1Context{Now: 1})
	if r.OK || !reflect.DeepEqual(r.Failed, []string{"<malformed>"}) || r.Reasons[0] != "malformed capability chain" {
		t.Fatalf("got %+v", r)
	}
}

func TestCaveatLangBadClockRefusesEveryEntryPoint(t *testing.T) {
	if r := ReserveMaxUses(NewMemoryStateStore(), nil, 0.5); r.OK || !strings.Contains(r.Reason, "not a safe integer") {
		t.Fatalf("got %+v", r)
	}
	if r := VerifyNarrow(nil, nil, nil, NarrowBinding{Now: 1e300}); r.OK || !strings.Contains(r.Reason, "not a safe integer") {
		t.Fatalf("got %+v", r)
	}
	g := map[string]any{"caveats": []any{}}
	r := EvaluateK1(g, nil, &K1Input{}, K1Context{Now: 1e300})
	if r.OK || !strings.Contains(r.Reasons[0], "not a safe integer") {
		t.Fatalf("got %+v", r)
	}
}

func TestCaveatLangReserveMaxUsesFailsClosed(t *testing.T) {
	bound := []BoundCaveat{{Caveat: map[string]any{"type": "max_uses", "id": "u", "n": jsNumber(1), "until": jsNumber(100)}, CapHash: "h"}}
	if r := ReserveMaxUses(clFailStore{}, bound, 1); r.OK || !strings.Contains(r.Reason, "db down") {
		t.Fatalf("a failing store must refuse: %+v", r)
	}
	if r := ReserveMaxUses(nil, bound, 1); r.OK {
		t.Fatalf("no store must refuse: %+v", r)
	}
	// the same id on two hops is two different caveats, and each hop has its own slots
	bound = append(bound, BoundCaveat{Caveat: bound[0].Caveat, CapHash: "h2"})
	store := NewMemoryStateStore()
	if r := ReserveMaxUses(store, bound, 1); !r.OK || r.Spent != 2 {
		t.Fatalf("got %+v", r)
	}
	if r := ReserveMaxUses(store, bound, 1); r.OK || !strings.Contains(r.Reason, "max_uses 'u' is exhausted") {
		t.Fatalf("got %+v", r)
	}
}

func TestCaveatLangSealedAndSpiffeOutcomes(t *testing.T) {
	root := map[string]any{"holder": "a", "caveats": []any{map[string]any{"type": "sealed"}}}
	child := map[string]any{"holder": "b", "caveats": []any{map[string]any{"type": "sealed"}, map[string]any{"type": "spiffe_bound", "spiffe_prefix": "spiffe://acme.test/ns"}}}
	r := EvaluateK1(root, []any{root, child}, &K1Input{SpiffeID: "spiffe://acme.test/ns/prod"}, K1Context{Now: 1})
	if r.OK || !reflect.DeepEqual(r.Failed, []string{"sealed"}) || r.Reasons[0] != "a hop was appended below a sealed hop" {
		t.Fatalf("a hop below a seal must fail only the seal: %+v", r)
	}
	r = EvaluateK1(root, []any{root, child}, &K1Input{SpiffeID: "spiffe://acme.test/nsx"}, K1Context{Now: 1})
	if !reflect.DeepEqual(r.Failed, []string{"sealed", "spiffe_bound"}) {
		t.Fatalf("a sibling prefix is not below the prefix: %+v", r)
	}
	if SpiffeIDError("spiffe://acme.test/a\n") == "" {
		t.Fatal("a trailing newline is not part of a SPIFFE ID")
	}
}

func TestCaveatLangScalarsNeverCoerce(t *testing.T) {
	for _, c := range [][2]any{{jsNumber(1), true}, {jsNumber(1), "1"}, {true, "1"}} {
		if scalarEqV(c[0], c[1]) {
			t.Fatalf("%v equals %v", c[0], c[1])
		}
	}
	if NeedsDischargeError(map[string]any{"type": "needs_discharge", "id": "a\n", "issuer": "i", "issuer_class": "human", "bind": "chain_hop", "ttl_ms": jsNumber(1), "require": []any{}}) == "" {
		t.Fatal("an id with a trailing newline is malformed")
	}
}

func TestCaveatLangAuthorizeWiring(t *testing.T) {
	nd := map[string]any{"type": "needs_discharge"}
	exp := map[string]any{"type": "expires"}
	plain := []any{map[string]any{"type": "max_spend"}}
	got := k1StockList([]any{nd, exp, map[string]any{"type": "sealed"}}, plain).([]any)
	if len(got) != 2 || got[0].(map[string]any)["type"] != "expires" {
		t.Fatalf("K1 types leave the stock list, plain joins it: %v", got)
	}
	if k1StockList("not a list", plain) != any("not a list") {
		t.Fatal("a non-list is returned unchanged so the stock evaluator refuses it")
	}
	if !k1HasMaxUses([]BoundCaveat{{Caveat: map[string]any{"type": "max_uses"}}}) || k1HasMaxUses([]BoundCaveat{{Caveat: nd}, {Caveat: 5}}) {
		t.Fatal("k1HasMaxUses")
	}
	ki := callK1(func(map[string]any) (*K1Input, error) { panic("boom") }, nil)
	if ki != nil {
		t.Fatal("a panicking callback is no input")
	}
	if callK1(func(map[string]any) (*K1Input, error) { return nil, nil }, nil) != nil || callK1(func(map[string]any) (*K1Input, error) { return &K1Input{}, errors.New("x") }, nil) != nil {
		t.Fatal("a nil result or an error is no input")
	}
	ki = callK1(func(map[string]any) (*K1Input, error) { return &K1Input{SpiffeID: "s"}, nil }, nil)
	if ki == nil || ki.SpiffeID != "s" {
		t.Fatal("callK1 passes the input through")
	}
}

func TestCaveatLangK1UnconfiguredVectors(t *testing.T) {
	for _, v := range clVectors(t, "k1_unconfigured", 9) {
		t.Run(v["name"].(string), func(t *testing.T) {
			in := v["input"].(map[string]any)
			allow, failed := EvaluateCaveatsK1(in["grant"], in["chain"], nil, in["context"].(map[string]any))
			e := v["expect"].(map[string]any)
			want := []string{}
			for _, x := range e["failed"].([]any) {
				want = append(want, x.(string))
			}
			if allow != e["allow"].(bool) || !reflect.DeepEqual(failed, want) {
				t.Fatalf("got allow=%v failed=%v, want allow=%v failed=%v", allow, failed, e["allow"], want)
			}
		})
	}
}

func TestCaveatLangNoK1InputRefusesEveryK1Caveat(t *testing.T) {
	sealed := map[string]any{"type": "sealed"}
	root := map[string]any{"holder": "a", "caveats": []any{}}
	child := map[string]any{"holder": "b", "caveats": []any{sealed}} // added by a narrow-less delegated hop
	chain := []any{root, child}
	if !k1Present(root, chain) || k1Present(root, []any{root}) || k1Present(5, 5) {
		t.Fatal("k1Present: a K1 caveat anywhere in the chain, nothing else")
	}
	r := EvaluateK1(root, chain, nil, K1Context{Now: 1})
	if r.OK || !reflect.DeepEqual(r.Failed, []string{"sealed"}) || r.Reasons[0] != "the caveat language is not configured (no k1 input)" {
		t.Fatalf("nil input must refuse: %+v", r)
	}
	if r := EvaluateK1(root, chain, &K1Input{}, K1Context{Now: 1}); !r.OK {
		t.Fatalf("an empty but present input is configured: %+v", r)
	}
}

// clConsumeOnceReplay runs the consume_once_ttl steps against any OnceStore.
func clConsumeOnceReplay(t *testing.T, st OnceStore, v map[string]any) {
	t.Helper()
	steps := v["input"].(map[string]any)["steps"].([]any)
	want := v["expect"].(map[string]any)["results"].([]any)
	if len(steps) != len(want) {
		t.Fatalf("%d steps, %d results", len(steps), len(want))
	}
	for i, x := range steps {
		s := x.(map[string]any)
		got, err := st.ConsumeOnce(s["key"].(string), int64(clNum(t, s["retain_until"])), int64(clNum(t, s["now"])))
		res := "false"
		if err != nil {
			res = "error"
		} else if got {
			res = "true"
		}
		if res != want[i] {
			t.Fatalf("step %d: %s, want %v", i, res, want[i])
		}
	}
}

func TestCaveatLangConsumeOnceTTLVectorsMemory(t *testing.T) {
	for _, v := range clVectors(t, "consume_once_ttl", 9) {
		t.Run(v["name"].(string), func(t *testing.T) { clConsumeOnceReplay(t, NewMemoryStateStore(), v) })
	}
}

func TestCaveatLangMemoryStoreImplementsOnceStore(t *testing.T) {
	var _ OnceStore = (*MemoryStateStore)(nil)
	st := NewMemoryStateStore()
	for i := 0; i < 1100; i++ { // past the pruning threshold: expired records go, a live one stays
		if _, err := st.ConsumeOnce(strconv.Itoa(i), 10, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ConsumeOnce("live", 1000, 1); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.ConsumeOnce("new", 2000, 500); !ok {
		t.Fatal("a new key is consumed")
	}
	if len(st.once) != 2 {
		t.Fatalf("expired records are pruned, live ones kept: %d", len(st.once))
	}
	if ok, _ := st.ConsumeOnce("live", 2000, 500); ok {
		t.Fatal("a live record refuses")
	}
}

// onceFallbackStore is a StateStore that is not an OnceStore: ReserveMaxUses falls back to Claim.
type onceFallbackStore struct{ inner *MemoryStateStore }

func (o onceFallbackStore) Claim(k string, c int64) (ClaimResult, error) { return o.inner.Claim(k, c) }

func TestCaveatLangReserveMaxUsesSlotsExpire(t *testing.T) {
	cm := map[string]any{"type": "max_uses", "id": "u", "n": jsNumber(1), "until": jsNumber(100)}
	bound := []BoundCaveat{{Caveat: cm, CapHash: "h"}}
	st := NewMemoryStateStore()
	if r := ReserveMaxUses(st, bound, 10); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := ReserveMaxUses(st, bound, 11); r.OK {
		t.Fatalf("the slot is spent: %+v", r)
	}
	if len(st.once) != 1 || st.once[MaxUsesSlotKey("h", "u", 0)] != 100 {
		t.Fatalf("the slot is remembered until `until`: %v", st.once)
	}
	if r := ReserveMaxUses(onceFallbackStore{NewMemoryStateStore()}, bound, 10); !r.OK {
		t.Fatalf("a store without OnceStore uses Claim: %+v", r)
	}
}

func TestCaveatLangK1HeadersVectors(t *testing.T) {
	for _, v := range clVectors(t, "k1_headers", 15) {
		t.Run(v["name"].(string), func(t *testing.T) {
			h := http.Header{}
			for k, x := range v["input"].(map[string]any)["headers"].(map[string]any) {
				h.Add(k, x.(string))
			}
			got, err := PresentedK1(h)
			e := v["expect"].(map[string]any)
			if (err == nil) != e["ok"].(bool) {
				t.Fatalf("err = %v, want ok=%v", err, e["ok"])
			}
			if err != nil {
				return
			}
			have := map[string]any{}
			if got.Discharges != nil {
				have["discharges"] = got.Discharges
			}
			if got.HasNarrow {
				have["narrow"] = got.Narrow
			}
			if !clCanonEq(t, have, e["value"]) {
				t.Fatalf("got %v, want %v", have, e["value"])
			}
		})
	}
}

func TestCaveatLangMergePresentedK1(t *testing.T) {
	h := http.Header{}
	h.Set("PCA-Discharges", "W10") // []
	h.Set("PCA-Narrow", "eyJhIjoxfQ")
	m := mergePresentedK1(h, &K1Input{SpiffeID: "s"})
	if m.SpiffeID != "s" || m.Discharges == nil || !m.HasNarrow {
		t.Fatalf("presented headers fill what the own input leaves unset: %+v", m)
	}
	own := &K1Input{Discharges: []any{"own"}, Narrow: "own", HasNarrow: true}
	if m := mergePresentedK1(h, own); len(m.Discharges) != 1 || m.Narrow != "own" {
		t.Fatalf("the own input wins: %+v", m)
	}
	h.Set("PCA-Discharges", "!!!!") // unreadable: no discharges, the own input is kept
	if m := mergePresentedK1(h, &K1Input{SpiffeID: "s"}); m.Discharges != nil || m.HasNarrow || m.SpiffeID != "s" {
		t.Fatalf("unreadable headers are no discharges: %+v", m)
	}
	h.Set("PCA-Discharges", "W10")
	h.Add("PCA-Discharges", "W10")
	if _, err := PresentedK1(h); err == nil {
		t.Fatal("a header sent twice is ambiguous")
	}
}
