package pca

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// R5 N5: caveats.go and caveat_lang.go survivors. Reference: packages/pca/src/caveats.ts and caveat-lang.ts.

func TestR5N5FinNumKinds(t *testing.T) {
	for _, v := range []any{float32(5), float64(5), int(5), int8(5), int16(5), int32(5), int64(5), uint(5), uint8(5), uint16(5),
		uint32(5), uint64(5), json.Number("5")} {
		if f, ok := finNum(v); !ok || f != 5 {
			t.Errorf("%T: %v %v", v, f, ok)
		}
	}
	if f, ok := finNum(json.Number("abc")); ok || f != 0 {
		t.Errorf("unparsable lexeme: %v %v", f, ok)
	}
	if _, ok := finNum("5"); ok {
		t.Error("a string is not a number")
	}
}

func TestR5N5CaveatSatisfiedRecovers(t *testing.T) {
	old := caveatEval
	defer func() { caveatEval = old }()
	caveatEval = func(any, map[string]any) bool { panic("r5") }
	got := true
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic escaped caveatSatisfied: %v", r)
			}
		}()
		got = caveatSatisfied(map[string]any{"type": "expires"}, nil)
	}()
	if got {
		t.Error("a panicking evaluation satisfied the caveat")
	}
}

func TestR5N5ClPanicText(t *testing.T) {
	if got := clPanicText(errors.New("e1")); got != "e1" {
		t.Errorf("error: %q", got)
	}
	if got := clPanicText("s1"); got != "s1" {
		t.Errorf("string: %q", got)
	}
	if got := clPanicText(5); got != "unknown" {
		t.Errorf("other: %q", got)
	}
}

func TestR5N5BoundCaveatsEmptyIsNotNil(t *testing.T) {
	out, ok := BoundCaveats(map[string]any{"holder": "h", "caveats": []any{}}, nil)
	if !ok || out == nil || len(out) != 0 {
		t.Errorf("empty caveat list: %#v %v", out, ok)
	}
}

func TestR5N5EvaluateCaveatsK1Clock(t *testing.T) {
	// no clock in the context: the K1 evaluation refuses (the default now is not a safe integer)
	g := map[string]any{"holder": "h", "caveats": []any{}}
	allow, failed := EvaluateCaveatsK1(g, nil, &K1Input{}, map[string]any{})
	if allow || !reflect.DeepEqual(failed, []string{"<malformed>"}) {
		t.Errorf("no clock: %v %v", allow, failed)
	}
}

func TestR5N5EvaluateCaveatsK1NonArrayCaveats(t *testing.T) {
	g := map[string]any{"holder": "h", "caveats": "x"}
	allow, failed := EvaluateCaveatsK1(g, nil, &K1Input{}, map[string]any{"now": jnum(1500)})
	if allow {
		t.Error("a non-array caveat list allowed")
	}
	found := false
	for _, f := range failed {
		if f == "<malformed caveats>" {
			found = true
		}
	}
	if !found {
		t.Errorf("stock failure missing: %v", failed)
	}
}

type r5OnceStore struct {
	once   bool
	claims int
}

func (s *r5OnceStore) Claim(string, int64) (ClaimResult, error) {
	s.claims++
	return ClaimResult{OK: true}, nil
}
func (s *r5OnceStore) ConsumeOnce(string, int64, int64) (bool, error) { return s.once, nil }

func TestR5N5ReserveMaxUsesOnceStoreDoesNotFallThrough(t *testing.T) {
	bound := []BoundCaveat{{Caveat: map[string]any{"type": "max_uses", "id": "u", "n": jsNumber(1), "until": jsNumber(100)}, CapHash: "h"}}
	st := &r5OnceStore{once: false}
	if r := ReserveMaxUses(st, bound, 1); r.OK || r.Reason != "max_uses 'u' is exhausted" || st.claims != 0 {
		t.Errorf("exhausted once store: %+v claims %d", r, st.claims)
	}
	st = &r5OnceStore{once: true}
	if r := ReserveMaxUses(st, bound, 1); !r.OK || r.Spent != 1 || st.claims != 0 {
		t.Errorf("free once store: %+v claims %d", r, st.claims)
	}
}

// The first discharge that verifies decides the claims (the reference breaks at the first), not the last.
func TestR5N5EvaluateK1FirstDischargeWins(t *testing.T) {
	pq := newWBPQKey(t)
	need := map[string]any{"type": "needs_discharge", "id": "c1", "issuer": "iss", "issuer_class": "org", "bind": "chain_hop",
		"ttl_ms": jnum(5000), "require": []any{}}
	derive := map[string]any{"type": "derive", "id": "d1",
		"defs":  []any{map[string]any{"name": "r", "kind": "claim", "caveat_id": "c1", "claim": "role"}},
		"check": map[string]any{"op": "eq", "a": map[string]any{"ref": "r"}, "b": map[string]any{"const": "a"}}}
	grant := map[string]any{"issuer": "i", "holder": "h", "caveats": []any{need, derive}}
	ch := g12Hash(t, grant)
	dis := func(role string) map[string]any {
		d := map[string]any{"v": jnum(1), "kind": "pca-discharge", "caveat_id": "c1", "issuer": "iss", "cap_hash": ch, "bind": "chain_hop",
			"claims": map[string]any{"role": role}, "iat": jnum(1000), "not_after": jnum(2000), "nonce": b64.EncodeToString(make([]byte, 16))}
		return signArtPQ(t, pq, DischargeDomain, d)
	}
	k1 := &K1Input{
		Pins:       []DischargePin{{PinnedSigner: PinnedSigner{PK: "pin-id", PQPK: pq.pk}, Label: "iss", Class: "org"}},
		Discharges: []any{dis("a"), dis("b")},
	}
	r := EvaluateK1(grant, nil, k1, K1Context{Now: 1500})
	if !r.OK {
		t.Errorf("first discharge did not win: %+v", r)
	}
}
