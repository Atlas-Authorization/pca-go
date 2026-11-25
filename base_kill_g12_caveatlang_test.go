package pca

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestG12CaveatLangSmallHelpers(t *testing.T) {
	for _, c := range []struct {
		f    float64
		want bool
	}{{maxSafeInt, true}, {-maxSafeInt, true}, {0, true}, {math.Copysign(0, -1), false}, {0.5, false}, {math.NaN(), false}} {
		if clSafeF(c.f) != c.want {
			t.Errorf("clSafeF(%v) != %v", c.f, c.want)
		}
	}
	for _, id := range []string{"z9", "9", "a"} {
		if !clID(id) {
			t.Errorf("clID(%q)", id)
		}
	}
	m := map[string]any{}
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, k := range []string{"h", "c", "a", "g", "e", "b", "f", "d"} {
		m[k] = true
	}
	for i := 0; i < 5; i++ {
		if got := clSortedKeys(m); !reflect.DeepEqual(got, want) {
			t.Fatalf("clSortedKeys = %v", got)
		}
	}
	// "\xff" decodes to U+FFFD: equal UTF-16 units, so the sort must leave them in place (a strict comparison)
	xs := []string{"�", "\xff"}
	clSortUTF16(xs)
	if xs[0] != "�" || xs[1] != "\xff" {
		t.Errorf("clSortUTF16 reordered equal units: %q", xs)
	}
	ys := []string{"b", "￿", "\U00010000", "a"}
	clSortUTF16(ys)
	if !reflect.DeepEqual(ys, []string{"a", "b", "\U00010000", "￿"}) {
		t.Errorf("clSortUTF16 = %q", ys)
	}
	if got := clStrings([]any{"a", 1, "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("clStrings = %q", got)
	}
	if e := SpiffeIDError("spiffe://z9/Zz9"); e != "" {
		t.Errorf("SpiffeIDError: %s", e)
	}
	if IsK1Caveat("x") {
		t.Error("a string is not a caveat")
	}
}

func TestG12BoundCaveatsHashFailures(t *testing.T) {
	cv := []any{map[string]any{"type": "x"}}
	if out, ok := BoundCaveats(map[string]any{"holder": "h", "caveats": cv}, nil); !ok || len(out) != 1 || out[0].Hop != 0 || out[0].CapHash == "" {
		t.Fatalf("baseline: %v %v", out, ok)
	}
	if out, ok := BoundCaveats(map[string]any{"holder": "h", "caveats": cv, "x": "\xed\xa0\x80"}, nil); ok || out != nil {
		t.Errorf("unhashable hop: %v %v", out, ok)
	}
	old := clCapHash
	defer func() { clCapHash = old }()
	clCapHash = func(map[string]any) (string, error) { panic("g12") }
	if out, ok := BoundCaveats(map[string]any{"holder": "h", "caveats": cv}, nil); ok || out != nil {
		t.Errorf("panicking hash: %v %v", out, ok)
	}
}

// ---- discharges

func g12Discharge(t *testing.T, pq wbPQKey, capHash string, pqSig any) map[string]any {
	d := map[string]any{"v": jnum(1), "kind": "pca-discharge", "caveat_id": "c1", "issuer": "iss", "cap_hash": capHash, "bind": "chain_hop",
		"claims": map[string]any{}, "iat": jnum(1000), "not_after": jnum(2000), "nonce": b64.EncodeToString(make([]byte, 16))}
	if pqSig != nil {
		d["pq_sig"] = pqSig
	}
	return signArtPQ(t, pq, DischargeDomain, d)
}

func TestG12VerifyDischargeDigestFailures(t *testing.T) {
	pq := newWBPQKey(t)
	ch := b64.EncodeToString(make([]byte, 32))
	caveat := map[string]any{"type": "needs_discharge", "id": "c1", "issuer": "iss", "issuer_class": "org", "bind": "chain_hop", "ttl_ms": jnum(5000), "require": []any{}}
	bind := DischargeBinding{CapHash: ch, Now: 1500, Pins: []DischargePin{{PinnedSigner: PinnedSigner{PK: "pin-id", PQPK: pq.pk}, Label: "iss", Class: "org"}}}
	if v := VerifyDischarge(g12Discharge(t, pq, ch, nil), caveat, bind); !v.OK || v.Digest == "" {
		t.Fatalf("baseline: %+v", v)
	}
	// an ml-dsa-65 discharge ignores pq_sig: one that is not canonical JSON passes the signature but has no digest
	if v := VerifyDischarge(g12Discharge(t, pq, ch, "\xed\xa0\x80"), caveat, bind); v.OK || v.Reason != "discharge error (fail closed): canonicalize: lone surrogate in string" {
		t.Errorf("lone surrogate pq_sig: %+v", v)
	}
	old := clDischargeDigest
	defer func() { clDischargeDigest = old }()
	clDischargeDigest = func(any) (string, error) { panic("g12") }
	if v := VerifyDischarge(g12Discharge(t, pq, ch, nil), caveat, bind); v.OK || v.Reason != "discharge error (fail closed): g12" {
		t.Errorf("panic: %+v", v)
	}
}

// ---- narrow blocks

func g12Narrow(capHash, holder string) map[string]any {
	return map[string]any{"v": jnum(1), "kind": "pca-narrow", "cap_hash": capHash, "holder": holder, "caveats": []any{map[string]any{"type": "x"}},
		"iat": jnum(1000), "not_after": jnum(2000), "nonce": b64.EncodeToString(make([]byte, 16))}
}

func g12Hash(t *testing.T, m map[string]any) string {
	h, err := CapHash(normalizeJSON(m).(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestG12VerifyNarrowLeafHashFailures(t *testing.T) {
	k := newKey(t)
	leaf := map[string]any{"issuer": "i", "holder": k.id, "caveats": []any{}}
	n := signArt(t, k, NarrowDomain, g12Narrow(g12Hash(t, leaf), k.id))
	if v := VerifyNarrow(n, leaf, nil, NarrowBinding{Now: 1500}); !v.OK || len(v.Caveats) != 1 {
		t.Fatalf("baseline: %+v", v)
	}
	bad := map[string]any{"issuer": "i", "holder": k.id, "caveats": []any{}, "x": "\xed\xa0\x80"}
	if v := VerifyNarrow(n, bad, nil, NarrowBinding{Now: 1500}); v.OK || v.Reason != "narrow error (fail closed): canonicalize: lone surrogate in string" {
		t.Errorf("unhashable leaf: %+v", v)
	}
	old := clCapHash
	defer func() { clCapHash = old }()
	clCapHash = func(map[string]any) (string, error) { panic("g12") }
	if v := VerifyNarrow(n, leaf, nil, NarrowBinding{Now: 1500}); v.OK || v.Reason != "narrow error (fail closed): g12" {
		t.Errorf("panic: %+v", v)
	}
}

func TestG12VerifyNarrowPQHolderCommitment(t *testing.T) {
	k := newKey(t)
	pq := newWBPQKey(t)
	run := func(commit string) NarrowVerdict {
		leaf := map[string]any{"issuer": "i", "holder": k.id, "holder_pq": commit, "caveats": []any{}}
		n := signArtPQ(t, pq, NarrowDomain, g12Narrow(g12Hash(t, leaf), k.id))
		return VerifyNarrow(n, leaf, nil, NarrowBinding{Now: 1500})
	}
	if v := run(holderPqCommitment(pq.pk)); !v.OK {
		t.Errorf("committed PQ key: %+v", v)
	}
	if v := run(holderPqCommitment("another key")); v.OK || v.Reason != "narrow signature invalid" {
		t.Errorf("uncommitted PQ key: %+v", v)
	}
}

func TestG12EvaluateK1LeafRehashFailsClosed(t *testing.T) {
	k := newKey(t)
	grant := map[string]any{"issuer": "i", "holder": k.id, "caveats": []any{}}
	in := &K1Input{Narrow: signArt(t, k, NarrowDomain, g12Narrow(g12Hash(t, grant), k.id)), HasNarrow: true}
	if r := EvaluateK1(grant, nil, in, K1Context{Now: 1500}); !r.OK || len(r.Plain) != 1 {
		t.Fatalf("baseline: %+v", r)
	}
	old := clCapHash
	defer func() { clCapHash = old }()
	// VerifyNarrow hashes the leaf first (call 1); EvaluateK1's own hash of it (call 2) is the one that fails
	second := func(fail func() (string, error)) {
		calls := 0
		clCapHash = func(m map[string]any) (string, error) {
			calls++
			if calls == 2 {
				return fail()
			}
			return old(m)
		}
	}
	second(func() (string, error) { return "", errors.New("g12 seam") })
	r := EvaluateK1(grant, nil, in, K1Context{Now: 1500})
	if r.OK || !reflect.DeepEqual(r.Failed, []string{"narrow"}) || !reflect.DeepEqual(r.Reasons, []string{"narrow error (fail closed): g12 seam"}) {
		t.Errorf("error: %+v", r)
	}
	second(func() (string, error) { panic("g12") })
	r = EvaluateK1(grant, nil, in, K1Context{Now: 1500})
	if r.OK || !reflect.DeepEqual(r.Failed, []string{"<malformed>"}) || !reflect.DeepEqual(r.Reasons, []string{"caveat language error (fail closed): g12"}) {
		t.Errorf("panic: %+v", r)
	}
}

// ---- max_uses stores

type g12PanicClaim struct{}

func (g12PanicClaim) Claim(string, int64) (ClaimResult, error) { panic("g12 claim") }

type g12OnceDown struct{}

func (g12OnceDown) Claim(string, int64) (ClaimResult, error) { return ClaimResult{OK: true}, nil }
func (g12OnceDown) ConsumeOnce(string, int64, int64) (bool, error) {
	return false, errors.New("g12 once down")
}

type g12RecClaim struct{ counters []int64 }

func (s *g12RecClaim) Claim(_ string, c int64) (ClaimResult, error) {
	s.counters = append(s.counters, c)
	return ClaimResult{OK: true}, nil
}

func TestG12ReserveMaxUsesStores(t *testing.T) {
	bound := []BoundCaveat{{Caveat: map[string]any{"type": "max_uses", "id": "u", "n": jsNumber(1), "until": jsNumber(100)}, CapHash: "h"}}
	if r := ReserveMaxUses(g12PanicClaim{}, bound, 1); r.OK || r.Reason != "max_uses error (fail closed): g12 claim" {
		t.Errorf("panicking store: %+v", r)
	}
	if r := ReserveMaxUses(g12OnceDown{}, bound, 1); r.OK || r.Reason != "max_uses error (fail closed): g12 once down" {
		t.Errorf("ConsumeOnce error: %+v", r)
	}
	rec := &g12RecClaim{}
	if r := ReserveMaxUses(rec, bound, 1); !r.OK || r.Spent != 1 || !reflect.DeepEqual(rec.counters, []int64{1}) {
		t.Errorf("Claim fallback: %+v %v", r, rec.counters)
	}
}

func TestG12EvaluateDeriveRecovers(t *testing.T) {
	def := map[string]any{"kind": "count", "name": "n", "window_ms": jnum(1000)}
	c := map[string]any{"defs": []any{def}, "check": map[string]any{"const": true}}
	inp := DeriveInput{Now: 1000, History: []any{map[string]any{"t": jnum(1000), "verb": "v", "resource": "r"}}}
	if r, known := EvaluateDerive(c, inp); !r || !known {
		t.Fatalf("baseline: %v %v", r, known)
	}
	def["resource_prefix"] = jnum(5) // not a string: the prefix test panics
	if r, known := EvaluateDerive(c, inp); r || known {
		t.Errorf("panic: %v %v", r, known)
	}
}
