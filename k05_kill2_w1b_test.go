package pca

import (
	"encoding/json"
	"strings"
	"testing"
)

// w1b: round-2 kills (allowlist anchor entry/cache guards, witness cosignature count, bounded consistency paths, meshOpt,
// plan Check on a non-executable plan, revocation epoch shape, buffered DP draws).

// ---- allowlist_anchor.go anchorEntryOf: each conjunct of the refusal alone ----

func TestW1bAnchorEntryEachGuardAlone(t *testing.T) {
	dig := strings.Repeat("A", 43)
	entry := func(iss any, ver json.Number, d any) map[string]any {
		return map[string]any{"issuer": iss, "version": ver, "digest": d}
	}
	if e, ok := anchorEntryOf(entry("i", "1", dig)); !ok || e != (AnchorEntry{Issuer: "i", Version: 1, Digest: dig}) {
		t.Fatalf("control: %+v %v", e, ok)
	}
	for name, m := range map[string]map[string]any{
		// safeInt gives (MaxInt64, false) on a range error: !ok3 is the only failing conjunct (ver >= 1)
		"version out of int64 range": entry("i", "99999999999999999999", dig),
		"issuer over 200":            entry(strings.Repeat("i", 201), "1", dig),
		"version 0":                  entry("i", "0", dig),
		"digest not 43 b64u":         entry("i", "1", dig[:42]),
	} {
		if _, ok := anchorEntryOf(m); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- allowlist_anchor.go VerifyAllowlistAnchored: each consistency conjunct alone (cached tree empty or size 1) ----

func TestW1bAnchorCacheConsistencyEachGuardAlone(t *testing.T) {
	l := g11NewLog()
	empty := emptyTreeRoot()
	root := g11Digest("r")
	run := func(cachedSize int64, headSize int64, prev string, c map[string]any) AnchorResult {
		cached := l.signed("ins", "p", empty, "", cachedSize, g11Now)
		head := l.signed("ins", "p", root, prev, headSize, g11Now)
		ev := map[string]any{"head": head, "entries": []any{}, "proof": map[string]any{}, "consistency": c}
		return VerifyAllowlistAnchored(AnchorEntry{}, ev, AnchorOptions{Trust: l.trust(), NowMs: g11Now, CachedHead: cached})
	}
	cons := func(old, nw any, path []any) map[string]any {
		c := map[string]any{"oldSize": old, "newSize": nw}
		if path != nil {
			c["path"] = path
		}
		return c
	}
	// control: the consistency check passes, the empty feed then mismatches the head
	if r := run(0, 2, "x", cons(json.Number("0"), json.Number("2"), []any{})); r.Code != "feed-mismatch" {
		t.Fatalf("control: %+v", r)
	}
	for _, tc := range []struct {
		name               string
		cachedSize, headSz int64
		prev               string
		c                  map[string]any
	}{
		// a non-number oldSize reads as 0, which equals the empty cached tree's size
		{"oldSize not a number", 0, 2, "x", cons("0", json.Number("2"), []any{})},
		// a missing path reads as nil, which the size-0 consistency check accepts
		{"path missing", 0, 2, "x", cons(json.Number("0"), json.Number("2"), nil)},
		{"oldSize != cached size", 1, 3, "x", cons(json.Number("0"), json.Number("3"), []any{})},
		{"newSize != head size", 0, 3, "x", cons(json.Number("0"), json.Number("2"), []any{})},
		{"one-step append with a wrong prev_root", 0, 1, "zz", cons(json.Number("0"), json.Number("1"), []any{})},
		{"path not empty from size 0", 0, 2, "x", cons(json.Number("0"), json.Number("2"), []any{"AAAA"})},
	} {
		if r := run(tc.cachedSize, tc.headSz, tc.prev, tc.c); r.Ok || r.Code != "inconsistent-with-cache" {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
}

// ---- ledger.go VerifyWitnessCosignatures: a cosignature without a "key" member never counts ----

func TestW1bCosignatureWithoutKeyNeverCounts(t *testing.T) {
	w := g05Key(t, 0x61)
	pq, err := GeneratePqKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	sth := g05Sth()
	body := map[string]any{"guardian_epoch": g05N(0)}
	for _, k := range []string{"instance_id", "principal", "size", "root", "prev_root"} {
		body[k] = sth[k]
	}
	// a pure ML-DSA cosignature: the identity ("" when "key" is absent) is only the pin's lookup key
	cos, err := SignArtifact(sthWitnessDomain, body, w, &SuiteOpts{Alg: "ml-dsa-65", Pq: pq})
	if err != nil {
		t.Fatal(err)
	}
	pol := map[string]any{"threshold": g05N(1), "witnessKeys": []any{""}}
	pins := map[string]string{"": pq.Public}
	withKey := copyMap(cos)
	withKey["key"] = ""
	sth["witnesses"] = []any{withKey}
	if !VerifyWitnessCosignatures(sth, pol, pins) {
		t.Fatal("control: the same cosignature with key \"\" must count")
	}
	sth["witnesses"] = []any{cos}
	if VerifyWitnessCosignatures(sth, pol, pins) {
		t.Fatal("a cosignature without a key member counted")
	}
}

// ---- ledger.go maxConsistencyPath / mesh.go meshMaxPath: an over-long path is refused before any decoding ----

func w1bPath(n int) []any {
	p := make([]any, n)
	for i := range p {
		p[i] = b64.EncodeToString(make([]byte, 32))
	}
	return p
}

func TestW1bLedgerConsistencyPathCapIsExact(t *testing.T) {
	old := b64.EncodeToString(make([]byte, 32))
	allocs := func(n int) float64 {
		proof := map[string]any{"oldSize": json.Number("1"), "newSize": json.Number("2"), "path": w1bPath(n)}
		return testing.AllocsPerRun(5, func() {
			if VerifyLedgerConsistency(old, old, proof) {
				t.Fatal("an over-long path verified")
			}
		})
	}
	// 2*53+2 = 108: a 108-element path is decoded, a 109-element one is refused before any work
	if a108, a109 := allocs(108), allocs(109); !(a109 < a108) {
		t.Fatalf("cap is not 108: allocs(108)=%v allocs(109)=%v", a108, a109)
	}
}

func TestW1bMeshConsistencyPathCapIsExact(t *testing.T) {
	old := b64.EncodeToString(make([]byte, 32))
	allocs := func(n int) float64 {
		proof := map[string]any{"oldSize": json.Number("1"), "newSize": json.Number("2"), "path": w1bPath(n)}
		return testing.AllocsPerRun(5, func() {
			if meshConsistency(old, old, proof) {
				t.Fatal("an over-long path verified")
			}
		})
	}
	if a128, a129 := allocs(meshMaxPath), allocs(meshMaxPath+1); !(a129 < a128) {
		t.Fatalf("cap is not meshMaxPath: allocs(128)=%v allocs(129)=%v", a128, a129)
	}
}

// ---- mesh.go meshOpt: an invalid option yields (0, false) ----

func TestW1bMeshOptInvalidIsZero(t *testing.T) {
	for _, v := range []any{"x", json.Number("-1")} {
		if f, ok := meshOpt(map[string]any{"k": v}, "k", 5); ok || f != 0 {
			t.Errorf("%v: (%v, %v)", v, f, ok)
		}
	}
	if f, ok := meshOpt(map[string]any{}, "k", 5); !ok || f != 5 {
		t.Errorf("default: (%v, %v)", f, ok)
	}
}

// ---- plan_lifecycle.go Check: a non-executable plan is returned as Status said, whatever the options ----

func TestW1bPlanCheckNonExecutableUntouched(t *testing.T) {
	r := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return 1000 }})
	root := r.Draft("g", g09pNodes()).Record.Root
	want := r.Status("g", root, 1000)
	if want.Executable || want.Record == nil {
		t.Fatalf("control: %+v", want)
	}
	for name, o := range map[string]PlanCheckOptions{
		"absent node": {NodeID: "zz", Now: 1000},
		"other op":    {Operation: &Operation{Verb: "x", Resource: "y"}, Now: 1000},
	} {
		if s := r.Check("g", root, o); s.Executable || s.Reason != want.Reason {
			t.Errorf("%s: %+v want reason %q", name, s, want.Reason)
		}
	}
	// unknown plan (no record) with a node id: returned as is, never dereferenced
	unk := r.Status("g", "nope", 1000)
	if s := r.Check("g", "nope", PlanCheckOptions{NodeID: "a", Now: 1000}); s.Executable || s.Reason != unk.Reason || s.Record != nil {
		t.Errorf("unknown: %+v", s)
	}
}

// ---- revocation_staleness.go CheckRevocationEpoch: each shape conjunct alone ----

func TestW1bRevocationEpochShapeEachAlone(t *testing.T) {
	g := g05Key(t, 0x62)
	ep := func(k string, v any) map[string]any {
		m := map[string]any{"guardian": g.Public, "instance_id": "i", "grant_ref": "g", "epoch": g05N(1), "set_size": g05N(0),
			"root": "r", "issued_at": g05N(1), "not_after": g05N(2), "sig": "AAAA"}
		m[k] = v
		return m
	}
	o := EpochCheckOptions{GuardianPublic: g.Public, Now: 1}
	if r := CheckRevocationEpoch(ep("root", "r"), o); r.Reason != "revocation epoch signature invalid" {
		t.Fatalf("control: %+v", r)
	}
	for _, tc := range []struct {
		k string
		v any
	}{
		{"epoch", json.Number("1.5")}, {"epoch", g05N(-1)}, {"set_size", "x"}, {"set_size", g05N(-1)},
		{"issued_at", "x"}, {"not_after", "x"},
	} {
		if r := CheckRevocationEpoch(ep(tc.k, tc.v), o); r.OK || r.Reason != "malformed revocation epoch" {
			t.Errorf("%s=%v: %+v", tc.k, tc.v, r)
		}
	}
}

// ---- readvault.go next48: one hash block feeds five draws ----

func TestW1bDrawsRefillOnlyWhenEmpty(t *testing.T) {
	d := k5SeededDraws("s")
	for i := 1; i <= 6; i++ {
		d.next48()
		if wantBlock, wantBuf := int64((i+4)/5), (5-i%5)%5; d.block != wantBlock || len(d.buf) != wantBuf {
			t.Fatalf("after %d draws: block %d buf %d, want %d %d", i, d.block, len(d.buf), wantBlock, wantBuf)
		}
	}
}
