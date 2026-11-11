package pca

import "testing"

func TestF3_Beacon(t *testing.T) {
	kp, _ := NewKeyPair()
	other, _ := NewKeyPair()
	const now = 10_000_000
	issue := func(seq, at, val int64, scope string, k *KeyPair) map[string]any {
		b, err := IssueLivenessBeacon(k, "inst", scope, seq, at, val, nil)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	iss := []string{kp.Public}
	ok := issue(3, now-1000, 0, "", kp)
	if v := VerifyLivenessBeacon(ok, iss, now, "inst", "g1", nil); !v.OK {
		t.Fatalf("valid beacon refused: %q", v.Reason)
	}
	cases := []struct {
		name, want string
		b          map[string]any
		iss        []string
		inst, sc   string
		now        int64
	}{
		{"instance", "wrong instance", ok, iss, "other", "g1", now},
		{"unpinned", "issuer not pinned", issue(3, now-1000, 0, "", other), iss, "inst", "g1", now},
		{"scope", "scope not covered", issue(3, now-1000, 0, "g2", kp), iss, "inst", "g1", now},
		{"expired", "expired", ok, iss, "inst", "g1", now + 6*BeaconEpochMs},
		{"future", "not yet valid", issue(3, now+BeaconClockSkewMs+1, 0, "", kp), iss, "inst", "g1", now},
		{"nil", "malformed beacon", nil, iss, "inst", "g1", now},
	}
	for _, c := range cases {
		if v := VerifyLivenessBeacon(c.b, c.iss, c.now, c.inst, c.sc, nil); v.OK || v.Reason != c.want {
			t.Errorf("%s: got ok=%v %q want %q", c.name, v.OK, v.Reason, c.want)
		}
	}
	tam := issue(3, now-1000, 0, "", kp)
	tam["seq"] = jn("4")
	if v := VerifyLivenessBeacon(tam, iss, now, "inst", "g1", nil); v.OK || v.Reason != "bad signature" {
		t.Errorf("tampered: %+v", v)
	}
	if _, err := IssueLivenessBeacon(kp, "inst", "", 1, 0, BeaconMaxValidity+1, nil); err == nil {
		t.Error("validity above the hard max must not issue")
	}
	if !IsFrozenLiveness(nil, iss, now, "inst", "g1", nil) || IsFrozenLiveness([]map[string]any{ok}, iss, now, "inst", "g1", nil) {
		t.Error("frozen: absence freezes, a valid beacon thaws")
	}
	seq := int64(3)
	if v := AcceptBeacon(&seq, ok); v.OK || v.Reason != "replayed beacon: seq 3 <= 3" {
		t.Errorf("equal seq: %+v", v)
	}
	if v := AcceptBeacon(nil, ok); !v.OK {
		t.Errorf("first: %+v", v)
	}
	acc, _ := NewBeaconAcceptor(NewMemoryAtomicKV())
	if v := acc.Accept(ok, iss, now, "inst", "g1", nil); !v.OK {
		t.Fatalf("accept: %+v", v)
	}
	if v := acc.Accept(ok, iss, now, "inst", "g1", nil); v.OK || v.Reason != "replayed beacon: seq 3 <= 3" {
		t.Errorf("replay: %+v", v)
	}
	if v := acc.Accept(issue(4, now-500, 0, "", kp), iss, now, "inst", "g1", nil); !v.OK {
		t.Errorf("higher seq: %+v", v)
	}
	for _, c := range []struct {
		p, o, r, b bool
		want       string
	}{{false, false, false, false, "not-enforced"}, {true, false, false, false, "rejected"}, {true, true, true, false, "replayed"},
		{true, true, false, false, "unbound"}, {true, true, false, true, "pass"}} {
		if got := BeaconDecision(c.p, c.o, c.r, c.b); got != c.want {
			t.Errorf("decision %v: %s", c, got)
		}
	}
}

func TestF3_BeaconStep(t *testing.T) {
	kp, _ := NewKeyPair()
	const now = 10_000_000
	b, _ := IssueLivenessBeacon(kp, "inst", "", 5, now-1000, 0, nil)
	ref, _ := BeaconRef(b)
	store := NewMemoryStateStore()
	grant := map[string]any{"id": "g1"}
	run := func(in *BeaconInput, beaconRef string) (status, why string, seq *int64) {
		a := AuthorizeInput{StateStore: store, Beacon: func(string, map[string]any) *BeaconInput { return in }}
		p := map[string]any{"freshness": map[string]any{"beacon_ref": beaconRef}}
		seq = beaconStep(a, p, grant, "g1", now, func(_, s string) { status = s }, func(_, w string) { status, why = "fail", w })
		return
	}
	good := &BeaconInput{Beacon: b, Issuers: []string{kp.Public}, Instance: "inst"}
	if s, w, seq := run(good, ref); s != "pass" || w != "" || seq == nil || *seq != 5 {
		t.Fatalf("pass: %s %q %v", s, w, seq)
	}
	if s, w, _ := run(good, "x"); s != "fail" || w != "PCActn freshness.beacon_ref does not bind the presented beacon" {
		t.Errorf("unbound: %s %q", s, w)
	}
	_ = store.RaisePin("g1:beacon", 9)
	if s, w, _ := run(good, ref); s != "fail" || w != "beacon seq 5 is older than the last accepted 9 (replay)" {
		t.Errorf("replay: %s %q", s, w)
	}
	if s, _, _ := run(nil, ref); s != "" {
		t.Errorf("no beacon must report nothing (required-check absence freezes), got %q", s)
	}
	bad := &BeaconInput{Beacon: b, Issuers: nil, Instance: "inst"}
	if s, w, _ := run(bad, ref); s != "fail" || w != "issuer not pinned" {
		t.Errorf("rejected: %s %q", s, w)
	}
}
