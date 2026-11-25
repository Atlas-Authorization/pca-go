package pca

// Loopback tests of the distributed protocol: n parties and the trusted dealer as goroutines over real mutual TLS. The honest
// run must equal the cleartext composition (and the in-process malicious-secure runner); a lying dealer, a bad MAC and a
// misbehaving sender must abort every party with no output.

import (
	"errors"
	"math/big"
	"testing"
	"time"
)

func mpcpVectors(n int) []MpcDecisionVector {
	all := []MpcDecisionVector{{Allow: 1, T: 2, RQuant: 3}, {Allow: 1, T: 3, RQuant: 1}, {Allow: 1, T: 1, RQuant: 4}, {Allow: 0, T: 2, RQuant: 0}}
	return all[:n]
}

func mpcpRun(t *testing.T, o MpcLaunchOptions) []MpcNodeOutput {
	t.Helper()
	if o.Offline == "" {
		o.Offline = "trusted-dealer"
	}
	o.InsecureTrustedDealer = o.Offline == "trusted-dealer"
	if o.RecvTimeout == 0 {
		o.RecvTimeout = 20 * time.Second
	}
	outs, err := MpcLaunchLocal(o)
	if err != nil {
		t.Fatal(err)
	}
	return outs
}

func TestMpcNetLoopbackMatchesEngine(t *testing.T) {
	for _, n := range []int{2, 3, 4} {
		q := 6
		vs := mpcpVectors(n)
		want, err := MpcComposeClear(vs, q)
		if err != nil {
			t.Fatal(err)
		}
		eng, err := MpcComposeSecureMalicious(vs, &MpcMaliciousConfig{Q: &q, Seed: big.NewInt(7), InsecureTrustedDealer: true})
		if err != nil {
			t.Fatal(err)
		}
		if eng.Composed != want {
			t.Fatalf("n=%d engine %v != clear %v", n, eng.Composed, want)
		}
		outs := mpcpRun(t, MpcLaunchOptions{N: n, Q: q, Vectors: vs, DealerSeed: big.NewInt(11)})
		var digest string
		for _, o := range outs {
			if o.Err != nil {
				t.Fatalf("n=%d node %d (%s): %v", n, o.ID, o.Role, o.Err)
			}
			if o.Role == "dealer" {
				continue
			}
			r := o.Result
			if r.Composed != want || r.OfflineMode != "trusted-dealer" || !r.IdentifiableAbort || r.Multiplications != (n-1)*MpcChainCount(q) {
				t.Fatalf("n=%d party %d: %+v want %v", n, o.ID, r, want)
			}
			if digest != "" && r.TranscriptDigest != digest {
				t.Fatalf("n=%d transcript digests differ", n)
			}
			digest = r.TranscriptDigest
		}
	}
}

func mpcpAllAborted(t *testing.T, outs []MpcNodeOutput) {
	t.Helper()
	for _, o := range outs {
		if o.Role == "dealer" {
			continue
		}
		if o.Result != nil || o.Err == nil {
			t.Fatalf("party %d must abort with no output: %+v %v", o.ID, o.Result, o.Err)
		}
	}
}

// the first abort that is not a mere relay of someone else's claim
func mpcpFirstHandAbort(t *testing.T, outs []MpcNodeOutput) []*MpcNetAbort {
	var got []*MpcNetAbort
	for _, o := range outs {
		var a *MpcNetAbort
		if o.Role == "party" && errors.As(o.Err, &a) && a.Kind != "peer-abort" {
			got = append(got, a)
		}
	}
	if len(got) == 0 {
		t.Fatal("no party reported a first-hand abort")
	}
	return got
}

func TestMpcNetLyingDealerIsNamed(t *testing.T) {
	outs := mpcpRun(t, MpcLaunchOptions{N: 3, Q: 4, Vectors: mpcpVectors(3), DealerSeed: big.NewInt(3), DealerFault: &MpcDealerFault{KeepCDelta: big.NewInt(1)}})
	mpcpAllAborted(t, outs)
	for _, a := range mpcpFirstHandAbort(t, outs) {
		if a.Kind != "dealer" || a.Blamed == nil || *a.Blamed != 3 {
			t.Fatalf("want the dealer (3) blamed, got %v", a)
		}
	}
}

func TestMpcNetBadMacShareAbortsWithNoOutput(t *testing.T) {
	zero := 0
	outs := mpcpRun(t, MpcLaunchOptions{N: 3, Q: 4, Vectors: mpcpVectors(3), DealerSeed: big.NewInt(5), MacFaultAtInput: &zero})
	mpcpAllAborted(t, outs)
	mpcpFirstHandAbort(t, outs)
}

func TestMpcNetDuplicateFrameBlamesTheSender(t *testing.T) {
	dup := func(to int, raw []byte) [][]byte {
		if f := MpcParseFrame(raw[4:]); f != nil && f["rd"] == "mul0" {
			return [][]byte{raw, raw}
		}
		return [][]byte{raw}
	}
	outs := mpcpRun(t, MpcLaunchOptions{N: 3, Q: 4, Vectors: mpcpVectors(3), DealerSeed: big.NewInt(9), Tamper: map[int]func(int, []byte) [][]byte{1: dup}})
	mpcpAllAborted(t, outs)
	for _, a := range mpcpFirstHandAbort(t, outs) {
		if a.Kind != "duplicate" || a.Blamed == nil || *a.Blamed != 1 {
			t.Fatalf("want a duplicate blamed on 1, got %v", a)
		}
	}
}

func TestMpcNetRefusesUnopenedTrustedDealer(t *testing.T) {
	if _, err := MpcLaunchLocal(MpcLaunchOptions{N: 2, Q: 4, Vectors: mpcpVectors(2), Offline: "trusted-dealer"}); err == nil {
		t.Fatal("the trusted dealer needs the explicit opt-in")
	}
	if err := MpcRunDealer(MpcDealerConfig{N: 2}); err == nil {
		t.Fatal("MpcRunDealer needs the explicit opt-in")
	}
	if _, err := MpcRunParty(MpcPartyConfig{ID: 0, N: 2, Input: mpcpVectors(2)[0], Offline: "trusted-dealer"}); err == nil {
		t.Fatal("a party needs the explicit opt-in")
	}
}

func TestMpcNetNoDealerLoopbackMatchesEngine(t *testing.T) {
	for _, n := range []int{2, 3} {
		q := 4 // the third party's rQuant is 4: a smaller Q is a malformed vector
		vs := mpcpVectors(n)
		want, err := MpcComposeClear(vs, q)
		if err != nil {
			t.Fatal(err)
		}
		eng, err := MpcComposeSecureMalicious(vs, &MpcMaliciousConfig{Q: &q, Seed: big.NewInt(21)})
		if err != nil {
			t.Fatal(err)
		}
		if eng.Composed != want {
			t.Fatalf("n=%d engine %+v != clear %v", n, eng, want)
		}
		outs := mpcpRun(t, MpcLaunchOptions{N: n, Q: q, Vectors: vs, Offline: "no-dealer", RecvTimeout: 120 * time.Second})
		if len(outs) != n {
			t.Fatalf("no-dealer mode runs n nodes, got %d", len(outs))
		}
		digest := ""
		for _, o := range outs {
			if o.Err != nil {
				t.Fatalf("n=%d party %d: %v", n, o.ID, o.Err)
			}
			r := o.Result
			if r.Composed != want || r.OfflineMode != "no-dealer" || !r.IdentifiableAbort {
				t.Fatalf("n=%d party %d: %+v want %v", n, o.ID, r, want)
			}
			if digest != "" && r.TranscriptDigest != digest {
				t.Fatalf("n=%d transcript digests differ", n)
			}
			digest = r.TranscriptDigest
		}
	}
}

func TestMpcNetNoDealerDuplicateFrameBlamesTheSender(t *testing.T) {
	dup := func(to int, raw []byte) [][]byte {
		if f := MpcParseFrame(raw[4:]); f != nil && f["rd"] == "mul0" {
			return [][]byte{raw, raw}
		}
		return [][]byte{raw}
	}
	outs := mpcpRun(t, MpcLaunchOptions{N: 3, Q: 4, Vectors: mpcpVectors(3), Offline: "no-dealer", RecvTimeout: 120 * time.Second, Tamper: map[int]func(int, []byte) [][]byte{1: dup}})
	mpcpAllAborted(t, outs)
	for _, a := range mpcpFirstHandAbort(t, outs) {
		if a.Kind != "duplicate" || a.Blamed == nil || *a.Blamed != 1 {
			t.Fatalf("want a duplicate blamed on 1, got %v", a)
		}
	}
}
