package pca

// The online test-only behaviours of a malicious party (open-lie, mac-lie, bad-tag, sigma-lie, crash, silent): every honest
// party aborts with no output, and the pairwise tags name the liar where the evidence can.

import (
	"errors"
	"math/big"
	"testing"
)

func mpcbRun(t *testing.T, kind, round string) []MpcNodeOutput {
	t.Helper()
	return mpcpRun(t, MpcLaunchOptions{N: 3, Q: 4, Vectors: mpcpVectors(3), DealerSeed: big.NewInt(13),
		Behavior: map[int]string{1: kind}, BehaviorRound: map[int]string{1: round}})
}

func mpcbAborted(t *testing.T, outs []MpcNodeOutput) {
	t.Helper()
	for _, o := range outs {
		if o.Role == "party" && (o.Result != nil || o.Err == nil) {
			t.Fatalf("party %d must abort with no output: %+v %v", o.ID, o.Result, o.Err)
		}
	}
}

// the pairwise MAC on the liar's opened share fails at an honest party, which names party 1
func mpcbNamed(t *testing.T, outs []MpcNodeOutput) {
	t.Helper()
	for _, o := range outs {
		var a *MpcNetAbort
		if o.ID != 1 && o.Role == "party" && errors.As(o.Err, &a) && a.Kind == "mac-check" && a.Blamed != nil && *a.Blamed == 1 {
			return
		}
	}
	t.Fatal("no honest party named party 1 through the pairwise MAC")
}

func TestMpcNetOpenLieIsNamedByThePairwiseTag(t *testing.T) {
	outs := mpcbRun(t, "open-lie", "mul0")
	mpcbAborted(t, outs)
	mpcbNamed(t, outs)
}

func TestMpcNetBadTagIsNamedByThePairwiseTag(t *testing.T) {
	outs := mpcbRun(t, "bad-tag", "mul0")
	mpcbAborted(t, outs)
	mpcbNamed(t, outs)
}

func TestMpcNetMacLieFailsTheMacCheck(t *testing.T) {
	mpcbAborted(t, mpcbRun(t, "mac-lie", "mul1"))
}

func TestMpcNetSigmaLieFailsTheMacCheck(t *testing.T) {
	mpcbAborted(t, mpcbRun(t, "sigma-lie", ""))
}

func TestMpcNetCrashExitsWithStatusSevenOnReachingTheRound(t *testing.T) {
	old := mpcExit
	defer func() { mpcExit = old }()
	type crashed struct{ code int }
	mpcExit = func(code int) { panic(crashed{code}) }
	func() {
		defer func() {
			c, ok := recover().(crashed)
			if !ok || c.code != 7 {
				t.Fatalf("want exit 7, got %v", c)
			}
		}()
		_, _ = MpcRunParty(MpcPartyConfig{ID: 0, N: 1, Input: mpcpVectors(1)[0], SessionID: "s", Behavior: "crash", BehaviorRound: "prep", UnsafeTestHooks: true})
		t.Fatal("the party did not crash")
	}()
}

func TestMpcNetSilentReturnsTheSilentSentinel(t *testing.T) {
	_, err := MpcRunParty(MpcPartyConfig{ID: 0, N: 1, Input: mpcpVectors(1)[0], SessionID: "s", Behavior: "silent", BehaviorRound: "prep", UnsafeTestHooks: true})
	if !errors.Is(err, ErrMpcSilentParty) {
		t.Fatalf("want the silent sentinel, got %v", err)
	}
}

// mpcbCulprit mirrors the reference's assertAborted: every honest party aborts with no output, either directly with one of the
// kinds (blaming the culprit) or through a peer's relayed claim of one of the kinds.
func mpcbCulprit(t *testing.T, outs []MpcNodeOutput, culprit int, kinds ...string) {
	t.Helper()
	has := func(k string) bool {
		for _, x := range kinds {
			if x == k {
				return true
			}
		}
		return false
	}
	for _, o := range outs {
		if o.Role != "party" || o.ID == culprit {
			continue
		}
		var a *MpcNetAbort
		if o.Result != nil || !errors.As(o.Err, &a) {
			t.Fatalf("party %d must abort with no output: %+v %v", o.ID, o.Result, o.Err)
		}
		if a.Kind == "peer-abort" {
			if a.ClaimedKind != nil && !has(*a.ClaimedKind) {
				t.Fatalf("party %d: unexpected relayed kind %s", o.ID, *a.ClaimedKind)
			}
			continue
		}
		if !has(a.Kind) || a.Blamed == nil || *a.Blamed != culprit {
			t.Fatalf("party %d: abort %s blamed %v, want %v blamed %d", o.ID, a.Kind, a.Blamed, kinds, culprit)
		}
	}
}

func TestMpcNetEquivocationAbortsWithNoOutput(t *testing.T) {
	mpcbAborted(t, mpcbRun(t, "equivocate", "mul0"))
}

func TestMpcNetBadCoinOpenIsAttributable(t *testing.T) {
	mpcbCulprit(t, mpcbRun(t, "bad-coin-open", ""), 1, "commitment")
}

func TestMpcNetBadSigmaOpenIsAttributable(t *testing.T) {
	mpcbCulprit(t, mpcbRun(t, "bad-sigma-open", ""), 1, "commitment")
}

func TestMpcNetShortArrayIsMalformed(t *testing.T) {
	mpcbCulprit(t, mpcbRun(t, "short-array", "mul0"), 1, "malformed")
}

func TestMpcNetNoncanonicalElementIsMalformed(t *testing.T) {
	mpcbCulprit(t, mpcbRun(t, "noncanonical", "out"), 1, "malformed")
}
