package pca

import (
	"errors"
	"math"
	"testing"
)

// r5-7: undo.go survivors.

func r5n7NoPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

func TestR5N7_CompensationDigestOfNonJSONParams(t *testing.T) {
	d, err := CompensationDigest(UndoCompensation{Verb: "v", Resource: "r", Params: map[string]any{"x": make(chan int)}})
	if d != "" || err == nil || err.Error() != "undo: the compensation params are not JSON" {
		t.Fatalf("got %q %v", d, err)
	}
	if d, err := CompensationDigest(UndoCompensation{Verb: "v", Resource: "r", Params: map[string]any{}}); err != nil || d == "" {
		t.Fatalf("plain params: %q %v", d, err)
	}
}

// A panic inside the three fail-closed entry points is their refusal, never a panic out of them.
func TestR5N7_UndoFailClosedEntryPoints(t *testing.T) {
	defer func() { undoFault = nil }()
	undoFault = func() { panic("boom") }
	r5n7NoPanic(t, "UndoTokenCheck", func() {
		if got := UndoTokenCheck(map[string]any{}, "s", UndoTokenRecord{}, 0); got != "malformed" {
			t.Errorf("UndoTokenCheck: %q", got)
		}
	})
	r5n7NoPanic(t, "VerifyUndoReceipt", func() {
		if VerifyUndoReceipt(map[string]any{}, "s") {
			t.Error("VerifyUndoReceipt verified under a fault")
		}
	})
	r5n7NoPanic(t, "UndoTransition", func() {
		res := UndoTransition(map[string]any{}, map[string]any{"kind": "retry"}, 0)
		if res.Outcome != "refused" || res.Code != "invalid" || res.Reason != "evaluation error (fail closed)" {
			t.Errorf("UndoTransition: %+v", res)
		}
	})
}

// A receipt that verified always has a canonical digest; if it did not, the chain is refused as not canonical.
func TestR5N7_UndoChainDigestRefusal(t *testing.T) {
	key := undoSigner(t)
	rs := undoChain(t, key, [][3]any{{"opened", "open", int64(10)}})
	chain := func() string {
		return UndoReceiptChainError(UndoChainRecord{ID: "op_1", CompensationDigest: "cd", State: "open", Receipts: rs}, key.Public)
	}
	if e := chain(); e != "" {
		t.Fatalf("premise: %q", e)
	}
	defer func(old func(map[string]any) (string, error)) { undoReceiptDigestFn = old }(undoReceiptDigestFn)
	undoReceiptDigestFn = func(map[string]any) (string, error) { return "", errors.New("r5n7") }
	if e := chain(); e != "receipt 0 is not canonical" {
		t.Fatalf("got %q", e)
	}
}

// A window end past 2^53-1 has no safe JSON number: no obligation, and no half-built one.
func TestR5N7_UndoWindowObligationUnsafeEnd(t *testing.T) {
	o, ok := undoWindowObligation(&UndoAdmission{ID: "op_1", WindowEnd: math.MaxInt64})
	if o != nil || ok {
		t.Fatalf("got %v %v", o, ok)
	}
	if o, ok := undoWindowObligation(&UndoAdmission{ID: "op_1", WindowEnd: 1792930500000}); !ok || o == nil {
		t.Fatalf("safe end: %v %v", o, ok)
	}
}

// A panicking admission hook is no admission.
func TestR5N7_CallUndoAdmitPanic(t *testing.T) {
	adm, ob := callUndoAdmit(func(UndoAdmitInput) (*UndoAdmission, error) { panic("boom") }, UndoAdmitInput{})
	if adm != nil || ob != nil {
		t.Fatalf("got %v %v", adm, ob)
	}
}

// A token with ten members of which one required name is missing is malformed (not an empty code).
func TestR5N7_UndoTokenWithAMissingMemberIsMalformed(t *testing.T) {
	key := undoSigner(t)
	rec := UndoTokenRecord{ID: "op_1", Aud: "a", Principal: "p", CompensationDigest: "cd", WindowEnd: 2000}
	tok, err := SignUndoToken(rec, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range undoTokenMembers {
		bad := copyMap(tok)
		delete(bad, k)
		bad["extra"] = "x" // still ten members
		if got := UndoTokenCheck(bad, key.Public, rec, 1000); got != "malformed" {
			t.Errorf("without %s: %q", k, got)
		}
	}
}
