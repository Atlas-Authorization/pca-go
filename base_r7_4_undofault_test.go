package pca

import "testing"

// undoFaultAt() sits inside the failClosed scope of UndoTokenCheck and VerifyUndoReceipt. On a VALID token / receipt the
// fault must flip the answer to the refusal, so removing the call changes the outcome (an invalid input is refused anyway).
func TestR7N4_UndoFaultFlipsAValidTokenAndReceipt(t *testing.T) {
	defer func() { undoFault = nil }()
	key := undoSigner(t)
	rec := UndoTokenRecord{ID: "op_1", Aud: "aud", Principal: "p", CompensationDigest: "cd", RenderDigest: "", WindowEnd: 1000}
	tok, err := SignUndoToken(rec, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := SignUndoReceipt(UndoReceiptBody{Record: "op_1", Event: "opened", State: "open", At: 10, CompensationDigest: "cd"}, key)
	if err != nil {
		t.Fatal(err)
	}
	if got := UndoTokenCheck(tok, key.Public, rec, 500); got != "ok" {
		t.Fatalf("baseline token: %q", got)
	}
	if !VerifyUndoReceipt(r, key.Public) {
		t.Fatal("baseline receipt did not verify")
	}
	undoFault = func() { panic("boom") }
	if got := UndoTokenCheck(tok, key.Public, rec, 500); got != "malformed" {
		t.Errorf("token under a fault: %q", got)
	}
	if VerifyUndoReceipt(r, key.Public) {
		t.Error("receipt verified under a fault")
	}
}
