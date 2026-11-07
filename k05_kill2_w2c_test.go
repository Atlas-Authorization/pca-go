package pca

import (
	"bytes"
	"testing"
)

// A record missing its id or its state never decodes (the last two || of the guard).
func TestW2cDecodeOperationRecordRequiresIDAndState(t *testing.T) {
	if r, ok := decodeOperationRecord([]byte(`{"id":"a","state":"pending"}`)); !ok || r.ID != "a" || r.State != "pending" {
		t.Fatalf("valid record: %+v %v", r, ok)
	}
	for _, s := range []string{`{"state":"pending"}`, `{"id":"","state":"pending"}`, `{"id":"a"}`, `{"id":"a","state":""}`, ``} {
		if r, ok := decodeOperationRecord([]byte(s)); ok || r.ID != "" || r.State != "" {
			t.Errorf("%q decoded: %+v", s, r)
		}
	}
}

// A leaf hash that is not 32 bytes is refused even when the proof hashes it up to the root.
func TestW2cInclusionRefusesShortOrLongLeaf(t *testing.T) {
	p := bytes.Repeat([]byte{7}, 32)
	for _, n := range []int{31, 33} {
		leaf := bytes.Repeat([]byte{9}, n)
		if VerifyRFC9162Inclusion(leaf, 0, 2, [][]byte{p}, rfc9162Node(leaf, p)) {
			t.Errorf("a %d-byte leaf hash was accepted", n)
		}
	}
	leaf := bytes.Repeat([]byte{9}, 32)
	if !VerifyRFC9162Inclusion(leaf, 0, 2, [][]byte{p}, rfc9162Node(leaf, p)) {
		t.Fatal("a genuine 32-byte leaf proof was refused")
	}
}

// An unknown type string is "unknown type", never the later "unknown spec key".
func TestW2cSpecUnknownTypeMessage(t *testing.T) {
	n := 0
	if e := specError(map[string]any{"type": "bogus"}, 1, &n); e != "unknown type" {
		t.Errorf("specError: %q", e)
	}
	if e := ValidateArgSchema(map[string]any{"props": map[string]any{"a": map[string]any{"type": "bogus"}}}); e != "a: unknown type" {
		t.Errorf("ValidateArgSchema: %q", e)
	}
}

// A validly signed receipt with one malformed member still fails to verify (every || of the member guard).
func TestW2cUndoReceiptSignedButMalformed(t *testing.T) {
	key := undoSigner(t)
	good, err := SignUndoReceipt(UndoReceiptBody{Record: "op_1", Event: "opened", State: "open", At: 10, CompensationDigest: "cd"}, key)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyUndoReceipt(good, key.Public) {
		t.Fatal("genuine receipt refused")
	}
	for name, v := range map[string]any{"v": 2, "kind": "x", "state": "bogus", "note": 5, "prev": 5, "compensation_digest": 5} {
		body := withoutKeys(good, "sig")
		body[name] = v
		r, err := undoSign(UndoReceiptDomain, body, key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r) != 11 {
			t.Fatalf("%s: %d members", name, len(r))
		}
		if VerifyUndoReceipt(r, key.Public) {
			t.Errorf("signed receipt with bad %s verified", name)
		}
	}
}
