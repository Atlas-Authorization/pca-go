package pca

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func g11UndoKey(t *testing.T) *KeyPair {
	t.Helper()
	seed := make([]byte, 32)
	seed[0] = 77
	k, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func g11Nest(levels int) map[string]any {
	m := map[string]any{"x": "y"}
	for i := 1; i < levels; i++ {
		m = map[string]any{"a": m}
	}
	return m
}

func TestG11FailClosed(t *testing.T) {
	got := func() (s string) {
		defer failClosed(&s, func(r any) string { return fmt.Sprint("caught ", r) })
		panic("x")
	}()
	if got != "caught x" {
		t.Fatal(got)
	}
	got = func() (s string) {
		defer failClosed(&s, func(r any) string { return "caught" })
		return "fine"
	}()
	if got != "fine" {
		t.Fatal(got)
	}
}

// the params are read from depth 1: 32 nested objects pass the JSON check and only the canonicalizer refuses them (the body
// adds one level), 33 are refused as not JSON
func TestG11CompensationDigestParamsDepth(t *testing.T) {
	c := UndoCompensation{Verb: "v", Resource: "r", UndoOf: "u", DefDigest: "d"}
	c.Params = g11Nest(31)
	if _, err := CompensationDigest(c); err != nil {
		t.Fatal("31 levels:", err)
	}
	c.Params = g11Nest(32)
	if _, err := CompensationDigest(c); err == nil || !strings.Contains(err.Error(), "canonicalize: nesting too deep") {
		t.Fatal("32 levels:", err)
	}
	c.Params = g11Nest(33)
	if _, err := CompensationDigest(c); err == nil || err.Error() != "undo: the compensation params are not JSON" {
		t.Fatal("33 levels:", err)
	}
}

func TestG11UndoSign(t *testing.T) {
	key := g11UndoKey(t)
	if _, err := undoSign(UndoReceiptDomain, map[string]any{"a": "b"}, nil); err == nil || err.Error() != "signer_missing: the undo service key is required" {
		t.Fatal(err)
	}
	if _, err := undoSign(UndoReceiptDomain, map[string]any{"a": "\xed\xa0\x80"}, key); err == nil || !strings.Contains(err.Error(), "lone surrogate") {
		t.Fatal(err)
	}
	out, err := undoSign(UndoReceiptDomain, map[string]any{"a": "b"}, key)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := out["sig"].(string)
	if !undoDomainVerify(UndoReceiptDomain, key.Public, withoutKeys(out, "sig"), sig) {
		t.Fatal("the signature must cover the domain and the canonical body")
	}
	if _, err := SignUndoReceipt(UndoReceiptBody{Record: "r", Event: "opened", State: "open"}, nil); err == nil {
		t.Fatal("a receipt without a key")
	}
}

func TestG11UndoTokenNowBounds(t *testing.T) {
	key := g11UndoKey(t)
	const maxSafe = int64(1<<53 - 1)
	for _, tc := range []struct {
		windowEnd, now int64
		want           string
	}{
		{maxSafe, maxSafe, "ok"},
		{maxSafe, maxSafe + 1, "expired"},
		{0, -maxSafe, "ok"},
		{0, -maxSafe - 1, "expired"},
	} {
		rec := UndoTokenRecord{ID: "rec1", Aud: "aud", Principal: "p", CompensationDigest: "cd", WindowEnd: tc.windowEnd}
		tok, err := SignUndoToken(rec, key)
		if err != nil {
			t.Fatal(err)
		}
		if got := UndoTokenCheck(tok, key.Public, rec, tc.now); got != tc.want {
			t.Errorf("exp %d now %d: %s want %s", tc.windowEnd, tc.now, got, tc.want)
		}
	}
}

func TestG11EncodeUndoTokenRefusesNonCanonical(t *testing.T) {
	if s, err := EncodeUndoToken(map[string]any{"a": "\xed\xa0\x80"}); err == nil || s != "" {
		t.Fatalf("%q %v", s, err)
	}
}

func g11Receipt(t *testing.T, key *KeyPair, v any, extra bool) map[string]any {
	t.Helper()
	body := map[string]any{"v": v, "kind": UndoReceiptKind, "record": "rec1", "event": "opened", "state": "open", "at": 1,
		"compensation_digest": "cd", "prev": "", "note": "", "signer": key.Public}
	if extra {
		body["extra"] = "x"
	}
	r, err := undoSign(UndoReceiptDomain, body, key)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestG11VerifyUndoReceiptShape(t *testing.T) {
	key := g11UndoKey(t)
	if !VerifyUndoReceipt(g11Receipt(t, key, 1, false), key.Public) {
		t.Fatal("control")
	}
	// validly signed, but v is not a number / the receipt has a 12th member
	if VerifyUndoReceipt(g11Receipt(t, key, "1", false), key.Public) {
		t.Fatal("v as a string")
	}
	if VerifyUndoReceipt(g11Receipt(t, key, 1, true), key.Public) {
		t.Fatal("12 members")
	}
}

func TestG11ClipUnits(t *testing.T) {
	const loneHigh, loneLow = "\xed\xa0\x80", "\xed\xb0\x80" // U+D800, U+DC00 as carried lone units
	for i, tc := range []struct {
		s    string
		n    int
		want string
	}{
		{"a" + loneHigh, 2, "a" + loneHigh},         // exactly n units: returned as is
		{"abc", 0, ""},                              // n = 0
		{"abc", 2, "ab"},                            // no surrogates
		{"\U0001F600x", 1, ""},                      // a pair at the start is not split
		{"a\U0001F600", 2, "a"},                     // nor later
		{"a\U00010000", 2, "a"},                     // D800 DC00: the lowest pair
		{"a\U0010FFFF", 2, "a"},                     // DBFF DFFF: the highest pair
		{"a\U000103FF", 2, "a"},                     // D800 DFFF
		{"a" + loneLow + loneLow, 2, "a" + loneLow}, // a low unit before the cut is not a pair start
		{"ab" + loneLow, 2, "ab"},                   // a low unit after a non-surrogate
		{"a" + loneHigh + "", 2, "a" + loneHigh},   // U+E000 after a high unit is not a low surrogate
		{"a퟿" + loneLow, 2, "a퟿"},                   // U+D7FF is not a high surrogate
	} {
		if got := clipUnits(tc.s, tc.n); got != tc.want {
			t.Errorf("case %d: %q want %q", i, got, tc.want)
		}
	}
}

func TestG11ResolveUndoWindowNegativeInfinity(t *testing.T) {
	neg := math.Inf(-1)
	if got := ResolveUndoWindow(&neg, UndoWindowPolicy{}); got != UndoDefaultWindowMs {
		t.Fatal(got)
	}
}

func TestG11CallUndoAdmit(t *testing.T) {
	adm := UndoAdmission{ID: "op_1", WindowEnd: 1792930500000, Compensation: UndoCompensation{Verb: "payments.refund", Resource: "payments/acme"}}
	if got, o := callUndoAdmit(func(UndoAdmitInput) (*UndoAdmission, error) { a := adm; return &a, nil }, UndoAdmitInput{}); got == nil || o == nil {
		t.Fatal("control")
	}
	if got, o := callUndoAdmit(func(UndoAdmitInput) (*UndoAdmission, error) { a := adm; return &a, errors.New("x") }, UndoAdmitInput{}); got != nil || o != nil {
		t.Fatal("an admission with an error is no admission")
	}
	noVerb := adm
	noVerb.Compensation.Verb = ""
	if got, o := callUndoAdmit(func(UndoAdmitInput) (*UndoAdmission, error) { return &noVerb, nil }, UndoAdmitInput{}); got != nil || o != nil {
		t.Fatal("an admission without a compensation verb is no admission")
	}
}
