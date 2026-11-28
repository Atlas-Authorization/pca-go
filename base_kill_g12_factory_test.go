package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// ---- attest_factory.go: the recover, the identity-override merge gate and the DefaultHardware evidence default

type g12FakeVendor struct {
	res    HardwareResult
	panicV any
	gotEv  *map[string]any
}

func (f g12FakeVendor) verify(ev map[string]any, _ *AttestationBinding, _ int64) HardwareResult {
	if f.gotEv != nil {
		*f.gotEv = ev
	}
	if f.panicV != nil {
		panic(f.panicV)
	}
	return f.res
}

func TestG12VendorVerifyRecoversWithTheVendorPrefix(t *testing.T) {
	v := &VendorVerifier{vendor: "azure-maa", impl: g12FakeVendor{panicV: "boom"}}
	r := v.Verify(nil, nil, 0)
	if r.OK || r.Reason != "azure-maa verification error (fail closed): boom" {
		t.Fatalf("got %+v", r)
	}
}

func TestG12VendorVerifyOverrideGate(t *testing.T) {
	ov := map[string]any{"x": "over"}
	// a failed result is never merged, even with a measured map
	m := map[string]any{"a": "1"}
	r := (&VendorVerifier{vendor: "azure-maa", impl: g12FakeVendor{res: HardwareResult{Measured: m}}, overrides: ov}).Verify(nil, nil, 0)
	if _, has := r.Measured["x"]; has || len(r.Measured) != 1 {
		t.Fatalf("failed result merged: %v", r.Measured)
	}
	// an OK result without a measured map stays without one
	r = (&VendorVerifier{vendor: "azure-maa", impl: g12FakeVendor{res: HardwareResult{OK: true}}, overrides: ov}).Verify(nil, nil, 0)
	if r.Measured != nil {
		t.Fatalf("nil measured merged: %v", r.Measured)
	}
	// no overrides: the measured map is passed through as is (not copied)
	m2 := map[string]any{"a": "1"}
	r = (&VendorVerifier{vendor: "azure-maa", impl: g12FakeVendor{res: HardwareResult{OK: true, Measured: m2}}}).Verify(nil, nil, 0)
	r.Measured["probe"] = true
	if m2["probe"] != true {
		t.Fatal("without overrides the measured map must not be copied")
	}
	// overrides on an OK measured result are merged
	r = (&VendorVerifier{vendor: "azure-maa", impl: g12FakeVendor{res: HardwareResult{OK: true, Measured: map[string]any{"a": "1"}}}, overrides: ov}).Verify(nil, nil, 0)
	if r.Measured["x"] != "over" || r.Measured["a"] != "1" {
		t.Fatalf("not merged: %v", r.Measured)
	}
}

func TestG12DefaultHardwareUsesTheDocWithoutEvidenceFunc(t *testing.T) {
	var got map[string]any
	v := &VendorVerifier{vendor: "azure-maa", impl: g12FakeVendor{res: HardwareResult{OK: true, Bound: true}, gotEv: &got}}
	doc := map[string]any{"marker": "doc"}
	a, err := (&DefaultHardware{Verifier: v}).attest(5)(doc, PassportBinding{})
	if err != nil || !a.OK || !a.Bound || got["marker"] != "doc" {
		t.Fatalf("%+v %v %v", a, err, got)
	}
}

// ---- attest_jws.go

func TestG12JwsKeyTypeGates(t *testing.T) {
	rsaKey := certKey{pub: &rsa.PublicKey{N: big.NewInt(77), E: 3}, typ: "rsa"}
	ecKey := certKey{pub: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, typ: "ec"}
	if jwsES256OK(make([]byte, 64), []byte("x"), rsaKey) {
		t.Error("ES256 under an RSA key")
	}
	if jwsRS256OK(make([]byte, 64), []byte("x"), ecKey) {
		t.Error("RS256 under an EC key")
	}
	if k, c := jwkKtyCrv(certKey{pub: ed25519.PublicKey(make([]byte, 32)), typ: "ed25519"}); k != "OKP" || c != "Ed25519" {
		t.Errorf("ed25519: %s %s", k, c)
	}
	if k, c := jwkKtyCrv(certKey{typ: "unknown"}); k != "unknown" || c != "undefined" {
		t.Errorf("unknown: %s %s", k, c)
	}
}

func TestG12JwkRSAKeyBounds(t *testing.T) {
	const unsupported = "error:1E08010C:DECODER routines::unsupported"
	n := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xc5}, 256))
	for _, c := range []struct {
		n, e  string
		wantE int
	}{
		{"", "AQAB", 0},          // empty modulus
		{n, "AQ", 0},             // e = 1
		{n, "Ag", 0},             // e = 2
		{n, "Aw", 3},             // e = 3: the smallest accepted (and a one-byte exponent)
		{n, "f____w", 1<<31 - 1}, // the largest accepted
		{n, "gAAAAA", 0},         // 2^31
	} {
		k, err := jwkRSAKey(c.n, c.e)
		if c.wantE == 0 {
			if err == nil || err.Error() != unsupported {
				t.Errorf("n=%d e=%s: want refusal, got %v", len(c.n), c.e, err)
			}
			continue
		}
		pk, ok := k.pub.(*rsa.PublicKey)
		if err != nil || !ok || pk.E != c.wantE || k.typ != "rsa" {
			t.Errorf("e=%s: %v %+v", c.e, err, k)
		}
	}
}

func TestG12JwkECKeyOffCurve(t *testing.T) {
	_, err := jwkECKey("P-256", "AQ", "AQ")
	if err == nil || err.Error() != "error:1E08010C:DECODER routines::unsupported" {
		t.Fatalf("off-curve: %v", err)
	}
}

func TestG12JwkMarshalFailureFailsClosed(t *testing.T) {
	old := jwkMarshalSPKI
	defer func() { jwkMarshalSPKI = old }()
	seam := errors.New("g12 seam")
	jwkMarshalSPKI = func(any) ([]byte, error) { return nil, seam }
	if _, err := jwkRSAKey(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xc5}, 256)), "AQAB"); err != seam {
		t.Errorf("rsa: %v", err)
	}
	p := elliptic.P256().Params()
	x := base64.RawURLEncoding.EncodeToString(p.Gx.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(p.Gy.FillBytes(make([]byte, 32)))
	if _, err := jwkECKey("P-256", x, y); err != seam {
		t.Errorf("ec: %v", err)
	}
}

func TestG12ParseJWTEmptyAndSegmentErrors(t *testing.T) {
	if _, err := parseJWT("", "p"); err == nil || err.Error() != "p: empty token" {
		t.Errorf("empty: %v", err)
	}
	// a header that does not decode reports its canonical-form error
	if _, err := parseJWT("!!.e30.c2ln", "p"); err == nil || err.Error() != "p: malformed JSON segment: non-canonical compact JWS: bad-character" {
		t.Errorf("decode: %v", err)
	}
	// a segment that is not JSON, or repeats a member, is "invalid JSON", whatever the engine would say of it
	enc := base64.RawURLEncoding.EncodeToString
	const alg = `{"alg":"ES256"}`
	for name, text := range map[string]string{"truncated": "{", "not json": "not json", "duplicate member": `{"a":1,"a":2}`, "nested duplicate": `{"a":{"b":1,"b":2}}`} {
		if _, err := parseJWT(enc([]byte(alg))+"."+enc([]byte(text))+".c2ln", "p"); err == nil || err.Error() != "p: malformed JSON segment: invalid JSON" {
			t.Errorf("%s payload: %v", name, err)
		}
		if _, err := parseJWT(enc([]byte(text))+"."+enc([]byte(`{"iss":"i"}`))+".c2ln", "p"); err == nil || err.Error() != "p: malformed JSON segment: invalid JSON" {
			t.Errorf("%s header: %v", name, err)
		}
	}
	// deep nesting: V8's JSON.parse is iterative, so the reference parses a deeply nested segment and refuses the token downstream (the
	// header or payload is not an object). Go's parser is recursive and keeps its safety cap (MaxLenientDepth): below the cap the
	// segment parses and the token is refused downstream with the same reasons; above it (200000 brackets) it is refused as
	// "invalid JSON", a pinned stricter divergence. Neither panics or overflows the stack.
	nest := func(n int) []byte { return []byte(strings.Repeat("[", n) + strings.Repeat("]", n)) }
	for _, c := range []struct {
		depth             int
		payloadErr, hdErr string
	}{
		{10001, "p: payload is not a JSON object", "p: header is not a JSON object"},
		{MaxLenientDepth, "p: payload is not a JSON object", "p: header is not a JSON object"},
		{200000, "p: malformed JSON segment: invalid JSON", "p: malformed JSON segment: invalid JSON"},
	} {
		if _, err := parseJWT(enc([]byte(alg))+"."+enc(nest(c.depth))+".c2ln", "p"); err == nil || err.Error() != c.payloadErr {
			t.Errorf("payload nested %d deep: %v, want %q", c.depth, err, c.payloadErr)
		}
		if _, err := parseJWT(enc(nest(c.depth))+"."+enc([]byte(`{"iss":"i"}`))+".c2ln", "p"); err == nil || err.Error() != c.hdErr {
			t.Errorf("header nested %d deep: %v, want %q", c.depth, err, c.hdErr)
		}
	}
	// a genuine vendor token is not canonical JSON: 8.0, 1e3, 1.0 and -0 are read as written, not refused
	for _, n := range []string{"8.0", "1e3", "1.0", "-0", "1E+2"} {
		if _, err := parseJWT(enc([]byte(`{"alg":"ES256","n":`+n+`}`))+"."+enc([]byte(`{"iss":"i","n":`+n+`}`))+".c2ln", "p"); err != nil {
			t.Errorf("number %s must be read as written: %v", n, err)
		}
	}
}
