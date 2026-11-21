package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math"
	"math/big"
	"reflect"
	"testing"
)

func TestG10AttestSmallHelpers(t *testing.T) {
	if got := lengthPrefixed(""); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("lengthPrefixed(\"\") = %v", got)
	}
	if got := lengthPrefixed("ab"); !bytes.Equal(got, []byte{0, 0, 0, 2, 'a', 'b'}) {
		t.Fatalf("lengthPrefixed(ab) = %v", got)
	}
	b := AttestationBinding{HolderPub: "h", GrantRef: "g", Nonce: "n", Epoch: maxSafeInt}
	if _, err := attestationBindingBytes(b); err != nil {
		t.Fatalf("epoch 2^53-1: %v", err)
	}
	b.Epoch = maxSafeInt + 1
	if _, err := attestationBindingBytes(b); err == nil || err.Error() != "binding: epoch must be a non-negative safe integer" {
		t.Fatalf("epoch 2^53: %v", err)
	}

	if w := (HardwareResult{OK: true, Bound: true}).Wire(); !reflect.DeepEqual(w, map[string]any{"ok": true, "bound": true}) {
		t.Fatalf("wire without measured / hostAsserted: %v", w)
	}

	for _, r := range []rune{0x1680, 0x2029, 0x202f, 0x205f, 0x2000, 0x200a, 0x2005} {
		if !isJSSpace(r) {
			t.Errorf("isJSSpace(%#x) = false", r)
		}
	}
	for _, r := range []rune{0x1681, 0x202a, 0x2030, 0x2060, 0x1fff, 0x200b} {
		if isJSSpace(r) {
			t.Errorf("isJSSpace(%#x) = true", r)
		}
	}

	if isHexString("") || isHexString("abc") || !isHexString("ab") {
		t.Fatal("isHexString")
	}
	if got := decodeClaimBytes("AQ"); !bytes.Equal(got, []byte{1}) {
		t.Fatalf("decodeClaimBytes(AQ) = %v", got)
	}

	if v, err := jsonLenient([]byte(`1.50`)); err != nil || v != any(json.Number("1.50")) {
		t.Fatalf("jsonLenient number: %#v %v", v, err)
	}
	if v, err := jsonLenient([]byte(``)); err == nil || v != nil {
		t.Fatalf("jsonLenient empty: %v %v", v, err)
	}
	if _, err := jsonLenient([]byte(`{`)); err == nil || err.Error() == "unexpected data after the JSON value" {
		t.Fatalf("jsonLenient truncated: %v", err)
	}

	for _, c := range []struct {
		in any
		f  float64
		ok bool
	}{
		{json.Number("x"), 0, false}, {"str", 0, false}, {math.Inf(1), 0, false}, {math.Inf(-1), 0, false}, {math.NaN(), 0, false},
		{json.Number("1e999"), 0, false}, {json.Number("2.5"), 2.5, true}, {int64(3), 3, true},
	} {
		if f, ok := asFinite(c.in); f != c.f || ok != c.ok {
			t.Errorf("asFinite(%v) = %v %v", c.in, f, ok)
		}
	}
	if l, ok := asStrList([]any{"a", 1}); l != nil || ok {
		t.Fatalf("asStrList with a number: %v %v", l, ok)
	}

	for f, want := range map[float64]string{123456789: "123456789", 1e21: "1e+21", 1e-7: "1e-7", 1.5: "1.5", -3: "-3", 1 << 60: "1152921504606847000"} {
		if got := jsNumString(f); got != want {
			t.Errorf("jsNumString(%v) = %q, want %q", f, got, want)
		}
	}

	if got := mergeOverrides(map[string]any{"a": 1}, map[string]any{"a": 9, "b": 2, "c": 3}); !reflect.DeepEqual(got, map[string]any{"a": 9, "b": 2, "c": 3}) {
		t.Fatalf("mergeOverrides: %v", got)
	}
	if got := errMsg(nil); got != "invalid" {
		t.Fatalf("errMsg(nil) = %q", got)
	}
}

func TestG10EcPointOfKey(t *testing.T) {
	for _, c := range []struct {
		curve elliptic.Curve
		name  string
	}{{elliptic.P256(), "P-256"}, {elliptic.P384(), "P-384"}} {
		k, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		e, err := k.PublicKey.ECDH()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ecPointOfKey(certKey{pub: &k.PublicKey, typ: "ec"}, c.name)
		if err != nil || !bytes.Equal(got, e.Bytes()) {
			t.Fatalf("%s: %x %v, want %x", c.name, got, err, e.Bytes())
		}
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ecPointOfKey(certKey{pub: &k.PublicKey, typ: "rsa"}, "P-256"); err == nil || err.Error() != "public key is not EC (got rsa)" {
		t.Fatalf("typ rsa: %v", err)
	}
	if _, err := ecPointOfKey(certKey{pub: "not a key", typ: "ec"}, "P-256"); err == nil || err.Error() != "public key is not EC (got ec)" {
		t.Fatalf("non-ecdsa pub: %v", err)
	}
	if _, err := ecPointOfKey(certKey{pub: &k.PublicKey, typ: "ec"}, "P-384"); err == nil || err.Error() != "public key is not on P-384 (got P-256)" {
		t.Fatalf("wrong curve: %v", err)
	}
}

func TestG10DNNames(t *testing.T) {
	for in, want := range map[string]string{
		"#a": `\#a`, " a": `\ a`, "a ": `a\ `, "a b": "a b", "\x01": `\01`, "\x7f": `\7F`, "a,b": `a\,b`, "x": "x",
	} {
		if got := escapeDNValue(in); got != want {
			t.Errorf("escapeDNValue(%q) = %q, want %q", in, got, want)
		}
	}
	raw, err := asn1.Marshal(pkix.Name{CommonName: "c", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: 5}}}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	if got := nameText(raw); got != "CN=c\n1.2.3.4=5" {
		t.Fatalf("nameText: %q", got)
	}
	if got := nameText(append(append([]byte{}, raw...), 0)); got != "" {
		t.Fatalf("trailing bytes: %q", got)
	}
}

func TestG10RawECDSAAndPoints(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("m"))
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	if !verifyRawECDSA(&k.PublicKey, d[:], sig) {
		t.Fatal("a valid raw signature must verify")
	}
	// the same r and s with one zero byte in front of s: odd length, refused although the halves would still verify
	odd := append(append(append([]byte{}, sig[:48]...), 0), sig[48:]...)
	if verifyRawECDSA(&k.PublicKey, d[:], odd) || verifyRawECDSA(&k.PublicKey, d[:], nil) {
		t.Fatal("odd-length and empty signatures must not verify")
	}

	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P521()} {
		pk, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		e, err := pk.PublicKey.ECDH()
		if err != nil {
			t.Fatal(err)
		}
		pt := e.Bytes()
		got, ok := pointToKey(c, pt)
		if !ok || got.X.Cmp(pk.X) != 0 || got.Y.Cmp(pk.Y) != 0 {
			t.Fatalf("%s: a valid point", c.Params().Name)
		}
		bad := append([]byte{}, pt...)
		bad[0] = 0x05
		if k, ok := pointToKey(c, bad); ok || k != nil {
			t.Fatalf("%s: a 0x05 prefix", c.Params().Name)
		}
		size := (len(pt) - 1) / 2
		off := append([]byte{}, pt...)
		new(big.Int).Add(pk.Y, big.NewInt(1)).FillBytes(off[1+size:])
		if k, ok := pointToKey(c, off); ok || k != nil {
			t.Fatalf("%s: an off-curve point", c.Params().Name)
		}
	}
}

func TestG10AzureRuntimeDataShape(t *testing.T) {
	if got := checkAzureRuntimeDataBinding(make([]byte, 63), nil, testBinding); got != "report_data is not 64 bytes" {
		t.Fatalf("63 bytes: %q", got)
	}
	rd := make([]byte, 64)
	rd[32] = 1
	if got := checkAzureRuntimeDataBinding(rd, nil, testBinding); got != "report_data[32:64] is not zero (not an Azure runtime-data hash)" {
		t.Fatalf("byte 32 set: %q", got)
	}
}
