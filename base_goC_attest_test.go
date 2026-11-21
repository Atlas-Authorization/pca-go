package pca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestGoCJwkRsaExponentBounds(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	n := enc(k.N.Bytes())
	exp := func(e *big.Int) string { return enc(e.Bytes()) }
	pow := func(b uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), b) }
	ok := map[string]*big.Int{
		"e 3":      big.NewInt(3),
		"e 65537":  big.NewInt(65537),
		"e 2^31-1": new(big.Int).Sub(pow(31), big.NewInt(1)),
	}
	for name, e := range ok {
		if _, err := jwkRSAKey(n, exp(e)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	refused := map[string]*big.Int{
		"e 2^31+1":  new(big.Int).Add(pow(31), big.NewInt(1)),
		"e 2^32-1":  new(big.Int).Sub(pow(32), big.NewInt(1)),
		"e 2^64+5":  new(big.Int).Add(pow(64), big.NewInt(5)),
		"e 2^40+1":  new(big.Int).Add(pow(40), big.NewInt(1)),
		"e 2^33+1":  new(big.Int).Add(pow(33), big.NewInt(1)),
		"e 2^63+1":  new(big.Int).Add(pow(63), big.NewInt(1)),
		"e 2^128+1": new(big.Int).Add(pow(128), big.NewInt(1)),
	}
	const want = "error:1E08010C:DECODER routines::unsupported"
	for name, e := range refused {
		if _, err := jwkRSAKey(n, exp(e)); err == nil || err.Error() != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string][2]string{"n empty": {"", "AQAB"}, "e empty": {n, ""}, "both empty": {"", ""}} {
		if _, err := jwkRSAKey(c[0], c[1]); err == nil || err.Error() != want {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func goCPssRaw(t *testing.T, name string, raw []byte) {
	t.Helper()
	h, mgf, salt, ok := pssParamsRaw(raw)
	if ok || h != 0 || mgf != 0 || salt != 0 {
		t.Errorf("%s: %v %v %d %v", name, h, mgf, salt, ok)
	}
}

func TestGoCPssParamsRawFailuresAreZero(t *testing.T) {
	oid := func(c ...byte) []byte { return derTLV(0x06, c) }
	mgf1 := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08}
	other := oid(0x55, 0x04, 0x03)
	seq := func(parts ...[]byte) []byte { return derTLV(0x30, parts...) }
	one := derTLV(0x02, []byte{1})
	goCPssRaw(t, "not a sequence", []byte{0x05, 0x00})
	goCPssRaw(t, "truncated child", []byte{0x30, 0x01, 0xa0})
	goCPssRaw(t, "field with two children", seq(derTLV(0xa0, one, one)))
	goCPssRaw(t, "field with no children", seq(derTLV(0xa0)))
	goCPssRaw(t, "hash field not an algorithm", seq(derTLV(0xa0, one)))
	goCPssRaw(t, "unknown hash", seq(derTLV(0xa0, seq(other))))
	goCPssRaw(t, "mgf field not an algorithm", seq(derTLV(0xa1, one)))
	goCPssRaw(t, "mgf is not MGF1", seq(derTLV(0xa1, seq(other))))
	goCPssRaw(t, "mgf parameters not a sequence", seq(derTLV(0xa1, seq(oid(mgf1...), derTLV(0x05)))))
	goCPssRaw(t, "mgf parameters not an algorithm", seq(derTLV(0xa1, seq(oid(mgf1...), seq(one)))))
	goCPssRaw(t, "mgf hash unknown", seq(derTLV(0xa1, seq(oid(mgf1...), seq(other)))))
	goCPssRaw(t, "salt not an integer", seq(derTLV(0xa2, derTLV(0x04))))
	goCPssRaw(t, "salt too large", seq(derTLV(0xa2, derTLV(0x02, []byte{0x02, 0x00, 0x00, 0x00}))))
	goCPssRaw(t, "trailer not 1", seq(derTLV(0xa3, derTLV(0x02, []byte{2}))))
	goCPssRaw(t, "unknown field", seq(derTLV(0xa4, one)))
}

func TestGoCKeyOfCertPssRestriction(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bits := derTLV(0x03, append([]byte{0}, x509.MarshalPKCS1PublicKey(&key.PublicKey)...))
	pssOID := derTLV(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a})
	spki := func(params ...[]byte) *attCert {
		alg := derTLV(0x30, append([][]byte{pssOID}, params...)...)
		return &attCert{RawSPKI: derTLV(0x30, alg, bits)}
	}
	sha256Alg := derTLV(0x30, derTLV(0x06, h8Sha256), derTLV(0x05))
	open, err := keyOfCert(spki())
	if err != nil || open.typ != "rsa-pss" || open.pss != nil {
		t.Fatalf("no parameters: %+v %v", open, err)
	}
	restricted, err := keyOfCert(spki(derTLV(0x30, derTLV(0xa0, sha256Alg))))
	want := &pssKeyRestriction{hash: crypto.SHA256, mgf: crypto.SHA1, salt: 20}
	if err != nil || restricted.typ != "rsa-pss" || !reflect.DeepEqual(restricted.pss, want) {
		t.Fatalf("parameters: %+v %v", restricted, err)
	}
	bad, err := keyOfCert(spki(derTLV(0x30, derTLV(0xa4, derTLV(0x02, []byte{1})))))
	if err != nil || bad.pss == nil || !bad.pss.bad {
		t.Fatalf("unparseable parameters: %+v %v", bad, err)
	}
}

func TestGoCParseRequireCrlForClamp(t *testing.T) {
	in := []any{json.Number("0"), json.Number("1"), json.Number("5"), json.Number("536870913"), json.Number("1073741823"), json.Number("1073741824"), json.Number("1073741825"), json.Number("1000000000000000")}
	got, err := parseRequireCrlFor(in, true)
	want := []int{0, 1, 5, 536870913, 1073741823, 1 << 30, 1 << 30, 1 << 30}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("clamp: %v %v", got, err)
	}
	if got, err := parseRequireCrlFor(nil, false); err != nil || got != "cdp" {
		t.Errorf("default: %v %v", got, err)
	}
}

func TestGoCCrlCoverageAllExcludesTheRoot(t *testing.T) {
	r := r11NewRig(t, true, true)
	rootCrl, icaCrl := r.crl(t, r.root, r.rootK), r.crl(t, r.ica, r.icaK)
	for _, rf := range []any{"all", "cdp"} {
		if got := checkNvidiaChainRevocation(r.chain, [][]byte{icaCrl, rootCrl}, g12Now, nil, rf); got != "" {
			t.Errorf("%v: the root is nobody's subject and needs no CRL: %q", rf, got)
		}
	}
}

func TestGoCFirmwarePolicyFalsyFloors(t *testing.T) {
	for _, v := range []any{"", false, json.Number("0"), nil} {
		p, err := compileFirmwarePolicy(map[string]any{"minVbiosVersion": v, "minDriverVersion": v})
		if err != nil || p.hasMinV || p.hasMinD {
			t.Errorf("%#v: %+v %v", v, p, err)
		}
	}
	p, err := compileFirmwarePolicy(map[string]any{"minVbiosVersion": "96.00.1A", "minDriverVersion": "535.86"})
	if err != nil || !p.hasMinV || !p.hasMinD || p.minVText != "96.00.1A" || p.minDText != "535.86" {
		t.Errorf("floors: %+v %v", p, err)
	}
	if _, err := compileFirmwarePolicy(map[string]any{"minVbiosVersion": json.Number("5")}); err == nil || err.Error() != "nvidiaCollateralHook: malformed minVbiosVersion '5'" {
		t.Errorf("non-string floor: %v", err)
	}
}
