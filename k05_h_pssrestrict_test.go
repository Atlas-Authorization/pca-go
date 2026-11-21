package pca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// H8: an rsa-pss issuer key whose SPKI carries RSASSA-PSS-params restricts the signatures it accepts: the hash and the MGF1 hash
// must be its own, and the salt at least as long as its own. A key without parameters is unrestricted.

func h8Params(hashOID, mgfOID []byte, salt int) []byte {
	alg := func(oid []byte) []byte { return derTLV(0x30, derTLV(0x06, oid), derTLV(0x05)) }
	return derTLV(0x30,
		derTLV(0xa0, alg(hashOID)),
		derTLV(0xa1, derTLV(0x30, derTLV(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08}), alg(mgfOID))),
		derTLV(0xa2, derTLV(0x02, []byte{byte(salt)})))
}

var (
	h8Sha256 = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	h8Sha384 = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}
)

func TestH8_PssParamsRaw(t *testing.T) {
	h, mgf, salt, ok := pssParamsRaw(h8Params(h8Sha384, h8Sha384, 48))
	if !ok || h != crypto.SHA384 || mgf != crypto.SHA384 || salt != 48 {
		t.Fatalf("384/384/48: %v %v %d %v", h, mgf, salt, ok)
	}
	h, mgf, salt, ok = pssParamsRaw(h8Params(h8Sha256, h8Sha384, 32))
	if !ok || h != crypto.SHA256 || mgf != crypto.SHA384 || salt != 32 {
		t.Fatalf("256/384/32: %v %v %d %v", h, mgf, salt, ok)
	}
	// the signature-side profile still demands MGF1 over the same hash
	if _, _, good := pssParams(h8Params(h8Sha256, h8Sha384, 32)); good {
		t.Error("a mixed-hash signature profile accepted")
	}
	if _, _, good := pssParams(h8Params(h8Sha384, h8Sha384, 48)); !good {
		t.Error("a same-hash profile refused")
	}
	if h, mgf, salt, ok := pssParamsRaw(nil); !ok || h != crypto.SHA1 || mgf != crypto.SHA1 || salt != 20 {
		t.Errorf("absent: %v %v %d %v", h, mgf, salt, ok)
	}
	if _, _, _, ok := pssParamsRaw([]byte{0x05, 0x00}); ok {
		t.Error("NULL parameters parsed")
	}
}

func TestH8_PssAllowedBy(t *testing.T) {
	restricted := &pssKeyRestriction{hash: crypto.SHA384, mgf: crypto.SHA384, salt: 48}
	for name, c := range map[string]struct {
		r      *pssKeyRestriction
		h, mgf crypto.Hash
		salt   int
		want   bool
	}{
		"unrestricted key, sha256":      {nil, crypto.SHA256, crypto.SHA256, 20, true},
		"384 / 384 / 48":                {restricted, crypto.SHA384, crypto.SHA384, 48, true},
		"384 / 384 / 64 (longer salt)":  {restricted, crypto.SHA384, crypto.SHA384, 64, true},
		"384 / 384 / 20 (shorter salt)": {restricted, crypto.SHA384, crypto.SHA384, 20, false},
		"384 / 384 / 47":                {restricted, crypto.SHA384, crypto.SHA384, 47, false},
		"sha256 under a sha384 key":     {restricted, crypto.SHA256, crypto.SHA256, 48, false},
		"sha384 with MGF1 sha256":       {restricted, crypto.SHA384, crypto.SHA256, 48, false},
		"unparseable key parameters":    {&pssKeyRestriction{bad: true}, crypto.SHA1, crypto.SHA1, 20, false},
	} {
		if got := pssAllowedBy(c.r, c.h, c.mgf, c.salt); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// An end-to-end check on the certificate signature: a child signed with SHA-256 PSS is refused under a SHA-384-restricted issuer
// key and accepted under an unrestricted one.
func TestH8_CertSignatureUnderARestrictedPssKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tbs := []byte("tbs bytes")
	sum := sha256.Sum256(tbs)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	p256 := h8Params(h8Sha256, h8Sha256, 32)
	child := &attCert{SigOID: "1.2.840.113549.1.1.10", SigParams: p256, RawTBS: tbs, Signature: sig}
	open := certKey{pub: &key.PublicKey, typ: "rsa-pss"}
	if !certSigOK(child, open) {
		t.Fatal("an unrestricted key must accept its own SHA-256 PSS signature")
	}
	same := open
	same.pss = &pssKeyRestriction{hash: crypto.SHA256, mgf: crypto.SHA256, salt: 32}
	if !certSigOK(child, same) {
		t.Error("a key restricted to what the signature uses must accept it")
	}
	narrow := open
	narrow.pss = &pssKeyRestriction{hash: crypto.SHA384, mgf: crypto.SHA384, salt: 48}
	if certSigOK(child, narrow) {
		t.Error("a SHA-384-restricted key accepted a SHA-256 signature")
	}
	// SHA-384 with salt 48 under the SHA-384 key
	sum384 := sha512.Sum384(tbs)
	sig384, err := rsa.SignPSS(rand.Reader, key, crypto.SHA384, sum384[:], &rsa.PSSOptions{SaltLength: 48})
	if err != nil {
		t.Fatal(err)
	}
	c384 := &attCert{SigOID: "1.2.840.113549.1.1.10", SigParams: h8Params(h8Sha384, h8Sha384, 48), RawTBS: tbs, Signature: sig384}
	if !certSigOK(c384, narrow) {
		t.Error("SHA-384 / salt 48 under the SHA-384 / 48 key")
	}
	// the same key but a salt of 20 in the signature parameters: refused
	short, err := rsa.SignPSS(rand.Reader, key, crypto.SHA384, sum384[:], &rsa.PSSOptions{SaltLength: 20})
	if err != nil {
		t.Fatal(err)
	}
	if certSigOK(&attCert{SigOID: "1.2.840.113549.1.1.10", SigParams: h8Params(h8Sha384, h8Sha384, 20), RawTBS: tbs, Signature: short}, narrow) {
		t.Error("a salt shorter than the key's was accepted")
	}
}
