package pca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// A PKCS#1 v1.5 signature under an rsa-pss key (SPKI OID ...1.10) is refused on every PKCS#1 path; the same key as rsaEncryption passes.
func TestK05RsaPssKeyRefusesPkcs1(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pss"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := certFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := keyOfCert(c)
	if err != nil || rsaKey.typ != "rsa" {
		t.Fatalf("rsaEncryption key: %+v %v", rsaKey, err)
	}
	rsaOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	pssOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}
	if bytes.Count(c.RawSPKI, rsaOID) != 1 {
		t.Fatal("no rsaEncryption OID in the SPKI")
	}
	pssKey, err := keyOfCert(&attCert{RawSPKI: bytes.Replace(c.RawSPKI, rsaOID, pssOID, 1)})
	if err != nil || pssKey.typ != "rsa-pss" {
		t.Fatalf("rsa-pss key: %+v %v", pssKey, err)
	}

	msg := []byte("signed bytes")
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sha256Sum(msg))
	if err != nil {
		t.Fatal(err)
	}
	if !jwsRS256OK(sig, msg, rsaKey) || jwsRS256OK(sig, msg, pssKey) {
		t.Fatalf("jws: rsa %v, pss %v", jwsRS256OK(sig, msg, rsaKey), jwsRS256OK(sig, msg, pssKey))
	}
	if !crlSigOK(msg, sig, rsaKey) || crlSigOK(msg, sig, pssKey) {
		t.Fatalf("crl: rsa %v, pss %v", crlSigOK(msg, sig, rsaKey), crlSigOK(msg, sig, pssKey))
	}
	if !certSigOK(c, rsaKey) || certSigOK(c, pssKey) {
		t.Fatalf("cert: rsa %v, pss %v", certSigOK(c, rsaKey), certSigOK(c, pssKey))
	}
}
