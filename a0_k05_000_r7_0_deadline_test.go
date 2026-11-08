package pca

// r7 N0: mutants of attest_cert.go's error branches (`if err != nil` forced true, `!=` flipped) make the parser return
// (nil, nil) on a VALID certificate, so every later test dereferenced a nil *attCert and the process panicked with no test
// failing. These tests run first (a0_ sorts before the others), parse valid input under a recover, and fail with an ordinary
// assertion instead.

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func r7n0safe(f func()) (panicked any) {
	defer func() { panicked = recover() }()
	f()
	return nil
}

func TestR7N0_ParseValidCertNeverNilNoPanic(t *testing.T) {
	full := g03base()
	full.tail = append([]byte{0x81, 0x01, 0x00, 0x82, 0x01, 0x00}, g03exts(
		g03ext(g03oidBasicC, derTLV(0x01, []byte{0xff}), derTLV(0x04, []byte{0x00})),
		g03ext(g03oidKeyUsage, derTLV(0x04, []byte{0x05})),
	)...)
	noVersion := g03base()
	noVersion.version = nil
	for name, b := range map[string]g03cert{"base": g03base(), "full": full, "no version": noVersion} {
		var c *attCert
		var err error
		if p := r7n0safe(func() { c, err = parseCertDER(b.der()) }); p != nil {
			t.Errorf("%s: parseCertDER panicked: %v", name, p)
			continue
		}
		if err != nil || c == nil {
			t.Errorf("%s: parseCertDER = %v, %v; a valid certificate must parse", name, c, err)
			continue
		}
		if c.SigOID != "1.2.840.10045.4.3.2" || len(c.Raw) == 0 || len(c.RawIssuer) == 0 || len(c.RawSubject) == 0 || len(c.RawSPKI) == 0 || len(c.RawTBS) == 0 {
			t.Errorf("%s: parsed fields incomplete: %+v", name, c)
		}
	}
	var c *attCert
	var err error
	if p := r7n0safe(func() { c, err = parseCertDER(full.der()) }); p != nil || err != nil || c == nil || len(c.exts) != 2 {
		t.Errorf("extensions: %v %v %v", p, err, c)
	}
}

func TestR7N0_CertFromPEMValidNeverNil(t *testing.T) {
	_, cert := g03ecCert(t)
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	var c *attCert
	var err error
	if p := r7n0safe(func() { c, err = certFromPEM(text) }); p != nil {
		t.Fatalf("certFromPEM panicked: %v", p)
	}
	if err != nil || c == nil || !bytes.Equal(c.Raw, cert.Raw) {
		t.Fatalf("certFromPEM of a valid certificate = %v, %v", c, err)
	}
}

func TestR7N0_KeyOfCertValidNoPanic(t *testing.T) {
	_, cert := g03ecCert(t)
	rk := g03rsaKey(t)
	pk1 := x509.MarshalPKCS1PublicKey(&rk.PublicKey)
	rows := []struct {
		name string
		spki []byte
		typ  string
	}{
		{"ec", cert.RawSubjectPublicKeyInfo, "ec"},
		{"rsa", derTLV(0x30, derTLV(0x30, g03oidRsaEnc, []byte{0x05, 0x00}), derTLV(0x03, append([]byte{0x00}, pk1...))), "rsa"},
		{"rsa-pss", derTLV(0x30, derTLV(0x30, g03oidRsaPss), derTLV(0x03, append([]byte{0x00}, pk1...))), "rsa-pss"},
	}
	for _, r := range rows {
		var k certKey
		var err error
		if p := r7n0safe(func() { k, err = keyOfCert(&attCert{RawSPKI: r.spki}) }); p != nil {
			t.Errorf("%s: keyOfCert panicked: %v", r.name, p)
			continue
		}
		if err != nil || k.typ != r.typ || k.pub == nil {
			t.Errorf("%s: keyOfCert = %+v, %v", r.name, k, err)
		}
	}
}
