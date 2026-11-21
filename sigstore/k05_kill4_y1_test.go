package pcasigstore

// y1 mutation kills. References: sigstore.ts oidText, verifySct and rfc3339, and OpenSSL's X509_check_akid behind
// X509Certificate.checkIssued (key id compared only when the issuer has one, serial and issuer name read from the issuer's TBS).

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func y1AKI(v []byte) pkix.Extension {
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: v}
}

// y1Versionless is a certificate shape with no [0] version: serial 5, algorithm, issuer name, and optionally an extensions
// wrapper (no wrapper: the shape of a v1 certificate, which parseCert refuses and an OpenSSL issuer lookup accepts). Returns
// the DER and the issuer name's full TLV.
func y1Versionless(extensions bool) ([]byte, []byte) {
	issuer := enc(0x30, enc(0x31, enc(0x30, []byte{0x06, 1, 0x2a, 0x0c, 2, 'y', '1'})))
	tbs := append(append(enc(0x02, []byte{5}), enc(0x30, []byte{0x06, 1, 0x2a})...), issuer...)
	if extensions {
		tbs = append(tbs, enc(0xa3, enc(0x30, nil))...)
	}
	return enc(0x30, enc(0x30, tbs)), issuer
}

// A refused date reads as no value at all (the reference's NaN), whichever check refused it.
func TestY1SigstoreRFC3339RefusalCarriesNoValue(t *testing.T) {
	for _, in := range []string{
		"not a date",
		"2026-13-01T00:00:00Z",
		"2026-01-01T25:00:00Z",
		"2026-01-01T00:00:00+24:00",
	} {
		if got, ok := rfc3339(in); ok || got != 0 {
			t.Errorf("rfc3339(%q) = %d %v, want 0 false", in, got, ok)
		}
	}
}

// 0x80 opens an arc after any byte with a clear high bit, an odd one included (sigstore.ts oidText: !(b[i - 1] & 0x80)).
func TestY1SigstoreOIDLeadingZeroAfterOddByte(t *testing.T) {
	b := []byte{0x2a, 0x01, 0x80, 0x01}
	err := catch(func() { oidText(b, tlvT{6, 0, 0, len(b)}) })
	if err == nil || err.Error() != "OID arc is not minimally encoded" {
		t.Errorf("0x80 after 0x01: %v", err)
	}
}

// The 47-byte floor comes before the version byte (sigstore.ts verifySct), so a short SCT of an unknown version is truncated,
// not skipped as unknown.
func TestY1SigstoreSCTFloorBeforeVersion(t *testing.T) {
	f := newSCTFixture(t)
	s := make([]byte, 46)
	s[0] = 1
	leaf, _ := f.leaf(func([]byte) []byte { return list(entry(s)) })
	if got := verifySCT(leaf, fullCert(f.ca.Raw), f.roots); got != "SCT truncated" {
		t.Errorf("46-byte SCT of version 1: %q", got)
	}
}

// An issuer parseCert cannot read (no extensions) has no subject key id: nothing disagrees with the subject's key link.
func TestY1SigstoreIssuerWithoutExtensions(t *testing.T) {
	up, _ := y1Versionless(false)
	if _, err := parsedOrNil(up); err == nil {
		t.Fatal("fixture: parseCert read a certificate without extensions")
	}
	if !keyIDsMatch(selfSigned(t, nil), up) {
		t.Error("no authority key id, issuer without extensions")
	}
	if !keyIDsMatch(selfSigned(t, nil, y1AKI([]byte{0x30, 5, 0x80, 3, 9, 9, 9})), up) {
		t.Error("an authority key id, issuer without a subject key id")
	}
}

// Without a [0] version the TBS members start one place earlier.
func TestY1SigstoreTBSFieldWithoutVersion(t *testing.T) {
	up, issuer := y1Versionless(true)
	pc := parseCert(up)
	if got := pc.tbsField(0); !bytes.Equal(got, []byte{5}) {
		t.Errorf("serial: % x", got)
	}
	if got := pc.tbsField(2); !bytes.Equal(got, issuer) {
		t.Errorf("issuer: % x", got)
	}
	if !keyIDsMatch(selfSigned(t, nil, y1AKI([]byte{0x30, 3, 0x82, 1, 5})), up) {
		t.Error("the issuer's own serial")
	}
	if keyIDsMatch(selfSigned(t, nil, y1AKI([]byte{0x30, 3, 0x82, 1, 6})), up) {
		t.Error("another serial")
	}
}

// The issuer name comes back as its full TLV, header included: an AKI directoryName holds the whole Name. The expected bytes
// come from crypto/x509, not from tbsField.
func TestY1SigstoreTBSFieldIssuerNameIsFullTLV(t *testing.T) {
	up := selfSigned(t, nil)
	c, err := x509.ParseCertificate(up)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseCert(up).tbsField(2); !bytes.Equal(got, c.RawIssuer) {
		t.Errorf("issuer: % x, want % x", got, c.RawIssuer)
	}
	if !keyIDsMatch(selfSigned(t, nil, y1AKI(enc(0x30, enc(0xa1, enc(0xa4, c.RawIssuer))))), up) {
		t.Error("an AKI directoryName naming the issuer's own issuer")
	}
}
