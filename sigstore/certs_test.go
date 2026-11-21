package pcasigstore

// Certificate helpers on inputs the k05 corpus does not carry: DER length forms at every boundary (enc), basicConstraints
// shapes, the Fulcio raw/DER extension split, and malformed authority key identifiers (X509_check_issued's lenient rule).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"
	"testing"
	"time"
)

func TestSigstoreEncLengths(t *testing.T) {
	for _, c := range []struct {
		n    int
		head []byte
	}{
		{0, []byte{0x30, 0}},
		{0x7f, []byte{0x30, 0x7f}},
		{0x80, []byte{0x30, 0x81, 0x80}},
		{0xff, []byte{0x30, 0x81, 0xff}},
		{0x100, []byte{0x30, 0x82, 0x01, 0x00}},
		{0xffff, []byte{0x30, 0x82, 0xff, 0xff}},
		{0x10000, []byte{0x30, 0x83, 0x01, 0x00, 0x00}},
		{0x10203, []byte{0x30, 0x83, 0x01, 0x02, 0x03}},
	} {
		body := bytes.Repeat([]byte{7}, c.n)
		got := enc(0x30, body)
		if !bytes.Equal(got, append(append([]byte{}, c.head...), body...)) {
			t.Errorf("enc(%#x bytes): header % x, want % x", c.n, got[:min(len(got), len(c.head))], c.head)
		}
	}
}

func TestSigstoreBasicConstraintsCA(t *testing.T) {
	for _, c := range []struct {
		name  string
		value []byte // nil: no extension
		want  bool
	}{
		{"absent", nil, false},
		{"a SET, not a SEQUENCE", []byte{0x31, 3, 1, 1, 0xff}, false},
		{"empty SEQUENCE", []byte{0x30, 0}, false},
		{"first element not a BOOLEAN", []byte{0x30, 3, 2, 1, 1}, false},
		{"two-byte BOOLEAN", []byte{0x30, 4, 1, 2, 0xff, 0xff}, false},
		{"cA false", []byte{0x30, 3, 1, 1, 0}, false},
		{"cA true", []byte{0x30, 3, 1, 1, 0xff}, true},
		{"cA non-zero (BER true)", []byte{0x30, 3, 1, 1, 1}, true},
		{"cA true and a path length", []byte{0x30, 6, 1, 1, 0xff, 2, 1, 0}, true},
	} {
		pc := &parsedCert{}
		if c.value != nil {
			pc.exts = []ext{{oid: "2.5.29.19", value: c.value}}
		}
		var got bool
		if err := catch(func() { got = pc.basicConstraintsCA() }); err != nil {
			t.Errorf("%s: threw %v", c.name, err)
		} else if got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestSigstoreFulcioExtForms(t *testing.T) {
	der := []byte{0x0c, 2, 'h', 'i'}
	for _, c := range []struct {
		n    int
		raw  bool // the value is the string itself, not a DER UTF8String
		want string
	}{
		{1, true, "\x0c\x02hi"}, {6, true, "\x0c\x02hi"}, {7, false, "hi"}, {8, false, "hi"}, {12, false, "hi"},
	} {
		pc := &parsedCert{exts: []ext{{oid: oidFulcio + strconv.Itoa(c.n), value: der}}}
		var got *string
		if err := catch(func() { got = fulcioExt(pc, c.n) }); err != nil || got == nil || *got != c.want {
			t.Errorf(".1.%d: got %v (err %v), want %q", c.n, got, err, c.want)
		}
		// a raw value that is not DER is refused only in the DER form
		pc.exts[0].value = []byte("hi")
		err := catch(func() { fulcioExt(pc, c.n) })
		if (err == nil) != c.raw {
			t.Errorf(".1.%d raw text: err %v", c.n, err)
		}
	}
	if fulcioExt(&parsedCert{}, 8) != nil {
		t.Error("absent extension")
	}
}

// selfSigned issues a certificate carrying the given raw extensions (an AKI or SKI given here replaces Go's own).
func selfSigned(t *testing.T, ski []byte, extra ...pkix.Extension) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4e9, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: ski, ExtraExtensions: extra}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSigstoreKeyIDsMatch(t *testing.T) {
	akiOID := asn1.ObjectIdentifier{2, 5, 29, 35}
	aki := func(v []byte) pkix.Extension { return pkix.Extension{Id: akiOID, Value: v} }
	up := selfSigned(t, []byte{1, 2, 3})
	for _, c := range []struct {
		name string
		aki  []byte
		want bool
	}{
		{"same key id", []byte{0x30, 5, 0x80, 3, 1, 2, 3}, true},
		{"other key id", []byte{0x30, 5, 0x80, 3, 1, 2, 4}, false},
		{"AKI not a SEQUENCE", []byte{0x04, 1, 0}, false},
		{"empty AKI SEQUENCE", []byte{0x30, 0}, true},
		{"AKI serial of another certificate", []byte{0x30, 3, 0x82, 1, 5}, false},
		{"AKI serial of the issuer", []byte{0x30, 3, 0x82, 1, 3}, true},
		{"AKI member with an unknown tag", []byte{0x30, 3, 0x83, 1, 3}, false},
		{"AKI members out of order", []byte{0x30, 8, 0x82, 1, 3, 0x80, 3, 1, 2, 3}, false},
		{"AKI member repeated", []byte{0x30, 10, 0x80, 3, 1, 2, 3, 0x80, 3, 1, 2, 3}, false},
		{"AKI trailing bytes", []byte{0x30, 0, 0}, false},
		{"AKI first directoryName not the issuer", []byte{0x30, 6, 0xa1, 4, 0xa4, 2, 0x30, 0}, false},
		{"AKI generalNames without a directoryName", []byte{0x30, 5, 0xa1, 3, 0x82, 1, 0x78}, true},
	} {
		if got := keyIDsMatch(selfSigned(t, nil, aki(c.aki)), up); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	if !keyIDsMatch(selfSigned(t, nil, aki([]byte{0x30, 5, 0x80, 3, 9, 9, 9})), selfSigned(t, nil)) {
		t.Error("an issuer without a subject key id cannot disagree")
	}
	if keyIDsMatch(selfSigned(t, nil, aki([]byte{0x04, 1, 0})), selfSigned(t, nil)) {
		t.Error("an AKI that does not decode, under an issuer without a subject key id")
	}
	ski := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{0x03, 1, 0}}
	if keyIDsMatch(selfSigned(t, nil), selfSigned(t, nil, ski)) {
		t.Error("an issuer SKI that does not decode")
	}
	ski.Value = []byte{0x04, 0, 0}
	if keyIDsMatch(selfSigned(t, nil), selfSigned(t, nil, ski)) {
		t.Error("an issuer SKI with trailing bytes")
	}
	// the first directoryName is compared with the issuer's own issuer
	upCert, _ := parsedOrNil(up)
	name := upCert.tbsField(2)
	gen := enc(0xa1, enc(0xa4, name))
	if !keyIDsMatch(selfSigned(t, nil, aki(enc(0x30, gen))), up) {
		t.Error("the issuer's own issuer name")
	}
}

func TestSigstoreParseCertRefusals(t *testing.T) {
	// one extension: OID 1.2, then a BOOLEAN where the OCTET STRING value belongs
	badExt := []byte{0x30, 0x0e, 0x30, 0x0c, 0xa3, 0x0a, 0x30, 0x08, 0x30, 0x06, 0x06, 0x01, 0x2a, 0x01, 0x01, 0xff}
	for _, c := range []struct {
		name string
		der  []byte
		want string
	}{
		{"a SET", []byte{0x31, 0}, "certificate is not one SEQUENCE"},
		{"trailing byte", []byte{0x30, 0, 0}, "certificate is not one SEQUENCE"},
		{"empty", []byte{0x30, 0}, "no TBSCertificate"},
		{"TBS not a SEQUENCE", []byte{0x30, 2, 0x31, 0}, "no TBSCertificate"},
		{"TBS only, no extensions", []byte{0x30, 2, 0x30, 0}, "no extensions"},
		{"no [3]", []byte{0x30, 4, 0x30, 2, 0x02, 0}, "no extensions"},
		{"empty [3]", []byte{0x30, 4, 0x30, 2, 0xa3, 0}, "extensions malformed"},
		{"[3] not a SEQUENCE", []byte{0x30, 6, 0x30, 4, 0xa3, 2, 0x31, 0}, "extensions malformed"},
		{"value not an OCTET STRING", badExt, "extension value is not an OCTET STRING"},
	} {
		err := catch(func() { parseCert(c.der) })
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	// a minimal accepted shape: TBS { [3] { SEQUENCE { SEQUENCE { OID 1.2, OCTET STRING "" } } } }
	ok := []byte{0x30, 0x0d, 0x30, 0x0b, 0xa3, 0x09, 0x30, 0x07, 0x30, 0x05, 0x06, 0x01, 0x2a, 0x04, 0x00}
	var pc *parsedCert
	if err := catch(func() { pc = parseCert(ok) }); err != nil || len(pc.exts) != 1 || pc.exts[0].oid != "1.2" {
		t.Errorf("minimal certificate: %v", err)
	}
}

func TestSigstoreJSONExactlyOneValue(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{{`{}`, true}, {" {} \n", true}, {`{}}`, false}, {`{}]`, false}, {`{} {}`, false}, {`{} x`, false}, {`{`, false}, {``, false}} {
		if _, got := decodeOneJSON([]byte(c.in)); got != c.want {
			t.Errorf("%q: %v", c.in, got)
		}
	}
	if _, err := ParseTrustedRoot([]byte(`{}}`)); err == nil || err.Error() != "not a trusted root v0.1" {
		t.Errorf("trusted root: %v", err)
	}
}

func TestSigstoreSanGeneralNameTags(t *testing.T) {
	for _, tag := range []byte{0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88} {
		if !sanDecodes(g07sMiniCert([]byte{0x30, 2, tag, 0})) {
			t.Errorf("GeneralName tag %#x refused", tag)
		}
	}
	for _, tag := range []byte{0x80, 0x83, 0x84, 0x85, 0x89, 0x04, 0xa1, 0xa2} {
		if sanDecodes(g07sMiniCert([]byte{0x30, 2, tag, 0})) {
			t.Errorf("tag %#x accepted", tag)
		}
	}
}
