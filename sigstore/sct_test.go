package pcasigstore

// verifySCT on crafted SCT lists: every refusal reason at its exact boundary, and the signed structure's length fields
// on a TBS of 64 KiB or more and an SCT extension of 256 bytes or more (the k05 corpus only carries real-sized
// certificates, where every high length byte is zero).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

type sctFixture struct {
	t        *testing.T
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	logKey   *ecdsa.PrivateKey
	logID    []byte
	roots    *PinnedRoots
	big      bool // pad the TBS past 64 KiB
	issuerKH []byte
}

func newSCTFixture(t *testing.T) *sctFixture {
	f := &sctFixture{t: t}
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4e9, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &f.caKey.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.ca, _ = x509.ParseCertificate(der)
	f.issuerKH = sha256Of(f.ca.RawSubjectPublicKeyInfo)
	f.logKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&f.logKey.PublicKey)
	f.logID = sha256Of(spki)
	f.roots = &PinnedRoots{ctlogs: []PinnedLog{{keyID: f.logID, key: &f.logKey.PublicKey, valid: validity{0, forever}}}}
	return f
}

// leaf issues a leaf whose last extension is the SCT extension with value extValue (nil: no SCT extension), plus the
// TBS of the same leaf without it (the precertificate TBS the SCT signs).
func (f *sctFixture) leaf(extValue func(tbs []byte) []byte) (*parsedCert, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4e9, 0),
		KeyUsage: x509.KeyUsageDigitalSignature}
	if f.big {
		pad, _ := asn1.Marshal(make([]byte, 70000))
		tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: pad}}
	}
	pre, err := x509.CreateCertificate(rand.Reader, tpl, f.ca, &key.PublicKey, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	pc, _ := x509.ParseCertificate(pre)
	tbs := pc.RawTBSCertificate
	if extValue == nil {
		return parseCert(pre), tbs
	}
	tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: extValue(tbs)})
	der, err := x509.CreateCertificate(rand.Reader, tpl, f.ca, &key.PublicKey, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return parseCert(der), tbs
}

// sct builds one SCT (v1): logID, timestamp, extensions, SHA-256 + ECDSA, signed over the RFC 6962 precert structure.
func (f *sctFixture) sct(tbs []byte, logID []byte, ex []byte, tail []byte) []byte {
	ts := uint64(1_700_000_000_000)
	signed := []byte{0, 0}
	signed = binary.BigEndian.AppendUint64(signed, ts)
	signed = append(signed, 0, 1)
	signed = append(signed, f.issuerKH...)
	signed = append(signed, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
	signed = append(signed, tbs...)
	signed = append(signed, byte(len(ex)>>8), byte(len(ex)))
	signed = append(signed, ex...)
	h := sha256.Sum256(signed)
	sig, _ := ecdsa.SignASN1(rand.Reader, f.logKey, h[:])
	s := []byte{0}
	s = append(s, logID...)
	s = binary.BigEndian.AppendUint64(s, ts)
	s = binary.BigEndian.AppendUint16(s, uint16(len(ex)))
	s = append(s, ex...)
	s = append(s, 4, 3)
	s = binary.BigEndian.AppendUint16(s, uint16(len(sig)))
	s = append(s, sig...)
	return append(s, tail...)
}

func entry(s []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(s))), s...) }

// list wraps entries (raw bytes after the 2-byte total) as the extension value: OCTET STRING { u16 total || entries }.
func list(body []byte) []byte {
	v, _ := asn1.Marshal(append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...))
	return v
}

func octet(b []byte) []byte { v, _ := asn1.Marshal(b); return v }

func TestSigstoreSCTRefusals(t *testing.T) {
	f := newSCTFixture(t)
	issuer := fullCert(f.ca.Raw)
	other := make([]byte, 32)
	// a structurally valid SCT of exactly 47 bytes (no extensions, empty signature)
	min47 := append(append(append([]byte{0}, other...), make([]byte, 8)...), 0, 0, 4, 3, 0, 0)
	cases := []struct {
		name string
		ext  func(tbs []byte) []byte
		want string
	}{
		{"no SCT extension", nil, "no embedded SCT"},
		{"not an OCTET STRING", func([]byte) []byte { v, _ := asn1.Marshal([]int{1}); return v }, "SCT list is not an OCTET STRING"},
		{"one-byte list", func([]byte) []byte { return octet([]byte{0}) }, "SCT list length"},
		{"empty list", func([]byte) []byte { return octet([]byte{0, 0}) }, "no SCT from a pinned CT log"},
		{"total disagrees", func([]byte) []byte { return octet([]byte{0, 1, 0, 0}) }, "SCT list length"},
		{"good", func(tbs []byte) []byte { return list(entry(f.sct(tbs, f.logID, nil, nil))) }, ""},
		{"unpinned log", func(tbs []byte) []byte { return list(entry(f.sct(tbs, other, nil, nil))) }, "no SCT from a pinned CT log"},
		{"unpinned then pinned", func(tbs []byte) []byte {
			return list(append(entry(f.sct(tbs, other, nil, nil)), entry(f.sct(tbs, f.logID, nil, nil))...))
		}, ""},
		{"one trailing byte", func(tbs []byte) []byte { return list(append(entry(f.sct(tbs, other, nil, nil)), 0)) }, "SCT truncated"},
		{"entry past the list", func(tbs []byte) []byte { s := f.sct(tbs, f.logID, nil, nil); return list(entry(s)[:len(s)]) }, "SCT truncated"},
		{"46-byte SCT", func([]byte) []byte { return list(entry(min47[:46])) }, "SCT truncated"},
		{"47-byte SCT", func([]byte) []byte { return list(entry(min47)) }, "no SCT from a pinned CT log"},
		{"47 bytes, extensions overrun the header", func([]byte) []byte {
			s := append([]byte{}, min47...)
			s[42] = 1 // extLen 1: the hash/sig header would end one byte past the SCT
			return list(entry(s))
		}, "SCT truncated"},
		{"signature length overruns", func(tbs []byte) []byte {
			s := f.sct(tbs, f.logID, nil, nil)
			return list(entry(s[:len(s)-1]))
		}, "SCT malformed"},
		{"trailing byte after the signature", func(tbs []byte) []byte { return list(entry(f.sct(tbs, f.logID, nil, []byte{0}))) }, "SCT malformed"},
		{"not v1", func(tbs []byte) []byte { s := f.sct(tbs, f.logID, nil, nil); s[0] = 1; return list(entry(s)) }, "no SCT from a pinned CT log"},
		{"wrong signature", func(tbs []byte) []byte { return list(entry(f.sct(append([]byte{1}, tbs...), f.logID, nil, nil))) }, "SCT signature invalid"},
	}
	for _, c := range cases {
		leaf, _ := f.leaf(c.ext)
		var got string
		if err := catch(func() { got = verifySCT(leaf, issuer, f.roots) }); err != nil {
			t.Errorf("%s: threw %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// The high length bytes: a TBS of 64 KiB..128 KiB (24-bit length 0x01xxxx) and an SCT extension block of 300 bytes
// (16-bit length 0x012c; the SCT itself then exceeds 255 bytes, so every u16 read has a non-zero high byte).
func TestSigstoreSCTLongFields(t *testing.T) {
	f := newSCTFixture(t)
	f.big = true
	issuer := fullCert(f.ca.Raw)
	ex := make([]byte, 300)
	for i := range ex {
		ex[i] = byte(i)
	}
	leaf, tbs := f.leaf(func(tbs []byte) []byte { return list(entry(f.sct(tbs, f.logID, ex, nil))) })
	if len(tbs) < 1<<16 || len(tbs) >= 1<<17 {
		t.Fatalf("fixture: TBS is %d bytes, want 64..128 KiB", len(tbs))
	}
	if got := verifySCT(leaf, issuer, f.roots); got != "" {
		t.Fatalf("long SCT: %q", got)
	}
	// the same SCT signed over a 16-bit-truncated TBS length must not verify
	bad, _ := f.leaf(func(tbs []byte) []byte { return list(entry(f.sct(tbs[:len(tbs)&0xffff], f.logID, ex, nil))) })
	if got := verifySCT(bad, issuer, f.roots); got != "SCT signature invalid" {
		t.Fatalf("truncated TBS length: %q", got)
	}
}
