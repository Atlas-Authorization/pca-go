package pca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---- SPDM transcript builders

func g10nvBlock(idx byte, body []byte) []byte {
	return append([]byte{idx, 1, byte(len(body)), byte(len(body) >> 8)}, body...)
}

func g10nvDMTF(val []byte) []byte {
	return append([]byte{0x80, byte(len(val)), byte(len(val) >> 8)}, val...)
}

// g10nvRaw is request||response with the given request nonce, block count, raw measurement record and opaque data, and a
// zero signature.
func g10nvRaw(nonce []byte, numBlocks int, record, opaque []byte) []byte {
	req := make([]byte, spdmReqLen)
	req[0], req[1] = 0x11, 0xe0
	copy(req[4:4+spdmNonceLen], nonce)
	n := len(record)
	resp := []byte{0x11, 0x60, 0, 0, byte(numBlocks), byte(n), byte(n >> 8), byte(n >> 16)}
	resp = append(resp, record...)
	resp = append(resp, make([]byte, spdmNonceLen)...)
	resp = append(resp, byte(len(opaque)), byte(len(opaque)>>8))
	resp = append(resp, opaque...)
	resp = append(resp, make([]byte, spdmSigLen)...)
	return append(req, resp...)
}

func g10nvParseErr(t *testing.T, name string, b []byte, want string) {
	t.Helper()
	rep, err := parseNvidiaSpdmEvidence(b)
	if rep != nil || err == nil || err.Error() != want {
		t.Errorf("%s: %v %v, want %q", name, rep, err, want)
	}
}

func TestG10NvidiaSpdmParseBounds(t *testing.T) {
	short := make([]byte, spdmReqLen+8+spdmNonceLen+2+spdmSigLen-1)
	short[1] = 0xe0
	g10nvParseErr(t, "one byte short", short, "parseNvidiaSpdmEvidence: transcript too short (174)")

	over := g10nvRaw(nil, 0, nil, nil)
	over[spdmReqLen+5] = 1 // a 1-byte record that is not there
	g10nvParseErr(t, "record overruns", over, "parseNvidiaSpdmEvidence: measurement record length overruns transcript")

	g10nvParseErr(t, "3-byte record", g10nvRaw(nil, 0, []byte{0, 0, 0}, nil), "parseNvidiaSpdmEvidence: truncated measurement block header")
	g10nvParseErr(t, "block size 2", g10nvRaw(nil, 1, g10nvBlock(1, []byte{0x80, 0}), nil), "parseNvidiaSpdmEvidence: measurement block overruns record")
	g10nvParseErr(t, "DMTF value overruns", g10nvRaw(nil, 1, g10nvBlock(1, []byte{0x80, 3, 0, 0xaa, 0xbb}), nil), "parseNvidiaSpdmEvidence: DMTF value overruns measurement block")
	g10nvParseErr(t, "3-byte opaque", g10nvRaw(nil, 0, nil, []byte{1, 0, 0}), "parseNvidiaSpdmEvidence: truncated opaque TLV header")
	g10nvParseErr(t, "TLV overruns", g10nvRaw(nil, 0, nil, []byte{3, 0, 1, 0}), "parseNvidiaSpdmEvidence: opaque TLV overruns opaque data")

	// a block of exactly the minimum size 3 (empty value) and an opaque TLV of exactly its 4-byte header
	rep, err := parseNvidiaSpdmEvidence(g10nvRaw(nil, 1, g10nvBlock(7, g10nvDMTF(nil)), []byte{3, 0, 0, 0}))
	if err != nil || len(rep.measurements) != 1 || rep.measurements[0].index != 7 || len(rep.measurements[0].digest) != 0 {
		t.Fatalf("minimal block: %+v %v", rep, err)
	}
	if v, ok := rep.opaque[3]; !ok || len(v) != 0 || len(rep.opaque) != 1 {
		t.Fatalf("empty TLV: %v", rep.opaque)
	}

	// a measurement record of 65536 bytes: the record length's third byte counts
	big1 := make([]byte, 65522)
	big1[0], big1[65521] = 0x11, 0x22
	record := append(g10nvBlock(1, g10nvDMTF(big1)), g10nvBlock(2, g10nvDMTF(nil))...)
	if len(record) != 65536 {
		t.Fatalf("record length %d", len(record))
	}
	rep, err = parseNvidiaSpdmEvidence(g10nvRaw(nil, 2, record, nil))
	if err != nil || len(rep.measurements) != 2 || rep.measurements[1].index != 2 || string(rep.measurements[0].digest) != string(big1) {
		t.Fatalf("24-bit record length: %v", err)
	}
}

func TestG10NvidiaJsSliceAndVbios(t *testing.T) {
	for _, c := range []struct {
		from, to int
		want     string
	}{
		{0, 6, "abcdef"}, {-2, 6, "ef"}, {-10, 3, "abc"}, {-6, 2, "ab"}, {0, 10, "abcdef"}, {4, 2, ""}, {3, 3, ""}, {2, -1, "cde"},
	} {
		if got := jsSlice("abcdef", c.from, c.to); got != c.want {
			t.Errorf("jsSlice(%d,%d) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
	for raw, want := range map[string]string{"\x01\x02\x03": "20.13.0", "\xab": "b", "\x00\x9f\x00\x96\x04\xcc\xbb\xaa": "96.00.9f.00.04"} {
		if got := formatVbiosVersion([]byte(raw)); got != want {
			t.Errorf("vbios %x = %q, want %q", raw, got, want)
		}
	}
}

func TestG10NvidiaJsNumberFromString(t *testing.T) {
	for _, c := range []struct {
		in string
		f  float64
		ok bool
	}{
		{"", 0, true}, {"  ", 0, true}, {"abc", 0, false}, {" 7 ", 7, true}, {"1e0", 1, true},
	} {
		if f, ok := jsNumberFromString(c.in); f != c.f || ok != c.ok {
			t.Errorf("%q: %v %v, want %v %v", c.in, f, ok, c.f, c.ok)
		}
	}
}

// ---- a P-384 device chain and a signed transcript

type g10nvRig struct {
	rootKey, leafKey *ecdsa.PrivateKey
	root, leaf       *x509.Certificate
	nb, na           time.Time
}

func g10nvP384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (r *g10nvRig) cert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl.NotBefore, tmpl.NotAfter, tmpl.SerialNumber = r.nb, r.na, big.NewInt(3)
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newG10nvRig(t *testing.T) *g10nvRig {
	r := &g10nvRig{rootKey: g10nvP384(t), leafKey: g10nvP384(t),
		nb: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), na: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)}
	r.root = r.cert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "nv root"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, nil, &r.rootKey.PublicKey, r.rootKey)
	r.leaf = r.cert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "GH100 leaf"}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}, r.root, &r.leafKey.PublicKey, r.rootKey)
	return r
}

func g10nvPEM(cs ...*x509.Certificate) string {
	var sb strings.Builder
	for _, c := range cs {
		sb.WriteString("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(c.Raw) + "\n-----END CERTIFICATE-----\n")
	}
	return sb.String()
}

func g10nvPin(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

// signed is the transcript with its last 96 bytes replaced by the leaf's raw ECDSA-P384 signature.
func (r *g10nvRig) signed(t *testing.T, b []byte) []byte {
	t.Helper()
	h := sha512.Sum384(b[:len(b)-spdmSigLen])
	sr, ss, err := ecdsa.Sign(rand.Reader, r.leafKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sr.FillBytes(b[len(b)-spdmSigLen : len(b)-48])
	ss.FillBytes(b[len(b)-48:])
	return b
}

func TestG10NvidiaDeviceChain(t *testing.T) {
	r := newG10nvRig(t)
	pins := []string{g10nvPin(r.root)}
	now := int64(1_800_000_000_000)
	if c, why := verifyNvidiaDeviceChain(g10nvPEM(r.leaf, r.root), pins, now); c == nil || why != "" {
		t.Fatalf("good chain: %q", why)
	}
	ca := func(cn string, parent *x509.Certificate, signer, key *ecdsa.PrivateKey) *x509.Certificate {
		return r.cert(t, &x509.Certificate{Subject: pkix.Name{CommonName: cn}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, parent, &key.PublicKey, signer)
	}
	k3, k2, k1, kl := g10nvP384(t), g10nvP384(t), g10nvP384(t), g10nvP384(t)
	i3 := ca("i3", r.root, r.rootKey, k3)
	i2 := ca("i2", i3, k3, k2)
	i1 := ca("i1", i2, k2, k1)
	l5 := r.cert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "l5"}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}, i1, &kl.PublicKey, k1)
	if c, why := verifyNvidiaDeviceChain(g10nvPEM(l5, i1, i2, i3, r.root), pins, now); c == nil || why != "" {
		t.Fatalf("five certificates: %q", why)
	}
	if c, why := verifyNvidiaDeviceChain(g10nvPEM(r.root, r.root, r.root, r.root, r.root, r.root), pins, now); c != nil || why != "device chain unparseable: parsePemChain: chain longer than 5" {
		t.Fatalf("six certificates: %q", why)
	}
	bad := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
	_, perr := certFromPEM(bad)
	if perr == nil {
		t.Fatal("garbage must not parse")
	}
	if c, why := verifyNvidiaDeviceChain(g10nvPEM(r.leaf)+bad, pins, now); c != nil || why != "device chain unparseable: "+errMsg(perr) {
		t.Fatalf("garbage block: %q", why)
	}
	if c, why := verifyNvidiaDeviceChain(g10nvPEM(r.leaf, r.root), pins, r.na.UnixMilli()+1); c != nil || why != "device chain cert #0 is outside its validity window" {
		t.Fatalf("one ms after notAfter: %q", why)
	}
	// a CA that is not self-signed, pinned as the root
	ik := g10nvP384(t)
	inter := r.cert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "nv inter"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, r.root, &ik.PublicKey, r.rootKey)
	if c, why := verifyNvidiaDeviceChain(g10nvPEM(inter), []string{g10nvPin(inter)}, now); c != nil || why != "device chain root is not a self-signed CA" {
		t.Fatalf("not self-signed: %q", why)
	}
	// certIsCA on bytes the strict reader refuses
	a, err := parseCertDER(r.root.Raw)
	if err != nil || !certIsCA(a) {
		t.Fatalf("root is a CA: %v", err)
	}
	if certIsCA(&attCert{Raw: append(append([]byte{}, r.root.Raw...), 0)}) {
		t.Fatal("an unreadable certificate is not a CA")
	}
}

func TestG10NvidiaVerifierMeasurementOrder(t *testing.T) {
	same := []string{" 1", "+1", "001", "01", "1", "1.0", "1.00", "1e0"} // all index 1, in byte order
	meas := map[string]any{"0": "D0", "255": "Dff"}
	want := []nvMeasurement{{0, "d0"}}
	for _, k := range same {
		meas[k] = "S" + k
		want = append(want, nvMeasurement{1, "s" + k})
	}
	var rest []nvMeasurement
	for i := 2; i <= 40; i++ {
		k := big.NewInt(int64(i)).String()
		meas[k] = "N" + k
		rest = append(rest, nvMeasurement{i, "n" + k})
	}
	want = append(append(want, rest...), nvMeasurement{255, "dff"})
	v, err := newNvidiaVerifier(map[string]any{"rootSpkiSha256": []any{"aa"}, "policy": map[string]any{"measurements": meas}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.want, want) {
		t.Fatalf("want order:\n got  %v\n want %v", v.want, want)
	}
	for _, k := range []string{"abc", "-1", "1.5", "256"} {
		_, err := newNvidiaVerifier(map[string]any{"rootSpkiSha256": []any{"aa"}, "policy": map[string]any{"measurements": map[string]any{k: "aa"}}})
		if err == nil || err.Error() != "createNvidiaSpdmVerifier: measurement index out of range" {
			t.Errorf("index %q: %v", k, err)
		}
	}
}

func TestG10NvidiaVerify(t *testing.T) {
	r := newG10nvRig(t)
	now := int64(1_800_000_000_000)
	pem := g10nvPEM(r.leaf, r.root)
	raw, err := attestationBindingBytes(*testBinding)
	if err != nil {
		t.Fatal(err)
	}
	nonce := sha256Sum(raw)
	d1, d2 := []byte{1, 1, 1}, []byte{2, 2, 2, 2}
	vb := []byte{0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa}
	opaque := append([]byte{3, 0, 7, 0}, []byte("550.54\x00")...)
	opaque = append(append(opaque, 6, 0, byte(len(vb)), 0), vb...)
	ver := func(m map[string]any) *VendorVerifier {
		v, err := VerifierFromConfig("nvidia-gpu-spdm", map[string]any{"rootSpkiSha256": []any{g10nvPin(r.root)}, "policy": map[string]any{"measurements": m}})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	ev := func(b []byte) map[string]any {
		return map[string]any{"evidence": base64.StdEncoding.EncodeToString(b), "certChainPem": pem}
	}
	sum := func(parts ...[]byte) string {
		h := sha512.New384()
		for _, p := range parts {
			h.Write(p)
		}
		return hex.EncodeToString(h.Sum(nil))
	}

	// blocks out of index order: the measurements hash is over them in index order
	b := r.signed(t, g10nvRaw(nonce, 2, append(g10nvBlock(2, g10nvDMTF(d2)), g10nvBlock(1, g10nvDMTF(d1))...), opaque))
	v := ver(map[string]any{"1": hex.EncodeToString(d1), "2": hex.EncodeToString(d2)})
	res := v.Verify(ev(b), testBinding, now)
	if !res.OK || !res.Bound || res.HostAsserted["gpu_measurements_sha384"] != sum(d1, d2) || res.HostAsserted["driver_version"] != "550.54" ||
		res.HostAsserted["vbios_version"] != "96.00.9f.00.04" || res.HostAsserted["leaf_subject"] != "CN=GH100 leaf" {
		t.Fatalf("good report: %+v", res)
	}
	if got := v.Verify(ev(b), nil, now); got.OK || got.Reason != "no expected attestation binding supplied" {
		t.Fatalf("no binding: %+v", got)
	}
	if got := v.Verify(map[string]any{"certChainPem": pem}, testBinding, now); got.OK || got.Reason != "no NVIDIA GPU evidence for this action" {
		t.Fatalf("no evidence member: %+v", got)
	}

	// two blocks with one index keep their report order (stable)
	da, db := []byte{0xa}, []byte{0xb}
	b2 := r.signed(t, g10nvRaw(nonce, 2, append(g10nvBlock(1, g10nvDMTF(da)), g10nvBlock(1, g10nvDMTF(db))...), nil))
	res = ver(map[string]any{"1": hex.EncodeToString(db)}).Verify(ev(b2), testBinding, now)
	if !res.OK || res.HostAsserted["gpu_measurements_sha384"] != sum(da, db) {
		t.Fatalf("duplicate index: %+v", res)
	}
}
