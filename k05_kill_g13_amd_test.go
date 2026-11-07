package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Mutation kills for attest_amd.go: a generated P-384 ARK -> ASK -> VCEK chain (pinned through the verifier's pin argument)
// and a genuinely signed 1184-byte report.

var (
	g13amdNB     = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	g13amdNA     = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	g13amdVcekNA = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	g13amdNow    = time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	g13amdChip   = bytes.Repeat([]byte{0xc1}, 64)
	g13amdTcb    = uint64(1) | uint64(2)<<8 | uint64(7)<<48 | uint64(8)<<56 // bootloader 1, tee 2, snp 7, microcode 8
)

func g13amdOID(arcs ...int) asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1}, arcs...)
}

func g13amdExts() []pkix.Extension {
	spl := func(v byte) []byte { return []byte{0x02, 0x01, v} }
	return []pkix.Extension{
		{Id: g13amdOID(4), Value: g13amdChip},
		{Id: g13amdOID(3, 1), Value: spl(1)},
		{Id: g13amdOID(3, 2), Value: spl(2)},
		{Id: g13amdOID(3, 3), Value: spl(7)},
		{Id: g13amdOID(3, 8), Value: spl(8)},
	}
}

type g13amdChain struct {
	askKey, vcekKey *ecdsa.PrivateKey
	ask             *x509.Certificate
	vcekDer         []byte
	arkPEM, askPEM  string
	pin             string
}

func g13amdP384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func g13amdCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer any) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func g13amdPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func g13amdCA(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: g13amdNB, NotAfter: g13amdNA,
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
}

// leaf is a VCEK (AMD extensions included) for pub, signed by the ASK.
func (f *g13amdChain) leaf(t *testing.T, pub any, ku x509.KeyUsage) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "g13 VCEK"}, NotBefore: g13amdNB, NotAfter: g13amdVcekNA,
		KeyUsage: ku, ExtraExtensions: g13amdExts()}
	return g13amdCert(t, tmpl, f.ask, pub, f.askKey)
}

func g13amdNew(t *testing.T) *g13amdChain {
	t.Helper()
	arkKey := g13amdP384(t)
	f := &g13amdChain{askKey: g13amdP384(t), vcekKey: g13amdP384(t)}
	arkT := g13amdCA("g13 ARK", 1)
	arkDer := g13amdCert(t, arkT, arkT, &arkKey.PublicKey, arkKey)
	ark, err := x509.ParseCertificate(arkDer)
	if err != nil {
		t.Fatal(err)
	}
	askDer := g13amdCert(t, g13amdCA("g13 ASK", 2), ark, &f.askKey.PublicKey, arkKey)
	if f.ask, err = x509.ParseCertificate(askDer); err != nil {
		t.Fatal(err)
	}
	f.vcekDer = f.leaf(t, &f.vcekKey.PublicKey, x509.KeyUsageDigitalSignature)
	f.arkPEM, f.askPEM = g13amdPEM(arkDer), g13amdPEM(askDer)
	h := sha512.Sum384(ark.RawSubjectPublicKeyInfo)
	f.pin = hex.EncodeToString(h[:])
	return f
}

func (f *g13amdChain) chain(vcekDer []byte, now int64, skew any) (string, *ecdsa.PublicKey, []byte) {
	return verifyAmdCertChain(vcekDer, f.askPEM+f.arkPEM, f.pin, now, skew)
}

// resign replaces old with repl (same length) in the tbs of der and signs it again with the ASK.
func (f *g13amdChain) resign(t *testing.T, der, old, repl []byte) []byte {
	t.Helper()
	var c struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(c.TBS.FullBytes, old) || len(old) != len(repl) {
		t.Fatalf("tbs has no %q", old)
	}
	tbs := bytes.Replace(c.TBS.FullBytes, old, repl, 1)
	sig, err := ecdsa.SignASN1(rand.Reader, f.askKey, sha384Sum(tbs))
	if err != nil {
		t.Fatal(err)
	}
	c.TBS = asn1.RawValue{FullBytes: tbs}
	c.Sig = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	out, err := asn1.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestG13AmdCertChain(t *testing.T) {
	f := g13amdNew(t)
	if r, pub, tbs := f.chain(f.vcekDer, g13amdNow, nil); r != "" || pub == nil || tbs == nil {
		t.Fatalf("valid chain: %q", r)
	}
	if r, _, _ := f.chain(f.vcekDer, g13amdNow, json.Number("0")); r != "" {
		t.Fatalf("a zero clock skew is allowed: %q", r)
	}
	// 1 s before the VCEK's notAfter, a 5 s skew must not make it expired (now - skew is compared, not now + skew)
	if r, _, _ := f.chain(f.vcekDer, g13amdVcekNA.UnixMilli()-1000, json.Number("5000")); r != "" {
		t.Fatalf("inside the skew before notAfter: %q", r)
	}
	garbage := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	for name, pemText := range map[string]string{"ASK unreadable": garbage + f.arkPEM, "ARK unreadable": f.askPEM + garbage} {
		if r, _, _ := verifyAmdCertChain(f.vcekDer, pemText, f.pin, g13amdNow, nil); !strings.HasPrefix(r, "AMD chain verification error: ") {
			t.Fatalf("%s: %q", name, r)
		}
	}

	badNA := f.resign(t, f.vcekDer, []byte("310101000000Z"), []byte("310101000000X"))
	if r, _, _ := f.chain(badNA, g13amdNow, nil); r != "VCEK certificate validity is unparseable" {
		t.Fatalf("unparseable notAfter: %q", r)
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edLeaf := f.leaf(t, edPub, x509.KeyUsageDigitalSignature)
	// x509 cannot issue an X25519 certificate: the Ed25519 SPKI with its algorithm OID 1.3.101.112 turned into 1.3.101.110
	// (same length) is one, re-signed by the ASK
	spkiHead := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65}
	x25519Leaf := f.resign(t, edLeaf, append(append([]byte{}, spkiHead...), 0x70), append(append([]byte{}, spkiHead...), 0x6e))
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		der  []byte
		want string
	}{
		{"X25519 VCEK", x25519Leaf, "AMD chain verification error: error:1E08010C:DECODER routines::unsupported"},
		{"Ed25519 VCEK", edLeaf, "AMD chain verification error: VCEK is not EC secp384r1 (got ed25519/undefined)"},
		{"P-256 VCEK", f.leaf(t, &p256.PublicKey, x509.KeyUsageDigitalSignature), "AMD chain verification error: VCEK is not EC secp384r1 (got ec/prime256v1)"},
	} {
		if r, pub, tbs := f.chain(c.der, g13amdNow, nil); r != c.want || pub != nil || tbs != nil {
			t.Fatalf("%s: %q", c.name, r)
		}
	}
}

func g13amdExtTbs(exts ...[]byte) []byte {
	return g09dTLV(0x30, g09dTLV(0x02, g09dRaw(1)), g09dTLV(0xa3, g09dTLV(0x30, exts...)))
}

var (
	g13amdHwOID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01, 0x04}
	g13amdSplOI = func(k byte) []byte { return []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01, 0x03, k} }
)

func TestG13AmdReportBinding(t *testing.T) {
	r := &snpReport{chipID: g13amdChip, reportedTcb: g13amdTcb}
	spl := func(k byte, crit bool, v []byte) []byte { return g09dExt(g13amdSplOI(k), crit, v) }
	int1 := func(v byte) []byte { return []byte{0x02, 0x01, v} }
	hw := g09dExt(g13amdHwOID, false, g13amdChip)
	good := [][]byte{spl(1, false, int1(1)), spl(2, false, int1(2)), spl(3, false, int1(7)), spl(8, false, int1(8))}
	if got := checkVcekReportBinding(g13amdExtTbs(append([][]byte{hw}, good...)...), r); got != "" {
		t.Fatalf("valid binding: %q", got)
	}
	f := g13amdNew(t)
	if tbs, err := tbsOfCertificate(f.vcekDer); err != nil || checkVcekReportBinding(tbs, r) != "" {
		t.Fatalf("generated VCEK binding: %v", err)
	}
	if got := checkVcekReportBinding([]byte{0x01}, r); !strings.HasPrefix(got, "VCEK extensions malformed: ") {
		t.Fatalf("garbage tbs: %q", got)
	}
	with := func(i int, e []byte) [][]byte {
		l := append([][]byte{hw}, good...)
		l[i] = e
		return l
	}
	for _, c := range []struct {
		name string
		exts [][]byte
		want string
	}{
		{"hwID critical", with(0, g09dExt(g13amdHwOID, true, g13amdChip)), "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)"},
		{"tee critical", with(2, spl(2, true, int1(2))), "VCEK tee SPL extension is marked critical (the AMD profile is non-critical)"},
		{"bootloader not an INTEGER", with(1, spl(1, false, []byte{0x04, 0x01, 0x01})), "VCEK bootloader SPL extension is not a DER INTEGER"},
		{"tee mismatch", with(2, spl(2, false, int1(0))), "VCEK tee SPL 0 does not match report reported_tcb (2) — TCB downgrade?"},
	} {
		if got := checkVcekReportBinding(g13amdExtTbs(c.exts...), r); got != c.want {
			t.Fatalf("%s: %q", c.name, got)
		}
	}
}

func TestG13AmdDecodeSpl(t *testing.T) {
	for _, c := range []struct {
		v    []byte
		n    int
		want string
	}{
		{[]byte{0x02, 0x01, 0x05}, 5, ""},
		{[]byte{0x02, 0x02, 0x00, 0x80}, 128, ""},
		{[]byte{0x02, 0x02, 0x00, 0xff}, 255, ""},
		{[]byte{0x02, 0x01}, 0, "is not a DER INTEGER"},
		{[]byte{0x03, 0x01, 0x05}, 0, "is not a DER INTEGER"},
		{[]byte{0x02, 0x00, 0x05}, 0, "has a wrong-length INTEGER"},
		{[]byte{0x02, 0x03, 0x00, 0x80, 0x00}, 0, "has a wrong-length INTEGER"},
		{[]byte{0x02, 0x01, 0x05, 0x06}, 0, "has a wrong-length INTEGER"},
		{[]byte{0x02, 0x01, 0x80}, 0, "is negative"},
		{[]byte{0x02, 0x02, 0x01, 0x00}, 0, "is out of range (> 255)"},
		{[]byte{0x02, 0x02, 0x00, 0x7f}, 0, "is a non-minimal INTEGER"},
		{[]byte{0x02, 0x02, 0x00, 0x01}, 0, "is a non-minimal INTEGER"},
	} {
		if n, why := decodeSpl(c.v); n != c.n || why != c.want {
			t.Fatalf("decodeSpl(% x) = %d %q, want %d %q", c.v, n, why, c.n, c.want)
		}
	}
}

func TestG13AmdParseJSBigInt(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string // decimal, or "err"
	}{
		{true, "1"}, {false, "0"}, {"", "0"}, {"  ", "0"}, {"12", "12"}, {"-5", "-5"},
		{"0x1f", "31"}, {"0x1", "1"}, {"0o17", "15"}, {"0b101", "5"},
		{"1x5", "err"}, {"0x-1", "err"}, {"0x+1", "err"}, {"0x", "err"},
		{json.Number("5"), "5"}, {json.Number("1e3"), "1000"}, {json.Number("1.5"), "err"},
		{json.Number("9007199254740993"), "9007199254740993"},
	} {
		n, err := parseJSBigInt(c.v)
		got := "err"
		if err == nil {
			got = n.String()
		}
		if got != c.want {
			t.Fatalf("parseJSBigInt(%#v) = %s (%v), want %s", c.v, got, err, c.want)
		}
	}
}

func TestG13AmdPolicyAndConfig(t *testing.T) {
	r := &snpReport{sigAlgo: 1, committedTcb: 5}
	for _, c := range []struct {
		name string
		p    snpPolicy
		want string
	}{
		{"committed tcb at the minimum, no allowlists", snpPolicy{requireEcdsaP384: true, minCommittedTcb: big.NewInt(5)}, ""},
		{"committed tcb below the minimum", snpPolicy{minCommittedTcb: big.NewInt(6)}, "committed_tcb below minimum (rollback?)"},
		{"vmpl named but not any", snpPolicy{requireVmpl: "x"}, "vmpl 0 is not the required x"},
		{"vmpl any", snpPolicy{requireVmpl: "any"}, ""},
	} {
		if got := c.p.check(r); got != c.want {
			t.Fatalf("%s: %q", c.name, got)
		}
	}
	if l, ok := hexListOf([]any{"a", json.Number("1")}); ok || l != nil {
		t.Fatalf("a non-string entry: %v %v", l, ok)
	}
	if l, ok := hexListOf([]any{"a"}); !ok || len(l) != 1 {
		t.Fatalf("string list: %v %v", l, ok)
	}
	if _, err := newAmdVerifier(map[string]any{"family": "milan", "binding": "report-data"}); err == nil ||
		err.Error() != "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)" {
		t.Fatalf("no policy: %v", err)
	}
	raw := make([]byte, snpReportLen)
	binary.LittleEndian.PutUint64(raw[snpOffCommittedTcb:], 0x0102030405060708)
	if rep, err := parseSnpReport(raw); err != nil || rep.committedTcb != 0x0102030405060708 {
		t.Fatalf("committed tcb offset: %v", err)
	}
}

// g13amdReport is a report signed by key whose r and s have a non-zero top byte (and s a non-zero second byte).
func g13amdReport(t *testing.T, key *ecdsa.PrivateKey, meas []byte) []byte {
	t.Helper()
	raw := make([]byte, snpReportLen)
	binary.LittleEndian.PutUint32(raw[snpOffSigAlgo:], 1)
	binary.LittleEndian.PutUint64(raw[snpOffReportedTcb:], g13amdTcb)
	copy(raw[snpOffMeasurement:], meas)
	copy(raw[snpOffChipID:], g13amdChip)
	put := func(off int, v *big.Int) {
		be := v.FillBytes(make([]byte, 48))
		for i := range be {
			raw[off+i] = be[47-i]
		}
	}
	for i := 0; i < 64; i++ {
		r, s, err := ecdsa.Sign(rand.Reader, key, sha384Sum(raw[:snpOffSignedEnd]))
		if err != nil {
			t.Fatal(err)
		}
		put(snpOffSigR, r)
		put(snpOffSigS, s)
		if raw[snpOffSigR+47] != 0 && raw[snpOffSigS+47] != 0 && raw[snpOffSigS+1] != 0 {
			return raw
		}
	}
	t.Fatal("no signature with non-zero edge bytes")
	return nil
}

func TestG13AmdVerifyReport(t *testing.T) {
	f := g13amdNew(t)
	meas := bytes.Repeat([]byte{0x3c}, 48)
	v := &amdVerifier{pin: f.pin, binding: "report-data", policy: snpPolicy{measurements: []string{toHexLower(meas)}, requireEcdsaP384: true}}
	raw := g13amdReport(t, f.vcekKey, meas)
	if why, rep := v.verifyReport(raw, f.vcekDer, f.askPEM+f.arkPEM, g13amdNow, nil); why != "" || rep == nil {
		t.Fatalf("genuine report: %q", why)
	}
	for _, off := range []int{snpOffSigR + 48, snpOffSigR + 71, snpOffSigS + 48, snpOffSigS + 71, snpOffSigS + 72, snpReportLen - 1} {
		bad := append([]byte{}, raw...)
		bad[off] = 1
		if why, rep := v.verifyReport(bad, f.vcekDer, f.askPEM+f.arkPEM, g13amdNow, nil); why != "report signature block has non-zero reserved bytes" || rep != nil {
			t.Fatalf("reserved byte 0x%x: %q", off, why)
		}
	}
	rep, err := parseSnpReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !verifySnpReportSignature(rep, &f.vcekKey.PublicKey) {
		t.Fatal("genuine signature refused")
	}
	n := elliptic.P384().Params().N
	for name, sig := range map[string][2]*big.Int{"r = 0": {big.NewInt(0), big.NewInt(1)}, "s = n": {big.NewInt(1), n}} {
		le := func(v *big.Int) []byte {
			b := v.FillBytes(make([]byte, 72))
			for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
				b[i], b[j] = b[j], b[i]
			}
			return b
		}
		bad := *rep
		bad.sigR, bad.sigS = le(sig[0]), le(sig[1])
		if verifySnpReportSignature(&bad, &f.vcekKey.PublicKey) {
			t.Fatalf("%s accepted", name)
		}
	}
}
