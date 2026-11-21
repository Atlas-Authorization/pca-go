package pca

// g03: the Azure MAA verifier's construction, x5c chain walk, signing-key resolution and claim checks, each row pinning the
// exact reason so the anchor / link / clock-skew boundary mutants are observable.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func g03pem(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func g03b64(der []byte) string { return base64.StdEncoding.EncodeToString(der) }

func g03ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// a structurally valid certificate (valid 2025..2035) whose key algorithm no reader knows
func g03unknownKeyCert() []byte {
	b := g03base()
	b.spki = derTLV(0x30, derTLV(0x30, g03oid123), derTLV(0x03, []byte{0x00, 0x01}))
	return b.der()
}

func TestG03MaaNewVerifierAnchorsSum(t *testing.T) {
	cfg := map[string]any{
		"trustedIssuers": []any{"https://i"},
		"trustAnchors":   map[string]any{"rootCertsPem": []any{"x"}, "rootSpkiSha256": []any{"aa"}},
		"policy":         map[string]any{"tdxMrtds": []any{"aa"}},
	}
	v, err := newMaaVerifier(cfg)
	if err != nil || len(v.anchors.rootCertsPem) != 1 || len(v.anchors.rootSpki) != 1 {
		t.Fatalf("one PEM root and one SPKI pin: %v", err)
	}
}

func TestG03MaaX5cChain(t *testing.T) {
	const want0 = "x5c link 0 is not signed by the certificate above it"
	const want1 = "x5c link 1 is not signed by the certificate above it"
	const noAnchor = "x5c chain does not anchor in a configured MAA trust root"
	const noConfig = "no MAA trust anchor configured (fail closed)"
	kR, kI, kT, kX, kL, kS := g03ecKey(t), g03ecKey(t), g03ecKey(t), g03ecKey(t), g03ecKey(t), g03ecKey(t)
	R := g03x509(t, "R", &kR.PublicKey, nil, kR, 0)
	I := g03x509(t, "I", &kI.PublicKey, R, kR, 0)
	T := g03x509(t, "T", &kT.PublicKey, R, kR, 0)
	X := g03x509(t, "X", &kX.PublicKey, nil, kX, 0)
	LbyX := scCert(t, "L", kL, X, kX, scLeaf)
	LbyI := scCert(t, "L", kL, I, kI, scLeaf)
	S := g03x509(t, "S", &kS.PublicKey, nil, kS, 0)
	// a self-signed certificate whose signature is broken (structure intact): anchors only by its SPKI fingerprint
	bad := append([]byte{}, S.Raw...)
	bad[len(bad)-1] ^= 0x01

	byR := maaAnchors{rootCertsPem: []string{g03pem(R.Raw)}}
	rows := []struct {
		name string
		a    maaAnchors
		x5c  []any
		want string // "" = accepted
	}{
		{"empty chain", maaAnchors{}, nil, "empty x5c certificate chain"},
		{"no anchors at all", maaAnchors{}, []any{g03b64(S.Raw)}, noConfig},
		{"only an empty SPKI pin", maaAnchors{rootSpki: []string{""}}, []any{g03b64(S.Raw)}, noConfig},
		{"root PEM unreadable", maaAnchors{rootCertsPem: []string{"junk"}}, []any{g03b64(S.Raw)}, "x5c chain verification error (fail closed): error:0480006C:PEM routines::no start line"},
		{"root key unreadable", maaAnchors{rootCertsPem: []string{g03pem(g03unknownKeyCert())}}, []any{g03b64(S.Raw)}, "x5c chain verification error (fail closed): " + g03unsupp},
		{"x5c key unreadable", maaAnchors{rootSpki: []string{"aa"}}, []any{g03b64(g03unknownKeyCert())}, "x5c chain verification error (fail closed): " + g03unsupp},
		{"leaf not signed by the next", byR, []any{g03b64(LbyX.Raw), g03b64(I.Raw)}, want0},
		{"middle link broken", byR, []any{g03b64(LbyI.Raw), g03b64(I.Raw), g03b64(T.Raw)}, want1},
		{"leaf <- I <- R", byR, []any{g03b64(LbyI.Raw), g03b64(I.Raw)}, ""},
		{"I <- R, R not in chain", byR, []any{g03b64(I.Raw)}, ""},
		{"S under R", byR, []any{g03b64(S.Raw)}, noAnchor},
		{"broken self-signature anchored by its PEM fingerprint", maaAnchors{rootCertsPem: []string{g03pem(bad)}}, []any{g03b64(bad)}, ""},
	}
	for _, r := range rows {
		leaf, why := func() (c *attCert, why string) {
			defer func() {
				if x := recover(); x != nil {
					why = "panic"
				}
			}()
			return r.a.verifyX5cChain(r.x5c, tokNow, 0)
		}()
		if why != r.want || (r.want == "") != (leaf != nil) {
			t.Errorf("%s: %q (leaf %v), want %q", r.name, why, leaf != nil, r.want)
		}
	}
}

func TestG03MaaResolveSigningX5c(t *testing.T) {
	const none = "no signing x5c available (no JWKS and no header x5c)"
	two := map[string]any{"keys": []any{map[string]any{"kid": "a", "x5c": []any{"A"}}, map[string]any{"kid": "b", "x5c": []any{"B"}}}}
	rows := []struct {
		name string
		tok  *jwtParsed
		jwks any
		n    int // chain length; -1 = nil
		why  string
	}{
		{"x5c listed but not in the header", &jwtParsed{x5c: []string{"a"}}, nil, -1, none},
		{"header x5c empty", &jwtParsed{hasX5c: true, x5c: []string{}}, nil, -1, none},
		{"header x5c of one", &jwtParsed{hasX5c: true, x5c: []string{"a"}}, nil, 1, ""},
		{"empty kid with two JWKS keys", &jwtParsed{hasKid: true}, two, -1, "token has no kid and the JWKS publishes multiple keys (ambiguous)"},
		{"no kid, one JWKS key without x5c", &jwtParsed{}, map[string]any{"keys": []any{map[string]any{"kid": "a"}}}, -1, "JWKS key carries no x5c chain"},
		{"no kid, one JWKS key with x5c", &jwtParsed{}, map[string]any{"keys": []any{map[string]any{"x5c": []any{"A", "B"}}}}, 2, ""},
	}
	for _, r := range rows {
		c, why := resolveSigningX5c(r.tok, r.jwks)
		if why != r.why || (r.n < 0) != (c == nil) || (r.n >= 0 && len(c) != r.n) {
			t.Errorf("%s: %v %q, want n=%d %q", r.name, c, why, r.n, r.why)
		}
	}
}

func TestG03MaaJwsSignatureKey(t *testing.T) {
	v := &maaVerifier{}
	unknown, err := parseCertDER(g03unknownKeyCert())
	if err != nil {
		t.Fatal(err)
	}
	if got := v.jwsSignature(&jwtParsed{alg: "ES256"}, unknown); got != "x5c chain verification error (fail closed): "+g03unsupp {
		t.Errorf("unreadable key: %q", got)
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	spki, err := x509.MarshalPKIXPublicKey(&k384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.jwsSignature(&jwtParsed{alg: "ES256", signature: make([]byte, 64)}, &attCert{RawSPKI: spki}); got != "ES256 token but signing key is EC/P-384 (not EC P-256)" {
		t.Errorf("P-384 key: %q", got)
	}
}

func TestG03MaaEmptyToken(t *testing.T) {
	v := &maaVerifier{}
	if r := v.verify(map[string]any{"token": ""}, testBinding, tokNow); r.OK || r.Reason != "no Azure MAA token for this action" {
		t.Errorf("empty token: %+v", r)
	}
}

func TestG03MaaClockSkewAndBinding(t *testing.T) {
	key := g03ecKey(t)
	cert := g03x509(t, "maa", &key.PublicKey, nil, key, 0)
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	rawBinding, err := attestationBindingBytes(*testBinding)
	if err != nil {
		t.Fatal(err)
	}
	mrtd := zeros96
	nowSec := tokNow / 1000
	ver := func(skew float64) *maaVerifier {
		v, err := newMaaVerifier(map[string]any{
			"trustedIssuers": []any{"https://maa.test"},
			"trustAnchors":   map[string]any{"rootSpkiSha256": []any{hex.EncodeToString(pin[:])}},
			"policy":         map[string]any{"tdxMrtds": []any{mrtd}},
			"clockSkewMs":    skew,
		})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	hdr := mustJSON(t, map[string]any{"alg": "ES256", "x5c": []any{g03b64(cert.Raw)}})
	tok := func(exp int64, iat *int64) string {
		p := map[string]any{
			"iss": "https://maa.test", "exp": exp,
			"x-ms-isolation-tee": map[string]any{"x-ms-attestation-type": "tdxvm", "tdx_mrtd": mrtd, "tdx_report_data": hex.EncodeToString(rawBinding)},
		}
		if iat != nil {
			p["iat"] = *iat
		}
		return signES256(t, key, hdr, mustJSON(t, p))
	}
	iat := func(v int64) *int64 { return &v }
	rows := []struct {
		name string
		skew float64
		tok  string
		b    *AttestationBinding
		want string // "" = OK
	}{
		{"skew 1000: exp = now-1 still valid", 1000, tok(nowSec-1, nil), testBinding, ""},
		{"skew 1000: exp = now-2 expired", 1000, tok(nowSec-2, nil), testBinding, "MAA token expired"},
		{"skew 1001 rounds up to 2 s", 1001, tok(nowSec-2, nil), testBinding, ""},
		{"skew 1001: exp = now-3 expired", 1001, tok(nowSec-3, nil), testBinding, "MAA token expired"},
		{"iat = now+skew accepted", 1000, tok(nowSec+3600, iat(nowSec+1)), testBinding, ""},
		{"iat = now+skew+1 in the future", 1000, tok(nowSec+3600, iat(nowSec+2)), testBinding, "MAA token issued in the future (iat)"},
		{"no expected binding", 1000, tok(nowSec+3600, nil), nil, "no expected attestation binding supplied"},
		{"binding not constructible", 1000, tok(nowSec+3600, nil), &AttestationBinding{}, "binding not constructible: binding: holderPub required"},
	}
	for _, r := range rows {
		got := func() (res HardwareResult) {
			defer func() {
				if x := recover(); x != nil {
					res = HardwareResult{Reason: "panic"}
				}
			}()
			return ver(r.skew).verify(map[string]any{"token": r.tok}, r.b, tokNow)
		}()
		if (r.want == "") != got.OK || got.Reason != r.want {
			t.Errorf("%s: %+v, want %q", r.name, got, r.want)
		}
	}
}

func TestG03MaaHostAssertedOptionalClaims(t *testing.T) {
	sev := &maaVerifier{policy: maaPolicy{hasSev: true, sevSnp: []string{"aa"}}}
	r := sev.sevSnpResult(map[string]any{"x-ms-sevsnpvm-launchmeasurement": "AA"})
	if _, has := r.HostAsserted["host_data"]; !r.OK || has || r.HostAsserted["attestation_type"] != "sevsnpvm" {
		t.Errorf("sev without host data: %+v", r)
	}
	tdx := &maaVerifier{policy: maaPolicy{hasTdx: true, tdx: []string{"aa"}, tdxStatuses: []string{""}, hasTdxStatuses: true}}
	r = tdx.tdxResult(map[string]any{"tdx_mrtd": "aa", "attester_tcb_status": ""})
	if _, has := r.HostAsserted["tcb_status"]; !r.OK || has || r.HostAsserted["attestation_type"] != "tdxvm" {
		t.Errorf("tdx with an empty (accepted) tcb status: %+v", r)
	}
}
