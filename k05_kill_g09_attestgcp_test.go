package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// g09 mutation kills for attest_gcp.go: JWK key building, the x5c chain anchor, root PEM reading, signing-key resolution,
// the skew rounding and the window edges of the verifier.

func g09gKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// g09gCert issues a certificate for key, signed by parent (self-signed when parent is nil).
func g09gCert(t *testing.T, key *ecdsa.PrivateKey, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, from, to time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: cn}, NotBefore: from, NotAfter: to,
		BasicConstraintsValid: true, IsCA: cn != "leaf", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	if cn == "leaf" {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func g09gB64(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }

func g09gPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func g09gSpki(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	ac, err := parseCertDER(c.Raw)
	if err != nil {
		t.Fatal(err)
	}
	k, err := keyOfCert(ac)
	if err != nil {
		t.Fatal(err)
	}
	return k.spkiSHA256()
}

type g09gPKI struct {
	caKey, leafKey, otherKey *ecdsa.PrivateKey
	ca, leaf, other, expired *x509.Certificate
}

func g09gNewPKI(t *testing.T) g09gPKI {
	base := time.UnixMilli(tokNow).UTC()
	from, to := base.Add(-time.Hour), base.Add(time.Hour)
	p := g09gPKI{caKey: g09gKey(t), leafKey: g09gKey(t), otherKey: g09gKey(t)}
	p.ca = g09gCert(t, p.caKey, "ca", nil, nil, from, to)
	p.leaf = g09gCert(t, p.leafKey, "leaf", p.ca, p.caKey, from, to)
	p.other = g09gCert(t, p.otherKey, "other", nil, nil, from, to)
	p.expired = g09gCert(t, p.otherKey, "old", nil, nil, base.Add(-3*time.Hour), base.Add(-2*time.Hour))
	return p
}

func TestG09GcpNewVerifierAnchors(t *testing.T) {
	ok := []string{
		`{"trustedIssuers":["https://i"],"trustAnchors":{"trustedJwks":{"keys":[{}]},"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`,
		`{"trustedIssuers":["https://i"],"trustAnchors":{"trustedJwks":{"keys":[{}]},"rootCertsPem":["x"]},"policy":{"imageDigests":["sha256:x"]}}`,
	}
	for _, c := range ok {
		if _, err := newGcpVerifier(cfgOf(t, c)); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	_, err := newGcpVerifier(cfgOf(t, `{"trustedIssuers":[""],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`))
	if err == nil || err.Error() != "createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string" {
		t.Errorf("empty issuer: %v", err)
	}
}

func TestG09GcpJwkKey(t *testing.T) {
	p := g09gNewPKI(t)
	ec := jwkOf(p.leafKey, "k")
	want, w := jwkKey(ec)
	if w != "" {
		t.Fatalf("EC jwk: %s", w)
	}
	withN := jwkOf(p.leafKey, "k")
	withN["n"] = "AQAB" // n without e is not an RSA key
	if k, why := jwkKey(withN); why != "" || k.spkiSHA256() != want.spkiSHA256() {
		t.Errorf("EC jwk with a stray n: %q", why)
	}
	unusable := "JWKS key is not a usable public key: error:1E08010C:DECODER routines::unsupported"
	neither := "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate"
	del := func(k string) map[string]any { m := jwkOf(p.leafKey, "k"); delete(m, k); return m }
	okp := jwkOf(p.leafKey, "k")
	okp["kty"] = "OKP"
	for _, c := range []struct {
		name string
		jwk  map[string]any
		want string
	}{
		{"rsa e too small", map[string]any{"n": "AQAB", "e": "AQ"}, unusable},
		{"ec off curve", map[string]any{"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ"}, unusable},
		{"kty not EC", okp, neither},
		{"no crv", del("crv"), neither},
		{"no x", del("x"), neither},
		{"no y", del("y"), neither},
		{"empty x5c", map[string]any{"x5c": []any{}}, neither},
	} {
		if k, why := jwkKey(c.jwk); why != c.want || k.pub != nil {
			t.Errorf("%s: %q, want %q", c.name, why, c.want)
		}
	}
	_, perr := parseCertDER(nodeB64("AAAA"))
	if _, why := jwkKey(map[string]any{"x5c": []any{"AAAA"}}); why != "JWKS key is not a usable public key: "+errMsg(perr) {
		t.Errorf("garbage x5c: %q", why)
	}
	// a structurally valid certificate whose EC point is off the curve: the certificate parses, its key does not
	der := append([]byte{}, p.leaf.Raw...)
	x, y := make([]byte, 32), make([]byte, 32)
	p.leafKey.X.FillBytes(x)
	p.leafKey.Y.FillBytes(y)
	i := bytes.Index(der, append(x, y...))
	if i < 0 {
		t.Fatal("leaf point not found")
	}
	der[i+63] ^= 0x01
	if _, err := parseCertDER(der); err != nil {
		t.Fatalf("tampered cert must still parse: %v", err)
	}
	if k, why := jwkKey(map[string]any{"x5c": []any{base64.StdEncoding.EncodeToString(der)}}); !strings.HasPrefix(why, "JWKS key is not a usable public key: ") || k.pub != nil {
		t.Errorf("off-curve x5c key: %q", why)
	}
}

func TestG09GcpX5cChain(t *testing.T) {
	p := g09gNewPKI(t)
	v := &gcpVerifier{spkiPins: map[string]bool{}}
	_, perr := parseCertDER(nodeB64("AAAA"))
	for _, c := range []struct {
		name  string
		chain []any
		want  string
	}{
		{"empty", []any{}, "empty x5c certificate chain"},
		{"empty entry", []any{""}, "empty x5c entry at index 0"},
		{"garbage", []any{"AAAA"}, "malformed x5c certificate at index 0: " + errMsg(perr)},
		{"expired", []any{g09gB64(p.expired)}, "x5c certificate at index 0 is outside its validity window"},
		{"bad link", []any{g09gB64(p.leaf), g09gB64(p.other)}, "x5c link 0 is not signed by the certificate above it"},
		{"unanchored", []any{g09gB64(p.leaf), g09gB64(p.ca)}, "x5c chain does not anchor in a configured GCP trust root"},
	} {
		if got := v.verifyJwkX5cChain(c.chain, tokNow); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	pinned := &gcpVerifier{spkiPins: map[string]bool{g09gSpki(t, p.ca): true}}
	if got := pinned.verifyJwkX5cChain([]any{g09gB64(p.leaf), g09gB64(p.ca)}, tokNow); got != "" {
		t.Errorf("pinned CA: %q", got)
	}
	wrongRoot := &gcpVerifier{spkiPins: map[string]bool{}, rootCertsPem: []string{g09gPEM(p.other)}}
	if got := wrongRoot.verifyJwkX5cChain([]any{g09gB64(p.leaf), g09gB64(p.ca)}, tokNow); got != "x5c chain does not anchor in a configured GCP trust root" {
		t.Errorf("unrelated root: %q", got)
	}
	root := &gcpVerifier{spkiPins: map[string]bool{}, rootCertsPem: []string{g09gPEM(p.ca)}}
	if got := root.verifyJwkX5cChain([]any{g09gB64(p.leaf), g09gB64(p.ca)}, tokNow); got != "" {
		t.Errorf("configured root: %q", got)
	}
}

func TestG09GcpRootKeyFromPEM(t *testing.T) {
	k := g09gKey(t)
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := rootKeyFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})))
	if !ok || !bytes.Equal(got.spki, spki) || got.typ != "ec" {
		t.Errorf("bare public key: %+v %v", got, ok)
	}
	for _, text := range []string{"x", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}))} {
		if got, ok := rootKeyFromPEM(text); ok || got.pub != nil || got.spki != nil {
			t.Errorf("%q: %+v %v", text, got, ok)
		}
	}
}

func TestG09GcpPickAndSigningKey(t *testing.T) {
	p := g09gNewPKI(t)
	k1 := jwkOf(p.leafKey, "k1")
	if got := pickJwk(&jwtParsed{hasKid: true, kid: ""}, []map[string]any{k1}); !reflect.DeepEqual(got, k1) {
		t.Errorf("an empty kid falls back to the sole key: %v", got)
	}
	leafKey, _ := jwkKey(k1)
	otherJwk := jwkOf(p.otherKey, "t1")
	evJwk := jwkOf(p.caKey, "e1")
	ev := func(j map[string]any) any { return map[string]any{"keys": []any{j}} }
	notAnchored := "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"
	noKid := "no kid on the token and no unambiguous single signing key available"
	cases := []struct {
		name string
		v    *gcpVerifier
		tok  *jwtParsed
		ev   any
		want string
		spki string // when want == ""
	}{
		{"header x5c, unanchored", &gcpVerifier{spkiPins: map[string]bool{"aa": true}}, &jwtParsed{hasX5c: true, x5c: []string{g09gB64(p.other)}}, nil,
			"signing key not trusted: x5c chain does not anchor in a configured GCP trust root", ""},
		{"empty kid, two keys", &gcpVerifier{spkiPins: map[string]bool{}, trustedKeys: []map[string]any{k1, otherJwk}}, &jwtParsed{hasKid: true, kid: ""}, nil, noKid, ""},
		{"empty header x5c", &gcpVerifier{spkiPins: map[string]bool{"aa": true}}, &jwtParsed{hasX5c: true, x5c: []string{}}, nil, noKid, ""},
		{"trusted kid beats header x5c", &gcpVerifier{spkiPins: map[string]bool{}, trustedKeys: []map[string]any{k1}},
			&jwtParsed{hasKid: true, kid: "k1", hasX5c: true, x5c: []string{g09gB64(p.other)}}, nil, "", leafKey.spkiSHA256()},
		{"evidence key not trusted", &gcpVerifier{spkiPins: map[string]bool{}, trustedKeys: []map[string]any{otherJwk}}, &jwtParsed{hasKid: true, kid: "e1"}, ev(evJwk), notAnchored, ""},
		{"jwk empty x5c", &gcpVerifier{spkiPins: map[string]bool{"aa": true}}, &jwtParsed{hasKid: true, kid: "e1"},
			ev(map[string]any{"kid": "e1", "kty": "EC", "crv": "P-256", "x": evJwk["x"], "y": evJwk["y"], "x5c": []any{}}), notAnchored, ""},
		{"jwk x5c without roots or pins", &gcpVerifier{spkiPins: map[string]bool{}, trustedKeys: []map[string]any{otherJwk}}, &jwtParsed{hasKid: true, kid: "e1"},
			ev(map[string]any{"kid": "e1", "kty": "EC", "crv": "P-256", "x": evJwk["x"], "y": evJwk["y"], "x5c": []any{g09gB64(p.ca)}}), notAnchored, ""},
		{"jwk without x5c, roots configured", &gcpVerifier{spkiPins: map[string]bool{}, rootCertsPem: []string{g09gPEM(p.ca)}}, &jwtParsed{hasKid: true, kid: "e1"}, ev(evJwk), notAnchored, ""},
		{"header x5c anchored by root", &gcpVerifier{spkiPins: map[string]bool{}, rootCertsPem: []string{g09gPEM(p.ca)}}, &jwtParsed{hasX5c: true, x5c: []string{g09gB64(p.leaf)}}, nil, "", leafKey.spkiSHA256()},
		{"header x5c anchored by pin", &gcpVerifier{spkiPins: map[string]bool{g09gSpki(t, p.ca): true}}, &jwtParsed{hasX5c: true, x5c: []string{g09gB64(p.leaf), g09gB64(p.ca)}}, nil, "", leafKey.spkiSHA256()},
	}
	for _, c := range cases {
		k, why := c.v.signingKey(c.tok, c.ev, tokNow)
		if why != c.want {
			t.Errorf("%s: %q, want %q", c.name, why, c.want)
			continue
		}
		if c.want == "" && k.spkiSHA256() != c.spki {
			t.Errorf("%s: wrong key", c.name)
		}
		if c.want != "" && k.pub != nil {
			t.Errorf("%s: a failure must carry no key", c.name)
		}
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	v := &gcpVerifier{}
	if got := v.jwsSignature(&jwtParsed{alg: "ES256", signature: make([]byte, 64)}, keyInfoOf(&p384.PublicKey, der)); got != "ES256 token but signing key is EC/P-384 (not EC P-256)" {
		t.Errorf("P-384 under ES256: %q", got)
	}
	if got := nonceCandidates([]any{"", "a"}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("nonceCandidates %v", got)
	}
}

func g09gClaims(t *testing.T, mut func(m map[string]any)) string {
	t.Helper()
	nowSec := tokNow / 1000
	m := map[string]any{
		"iss": gcpIssuer, "exp": nowSec + 3600, "iat": nowSec - 60, "nbf": nowSec - 60,
		"swname": "CONFIDENTIAL_SPACE", "swversion": []any{"240500"}, "hwmodel": "GCP_AMD_SEV", "dbgstat": "disabled-since-boot",
		"eat_nonce": []any{bindingB64(t, testBinding)},
		"submods":   map[string]any{"confidential_space": map[string]any{}, "container": map[string]any{"image_digest": "sha256:abc"}},
	}
	if mut != nil {
		mut(m)
	}
	return mustJSON(t, m)
}

func TestG09GcpVerifyEdges(t *testing.T) {
	key := g09gKey(t)
	hdr := `{"alg":"ES256","kid":"k1"}`
	nowSec := tokNow / 1000
	run := func(skew string, policy string, mut func(m map[string]any)) HardwareResult {
		c := cfgOf(t, `{"trustedIssuers":["`+gcpIssuer+`"],"trustAnchors":{},`+skew+`"policy":`+policy+`}`)
		c["trustAnchors"] = map[string]any{"trustedJwks": map[string]any{"keys": []any{jwkOf(key, "k1")}}}
		ver, err := VerifierFromConfig("gcp-confidential-space", c)
		if err != nil {
			t.Fatal(err)
		}
		return ver.Verify(map[string]any{"token": signES256(t, key, hdr, g09gClaims(t, mut))}, testBinding, tokNow)
	}
	pol := `{"imageDigests":["sha256:abc"]}`
	for _, c := range []struct {
		name, skew, policy string
		mut                func(m map[string]any)
		want               string // "" = OK
	}{
		{"skew 1000 rounds to 1 s", `"clockSkewMs":1000,`, pol, func(m map[string]any) { m["exp"] = nowSec - 2 }, "Confidential Space token expired"},
		{"skew 1001 rounds up to 2 s", `"clockSkewMs":1001,`, pol, func(m map[string]any) { m["exp"] = nowSec - 2 }, ""},
		{"nbf at now + skew", `"clockSkewMs":1000,`, pol, func(m map[string]any) { m["nbf"] = nowSec + 1 }, ""},
		{"iat at now + skew", `"clockSkewMs":1000,`, pol, func(m map[string]any) { m["iat"] = nowSec + 1 }, ""},
		{"no swname", "", pol, func(m map[string]any) { delete(m, "swname") }, "unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')"},
		{"empty swversion string", "", `{"imageDigests":["sha256:abc"],"allowedSwVersions":[""]}`, func(m map[string]any) { m["swversion"] = "" }, "swversion not in policy allowlist"},
		{"swversion string", "", `{"imageDigests":["sha256:abc"],"allowedSwVersions":["7"]}`, func(m map[string]any) { m["swversion"] = "7" }, ""},
	} {
		r := run(c.skew, c.policy, c.mut)
		if c.want == "" && !r.OK {
			t.Errorf("%s: %+v", c.name, r)
		}
		if c.want != "" && (r.OK || r.Reason != c.want) {
			t.Errorf("%s: %+v, want %q", c.name, r, c.want)
		}
	}
	ver, err := VerifierFromConfig("gcp-confidential-space", cfgOf(t, `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r := ver.Verify(map[string]any{"token": ""}, testBinding, tokNow); r.OK || r.Reason != "no GCP Confidential Space token for this action" {
		t.Errorf("empty token: %+v", r)
	}
}
