package pcasigstore

// g07 mutation kills: exact refusal messages on the DER / OID / time / checkpoint helpers, an RFC 3161 token and whole
// Sigstore bundles (Rekor v1 dsse / intoto with a SET, Rekor v2 hashedrekord with a TSA) built from fresh keys, so every stage
// of verifyCore can be reached and refused on purpose.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	pca "github.com/Atlas-Authorization/pca-go"
)

var g07sStd = base64.StdEncoding.EncodeToString

var g07sSerial int64 = 100

const (
	g07sV2Name     = "rekor.example"
	g07sIntegrated = 1_700_000_000 // 2023-11-14T22:13:20Z
	g07sGenTime    = "20231114221320Z"
)

func g07sOID(t *testing.T, arcs ...int) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.ObjectIdentifier(arcs))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func g07sCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func g07sEC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// g07sCert issues tpl for pub, signed by parent with signer (parent nil: self-signed), valid 2020..2035.
func g07sCert(t *testing.T, tpl *x509.Certificate, pub any, parent *x509.Certificate, signer any) (*x509.Certificate, []byte) {
	t.Helper()
	g07sSerial++
	tpl.SerialNumber = big.NewInt(g07sSerial)
	tpl.NotBefore, tpl.NotAfter = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, der
}

func g07sNC(t *testing.T, der []byte) *pca.NodeCert {
	t.Helper()
	c, err := pca.ParseNodeCert(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func g07sCAtpl(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
}

// g07sTSAToken is an RFC 3161 TimeStampToken (CMS SignedData over a TSTInfo) over data at genTime, signed by key.
func g07sTSAToken(t *testing.T, key *ecdsa.PrivateKey, data []byte, genTime string) []byte {
	t.Helper()
	alg := enc(0x30, g07sOID(t, 2, 16, 840, 1, 101, 3, 4, 2, 1))
	tstinfo := g07sOID(t, 1, 2, 840, 113549, 1, 9, 16, 1, 4)
	h := sha256.Sum256(data)
	tst := enc(0x30, g07sCat(enc(0x02, []byte{1}), g07sOID(t, 1, 2, 3), enc(0x30, g07sCat(alg, enc(0x04, h[:]))), enc(0x02, []byte{5}),
		enc(0x18, []byte(genTime))))
	th := sha256.Sum256(tst)
	attrs := g07sCat(
		enc(0x30, g07sCat(g07sOID(t, 1, 2, 840, 113549, 1, 9, 3), enc(0x31, tstinfo))),
		enc(0x30, g07sCat(g07sOID(t, 1, 2, 840, 113549, 1, 9, 4), enc(0x31, enc(0x04, th[:])))))
	sh := sha256.Sum256(enc(0x31, attrs))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sh[:])
	if err != nil {
		t.Fatal(err)
	}
	si := enc(0x30, g07sCat(enc(0x02, []byte{1}), enc(0x30, nil), alg, enc(0xa0, attrs), enc(0x30, g07sOID(t, 1, 2, 840, 10045, 4, 3, 2)), enc(0x04, sig)))
	sd := enc(0x30, g07sCat(enc(0x02, []byte{3}), enc(0x31, alg), enc(0x30, g07sCat(tstinfo, enc(0xa0, enc(0x04, tst)))), enc(0x31, si)))
	return enc(0x30, g07sCat(g07sOID(t, 1, 2, 840, 113549, 1, 7, 2), enc(0xa0, sd)))
}

// ------------------------------------------------------------------------------------------------ bundle fixture

type g07sFx struct {
	t       *testing.T
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caDER   []byte
	logKey  *ecdsa.PrivateKey
	logID   []byte
	edLog   ed25519.PrivateKey
	edLogID []byte
	tsaKey  *ecdsa.PrivateKey
	tsaDER  []byte
	roots   *PinnedRoots
}

func g07sNewFx(t *testing.T) *g07sFx {
	t.Helper()
	f := &g07sFx{t: t, caKey: g07sEC(t), logKey: g07sEC(t), tsaKey: g07sEC(t)}
	f.ca, f.caDER = g07sCert(t, g07sCAtpl("g07 ca"), &f.caKey.PublicKey, nil, f.caKey)
	spki, err := x509.MarshalPKIXPublicKey(&f.logKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f.logID = sha256Of(spki)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.edLog = edPriv
	f.edLogID = sha256Of([]byte(g07sV2Name+"\n"), []byte{1}, edPub)
	_, f.tsaDER = g07sCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "g07 tsa"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // self-signed: Node's checkIssued wants keyCertSign
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}, &f.tsaKey.PublicKey, nil, f.tsaKey)
	all := validity{0, forever}
	f.roots = &PinnedRoots{
		tlogs: []PinnedLog{{keyID: f.logID, key: &f.logKey.PublicKey, valid: all}, {keyID: f.edLogID, key: edPub, valid: all, v2Name: g07sV2Name}},
		cas:   []PinnedCA{{chain: []*pca.NodeCert{g07sNC(t, f.caDER)}, raw: [][]byte{f.caDER}, valid: all}},
		tsas:  []PinnedCA{{chain: []*pca.NodeCert{g07sNC(t, f.tsaDER)}, raw: [][]byte{f.tsaDER}, valid: all}},
	}
	return f
}

// leaf is a Fulcio-style leaf for pub: code signing, SAN URI https://id, OIDC issuer (.1.1, raw) https://issuer.
func (f *g07sFx) leaf(pub any) []byte {
	u, _ := url.Parse("https://id")
	_, der := g07sCert(f.t, &x509.Certificate{Subject: pkix.Name{CommonName: "g07 leaf"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, URIs: []*url.URL{u},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte("https://issuer")}}},
		pub, f.ca, f.caKey)
	return der
}

type g07sOpt struct {
	kind    string                        // "dsse" (default), "intoto" or "hashedrekord" (Rekor v2)
	ed25519 bool                          // an Ed25519 leaf key (else ECDSA P-256)
	payload []byte                        // nil: the default statement
	body    func(m map[string]any) []byte // the canonicalized body from the default body object (nil: its JSON)
	entry   func(e map[string]any)        // edits the transparency log entry last
}

const g07sStatement = `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"aa"}}],` +
	`"predicateType":"https://slsa.dev/provenance/v1","predicate":{"n":1}}`

func (f *g07sFx) bundle(o g07sOpt) []byte {
	t := f.t
	t.Helper()
	var leafPub any
	var sign func(m []byte) []byte
	if o.ed25519 {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafPub, sign = pub, func(m []byte) []byte { return ed25519.Sign(priv, m) }
	} else {
		k := g07sEC(t)
		leafPub = &k.PublicKey
		sign = func(m []byte) []byte {
			h := sha256.Sum256(m)
			s, err := ecdsa.SignASN1(rand.Reader, k, h[:])
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	leafDER := f.leaf(leafPub)
	payload := o.payload
	if payload == nil {
		payload = []byte(g07sStatement)
	}
	pae := DSSEPAE(inTotoPayloadType, payload)
	dsseSig := sign(pae)
	ph := sha256.Sum256(payload)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	payloadHash := map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(ph[:])}
	kind := o.kind
	if kind == "" {
		kind = "dsse"
	}
	ver := "0.0.2"
	var bodyObj map[string]any
	switch kind {
	case "dsse":
		ver = "0.0.1"
		bodyObj = map[string]any{"apiVersion": ver, "kind": kind, "spec": map[string]any{"payloadHash": payloadHash,
			"signatures": []any{map[string]any{"signature": g07sStd(dsseSig), "verifier": g07sStd(pemLeaf)}}}}
	case "intoto":
		bodyObj = map[string]any{"apiVersion": ver, "kind": kind, "spec": map[string]any{"content": map[string]any{"payloadHash": payloadHash,
			"envelope": map[string]any{"signatures": []any{map[string]any{"sig": g07sStd([]byte(g07sStd(dsseSig))), "publicKey": g07sStd(pemLeaf)}}}}}}
	default:
		dh := sha256.Sum256(pae)
		bodyObj = map[string]any{"apiVersion": ver, "kind": kind, "spec": map[string]any{"hashedRekordV002": map[string]any{
			"data": map[string]any{"algorithm": "SHA2_256", "digest": g07sStd(dh[:])},
			"signature": map[string]any{"content": g07sStd(dsseSig),
				"verifier": map[string]any{"x509Certificate": map[string]any{"rawBytes": g07sStd(leafDER)}}}}}}
	}
	var body []byte
	if o.body != nil {
		body = o.body(bodyObj)
	} else {
		body, _ = json.Marshal(bodyObj)
	}
	root := pca.RFC9162LeafHash(body)
	v2 := kind == "hashedrekord"
	cpBody := fmt.Sprintf("o\n1\n%s\n", g07sStd(root))
	var name string
	var keyID, cpSig []byte
	if v2 {
		name, keyID, cpSig = g07sV2Name, f.edLogID, ed25519.Sign(f.edLog, []byte(cpBody))
	} else {
		h := sha256.Sum256([]byte(cpBody))
		s, err := ecdsa.SignASN1(rand.Reader, f.logKey, h[:])
		if err != nil {
			t.Fatal(err)
		}
		name, keyID, cpSig = "o", f.logID, s
	}
	env := cpBody + "\n— " + name + " " + g07sStd(g07sCat(keyID[:4], cpSig)) + "\n"
	e := map[string]any{"logIndex": "7", "logId": map[string]any{"keyId": g07sStd(keyID)}, "kindVersion": map[string]any{"kind": kind, "version": ver},
		"canonicalizedBody": g07sStd(body),
		"inclusionProof": map[string]any{"logIndex": "0", "rootHash": g07sStd(root), "treeSize": "1", "hashes": []any{},
			"checkpoint": map[string]any{"envelope": env}}}
	vm := map[string]any{"certificate": map[string]any{"rawBytes": g07sStd(leafDER)}, "tlogEntries": []any{e}}
	if v2 {
		vm["timestampVerificationData"] = map[string]any{"rfc3161Timestamps": []any{
			map[string]any{"signedTimestamp": g07sStd(g07sTSAToken(t, f.tsaKey, dsseSig, g07sGenTime))}}}
	} else {
		msg := fmt.Sprintf(`{"body":"%s","integratedTime":%d,"logID":"%s","logIndex":%d}`, g07sStd(body), g07sIntegrated, hex.EncodeToString(keyID), 7)
		h := sha256.Sum256([]byte(msg))
		set, err := ecdsa.SignASN1(rand.Reader, f.logKey, h[:])
		if err != nil {
			t.Fatal(err)
		}
		e["integratedTime"] = strconv.Itoa(g07sIntegrated)
		e["inclusionPromise"] = map[string]any{"signedEntryTimestamp": g07sStd(set)}
	}
	if o.entry != nil {
		o.entry(e)
	}
	b, err := json.Marshal(map[string]any{"mediaType": mediaTypes[2], "verificationMaterial": vm,
		"dsseEnvelope": map[string]any{"payload": g07sStd(payload), "payloadType": inTotoPayloadType, "signatures": []any{map[string]any{"sig": g07sStd(dsseSig)}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func g07sSub(m map[string]any, path ...string) map[string]any {
	for _, k := range path {
		m = m[k].(map[string]any)
	}
	return m
}

func g07sMarshal(m map[string]any) []byte { b, _ := json.Marshal(m); return b }

func TestG07SigstoreBundles(t *testing.T) {
	f := g07sNewFx(t)
	for _, kind := range []string{"dsse", "intoto", "hashedrekord"} {
		r := VerifySigstoreBundleCore(f.bundle(g07sOpt{kind: kind}), f.roots)
		if !r.OK {
			t.Fatalf("%s bundle refused: %s: %s", kind, r.Code, r.Detail)
		}
		c := r.Core
		if c.Identity != "https://id" || c.OIDCIssuer != "https://issuer" || c.SignedTime != g07sIntegrated || len(c.Subjects) != 1 {
			t.Errorf("%s core: %+v", kind, c)
		}
		if n, _ := g07sSub(r.Statement, "predicate")["n"].(json.Number); n != "1" {
			t.Errorf("%s: statement numbers must stay JSON numbers: %#v", kind, r.Statement["predicate"])
		}
	}
	cases := []struct {
		name         string
		o            g07sOpt
		code, detail string
	}{
		{"kind without version", g07sOpt{entry: func(e map[string]any) { e["kindVersion"] = map[string]any{"kind": "dsse"} }},
			"tlog_kind", "unsupported entry "},
		{"unpinned log", g07sOpt{entry: func(e map[string]any) { e["logId"] = map[string]any{"keyId": g07sStd(make([]byte, 32))} }},
			"tlog_key", "the entry names a log the verifier did not pin"},
		{"checkpoint envelope a number", g07sOpt{entry: func(e map[string]any) {
			g07sSub(e, "inclusionProof")["checkpoint"] = map[string]any{"envelope": 5}
		}}, "tlog_checkpoint", "the checkpoint envelope is not a string"},
		{"body with trailing JSON", g07sOpt{body: func(m map[string]any) []byte { return append(g07sMarshal(m), " {}"...) }},
			"tlog_body", "fail closed: the entry body is not JSON"},
		{"body not JSON", g07sOpt{body: func(map[string]any) []byte { return []byte("x") }},
			"tlog_body", "fail closed: the entry body is not JSON"},
		{"body of another version", g07sOpt{body: func(m map[string]any) []byte { m["apiVersion"] = "0.0.2"; return g07sMarshal(m) }},
			"tlog_body", "the entry body is not the kind the bundle names"},
		{"dsse body without signatures", g07sOpt{body: func(m map[string]any) []byte {
			g07sSub(m, "spec")["signatures"] = []any{}
			return g07sMarshal(m)
		}}, "tlog_body", "the entry must name exactly one signature"},
		{"intoto body without signatures", g07sOpt{kind: "intoto", body: func(m map[string]any) []byte {
			g07sSub(m, "spec", "content", "envelope")["signatures"] = []any{}
			return g07sMarshal(m)
		}}, "tlog_body", "the entry must name exactly one signature"},
		{"hashedrekord unknown digest, Ed25519 leaf", g07sOpt{kind: "hashedrekord", ed25519: true, body: func(m map[string]any) []byte {
			g07sSub(m, "spec", "hashedRekordV002", "data")["algorithm"] = "MD5"
			return g07sMarshal(m)
		}}, "tlog_body", "the entry digest algorithm is not the signing key's"},
		{"statement with trailing JSON", g07sOpt{payload: []byte(g07sStatement + " {}")}, "statement", "fail closed: the statement is not JSON"},
		{"statement not JSON", g07sOpt{payload: []byte("x")}, "statement", "fail closed: the statement is not JSON"},
		{"statement without subjects", g07sOpt{payload: []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"p"}`)},
			"statement", "no subject"},
	}
	for _, c := range cases {
		r := VerifySigstoreBundleCore(f.bundle(c.o), f.roots)
		if r.OK || r.Code != c.code || r.Detail != c.detail {
			t.Errorf("%s: got %v %q %q, want %q %q", c.name, r.OK, r.Code, r.Detail, c.code, c.detail)
		}
	}
}

func TestG07SigstoreBundleEnvelope(t *testing.T) {
	if r := VerifySigstoreBundleCore([]byte(`{}`), nil); r.Code != "malformed" || r.Detail != "no trusted root" {
		t.Errorf("nil root: %+v", r)
	}
	roots := &PinnedRoots{}
	if r := VerifySigstoreBundleCore([]byte(`{"verificationMaterial":{}} {}`), roots); r.Code != "malformed" || r.Detail != "not a bundle" {
		t.Errorf("trailing JSON: %+v", r)
	}
	if r := VerifySigstoreBundleCore([]byte(`{"mediaType":0.000001,"verificationMaterial":{}}`), roots); r.Code != "media_type" ||
		r.Detail != "unsupported media type 0.000001" {
		t.Errorf("numeric media type: %+v", r)
	}
}

func TestG07SigstoreTrustedRoot(t *testing.T) {
	f := g07sNewFx(t)
	spki, _ := x509.MarshalPKIXPublicKey(&f.logKey.PublicKey)
	vf := map[string]any{"start": "2020-01-01T00:00:00Z"}
	root := g07sMarshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": []any{map[string]any{"publicKey": map[string]any{"rawBytes": g07sStd(spki), "keyDetails": "PKIX_ECDSA_P256_SHA_256", "validFor": vf},
			"logId": map[string]any{"keyId": g07sStd(f.logID)}}},
		"certificateAuthorities": []any{map[string]any{"certChain": map[string]any{"certificates": []any{map[string]any{"rawBytes": g07sStd(f.caDER)}}},
			"validFor": vf}}})
	if r, err := ParseTrustedRoot(root); err != nil || len(r.tlogs) != 1 || len(r.cas) != 1 {
		t.Fatalf("root: %v", err)
	}
	if _, err := ParseTrustedRoot(append(root, " {}"...)); err == nil || err.Error() != "not a trusted root v0.1" {
		t.Errorf("trailing JSON: %v", err)
	}
	msg := func(fn func()) string {
		if err := catch(fn); err != nil {
			return err.Error()
		}
		return ""
	}
	log := func(pk map[string]any, keyID []byte) map[string]any {
		return map[string]any{"publicKey": pk, "logId": map[string]any{"keyId": g07sStd(keyID)}}
	}
	garbage := []byte{0, 0, 0}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PublicKey(&rk.PublicKey)
	form, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	for _, c := range []struct {
		name  string
		entry any
		tl    bool
		want  string
	}{
		{"no publicKey", map[string]any{"logId": map[string]any{"keyId": "AA=="}}, true, "log entry malformed"},
		{"no logId", map[string]any{"publicKey": map[string]any{}}, true, "log entry malformed"},
		{"not an object", "x", true, "log entry malformed"},
		{"ECDSA key unreadable", log(map[string]any{"rawBytes": g07sStd(garbage), "keyDetails": "PKIX_ECDSA_P256_SHA_256", "validFor": vf},
			sha256Of(garbage)), true, "Failed to read asymmetric key"},
		{"RSA key unreadable", log(map[string]any{"rawBytes": g07sStd(garbage), "keyDetails": "PKCS1_RSA_PKCS1V5", "validFor": vf},
			sha256Of(garbage)), false, "Failed to read asymmetric key"},
		{"RSA key id wrong", log(map[string]any{"rawBytes": g07sStd(pkcs1), "keyDetails": "PKCS1_RSA_PKCS1V5", "validFor": vf},
			make([]byte, 32)), false, "log id is not the SHA-256 of its key"},
		{"RSA key id right", log(map[string]any{"rawBytes": g07sStd(pkcs1), "keyDetails": "PKCS1_RSA_PKCS1V5", "validFor": vf},
			sha256Of(form)), false, ""},
	} {
		if got := msg(func() { pinnedLog(c.entry, c.tl) }); got != c.want {
			t.Errorf("pinnedLog %s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := msg(func() {
		pinnedChain(map[string]any{"certChain": map[string]any{"certificates": []any{}}, "validFor": vf})
	}); got != "certificate authority entry malformed" {
		t.Errorf("empty certificate list: %q", got)
	}
	_, perr := pca.ParseNodeCert([]byte{0x30, 0})
	if perr == nil {
		t.Fatal("fixture: an empty SEQUENCE parsed as a certificate")
	}
	if got := msg(func() { fullCert([]byte{0x30, 0}) }); got != perr.Error() {
		t.Errorf("unparsable certificate: %q, want %q", got, perr.Error())
	}
	if got := msg(func() { fullCert(append(append([]byte{}, f.caDER...), 0)) }); got != "trailing bytes after the certificate" {
		t.Errorf("trailing byte: %q", got)
	}
}

func TestG07SigstoreDERMessages(t *testing.T) {
	msg := func(fn func()) string {
		if err := catch(fn); err != nil {
			return err.Error()
		}
		return ""
	}
	for _, c := range []struct {
		b     []byte
		limit int
		want  string
	}{
		{[]byte{0x30}, 1, "DER truncated"},
		{[]byte{0x30, 0, 0}, 1, "DER truncated"},
		{[]byte{0x30, 0x80}, 2, "DER length"},
		{[]byte{0x30, 0x85, 0, 0, 0, 0, 1}, 7, "DER length"},
		{[]byte{0x30, 0x82, 1}, 3, "DER length"},
		{[]byte{0x30, 0x82, 1, 0, 0}, 3, "DER length"},
	} {
		if got := msg(func() { tlv(c.b, 0, c.limit) }); got != c.want {
			t.Errorf("tlv(% x, %d): %q, want %q", c.b, c.limit, got, c.want)
		}
	}
	var e tlvT
	if got := msg(func() { e = tlv([]byte{0x30, 0x81, 0x00}, 0, 3) }); got != "" || e != (tlvT{0x30, 0, 3, 3}) {
		t.Errorf("long-form zero length ending at the limit: %q %+v", got, e)
	}
	if got := msg(func() { oidText([]byte{6, 0}, tlvT{6, 0, 2, 2}) }); got != "not an OID" {
		t.Errorf("empty OID: %q", got)
	}
	if got := msg(func() { oidText([]byte{0xff, 0x80, 1}, tlvT{6, 0, 1, 3}) }); got != "OID arc is not minimally encoded" {
		t.Errorf("leading 0x80 after a high byte: %q", got)
	}
	var o string
	if got := msg(func() { o = oidText([]byte{0x2a, 0x81, 0x80, 0x01}, tlvT{6, 0, 0, 4}) }); got != "" || o != "1.2.16385" {
		t.Errorf("0x80 inside an arc: %q %q", got, o)
	}
	if got := msg(func() { sanIdentity(&parsedCert{}) }); got != "no subjectAltName" {
		t.Errorf("no SAN: %q", got)
	}
	alg := enc(0x30, g07sOID(t, 1, 2))
	if got := msg(func() { digestOf(alg, tlv(alg, 0, len(alg))) }); got != "unsupported digest algorithm" {
		t.Errorf("digest 1.2: %q", got)
	}
	gt := func(tag byte, s string) (int64, string) {
		var v int64
		m := msg(func() { v = generalizedTime(append([]byte{tag, byte(len(s))}, s...), tlvT{int(tag), 0, 2, 2 + len(s)}) })
		return v, m
	}
	if _, m := gt(0x17, "20260601120030Z"); m != "genTime is not a GeneralizedTime" {
		t.Errorf("UTCTime tag: %q", m)
	}
	if _, m := gt(0x18, "x"); m != "genTime malformed" {
		t.Errorf("malformed genTime: %q", m)
	}
	if v, m := gt(0x18, "01000601120030Z"); m != "" || v != time.Date(100, 6, 1, 12, 0, 30, 0, time.UTC).UnixMilli() {
		t.Errorf("year 100: %d %q", v, m)
	}
	if _, m := gt(0x18, "00990601120030Z"); m != "genTime is not a real date" {
		t.Errorf("year 99: %q", m)
	}
}

// g07sMiniCert is the smallest shape parseCert accepts, carrying one subjectAltName extension with value san.
func g07sMiniCert(san []byte) []byte {
	ext := enc(0x30, g07sCat(enc(0x06, []byte{0x55, 0x1d, 0x11}), enc(0x04, san)))
	return enc(0x30, enc(0x30, enc(0xa3, enc(0x30, ext))))
}

func TestG07SigstoreCertChecks(t *testing.T) {
	if !sanDecodes([]byte{0}) {
		t.Error("an unreadable certificate is judged elsewhere")
	}
	if sanDecodes(g07sMiniCert([]byte{0x30, 2, 0x04, 5})) {
		t.Error("a SAN SEQUENCE with an overrunning element decoded")
	}
	if !sanDecodes(g07sMiniCert([]byte{0x30, 2, 0x82, 0})) {
		t.Error("a well-formed SAN refused")
	}
	rootKey, interKey, leafKey := g07sEC(t), g07sEC(t), g07sEC(t)
	at := int64(1_700_000_000_000)
	for _, interIsCA := range []bool{true, false} {
		rootC, rootDER := g07sCert(t, g07sCAtpl("g07 root"), &rootKey.PublicKey, nil, rootKey)
		interTpl := g07sCAtpl("g07 intermediate")
		if !interIsCA {
			interTpl = &x509.Certificate{Subject: pkix.Name{CommonName: "g07 intermediate"}, KeyUsage: x509.KeyUsageDigitalSignature}
		}
		interC, interDER := g07sCert(t, interTpl, &interKey.PublicKey, rootC, rootKey)
		_, leafDER := g07sCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "g07 chain leaf"}, KeyUsage: x509.KeyUsageDigitalSignature},
			&leafKey.PublicKey, interC, interKey)
		ca := &PinnedCA{chain: []*pca.NodeCert{g07sNC(t, leafDER), g07sNC(t, interDER), g07sNC(t, rootDER)}, raw: [][]byte{leafDER, interDER, rootDER}}
		if got := chainOK(ca, at); got != interIsCA {
			t.Errorf("three-certificate chain, intermediate CA %v: chainOK %v", interIsCA, got)
		}
	}
}

func TestG07SigstoreRFC3161(t *testing.T) {
	f := g07sNewFx(t)
	data := []byte("the signature")
	tok := g07sTSAToken(t, f.tsaKey, data, g07sGenTime)
	var ms int64
	if err := catch(func() { ms = verifyRFC3161(tok, data, f.roots.tsas) }); err != nil || ms != g07sIntegrated*1000 {
		t.Fatalf("token: %d %v", ms, err)
	}
	// a TSA certificate whose key node:crypto cannot read (an unknown named curve) is refused with that reader's error
	p256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	if !bytes.Contains(f.tsaDER, p256) {
		t.Fatal("fixture: no P-256 OID in the TSA certificate")
	}
	bad := bytes.Replace(f.tsaDER, p256, append(append([]byte{}, p256[:9]...), 0x08), 1)
	nc := g07sNC(t, bad)
	_, kerr := nc.PublicKey()
	if kerr == nil {
		t.Fatal("fixture: the unknown curve was read")
	}
	tsas := []PinnedCA{{chain: []*pca.NodeCert{nc}, raw: [][]byte{bad}, valid: validity{0, forever}}}
	if err := catch(func() { verifyRFC3161(tok, data, tsas) }); err == nil || err.Error() != kerr.Error() {
		t.Errorf("unreadable TSA key: %v, want %v", err, kerr)
	}
	sd := g07sOID(t, 1, 2, 840, 113549, 1, 7, 2)
	tst := g07sOID(t, 1, 2, 840, 113549, 1, 9, 16, 1, 4)
	for _, c := range []struct {
		name  string
		token []byte
		want  string
	}{
		{"response without a token", enc(0x30, enc(0x30, enc(0x02, []byte{0}))), "no timeStampToken"},
		{"empty first SEQUENCE", enc(0x30, enc(0x30, nil)), "not an OID"},
		{"two-byte first SEQUENCE", enc(0x30, enc(0x30, enc(0x02, nil))), "not an OID"},
		{"content type only", enc(0x30, sd), "not CMS SignedData"},
		{"TSTInfo OID only", enc(0x30, g07sCat(sd, enc(0xa0, enc(0x30, g07sCat(enc(0x02, []byte{3}), enc(0x31, nil), enc(0x30, tst)))))),
			"content is not TSTInfo"},
	} {
		if err := catch(func() { verifyRFC3161(c.token, data, nil) }); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	noEncap := enc(0x30, g07sCat(sd, enc(0xa0, enc(0x30, g07sCat(enc(0x02, []byte{3}), enc(0x31, nil))))))
	if err := catch(func() { verifyRFC3161(noEncap, data, nil) }); err == nil || !strings.Contains(err.Error(), "index out of range [-1]") {
		t.Errorf("no encapsulated content: %v", err)
	}
}

func TestG07SigstoreCheckpoint(t *testing.T) {
	k := g07sEC(t)
	log := &PinnedLog{keyID: bytes.Repeat([]byte{9}, 32), key: &k.PublicKey}
	root := bytes.Repeat([]byte{1}, 32)
	body := "o\n1\n" + g07sStd(root) + "\n"
	h := sha256.Sum256([]byte(body))
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	good := "— o " + g07sStd(g07sCat(log.keyID[:4], sig))
	const none = "no checkpoint signature by the pinned log key"
	for _, c := range []struct {
		name, text string
		size       int64
		want       string
	}{
		{"signed", body + "\n" + good + "\n", 1, ""},
		{"no blank line", "x", 1, "checkpoint has no signature block"},
		{"blank first line", "\n\nx", 1, "checkpoint body too short or without an origin"},
		{"three lines", "o\n1\n\nx", 1, "checkpoint body too short or without an origin"},
		{"size 0", "o\n0\n" + g07sStd(root) + "\n\n" + good, 0, "checkpoint size differs from the proof"},
		{"line without the dash", body + "\nx y\n", 1, none},
		{"empty name", body + "\n—  abc\n", 1, none},
		{"white space inside the name", body + "\n— a b abc\n", 1, none},
		{"white space first in the name", body + "\n—  b abc\n", 1, none},
	} {
		var got string
		if err := catch(func() { got = verifyCheckpoint(c.text, log, c.size, root) }); err != nil || got != c.want {
			t.Errorf("%s: %q (err %v), want %q", c.name, got, err, c.want)
		}
	}
}

func TestG07SigstoreHostname(t *testing.T) {
	for in, want := range map[string]string{
		"http://?x":   "",
		"http://@h":   "h",
		"https://[x/": "",
		"http://:80/": "",
	} {
		if got := hostname(in); got != want {
			t.Errorf("hostname(%q) = %q, want %q", in, got, want)
		}
	}
}
