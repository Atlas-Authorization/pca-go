// Package pcasigstore verifies a Sigstore bundle offline (track K9) and turns its SLSA v1 provenance into the facts
// pca.ProvenanceGate checks. A port of packages/pca-attest-eat/src/sigstore.ts on top of sigstore-go.
//
// It is a separate module so that core pca-go users do not pull sigstore-go's dependency tree.
//
// sigstore-go does the cryptography: trusted root parsing, Rekor v1 (SET, checkpoint-signed inclusion proof) and Rekor v2
// (hashedrekord over DSSE, Ed25519 signed-note checkpoint) entries, RFC 3161 timestamps, the certificate path at every
// verified time, the embedded SCT and the DSSE signature. This package adds what the reference requires on top: the
// bundle shape the reference accepts (v0.2 / v0.3 keyless DSSE in-toto bundles, exactly one signature and one log entry of a
// supported kind), EVERY RFC 3161 timestamp must verify (sigstore-go skips failing ones), an SCT is required exactly when
// the root lists CT logs, every certificate link (leaf, CA and TSA chains) passes X509_check_issued's key-identifier rule
// (crypto/x509 does not check it), and the identity, issuer and source come from the certificate with the reference's rules (one URI
// or email SAN, the two issuer extensions agree, DER UTF8String extensions). Never panics: hostile input is a refusal.
package pcasigstore

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"unicode/utf8"

	pca "github.com/Atlas-Authorization/pca-go"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

var mediaTypes = map[string]bool{
	"application/vnd.dev.sigstore.bundle+json;version=0.2": true,
	"application/vnd.dev.sigstore.bundle+json;version=0.3": true,
	"application/vnd.dev.sigstore.bundle.v0.3+json":        true,
}

const inTotoPayloadType = "application/vnd.in-toto+json"

var kinds = map[string]bool{"dsse/0.0.1": true, "intoto/0.0.2": true, "hashedrekord/0.0.2": true}

// Subject is one statement subject digest.
type Subject struct {
	Alg    string `json:"alg"`
	Digest string `json:"digest"`
}

// Timestamps counts the verified time sources.
type Timestamps struct {
	TSA int  `json:"tsa"`
	Set bool `json:"set"`
}

// Core is what a verified bundle establishes before any SLSA reading (the `core` of sigstore-vectors.json).
type Core struct {
	Identity      string     `json:"identity"`
	OIDCIssuer    string     `json:"oidc_issuer"`
	SourceRepo    string     `json:"source_repo,omitempty"`
	SourceRef     string     `json:"source_ref,omitempty"`
	SourceDigest  string     `json:"source_digest,omitempty"`
	PredicateType string     `json:"predicate_type"`
	Subjects      []Subject  `json:"subjects"`
	SignedTime    int64      `json:"signed_time"`
	RekorLogIndex int64      `json:"rekor_log_index"`
	Rekor         string     `json:"rekor"`
	Timestamps    Timestamps `json:"timestamps"`
}

// CoreResult is {OK, Core, Statement} or {Code, Detail}.
type CoreResult struct {
	OK        bool
	Core      Core
	Statement map[string]any
	Code      string
	Detail    string
}

// Result is {OK, Facts} (the facts member of a pca.ProvenanceGate input) or {Code, Detail}.
type Result struct {
	OK     bool
	Facts  map[string]any
	Code   string
	Detail string
}

// ParseTrustedRoot parses a Sigstore trusted_root.json (application/vnd.dev.sigstore.trustedroot+json;version=0.1).
func ParseTrustedRoot(js []byte) (*root.TrustedRoot, error) {
	var head struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(js, &head); err != nil || head.MediaType != "application/vnd.dev.sigstore.trustedroot+json;version=0.1" {
		return nil, fmt.Errorf("not a trusted root v0.1")
	}
	tr, err := root.NewTrustedRootFromJSON(js)
	if err != nil {
		return nil, err
	}
	if len(tr.RekorLogs()) == 0 || len(tr.FulcioCertificateAuthorities()) == 0 {
		return nil, fmt.Errorf("a trusted root needs a transparency log and a CA")
	}
	return tr, nil
}

// The JSON shape the pre-checks read (sigstore-go reads the same bytes as protobuf JSON).
type rawBundle struct {
	MediaType        string          `json:"mediaType"`
	MessageSignature json.RawMessage `json:"messageSignature"`
	DsseEnvelope     *struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
	VerificationMaterial *struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
		TlogEntries []struct {
			LogIndex    string `json:"logIndex"`
			KindVersion *struct {
				Kind    string `json:"kind"`
				Version string `json:"version"`
			} `json:"kindVersion"`
		} `json:"tlogEntries"`
		TimestampVerificationData *struct {
			RFC3161Timestamps []json.RawMessage `json:"rfc3161Timestamps"`
		} `json:"timestampVerificationData"`
	} `json:"verificationMaterial"`
}

var decIntRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

func decInt(s string) (int64, bool) {
	if !decIntRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n <= 1<<53-1
}

func b64(s string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(s) }

// VerifySigstoreBundleCore verifies a Sigstore bundle (JSON bytes) carrying a DSSE in-toto statement against tr. Never panics.
func VerifySigstoreBundleCore(bundleJSON []byte, tr *root.TrustedRoot) (res CoreResult) {
	no := func(code, detail string) CoreResult { return CoreResult{Code: code, Detail: detail} }
	defer func() {
		if r := recover(); r != nil {
			res = no("malformed", fmt.Sprintf("fail closed: %v", r))
		}
	}()
	if tr == nil {
		return no("malformed", "no trusted root")
	}
	var rb rawBundle
	if err := json.Unmarshal(bundleJSON, &rb); err != nil || rb.VerificationMaterial == nil {
		return no("malformed", "not a bundle")
	}
	if !mediaTypes[rb.MediaType] {
		return no("media_type", "unsupported media type "+rb.MediaType)
	}
	vm := rb.VerificationMaterial
	var certRaw string
	if rb.MediaType == "application/vnd.dev.sigstore.bundle+json;version=0.2" {
		if vm.X509CertificateChain != nil && len(vm.X509CertificateChain.Certificates) > 0 {
			certRaw = vm.X509CertificateChain.Certificates[0].RawBytes
		}
	} else if vm.Certificate != nil {
		certRaw = vm.Certificate.RawBytes
	}
	if certRaw == "" {
		return no("not_keyless", "no Fulcio certificate (public-key bundles are not supported)")
	}
	env := rb.DsseEnvelope
	if env == nil || rb.MessageSignature != nil {
		return no("envelope", "not a DSSE bundle")
	}
	if env.PayloadType != inTotoPayloadType {
		return no("envelope", "payloadType is not application/vnd.in-toto+json")
	}
	if len(env.Signatures) != 1 {
		return no("envelope", "a DSSE envelope must carry exactly one signature")
	}
	payload, err := b64(env.Payload)
	if err != nil {
		return no("malformed", "payload is not base64")
	}
	leafDer, err := b64(certRaw)
	if err != nil {
		return no("cert_parse", "certificate is not base64")
	}
	leaf, err := x509.ParseCertificate(leafDer)
	if err != nil {
		return no("cert_parse", err.Error())
	}
	if len(vm.TlogEntries) != 1 {
		return no("tlog_count", "exactly one transparency log entry is required")
	}
	t := vm.TlogEntries[0]
	kv := ""
	if t.KindVersion != nil {
		kv = t.KindVersion.Kind + "/" + t.KindVersion.Version
	}
	if !kinds[kv] {
		return no("tlog_kind", "unsupported entry "+kv)
	}
	logIndex, ok := decInt(t.LogIndex)
	if !ok {
		return no("tlog_key", "logIndex is not a decimal integer")
	}
	nTSA := 0
	if vm.TimestampVerificationData != nil {
		nTSA = len(vm.TimestampVerificationData.RFC3161Timestamps)
	}

	// ---- the cryptography: sigstore-go
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return no("malformed", err.Error())
	}
	// intermediates come from the trusted root, never from the bundle (sigstore-go would add a v0.2 chain's tail to the pool)
	if ch := b.VerificationMaterial.GetX509CertificateChain(); ch != nil && len(ch.Certificates) > 1 {
		ch.Certificates = ch.Certificates[:1]
	}
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if len(tr.CTLogs()) > 0 {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	v, err := verify.NewVerifier(tr, opts...)
	if err != nil {
		return no("malformed", err.Error())
	}
	vr, err := v.Verify(&b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe()))
	if err != nil {
		return no("signature", err.Error())
	}
	// client spec 4.2: EVERY RFC 3161 timestamp must verify (sigstore-go skips failing ones and drops a second token from the
	// same authority), so each token is checked here against the pinned authorities, and each counts
	tokens, err := b.Timestamps()
	sc, err2 := b.SignatureContent()
	if err != nil || err2 != nil || len(tokens) != nTSA {
		return no("tsa", "timestamps unreadable")
	}
	minMs := int64(math.MaxInt64)
	for _, tok := range tokens {
		var at *root.Timestamp
		for _, a := range tr.TimestampingAuthorities() {
			if ts, err := a.Verify(tok, sc.Signature()); err == nil && tsaLinked(a) {
				at = ts
				break
			}
		}
		if at == nil {
			return no("tsa", "an RFC 3161 timestamp did not verify")
		}
		minMs = min(minMs, at.Time.UnixMilli())
	}
	set := false
	for _, ts := range vr.VerifiedTimestamps {
		switch ts.Type {
		case "Tlog":
			set = true
		case "TimestampAuthority":
		default:
			return no("no_verified_time", "unexpected time source "+ts.Type)
		}
		minMs = min(minMs, ts.Timestamp.UnixMilli())
	}
	tsa := nTSA
	if len(vr.VerifiedTimestamps) == 0 {
		return no("no_verified_time", "no verified time")
	}
	if !caLinked(tr, leaf, vr.VerifiedTimestamps) {
		return no("cert_chain", "no pinned CA chain links the certificate by key identifier at every signing time")
	}
	if !bytes.Equal(b.VerificationMaterial.GetCertificate().GetRawBytes(), leafDer) && !bytes.Equal(firstChainCert(&b), leafDer) {
		return no("cert_parse", "sigstore-go verified another certificate")
	}

	// ---- identity (fulcio docs/oid-info.md)
	if leaf.IsCA {
		return no("cert_chain", "the leaf is a CA certificate")
	}
	identity, err := sanIdentity(leaf)
	if err != nil {
		return no("identity", err.Error())
	}
	issV2, has2, err2 := fulcioExt(leaf, 8)
	issV1, has1, err1 := fulcioExt(leaf, 1)
	if err1 != nil || err2 != nil {
		return no("identity", "issuer extension malformed")
	}
	if has1 && has2 && issV1 != issV2 {
		return no("identity", "the two issuer extensions disagree")
	}
	issuer := issV1
	if has2 {
		issuer = issV2
	}
	if issuer == "" {
		return no("identity", "no OIDC issuer extension")
	}
	c := Core{Identity: identity, OIDCIssuer: issuer, RekorLogIndex: logIndex, SignedTime: floorDiv(minMs, 1000), Rekor: "v1", Timestamps: Timestamps{TSA: tsa, Set: set}}
	if kv == "hashedrekord/0.0.2" {
		c.Rekor = "v2"
	}
	for _, x := range []struct {
		n   int
		dst *string
	}{{12, &c.SourceRepo}, {13, &c.SourceDigest}, {14, &c.SourceRef}} {
		s, _, err := fulcioExt(leaf, x.n)
		if err != nil {
			return no("identity", err.Error())
		}
		*x.dst = s
	}

	// ---- statement (read from the verified payload, keeping subject order)
	if !utf8.Valid(payload) {
		return no("statement", "payload is not UTF-8")
	}
	var st map[string]any
	if err := json.Unmarshal(payload, &st); err != nil {
		return no("statement", "payload is not a JSON object")
	}
	if st["_type"] != pca.InTotoStatementV1 {
		return no("statement", "not an in-toto Statement v1")
	}
	subs, _ := st["subject"].([]any)
	if len(subs) == 0 {
		return no("statement", "no subject")
	}
	for _, s := range subs {
		so, _ := s.(map[string]any)
		d, _ := so["digest"].(map[string]any)
		for _, a := range []string{"sha256", "sha512"} {
			if v, ok := d[a].(string); ok {
				c.Subjects = append(c.Subjects, Subject{a, v})
			}
		}
	}
	if len(c.Subjects) == 0 || len(c.Subjects) > 64 {
		return no("statement", "no sha256/sha512 subject digest (or more than 64)")
	}
	pt, ok := st["predicateType"].(string)
	if !ok {
		return no("statement", "no predicateType")
	}
	c.PredicateType = pt
	return CoreResult{OK: true, Core: c, Statement: st}
}

// linksOK is X509_check_issued's key-identifier rule on every link (the root against itself): when a certificate names an
// authority key id and its parent has a subject key id, they must be equal. crypto/x509 chain building does not refuse a
// parent whose subject key id differs, so the chains sigstore-go accepted are re-checked here.
func linksOK(chain []*x509.Certificate) bool {
	for i, c := range chain {
		up := chain[min(i+1, len(chain)-1)]
		if len(c.AuthorityKeyId) > 0 && len(up.SubjectKeyId) > 0 && !bytes.Equal(c.AuthorityKeyId, up.SubjectKeyId) {
			return false
		}
	}
	return true
}

// caLinked: one pinned Fulcio CA builds a key-identifier-consistent chain for the leaf at every verified time.
func caLinked(tr *root.TrustedRoot, leaf *x509.Certificate, times []verify.TimestampVerificationResult) bool {
	for _, a := range tr.FulcioCertificateAuthorities() {
		ca, ok := a.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}
		all := true
		for _, t := range times {
			chains, err := ca.Verify(leaf, t.Timestamp)
			linked := false
			for _, ch := range chains {
				linked = linked || linksOK(ch)
			}
			if err != nil || !linked {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// tsaLinked: the pinned timestamp authority's own chain (leaf, intermediates, root) is key-identifier consistent.
func tsaLinked(a root.TimestampingAuthority) bool {
	t, ok := a.(*root.SigstoreTimestampingAuthority)
	if !ok || t.Root == nil {
		return false
	}
	var ch []*x509.Certificate
	if t.Leaf != nil {
		ch = append(ch, t.Leaf)
	}
	return linksOK(append(append(ch, t.Intermediates...), t.Root))
}

func firstChainCert(b *bundle.Bundle) []byte {
	if ch := b.VerificationMaterial.GetX509CertificateChain(); ch != nil && len(ch.Certificates) > 0 {
		return ch.Certificates[0].GetRawBytes()
	}
	return nil
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && a < 0 {
		q--
	}
	return q
}

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

// sanIdentity: exactly one SAN, a URI or an email; anything else (OtherName, several names) is refused.
func sanIdentity(c *x509.Certificate) (string, error) {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidSAN) {
			continue
		}
		var seq asn1.RawValue
		if rest, err := asn1.Unmarshal(e.Value, &seq); err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence {
			return "", fmt.Errorf("subjectAltName malformed")
		}
		var n asn1.RawValue
		rest, err := asn1.Unmarshal(seq.Bytes, &n)
		if err != nil || len(rest) != 0 {
			return "", fmt.Errorf("subjectAltName must hold exactly one name")
		}
		if n.Class != asn1.ClassContextSpecific || n.IsCompound || (n.Tag != 6 && n.Tag != 1) {
			return "", fmt.Errorf("subjectAltName must be a URI or an email")
		}
		if !utf8.Valid(n.Bytes) {
			return "", fmt.Errorf("subjectAltName is not UTF-8")
		}
		return string(n.Bytes), nil
	}
	return "", fmt.Errorf("no subjectAltName")
}

// fulcioExt reads extension 1.3.6.1.4.1.57264.1.n: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8.
func fulcioExt(c *x509.Certificate, n int) (string, bool, error) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, n}
	for _, e := range c.Extensions {
		if !e.Id.Equal(oid) {
			continue
		}
		v := e.Value
		if n > 6 {
			var s asn1.RawValue
			rest, err := asn1.Unmarshal(v, &s)
			if err != nil || len(rest) != 0 || s.Class != asn1.ClassUniversal || s.Tag != asn1.TagUTF8String {
				return "", true, fmt.Errorf("extension .1.%d is not a DER UTF8String", n)
			}
			v = s.Bytes
		}
		if !utf8.Valid(v) {
			return "", true, fmt.Errorf("extension .1.%d is not UTF-8", n)
		}
		return string(v), true, nil
	}
	return "", false, nil
}

// VerifySigstoreBundle is VerifySigstoreBundleCore, then the SLSA v1 predicate: the facts pca.ProvenanceGate checks.
func VerifySigstoreBundle(bundleJSON []byte, tr *root.TrustedRoot) Result {
	r := VerifySigstoreBundleCore(bundleJSON, tr)
	if !r.OK {
		return Result{Code: r.Code, Detail: r.Detail}
	}
	st, c := r.Statement, r.Core
	if st["predicateType"] != pca.SLSAProvenanceV1 {
		return Result{Code: "predicate", Detail: fmt.Sprintf("predicate %v is not SLSA provenance v1", st["predicateType"])}
	}
	obj := func(v any) map[string]any { m, _ := v.(map[string]any); return m }
	pr := obj(st["predicate"])
	bd, rd := obj(pr["buildDefinition"]), obj(pr["runDetails"])
	buildType, ok1 := bd["buildType"].(string)
	builderID, ok2 := obj(rd["builder"])["id"].(string)
	if !ok1 || !ok2 || obj(bd["externalParameters"]) == nil {
		return Result{Code: "predicate", Detail: "buildType, externalParameters and builder.id are required (SLSA Build L1)"}
	}
	subs := make([]any, len(c.Subjects))
	for i, s := range c.Subjects {
		subs[i] = map[string]any{"alg": s.Alg, "digest": s.Digest}
	}
	f := map[string]any{
		"v": json.Number("1"), "predicate_type": pca.SLSAProvenanceV1, "build_type": buildType, "builder_id": builderID,
		"subjects": subs, "identity": c.Identity, "oidc_issuer": c.OIDCIssuer,
		"integrated_time": json.Number(strconv.FormatInt(c.SignedTime, 10)), "rekor_log_index": json.Number(strconv.FormatInt(c.RekorLogIndex, 10)),
	}
	for k, v := range map[string]string{"source_repo": c.SourceRepo, "source_ref": c.SourceRef, "source_digest": c.SourceDigest} {
		if v != "" {
			f[k] = v
		}
	}
	if deps, _ := bd["resolvedDependencies"].([]any); len(deps) > 0 {
		if d0 := obj(deps[0]); d0 != nil {
			if uri, ok := d0["uri"].(string); ok {
				ps := map[string]any{"uri": uri}
				if g, ok := obj(d0["digest"])["gitCommit"].(string); ok {
					ps["git_commit"] = g
				}
				f["provenance_source"] = ps
			}
		}
	}
	return Result{OK: true, Facts: f}
}
