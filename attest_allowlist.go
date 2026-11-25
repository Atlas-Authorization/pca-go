package pca

// Signed allowlist manifests (attest-allowlist): the operator-signed list of acceptable measurements, image digests, driver versions
// and MAA key pins that feeds the attestation verifiers' policies. Verification is strict and fail closed with a typed code; the
// transparency-anchored check of a verified manifest is VerifyAllowlistAnchored. Manifests are the language-neutral wire maps.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"
)

// AllowlistKinds is the closed set of allowlist entry kinds.
var AllowlistKinds = []string{"tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "gcp-image-digest", "nvidia-measurement", "nvidia-driver-version",
	"maa-signing-spki", "maa-chain-root-spki", "maa-chain-intermediate-spki", "attest-corroboration"}

const (
	allowlistDomain     = "pca-attest-allowlist/v1\n"
	allowlistMaxEntries = 10_000
)

var (
	alHex96   = regexp.MustCompile(`^[0-9a-f]{96}$`)
	alHex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	alImage   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	alDriver  = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6}){1,3}$`)
	alCorrob  = regexp.MustCompile(`^vantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}$`)
	alIssuer  = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
	alBodyKey = []string{"version", "issuedAt", "notBefore", "expiresAt", "entries"}
	alEntKey  = []string{"kind", "value", "label", "notAfter", "revoked"}
	alManKey  = []string{"body", "issuer", "alg", "sig", "pq_sig"}
)

// AllowlistIssuerKey is a registered issuer: its algorithm and the verifier-configured public keys (never read from the manifest).
// PqPub is the PQ public key (base64url) of the registered suite, when it has one.
type AllowlistIssuerKey struct {
	Alg      string
	EdPub    string
	PqPub    string
	NotAfter *int64 // stop trusting the issuer key after this time (epoch ms); nil: never
}

// VerifyAllowlistOptions configure VerifyAllowlistManifest.
type VerifyAllowlistOptions struct {
	IssuerKeys map[string]AllowlistIssuerKey
	NowMs      int64
	// MinVersion is a deployment-shipped floor; LastSeenVersion/LastSeenDigest is the high-water mark the caller persisted.
	MinVersion      *int64
	LastSeenVersion *int64
	LastSeenDigest  *string
	ClockSkewMs     *float64
	// MaxLifetimeMs rejects manifests whose expiresAt - notBefore exceeds it.
	MaxLifetimeMs *float64
}

// AllowlistResult is the outcome of VerifyAllowlistManifest: OK with the clean Body, Issuer, Alg, Version and Digest, or a typed Code
// (malformed, unknown-issuer, issuer-expired, alg-mismatch, bad-signature, not-yet-valid, expired, rollback, below-min-version,
// conflict, lifetime-too-long) with a Reason.
type AllowlistResult struct {
	OK           bool
	Code, Reason string
	Body         map[string]any
	Issuer, Alg  string
	Version      int64
	Digest       string
}

func alOnlyKeys(m map[string]any, allowed []string) bool {
	for k := range m {
		if !slices.Contains(allowed, k) {
			return false
		}
	}
	return true
}

func alEpoch(v any) (int64, bool) {
	n, ok := anySafeInt(v)
	return n, ok && n >= 0
}

func alHasControl(s string) bool {
	for _, u := range utf16.Encode([]rune(s)) {
		if u <= 0x1f || u == 0x7f {
			return true
		}
	}
	return false
}

func alValueError(kind, value, label string) string {
	switch kind {
	case "tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "nvidia-measurement":
		if !alHex96.MatchString(value) {
			return kind + " must be 96 lowercase hex chars"
		}
	case "gcp-image-digest":
		if !alImage.MatchString(value) {
			return "gcp-image-digest must be sha256:<64 lowercase hex>"
		}
	case "nvidia-driver-version":
		if !alDriver.MatchString(value) || len(value) > 16 {
			return "nvidia-driver-version must be a dotted version of at most 16 chars"
		}
	case "maa-signing-spki":
		if !alHex64.MatchString(value) {
			return "maa-signing-spki must be 64 lowercase hex chars"
		}
		if !alIssuer.MatchString(label) {
			return "maa-signing-spki label must be the https issuer URL (no path, no trailing slash)"
		}
	case "maa-chain-root-spki", "maa-chain-intermediate-spki":
		if !alHex64.MatchString(value) {
			return kind + " must be 64 lowercase hex chars"
		}
	case "attest-corroboration":
		if !alHex64.MatchString(value) {
			return "attest-corroboration must be a 64 lowercase hex evidence digest"
		}
		if !alCorrob.MatchString(label) {
			return "attest-corroboration label must be vantages=<n>;method=<text>"
		}
	}
	return ""
}

// parseAllowlistBody strictly validates an untrusted body and returns a clean copy (numbers as json numbers via normObj).
func parseAllowlistBody(x any) (map[string]any, error) {
	b, ok := x.(map[string]any)
	if !ok || !alOnlyKeys(b, alBodyKey) {
		return nil, errors.New("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries")
	}
	version, vok := anySafeInt(b["version"])
	if !vok || version < 1 {
		return nil, errors.New("version must be a positive integer")
	}
	issued, ok1 := alEpoch(b["issuedAt"])
	nb, ok2 := alEpoch(b["notBefore"])
	exp, ok3 := alEpoch(b["expiresAt"])
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New("issuedAt/notBefore/expiresAt must be integer epoch ms")
	}
	if nb >= exp {
		return nil, errors.New("notBefore must be before expiresAt")
	}
	if issued > exp {
		return nil, errors.New("issuedAt must not be after expiresAt")
	}
	entries, isArr := b["entries"].([]any)
	if !isArr || len(entries) > allowlistMaxEntries {
		return nil, errors.New("entries must be an array (bounded)")
	}
	seen := map[string]bool{}
	out := make([]any, 0, len(entries))
	for i, ev := range entries {
		e, isMap := ev.(map[string]any)
		if !isMap || !alOnlyKeys(e, alEntKey) {
			return nil, fmt.Errorf("entry %d: unexpected shape", i)
		}
		kind, k1 := e["kind"].(string)
		if !k1 || !slices.Contains(AllowlistKinds, kind) {
			return nil, fmt.Errorf("entry %d: unknown kind", i)
		}
		value, v1 := e["value"].(string)
		label, l1 := e["label"].(string)
		if !v1 || !l1 {
			return nil, fmt.Errorf("entry %d: value and label must be strings", i)
		}
		if n := len(utf16.Encode([]rune(label))); n < 1 || n > 200 || alHasControl(label) {
			return nil, fmt.Errorf("entry %d: label must be 1..200 printable chars", i)
		}
		if ve := alValueError(kind, value, label); ve != "" {
			return nil, fmt.Errorf("entry %d: %s", i, ve)
		}
		clean := map[string]any{"kind": kind, "value": value, "label": label}
		if na, has := e["notAfter"]; has {
			n, ok := alEpoch(na)
			if !ok {
				return nil, fmt.Errorf("entry %d: notAfter must be integer epoch ms", i)
			}
			clean["notAfter"] = n
		}
		if rv, has := e["revoked"]; has {
			if rv != true {
				return nil, fmt.Errorf("entry %d: revoked, when present, must be true", i)
			}
			clean["revoked"] = true
		}
		dup := kind + "\x00" + value
		if kind == "maa-signing-spki" {
			dup = kind + "\x00" + label + "\x00" + value
		}
		if seen[dup] {
			return nil, fmt.Errorf("entry %d: duplicate %s value", i, kind)
		}
		seen[dup] = true
		out = append(out, clean)
	}
	return normObj(map[string]any{"version": version, "issuedAt": issued, "notBefore": nb, "expiresAt": exp, "entries": out})
}

func allowlistSignedBytes(body map[string]any) ([]byte, error) {
	cb, err := CanonicalBytes(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(allowlistDomain), cb...), nil
}

// CreateAllowlistManifest validates operator input and returns the canonical body; any violation is an error.
func CreateAllowlistManifest(input map[string]any) (map[string]any, error) {
	return parseAllowlistBody(input)
}

// SignAllowlistManifest signs a body under alg with the issuer's key material (ed for ed25519 and hybrids, pq for the PQ half).
func SignAllowlistManifest(body map[string]any, issuer, alg string, ed *KeyPair, pq *PqKeyPair) (map[string]any, error) {
	clean, err := parseAllowlistBody(body)
	if err != nil {
		return nil, err
	}
	msg, err := allowlistSignedBytes(clean)
	if err != nil {
		return nil, err
	}
	sig, pqSig, err := signWithSuite(&SuiteOpts{Alg: alg, Pq: pq}, ed, msg)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"body": clean, "issuer": issuer, "alg": alg, "sig": sig}
	if pqSig != "" {
		out["pq_sig"] = pqSig
	}
	return out, nil
}

// RevokeAllowlistEntry derives the next body that revokes kind/value (adds or flips a tombstone) at version + 1; it must be re-signed.
// label is required to name a maa-signing-spki entry. It errors when the value is not well formed for its kind.
func RevokeAllowlistEntry(prev map[string]any, kind, value, label string, issuedAt, notBefore, expiresAt int64) (map[string]any, error) {
	pb, err := parseAllowlistBody(prev)
	if err != nil {
		return nil, err
	}
	version, _ := anySafeInt(pb["version"])
	entries, _ := pb["entries"].([]any)
	next := make([]any, len(entries))
	hit := false
	for i, ev := range entries {
		e := copyMap(ev.(map[string]any))
		if !hit && e["kind"] == kind && e["value"] == value && (kind != "maa-signing-spki" || e["label"] == label) {
			e["revoked"], hit = true, true
		}
		next[i] = e
	}
	if !hit {
		l := label
		if l == "" {
			l = "revoked"
		}
		next = append(next, map[string]any{"kind": kind, "value": value, "label": l, "revoked": true})
	}
	return parseAllowlistBody(map[string]any{"version": version + 1, "issuedAt": issuedAt, "notBefore": notBefore, "expiresAt": expiresAt, "entries": next})
}

// VerifyAllowlistManifest verifies a signed manifest: shape, issuer registration and expiry, algorithm, signature under the
// registered issuer key, validity window, lifetime, version floor, and rollback against the caller's high-water mark. It never
// panics; every failure is a typed code.
func VerifyAllowlistManifest(manifest any, o VerifyAllowlistOptions) (res AllowlistResult) {
	fail := func(code, reason string) AllowlistResult { return AllowlistResult{Code: code, Reason: reason} }
	defer func() {
		if r := recover(); r != nil {
			res = fail("malformed", fmt.Sprint(r))
		}
	}()
	m, isMap := manifest.(map[string]any)
	if !isMap || !alOnlyKeys(m, alManKey) {
		return fail("malformed", "manifest has an unexpected shape")
	}
	issuer, iok := m["issuer"].(string)
	if !iok || len(issuer) == 0 || len(utf16.Encode([]rune(issuer))) > 200 {
		return fail("malformed", "issuer must be a string")
	}
	alg, aok := m["alg"].(string)
	if !aok || !isRegisteredSuite(alg) {
		return fail("malformed", "unknown signature alg")
	}
	sig, sok := m["sig"].(string)
	if !sok {
		return fail("malformed", "sig must be a string")
	}
	pqSigV, hasPqSig := m["pq_sig"]
	if _, isS := pqSigV.(string); hasPqSig && !isS {
		return fail("malformed", "pq_sig must be a string")
	}
	if strings.HasPrefix(alg, "hybrid-") != hasPqSig {
		return fail("malformed", "pq_sig presence does not match the suite")
	}
	body, err := parseAllowlistBody(m["body"])
	if err != nil {
		return fail("malformed", err.Error())
	}
	reg, known := o.IssuerKeys[issuer]
	if !known {
		return fail("unknown-issuer", fmt.Sprintf("issuer '%s' is not registered", issuer))
	}
	if reg.Alg != alg {
		return fail("alg-mismatch", fmt.Sprintf("issuer is registered for '%s', manifest claims '%s'", reg.Alg, alg))
	}
	if reg.NotAfter != nil && o.NowMs > *reg.NotAfter {
		return fail("issuer-expired", "issuer key is past its notAfter")
	}
	msg, err := allowlistSignedBytes(body)
	if err != nil {
		return fail("malformed", err.Error())
	}
	key := PinnedPqKey{}
	if su, ok := resolveSigAlg(alg, true); ok && su.needsPqPk && reg.PqPub != "" {
		key = callerVouchedPqKey(reg.PqPub) // the registered key: configured by the verifier, never read from the manifest
	}
	if !verifyLeafSuite(alg, true, reg.EdPub, key, msg, sig, pqSigV) {
		return fail("bad-signature", "signature does not verify under the registered issuer key")
	}
	for _, f := range []struct {
		v    *float64
		name string
	}{{o.ClockSkewMs, "clockSkewMs"}, {o.MaxLifetimeMs, "maxLifetimeMs"}} {
		if f.v != nil && (math.IsNaN(*f.v) || math.IsInf(*f.v, 0)) {
			return fail("malformed", f.name+" must be a finite number")
		}
	}
	skew := 0.0
	if o.ClockSkewMs != nil {
		skew = math.Max(0, *o.ClockSkewMs)
	}
	version, _ := anySafeInt(body["version"])
	nb, _ := anySafeInt(body["notBefore"])
	exp, _ := anySafeInt(body["expiresAt"])
	now := float64(o.NowMs)
	if !(now+skew >= float64(nb)) {
		return fail("not-yet-valid", "manifest is not yet valid")
	}
	if !(now-skew <= float64(exp)) {
		return fail("expired", "manifest has expired")
	}
	if o.MaxLifetimeMs != nil && float64(exp-nb) > *o.MaxLifetimeMs {
		return fail("lifetime-too-long", "manifest lifetime exceeds maxLifetimeMs")
	}
	if o.MinVersion != nil && version < *o.MinVersion {
		return fail("below-min-version", fmt.Sprintf("version %d < minVersion %d", version, *o.MinVersion))
	}
	digest, err := HashCanonical(body)
	if err != nil {
		return fail("malformed", err.Error())
	}
	if o.LastSeenVersion != nil {
		if version < *o.LastSeenVersion {
			return fail("rollback", fmt.Sprintf("version %d is older than last seen %d", version, *o.LastSeenVersion))
		}
		if version == *o.LastSeenVersion && o.LastSeenDigest != nil && *o.LastSeenDigest != digest {
			return fail("conflict", "same version as last seen but a different body")
		}
	}
	return AllowlistResult{OK: true, Body: body, Issuer: issuer, Alg: alg, Version: version, Digest: digest}
}

// AllowlistDeniedValue names one entry of a projection's revoked or expired list.
type AllowlistDeniedValue struct{ Kind, Value, Label string }

// AllowlistProjection is a verified manifest projected into plain lists shaped for the verifiers' policies.
type AllowlistProjection struct {
	TdxMrtds, TdxRtmrs, SevSnpMeasurements, ImageDigests, NvidiaMeasurements []string
	// NvidiaDriverVersions are dotted versions; NvidiaCcDriverVersions the same as hex of the ASCII text zero-padded to the 16-byte slot.
	NvidiaDriverVersions, NvidiaCcDriverVersions []string
	// MaaSigningSpkis are the approved MAA signing-key SPKI SHA-256 pins by issuer URL.
	MaaSigningSpkis                              map[string][]string
	MaaChainRootSpkis, MaaChainIntermediateSpkis []string
	Corroboration                                []AllowlistDeniedValue
	// Revoked are tombstones (to strip from other lists); Expired are entries dropped because their own notAfter passed.
	Revoked, Expired           []AllowlistDeniedValue
	Version, ManifestExpiresAt int64
}

// DriverVersionSlotHex is the zero-padded 16-byte-slot hex of a dotted driver version (as NVIDIA CC policy driver versions are).
func DriverVersionSlotHex(version string) (string, error) {
	if !alDriver.MatchString(version) || len(version) > 16 {
		return "", errors.New("invalid driver version")
	}
	return hex.EncodeToString([]byte(version)) + strings.Repeat("0", 32-2*len(version)), nil
}

// ProjectAllowlist projects a VERIFIED result (OK) at nowMs: revoked entries and entries past their own notAfter are excluded, and a
// value revoked anywhere is excluded wherever it appears. A result that is not OK projects to an error.
func ProjectAllowlist(v AllowlistResult, nowMs int64) (*AllowlistProjection, error) {
	if !v.OK {
		return nil, errors.New("projectAllowlist: the manifest was not verified")
	}
	out := &AllowlistProjection{MaaSigningSpkis: map[string][]string{}}
	out.Version, _ = anySafeInt(v.Body["version"])
	out.ManifestExpiresAt, _ = anySafeInt(v.Body["expiresAt"])
	entries, _ := v.Body["entries"].([]any)
	denied := map[string]bool{}
	for _, ev := range entries {
		e := ev.(map[string]any)
		if e["revoked"] == true {
			denied[e["kind"].(string)+"\x00"+e["value"].(string)] = true
			out.Revoked = append(out.Revoked, AllowlistDeniedValue{e["kind"].(string), e["value"].(string), e["label"].(string)})
		}
	}
	for _, ev := range entries {
		e := ev.(map[string]any)
		kind, value, label := e["kind"].(string), e["value"].(string), e["label"].(string)
		if e["revoked"] == true || denied[kind+"\x00"+value] {
			continue
		}
		if na, has := e["notAfter"]; has {
			if n, _ := anySafeInt(na); nowMs > n {
				out.Expired = append(out.Expired, AllowlistDeniedValue{kind, value, label})
				continue
			}
		}
		switch kind {
		case "tdx-mrtd":
			out.TdxMrtds = append(out.TdxMrtds, value)
		case "tdx-rtmr":
			out.TdxRtmrs = append(out.TdxRtmrs, value)
		case "sev-snp-measurement":
			out.SevSnpMeasurements = append(out.SevSnpMeasurements, value)
		case "gcp-image-digest":
			out.ImageDigests = append(out.ImageDigests, value)
		case "nvidia-measurement":
			out.NvidiaMeasurements = append(out.NvidiaMeasurements, value)
		case "nvidia-driver-version":
			slot, err := DriverVersionSlotHex(value)
			if err != nil {
				return nil, err
			}
			out.NvidiaDriverVersions = append(out.NvidiaDriverVersions, value)
			out.NvidiaCcDriverVersions = append(out.NvidiaCcDriverVersions, slot)
		case "maa-signing-spki":
			out.MaaSigningSpkis[label] = append(out.MaaSigningSpkis[label], value)
		case "maa-chain-root-spki":
			out.MaaChainRootSpkis = append(out.MaaChainRootSpkis, value)
		case "maa-chain-intermediate-spki":
			out.MaaChainIntermediateSpkis = append(out.MaaChainIntermediateSpkis, value)
		case "attest-corroboration":
			out.Corroboration = append(out.Corroboration, AllowlistDeniedValue{Value: value, Label: label})
		}
	}
	return out, nil
}

// AzureMaaPolicyFields are the lists a projection supplies to an Azure MAA policy; empty lists are nil.
func AzureMaaPolicyFields(p *AllowlistProjection) (tdxMrtds, sevSnpMeasurements, tdxRtmrs []string) {
	return slices.Clone(p.TdxMrtds), slices.Clone(p.SevSnpMeasurements), slices.Clone(p.TdxRtmrs)
}

// IntelDcapPolicyFields are the MRTD list (always present; empty makes the verifier refuse) and the RTMR list (nil when empty).
func IntelDcapPolicyFields(p *AllowlistProjection) (mrtds, rtmrs []string) {
	return append([]string{}, p.TdxMrtds...), slices.Clone(p.TdxRtmrs)
}

// SevSnpPolicyFields is the SEV-SNP policy measurement allowlist of a projection.
func SevSnpPolicyFields(p *AllowlistProjection) []string {
	return append([]string{}, p.SevSnpMeasurements...)
}

// GcpCsPolicyFields is the Confidential Space image digest allowlist of a projection.
func GcpCsPolicyFields(p *AllowlistProjection) []string { return append([]string{}, p.ImageDigests...) }

// NvidiaCcPolicyFields are the NVIDIA CC measurements and the driver-version slots (nil when there are no driver entries).
func NvidiaCcPolicyFields(p *AllowlistProjection) (measurements, driverVersions []string) {
	return append([]string{}, p.NvidiaMeasurements...), slices.Clone(p.NvidiaCcDriverVersions)
}

// JSON is the projection under the reference member names (every list present, empty when it has no entries).
func (p *AllowlistProjection) JSON() map[string]any {
	list := func(l []string) []any {
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out
	}
	denied := func(l []AllowlistDeniedValue, kind bool) []any {
		out := make([]any, len(l))
		for i, d := range l {
			m := map[string]any{"value": d.Value, "label": d.Label}
			if kind {
				m["kind"] = d.Kind
			}
			out[i] = m
		}
		return out
	}
	spkis := make(map[string]any, len(p.MaaSigningSpkis))
	for issuer, l := range p.MaaSigningSpkis {
		spkis[issuer] = list(l)
	}
	return map[string]any{"tdxMrtds": list(p.TdxMrtds), "tdxRtmrs": list(p.TdxRtmrs), "sevSnpMeasurements": list(p.SevSnpMeasurements),
		"imageDigests": list(p.ImageDigests), "nvidiaMeasurements": list(p.NvidiaMeasurements), "nvidiaDriverVersions": list(p.NvidiaDriverVersions),
		"nvidiaCcDriverVersions": list(p.NvidiaCcDriverVersions), "maaSigningSpkis": spkis, "maaChainRootSpkis": list(p.MaaChainRootSpkis),
		"maaChainIntermediateSpkis": list(p.MaaChainIntermediateSpkis), "corroboration": denied(p.Corroboration, false),
		"revoked": denied(p.Revoked, true), "expired": denied(p.Expired, true),
		"version": jsNumber(float64(p.Version)), "manifestExpiresAt": jsNumber(float64(p.ManifestExpiresAt))}
}
