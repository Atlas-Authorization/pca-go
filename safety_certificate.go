package pca

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The safety certificate: a signed, machine-readable assertion of the risk-budget bound of a grant. Between two consecutive
// human co-signs the total risk of autonomous actions is at most B_max / kappa; the certificate states the policy parameters, that
// bound and (optionally) which checks ran with their evidence links, and a guardian signs it (Ed25519, ML-DSA-65 or both).
// VerifySafetyCertificate recomputes the bound from the certificate's own parameters and checks the signature, so a consumer
// never trusts the stated number. It is NOT a claim that the agent or the system is safe.
//
// A certificate is its decoded JSON object (map[string]any), as every signed artifact in this package: it can be tampered with
// member by member and the verifier answers for every shape.

const (
	// SafetyCertDomain separates the guardian signature from every other domain.
	SafetyCertDomain = "atlas-pca/safety-cert/v1\x00"
	// SafetyCertVersion is the certificate version.
	SafetyCertVersion = 1
	// SafetyCertScope is the only thing the arithmetic bound speaks about.
	SafetyCertScope = "risk-budget-bound"
	// MaxSafetyChecks bounds the checks list.
	MaxSafetyChecks = 64

	maxSafetyCheckID  = 64
	maxSafetyEvidence = 2048
)

// SafetyCheckEvidence links the evidence of a check: an https URL, or a 64-character lowercase hex SHA-256 of the artifact.
type SafetyCheckEvidence struct {
	Kind string `json:"kind"` // "url" or "sha256"
	Ref  string `json:"ref"`
}

// SafetyCheck is one check the guardian asserts about (the id is unique within a certificate).
type SafetyCheck struct {
	ID       string              `json:"id"`
	Status   string              `json:"status"` // "passed", "failed" or "not_run"
	Evidence SafetyCheckEvidence `json:"evidence"`
	At       int64               `json:"at"` // epoch ms the check ran (or was recorded as not run)
}

var safetySha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// safetyHTTPSPlain: a plain https URL, as `new URL` reads it: https scheme, a host, no user name and no password.
// shortcut: an approximation of the WHATWG parser on the cases that matter here (control characters stripped, forbidden host
// characters, port range); opaque forms such as "https:host" are refused, where WHATWG accepts them. Upgrade if a corpus asks.
func safetyHTTPSPlain(ref string) bool {
	ref = strings.Trim(ref, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ")
	ref = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(ref)
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" {
		return false
	}
	if u.User != nil {
		if _, hasPw := u.User.Password(); hasPw || u.User.Username() != "" {
			return false
		}
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n > 65535 {
			return false
		}
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if !strings.HasPrefix(u.Host, "[") && strings.ContainsAny(host, " #/:<>?@[\\]^|%") {
		return false
	}
	return true
}

// safetyObj is a JavaScript object view: an array is an object without these members.
func safetyObj(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case []any:
		return map[string]any{}, true
	}
	return nil, false
}

// ValidateSafetyChecks returns "" if the checks are well formed, else the first problem. checks is a decoded JSON value or a
// []SafetyCheck.
func ValidateSafetyChecks(checks any) string {
	if l, ok := checks.([]SafetyCheck); ok {
		checks = quorumWire(l)
	}
	list, ok := checks.([]any)
	if !ok {
		return "checks must be an array"
	}
	if len(list) > MaxSafetyChecks {
		return fmt.Sprintf("more than %d checks", MaxSafetyChecks)
	}
	seen := map[string]bool{}
	for _, c := range list {
		k, ok := safetyObj(c)
		if !ok {
			return "check is not an object"
		}
		id, isStr := k["id"].(string)
		if n := len(utf16Units(id)); !isStr || n == 0 || n > maxSafetyCheckID {
			return "check id must be a 1..64 char string"
		}
		if seen[id] {
			return "duplicate check id '" + id + "'"
		}
		seen[id] = true
		if s, _ := k["status"].(string); s != "passed" && s != "failed" && s != "not_run" {
			return "check '" + id + "' has an invalid status"
		}
		if !jsIsNonNeg(k["at"]) {
			return "check '" + id + "' has an invalid time"
		}
		e, ok := safetyObj(k["evidence"])
		ref, refStr := "", false
		if ok {
			ref, refStr = e["ref"].(string)
		}
		if !ok || !refStr {
			return "check '" + id + "' has no evidence link"
		}
		switch e["kind"] {
		case "sha256":
			if !safetySha256Re.MatchString(ref) {
				return "check '" + id + "' evidence digest is not 64 lowercase hex"
			}
		case "url":
			if len(utf16Units(ref)) > maxSafetyEvidence || !safetyHTTPSPlain(ref) {
				return "check '" + id + "' evidence URL must be a plain https URL"
			}
		default:
			return "check '" + id + "' has an invalid evidence kind"
		}
	}
	return ""
}

// SafetyCertificateBound is the provable bound B_max / kappa (0 if kappa <= 0).
func SafetyCertificateBound(bMax, kappa float64) float64 { return SafetyBound(bMax, kappa) }

// SafetyCertificateStatement is the canonical human-readable statement of the bound.
func SafetyCertificateStatement(bound float64) string {
	return "Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ " +
		jsNumberString(bound) + " (= B_max / κ). This is not a claim that the agent or the system is safe."
}

// SafetyCertificateMessage is the exact bytes the guardian signs: SafetyCertDomain followed by the canonical claim (the
// certificate without `sig` and `pq_sig`). A value with no stable encoding (a non-finite number) is an error.
func SafetyCertificateMessage(c map[string]any) ([]byte, error) {
	claim := withoutKeys(c, "sig", "pq_sig")
	b, ok := CanonicalBytesLenient(claim)
	if !ok {
		return nil, errors.New("canonicalize: non-finite number")
	}
	return append([]byte(SafetyCertDomain), b...), nil
}

// riskPolicyWire is the decoded `risk_policy` object of a typed policy (a decoded policy passes through).
func riskPolicyWire(p any) any {
	rp, ok := p.(RiskPolicy)
	if !ok {
		return p
	}
	n := func(f float64) any { return jsNumber(f) }
	return map[string]any{
		"weights": map[string]any{"alpha": n(rp.Weights.Alpha), "beta": n(rp.Weights.Beta), "gamma": n(rp.Weights.Gamma), "delta": n(rp.Weights.Delta), "epsilon": n(rp.Weights.Epsilon), "zeta": n(rp.Weights.Zeta)},
		"theta1":  n(rp.Theta1), "theta2": n(rp.Theta2), "kappa": n(rp.Kappa), "lambda": n(rp.Lambda), "rho": n(rp.Rho), "bMax": n(rp.BMax),
	}
}

// SafetyCertificateIssue is the input of IssueSafetyCertificate. Policy is a RiskPolicy or a decoded `risk_policy` object. Checks
// nil means no check claims (an empty non-nil list is a claim of none). IssuedAt nil is now (epoch ms). Suite nil is Ed25519; for
// ml-dsa-65 and the hybrid pass the guardian's ML-DSA key pair in Suite.Pq.
type SafetyCertificateIssue struct {
	Policy         any
	GuardianSecret *KeyPair
	GrantRef       *string
	Instance       *string
	Checks         []SafetyCheck
	IssuedAt       *float64
	Suite          *SuiteOpts
}

// IssueSafetyCertificate issues a signed safety certificate for a grant's risk policy: it validates the policy (a malformed one is
// an error), derives the bound and signs the claim with the guardian's key.
func IssueSafetyCertificate(o SafetyCertificateIssue) (map[string]any, error) {
	var checks any
	if o.Checks != nil {
		checks = quorumWire(o.Checks)
	}
	hasChecks := o.Checks != nil
	var issued any
	if o.IssuedAt != nil {
		issued = jsNumber(*o.IssuedAt)
	}
	var gr, in any
	if o.GrantRef != nil {
		gr = *o.GrantRef
	}
	if o.Instance != nil {
		in = *o.Instance
	}
	return issueSafetyCertificateValue(riskPolicyWire(o.Policy), o.GuardianSecret, gr, in, checks, hasChecks, issued, o.Suite)
}

// issueSafetyCertificateValue is IssueSafetyCertificate over decoded values; a nil grantRef, instance and issuedAt are absent, and
// checks is absent unless hasChecks (a present null is refused as not an array).
func issueSafetyCertificateValue(policy any, key *KeyPair, grantRef, instance, checks any, hasChecks bool, issuedAt any, suite *SuiteOpts) (map[string]any, error) {
	if bad := validateRiskPolicy(policy); bad != "" {
		return nil, errors.New("issueSafetyCertificate: " + bad)
	}
	alg := suite.alg()
	if _, ok := resolveSigAlg(alg, true); !ok {
		return nil, fmt.Errorf("issueSafetyCertificate: unknown signature alg '%s'", alg)
	}
	var checkRows any
	if hasChecks {
		if bad := ValidateSafetyChecks(checks); bad != "" {
			return nil, errors.New("issueSafetyCertificate: " + bad)
		}
		rows := []any{}
		for _, c := range checks.([]any) {
			m, _ := safetyObj(c)
			e, _ := safetyObj(m["evidence"])
			rows = append(rows, map[string]any{"id": m["id"], "status": m["status"], "evidence": map[string]any{"kind": e["kind"], "ref": e["ref"]}, "at": m["at"]})
		}
		checkRows = rows
	}
	p, _ := safetyObj(policy)
	if key == nil {
		return nil, errors.New("issueSafetyCertificate: a guardian key is required")
	}
	bMax, _ := jsNum(p["bMax"])
	kappa, _ := jsNum(p["kappa"])
	bound := SafetyBound(bMax, kappa)
	w, _ := safetyObj(p["weights"])
	weights := make(map[string]any, len(w))
	for k, v := range w {
		weights[k] = v
	}
	if issuedAt == nil {
		issuedAt = jsNumber(float64(time.Now().UnixMilli()))
	}
	base := map[string]any{
		"v":                        jsNumber(SafetyCertVersion),
		"statement":                SafetyCertificateStatement(bound),
		"scope":                    SafetyCertScope,
		"params":                   map[string]any{"bMax": p["bMax"], "kappa": p["kappa"], "theta1": p["theta1"], "theta2": p["theta2"], "lambda": p["lambda"], "rho": p["rho"], "weights": weights},
		"bound":                    jsNumber(bound),
		"blastRadiusPerCheckpoint": jsNumber(bound),
		"issued_at":                issuedAt,
		"guardian":                 key.Public,
	}
	if checkRows != nil {
		base["checks"] = checkRows
	}
	if grantRef != nil {
		base["grant_ref"] = grantRef
	}
	if instance != nil {
		base["instance"] = instance
	}
	pqPk, hasPq := SuitePqPublicKey(suite)
	claim, ok := bindSuiteFields(base, alg, true, pqPk, hasPq)
	if !ok {
		return nil, errors.New("issueSafetyCertificate: the suite needs a post-quantum key pair")
	}
	msg, err := SafetyCertificateMessage(claim)
	if err != nil {
		return nil, err
	}
	fields, err := SignSuiteArtifact(suite, key, msg)
	if err != nil {
		return nil, err
	}
	for k, v := range fields {
		claim[k] = v
	}
	return claim, nil
}

// SafetyVerifyOptions are the verifier's policy: a pinned guardian key, check ids that must have passed, a maximum age (which
// also refuses a certificate issued in the future; Now defaults to the clock), and the post-quantum key pins by guardian key.
// There is no option that accepts an unpinned post-quantum key: a certificate under such a suite verifies only against a pin.
type SafetyVerifyOptions struct {
	Guardian      *string
	RequireChecks []string
	MaxAgeMs      *float64
	Now           *float64
	PqPins        map[string]string
}

// SafetyCertificateVerdict is the outcome of verification. RecomputedBound is the bound recomputed from the certificate's own
// parameters, set when HasBound.
type SafetyCertificateVerdict struct {
	OK              bool
	Reason          string
	RecomputedBound float64
	HasBound        bool
}

// VerifySafetyCertificate verifies a safety certificate (its decoded JSON object). It never fails with an error; every fault is
// a reason. In order: shape and policy well-formedness, the stated bound and blastRadiusPerCheckpoint against the bound
// recomputed from the parameters, the pinned guardian key, the guardian signature, then the age and required-check policies
// (after the signature, so an unsigned certificate never learns which check was missing).
func VerifySafetyCertificate(cert any, opts SafetyVerifyOptions) SafetyCertificateVerdict {
	refuse := func(r string) SafetyCertificateVerdict { return SafetyCertificateVerdict{Reason: r} }
	m, ok := cert.(map[string]any)
	if !ok || !jsStrictEq(m["v"], jsNumber(SafetyCertVersion)) {
		return refuse("malformed certificate")
	}
	sig, okSig := m["sig"].(string)
	guardian, okG := m["guardian"].(string)
	if !okSig || !okG {
		return refuse("missing guardian/signature")
	}
	if m["scope"] != SafetyCertScope {
		return refuse("unknown scope")
	}
	if c, has := m["checks"]; has {
		if bad := ValidateSafetyChecks(c); bad != "" {
			return refuse("invalid checks: " + bad)
		}
	}
	params, ok := m["params"].(map[string]any)
	if !ok {
		params = map[string]any{}
	}
	if bad := validateRiskPolicy(params); bad != "" {
		return refuse("invalid parameters: " + bad)
	}
	bMax, _ := jsNum(params["bMax"])
	kappa, _ := jsNum(params["kappa"])
	recomputed := SafetyBound(bMax, kappa)
	fail := func(r string) SafetyCertificateVerdict {
		return SafetyCertificateVerdict{Reason: r, RecomputedBound: recomputed, HasBound: true}
	}
	if b, isNum := jsNum(m["bound"]); !isNum || math.IsNaN(b) || math.IsInf(b, 0) || b != recomputed {
		return fail("stated bound does not equal B_max/κ recomputed from the parameters")
	}
	if b, isNum := jsNum(m["blastRadiusPerCheckpoint"]); !isNum || b != recomputed {
		return fail("blastRadiusPerCheckpoint does not equal the recomputed bound")
	}
	if opts.Guardian != nil && *opts.Guardian != guardian {
		return fail("guardian key is not the pinned key")
	}
	alg, algPresent := m["alg"]
	if _, ok := resolveSigAlg(alg, algPresent); !ok {
		return fail("unknown signature alg")
	}
	msg, err := SafetyCertificateMessage(m)
	if err != nil {
		return refuse("malformed certificate: " + err.Error())
	}
	if !verifyPinnedSuite(alg, algPresent, guardian, m["pq_pk"], msg, sig, m["pq_sig"], opts.PqPins) {
		return fail("guardian signature does not verify")
	}
	if opts.MaxAgeMs != nil {
		now := float64(time.Now().UnixMilli())
		if opts.Now != nil {
			now = *opts.Now
		}
		issued, isNum := jsNum(m["issued_at"])
		if math.IsNaN(*opts.MaxAgeMs) || math.IsInf(*opts.MaxAgeMs, 0) || math.IsNaN(now) || math.IsInf(now, 0) || !isNum || math.IsNaN(issued) || math.IsInf(issued, 0) {
			return fail("invalid age policy or issue time")
		}
		if issued > now {
			return fail("certificate is issued in the future")
		}
		if now-issued > *opts.MaxAgeMs {
			return fail("certificate is older than maxAgeMs")
		}
	}
	checks, _ := m["checks"].([]any)
	for _, id := range opts.RequireChecks {
		var found map[string]any
		for _, c := range checks {
			if k, _ := safetyObj(c); k["id"] == id {
				found = k
				break
			}
		}
		if found == nil {
			return fail("required check '" + id + "' is not present")
		}
		if st, _ := found["status"].(string); st != "passed" {
			return fail("required check '" + id + "' is " + st)
		}
	}
	return SafetyCertificateVerdict{OK: true, RecomputedBound: recomputed, HasBound: true}
}

// EncodeSafetyCertificate is the canonical JSON text of a certificate (the lenient server-side form, not a signing form).
func EncodeSafetyCertificate(cert any) (string, error) {
	s, ok := CanonicalizeLenientServerOnly(cert)
	if !ok {
		return "", errors.New("canonicalize: non-finite number")
	}
	return s, nil
}

// DecodeSafetyCertificate parses a certificate from its JSON text, shape-guarded and bounded at MaxJSONBytes; nil for garbage.
// The result is not verified.
func DecodeSafetyCertificate(s string) map[string]any {
	if len(s) > MaxJSONBytes {
		return nil
	}
	x, err := ParseJSONLenient([]byte(s))
	if err != nil {
		return nil
	}
	m, ok := x.(map[string]any)
	if !ok || !jsStrictEq(m["v"], jsNumber(SafetyCertVersion)) {
		return nil
	}
	if _, ok := m["sig"].(string); !ok {
		return nil
	}
	if _, ok := m["guardian"].(string); !ok {
		return nil
	}
	switch m["params"].(type) {
	case map[string]any, []any:
		return m
	}
	return nil
}

// SafetyCertificateForCompliance verifies the certificate and, only if it verifies, returns the compliance-export row (which checks
// ran and where the evidence is; not a safety claim); nil otherwise.
func SafetyCertificateForCompliance(cert any, opts SafetyVerifyOptions) map[string]any {
	if !VerifySafetyCertificate(cert, opts).OK {
		return nil
	}
	m := cert.(map[string]any)
	rows := []any{}
	list, _ := m["checks"].([]any)
	for _, c := range list {
		k, _ := safetyObj(c)
		e, _ := safetyObj(k["evidence"])
		ev, _ := e["ref"].(string)
		if e["kind"] == "sha256" {
			ev = "sha256:" + ev
		}
		rows = append(rows, map[string]any{"id": k["id"], "status": k["status"], "evidence": ev})
	}
	return map[string]any{"control": SafetyCertScope, "guardian": m["guardian"], "issued_at": m["issued_at"], "bound": m["bound"], "checks": rows}
}
