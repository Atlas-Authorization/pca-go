package pca

// The post-quantum software attestation root (attest-pq-software): a software or HSM attestor signs a statement of the measured
// identity under ML-DSA, SLH-DSA or a hybrid, and a verifier appraises it as one root of the multi-root policy. It is software
// attestation (weights_measured is always false), not silicon-measured, but its signatures are post-quantum.

import (
	"errors"
	"fmt"
	"slices"
)

// PqAttestDomain separates PQ software attestation statements from every other signed surface.
const PqAttestDomain = "atlas-pca/attest-pq/v1\x00"

func pqSuiteHasPq(s sigSuite) bool {
	switch s.pq {
	case pqMlDsa65, pqMlDsa87, pqSlh128f, pqSlh256s:
		return true
	}
	return false
}

func pqStatementMessage(body map[string]any) ([]byte, error) {
	cb, err := CanonicalBytes(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(PqAttestDomain), cb...), nil
}

// PqAttestationClaims are the claims a PQ software attestor signs. Empty optional digests are omitted from the statement, except
// those named in KeepEmpty (the reference carries every claim that is not undefined, an empty string included).
type PqAttestationClaims struct {
	KeepEmpty                                             []string
	Measurement                                           string
	WeightsDigest, SystemPromptDigest, ToolManifestDigest string
	ModelID, Operator                                     string
	HolderPub, GrantRef                                   string
	Epoch                                                 float64
	Nonce                                                 string
}

// PqSoftwareAttestor signs PQ software attestation statements.
type PqSoftwareAttestor struct {
	// PqPublicKey is the base64url PQ public key (`pq_pk`) verifiers list as trusted.
	PqPublicKey string
	// Ed25519PublicKey is the classical key of a hybrid suite (empty otherwise).
	Ed25519PublicKey string
	suite            *SuiteOpts
	ed               *KeyPair
}

// CreatePqSoftwareAttestor builds an attestor for a post-quantum suite (pure or hybrid). A classical-only or unknown suite, a
// missing PQ key pair, or a hybrid without its Ed25519 key is an error.
func CreatePqSoftwareAttestor(alg string, pq *PqKeyPair, ed *KeyPair) (*PqSoftwareAttestor, error) {
	su, ok := resolveSigAlg(alg, true)
	if !ok {
		if slices.Contains(RegisteredSuites, alg) { // a registered suite this root does not take (the FN-DSA and LESS families)
			return nil, fmt.Errorf("createPqSoftwareAttestor: '%s' is classical; the PQ root requires a post-quantum suite", alg)
		}
		return nil, fmt.Errorf("createPqSoftwareAttestor: unknown signature alg '%s'", alg)
	}
	if !pqSuiteHasPq(su) {
		return nil, fmt.Errorf("createPqSoftwareAttestor: '%s' is classical; the PQ root requires a post-quantum suite", su.alg)
	}
	if pq == nil || pq.prim != su.pq {
		return nil, fmt.Errorf("createPqSoftwareAttestor: '%s' requires the matching PQ key material", su.alg)
	}
	if su.hasEd25519 && ed == nil {
		return nil, fmt.Errorf("createPqSoftwareAttestor: hybrid suite '%s' requires edSecret", su.alg)
	}
	a := &PqSoftwareAttestor{PqPublicKey: pq.Public, suite: &SuiteOpts{Alg: alg, Pq: pq}, ed: ed}
	if ed != nil {
		a.Ed25519PublicKey = ed.Public
	}
	return a, nil
}

// Attest signs a statement bound to holder, grant, epoch and nonce.
func (a *PqSoftwareAttestor) Attest(c PqAttestationClaims) (map[string]any, error) {
	binding, err := AttestationBindingB64u(ExpectedAttestationBinding{HolderPub: c.HolderPub, GrantRef: c.GrantRef, Epoch: c.Epoch, Nonce: c.Nonce})
	if err != nil {
		return nil, err
	}
	body := map[string]any{"measurement": c.Measurement, "binding": binding, "alg": a.suite.Alg, "pq_pk": a.PqPublicKey}
	if a.Ed25519PublicKey != "" {
		body["attestor_ed25519"] = a.Ed25519PublicKey
	}
	for k, v := range map[string]string{"weights_digest": c.WeightsDigest, "system_prompt_digest": c.SystemPromptDigest,
		"tool_manifest_digest": c.ToolManifestDigest, "model_id": c.ModelID, "operator": c.Operator} {
		if v != "" || slices.Contains(c.KeepEmpty, k) {
			body[k] = v
		}
	}
	n, err := normObj(body)
	if err != nil {
		return nil, err
	}
	msg, err := pqStatementMessage(n)
	if err != nil {
		return nil, err
	}
	sig, pqSig, err := signWithSuite(a.suite, a.ed, msg)
	if err != nil {
		return nil, err
	}
	n["sig"] = sig
	if pqSig != "" {
		n["pq_sig"] = pqSig
	}
	return n, nil
}

// PqSoftwarePolicy is the acceptance policy of the PQ software root. Measurements is a required non-empty allowlist.
type PqSoftwarePolicy struct {
	Measurements []string
	// WeightsMeasurements, when non-empty, also gates the statement's weights_digest.
	WeightsMeasurements []string
	// DeriveIdentity maps a statement to the measured identity (default: DefaultPqIdentity).
	DeriveIdentity func(statement map[string]any) MeasuredIdentity
}

// PqSoftwareVerifierOptions configure CreatePqSoftwareVerifier.
type PqSoftwareVerifierOptions struct {
	TrustedPqPublicKeys      []string
	TrustedEd25519PublicKeys []string
	// RequirePq nil means true: a classical-only suite is refused.
	RequirePq     *bool
	RequireHybrid bool
	// AllowedSuites, when non-nil, restricts the accepted suites.
	AllowedSuites []string
	Policy        PqSoftwarePolicy
	// ResolveEvidence finds the statement of an action; nil means none is configured (fail closed).
	ResolveEvidence func(doc, ctx map[string]any) map[string]any
}

// PqSoftwareVerifier is the PQ software root as an AttestationHardwareVerifier, labelled software / pq-software.
type PqSoftwareVerifier struct {
	o                     PqSoftwareVerifierOptions
	measurements, weights []string
	pq, ed                []string
	requirePq             bool
	derive                func(map[string]any) MeasuredIdentity
}

// DefaultPqIdentity maps a statement to the default measured identity: weights_measured is always false (software-attested).
func DefaultPqIdentity(st map[string]any) MeasuredIdentity {
	s := func(k string) string { v, _ := st[k].(string); return v }
	id := MeasuredIdentity{ModelID: s("model_id"), WeightsDigest: s("weights_digest"), RuntimeMeasurement: s("measurement"), Operator: s("operator")}
	if v, ok := st["system_prompt_digest"].(string); ok {
		id.SystemPromptDigest = &v
	}
	if v, ok := st["tool_manifest_digest"].(string); ok {
		id.ToolManifestDigest = &v
	}
	return id
}

// CreatePqSoftwareVerifier builds the verifier; it errors without a non-empty measurement allowlist or without a trusted PQ key.
func CreatePqSoftwareVerifier(o PqSoftwareVerifierOptions) (*PqSoftwareVerifier, error) {
	if len(o.Policy.Measurements) == 0 {
		return nil, errors.New("createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
	}
	if len(o.TrustedPqPublicKeys) == 0 {
		return nil, errors.New("createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)")
	}
	v := &PqSoftwareVerifier{o: o, measurements: slices.Clone(o.Policy.Measurements), weights: slices.Clone(o.Policy.WeightsMeasurements),
		pq: slices.Clone(o.TrustedPqPublicKeys), ed: slices.Clone(o.TrustedEd25519PublicKeys), requirePq: o.RequirePq == nil || *o.RequirePq, derive: o.Policy.DeriveIdentity}
	if v.derive == nil {
		v.derive = DefaultPqIdentity
	}
	return v, nil
}

// Assurance implements AssuranceLabeler.
func (v *PqSoftwareVerifier) Assurance() AssuranceLabel {
	return AssuranceLabel{Level: "software", Vendor: "pq-software"}
}

// VerifyHardware implements AttestationHardwareVerifier. It never panics.
func (v *PqSoftwareVerifier) VerifyHardware(doc, ctx map[string]any, _ int64, expected ExpectedAttestationBinding) (res HardwareResult) {
	defer func() {
		if r := recover(); r != nil {
			res = hwFail(fmt.Sprintf("pq-software verification error (fail closed): %v", r))
		}
	}()
	if v.o.ResolveEvidence == nil {
		return hwFail("no PQ-software evidence resolver configured (fail closed)")
	}
	st := v.o.ResolveEvidence(doc, ctx)
	alg, isStr := st["alg"].(string)
	if st == nil || !isStr {
		return hwFail("no PQ-software attestation statement for this action")
	}
	su, ok := resolveSigAlg(alg, true)
	if !ok {
		return hwFail(fmt.Sprintf("PQ statement declares an unknown signature alg '%s'", alg))
	}
	if v.requirePq && !pqSuiteHasPq(su) {
		return hwFail(fmt.Sprintf("PQ required: a classical-only suite '%s' is not accepted by the post-quantum root", su.alg))
	}
	if v.o.RequireHybrid && !(su.hasEd25519 && pqSuiteHasPq(su)) {
		return hwFail(fmt.Sprintf("hybrid required: suite '%s' is not a classical+PQ hybrid", su.alg))
	}
	if v.o.AllowedSuites != nil && !slices.Contains(v.o.AllowedSuites, su.alg) {
		return hwFail(fmt.Sprintf("suite '%s' is not in the allowed-suites list", su.alg))
	}
	pqPk, _ := st["pq_pk"].(string)
	if su.needsPqPk && (!isStrKey(st, "pq_pk") || !slices.Contains(v.pq, pqPk)) {
		return hwFail("PQ attestor key is not trusted")
	}
	edPk, _ := st["attestor_ed25519"].(string)
	if su.hasEd25519 && (!isStrKey(st, "attestor_ed25519") || !slices.Contains(v.ed, edPk)) {
		return hwFail("hybrid Ed25519 attestor key is not trusted")
	}
	body := make(map[string]any, len(st))
	for k, val := range st {
		if k != "sig" && k != "pq_sig" {
			body[k] = val
		}
	}
	msg, err := pqStatementMessage(body)
	if err != nil {
		return hwFail("PQ attestation signature does not verify")
	}
	key := PinnedPqKey{}
	if su.needsPqPk {
		key = callerVouchedPqKey(pqPk) // pq_pk is in the trusted set, checked above
	}
	if !verifyLeafSuite(alg, true, edPk, key, msg, st["sig"], st["pq_sig"]) {
		return hwFail("PQ attestation signature does not verify")
	}
	if expected == (ExpectedAttestationBinding{}) { // nothing supplied (the reference's missing `expected`)
		return hwFail("no expected attestation binding supplied")
	}
	want, err := AttestationBindingB64u(expected)
	if err != nil {
		return hwFail("binding not constructible: " + err.Error())
	}
	if b, ok := st["binding"].(string); !ok || b == "" {
		return hwFail("PQ statement is not bound (binding absent)")
	} else if b != want {
		return hwFail("PQ statement binding mismatch (holder/grant/epoch/nonce)")
	}
	if m, _ := st["measurement"].(string); !slices.Contains(v.measurements, m) || !isStrKey(st, "measurement") {
		return hwFail("measurement not in policy allowlist")
	}
	if len(v.weights) > 0 {
		if w, ok := st["weights_digest"].(string); !ok || !slices.Contains(v.weights, w) {
			return hwFail("measured weights digest not in policy allowlist")
		}
	}
	return HardwareResult{OK: true, Bound: true, Measured: v.derive(st).Map(), HostAsserted: map[string]string{"suite": su.alg}}
}

func isStrKey(m map[string]any, k string) bool { _, ok := m[k].(string); return ok }
