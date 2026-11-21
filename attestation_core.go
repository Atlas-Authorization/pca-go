package pca

// The attestation core of the reference (attestation.ts): the binding value, software-mode documents and the dev attestor, the
// measured identity and agent-binding match, the single-use nonce store and its entropy gate, the document registry, the
// verifier and its hook, the multi-root N-of-M verifier and the accountability anchor. Documents, contexts and bindings are the
// language-neutral maps of the wire (a context carries "pcactn" and "grant"). Every failure is closed, with the reference's reason.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// MaxAttestationAgeMs is the ceiling (5 minutes) on the age of a server-issued attestation nonce.
	MaxAttestationAgeMs = 5 * 60_000
	// DefaultNonceRetentionMs is how long (1 hour) MemoryNonceStore remembers a consumed nonce: 12x the quote-age ceiling.
	DefaultNonceRetentionMs = int64(60 * 60 * 1000)
	// MinAttestationNonceBytes is the minimum entropy (128 bits) of a server-issued attestation nonce.
	MinAttestationNonceBytes = 16
	// AttestAnchorDomain separates the anchored attestation-evidence digest.
	AttestAnchorDomain = "atlas-pca/attest-anchor/v1\x00"

	attestDocDomain = "atlas-pca/attest/v1\x00"
)

// ExpectedAttestationBinding is the server-side binding a quote's report_data must equal. NonceIssuedAt (epoch ms) is when the
// server issued the nonce; nil means unknown (hardware mode then fails closed).
type ExpectedAttestationBinding struct {
	HolderPub, GrantRef string
	Epoch               float64
	Nonce               string
	NonceIssuedAt       *float64
}

func (e ExpectedAttestationBinding) plain() AttestationBinding {
	return AttestationBinding{HolderPub: e.HolderPub, GrantRef: e.GrantRef, Epoch: e.Epoch, Nonce: e.Nonce}
}

// AttestationBindingBytes is the 64-byte report_data value SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)).
// It errors on an empty field or an epoch that is not a non-negative safe integer.
func AttestationBindingBytes(e ExpectedAttestationBinding) ([]byte, error) {
	return attestationBindingBytes(e.plain())
}

// AttestationBindingB64u is AttestationBindingBytes as base64url (what software-mode documents carry in `binding`).
func AttestationBindingB64u(e ExpectedAttestationBinding) (string, error) {
	b, err := attestationBindingBytes(e.plain())
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// AttestationDigest is base64url(sha256(canonical(document))): a content address of a full signed quote.
func AttestationDigest(doc map[string]any) (string, error) {
	n, err := normObj(doc)
	if err != nil {
		return "", err
	}
	return HashCanonical(n)
}

// MeasuredIdentity is the identity a verifier establishes for a document. WeightsMeasured is true only when the weights digest was
// hardware-measured; the two optional digests are nil when not measured.
type MeasuredIdentity struct {
	ModelID, WeightsDigest                 string
	WeightsMeasured                        bool
	RuntimeMeasurement, Operator           string
	SystemPromptDigest, ToolManifestDigest *string
	// unset marks the string members the wire form did not carry (the reference spells those `undefined` in its reasons).
	unset uint8
}

const (
	unsetModelID uint8 = 1 << iota
	unsetRuntime
	unsetOperator
)

// shown is the text of a member in a reason: the reference prints an absent member as `undefined`.
func (id MeasuredIdentity) shown(bit uint8, v string) string {
	if id.unset&bit != 0 {
		return "undefined"
	}
	return v
}

// MeasuredIdentityFromMap reads the wire form (model_id, weights_digest, weights_measured, runtime_measurement, operator and the
// optional system_prompt_digest and tool_manifest_digest).
func MeasuredIdentityFromMap(m map[string]any) MeasuredIdentity {
	s := func(k string) string { v, _ := m[k].(string); return v }
	opt := func(k string) *string {
		if v, ok := m[k].(string); ok {
			return &v
		}
		return nil
	}
	id := MeasuredIdentity{ModelID: s("model_id"), WeightsDigest: s("weights_digest"), WeightsMeasured: m["weights_measured"] == true,
		RuntimeMeasurement: s("runtime_measurement"), Operator: s("operator"), SystemPromptDigest: opt("system_prompt_digest"), ToolManifestDigest: opt("tool_manifest_digest")}
	for k, bit := range map[string]uint8{"model_id": unsetModelID, "runtime_measurement": unsetRuntime, "operator": unsetOperator} {
		if _, ok := m[k].(string); !ok {
			id.unset |= bit
		}
	}
	return id
}

// Map is the wire form of the identity.
func (id MeasuredIdentity) Map() map[string]any {
	m := map[string]any{"model_id": id.ModelID, "weights_digest": id.WeightsDigest, "weights_measured": id.WeightsMeasured,
		"runtime_measurement": id.RuntimeMeasurement, "operator": id.Operator}
	if id.SystemPromptDigest != nil {
		m["system_prompt_digest"] = *id.SystemPromptDigest
	}
	if id.ToolManifestDigest != nil {
		m["tool_manifest_digest"] = *id.ToolManifestDigest
	}
	return m
}

// AttestationClaims are the claims a caller supplies to mint a software-mode document. A document is bound (`binding`) to
// holder, grant and epoch plus the nonce only when HolderPub, GrantRef and Epoch are all set.
type AttestationClaims struct {
	ModelID, WeightsDigest, RuntimeMeasurement, Operator string
	SystemPromptDigest, ToolManifestDigest               *string
	Nonce                                                string
	IssuedAt, ExpiresAt                                  int64
	HolderPub, GrantRef                                  *string
	Epoch                                                *int64
}

// DevAttestor signs software-mode attestation documents for dev and CI: a self-asserted identity, not a hardware root.
type DevAttestor struct {
	// PublicKey is the base64url key a verifier lists in TrustedAttestorKeys.
	PublicKey string
	key       *KeyPair
	suite     *SuiteOpts
}

// CreateDevAttestor builds an attestor over a 32-byte Ed25519 seed and an optional signature suite (nil: ed25519). An unknown suite
// is an error.
func CreateDevAttestor(seed []byte, suite *SuiteOpts) (*DevAttestor, error) {
	kp, err := KeyPairFromSeedB64u(b64.EncodeToString(seed))
	if err != nil {
		return nil, err
	}
	if _, ok := resolveSigAlg(suite.alg(), true); !ok {
		return nil, fmt.Errorf("createDevAttestor: unknown signature alg '%s'", suite.alg())
	}
	return &DevAttestor{PublicKey: kp.Public, key: kp, suite: suite}, nil
}

// Attest signs a software-mode document over the claims; the suite and the attestor's PQ key are signed into the body.
func (a *DevAttestor) Attest(c AttestationClaims) (map[string]any, error) {
	body := map[string]any{"model_id": c.ModelID, "weights_digest": c.WeightsDigest, "runtime_measurement": c.RuntimeMeasurement,
		"operator": c.Operator, "nonce": c.Nonce, "issued_at": c.IssuedAt, "expires_at": c.ExpiresAt, "attestor": a.PublicKey, "mode": "software"}
	// additive: the optional digests are carried only when supplied, so a document without them signs as it always did
	if c.SystemPromptDigest != nil {
		body["system_prompt_digest"] = *c.SystemPromptDigest
	}
	if c.ToolManifestDigest != nil {
		body["tool_manifest_digest"] = *c.ToolManifestDigest
	}
	if c.HolderPub != nil && c.GrantRef != nil && c.Epoch != nil {
		bind, err := AttestationBindingB64u(ExpectedAttestationBinding{HolderPub: *c.HolderPub, GrantRef: *c.GrantRef, Epoch: float64(*c.Epoch), Nonce: c.Nonce})
		if err != nil {
			return nil, err
		}
		body["binding"] = bind
	}
	return a.signBody(body)
}

// signBody signs a ready document body (what Attest builds) under the attestor's key and suite.
func (a *DevAttestor) signBody(body map[string]any) (map[string]any, error) {
	return SignArtifact(attestDocDomain, body, a.key, a.suite)
}

func attNowMs() int64 { return time.Now().UnixMilli() }

// ---- agent-binding match --------------------------------------------------------------------------------------------

func bindList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	}
	return nil
}

func listHas(l []any, s string) bool {
	for _, x := range l {
		if v, ok := x.(string); ok && v == s {
			return true
		}
	}
	return false
}

// MatchAgentBinding matches an established identity against a grant's agent_binding and returns the reason of the first failure, or
// "" on a match. A pinned digest the identity does not carry fails closed; a malformed min_measurement fails closed.
func MatchAgentBinding(id MeasuredIdentity, binding map[string]any) string {
	if l := bindList(binding["model_allowlist"]); len(l) > 0 && !listHas(l, id.ModelID) {
		return fmt.Sprintf("model_id %s not in model_allowlist", id.shown(unsetModelID, id.ModelID))
	}
	if mm, present := binding["min_measurement"]; present && mm != "" {
		if s, isStr := mm.(string); isStr {
			if id.RuntimeMeasurement != s {
				return "runtime_measurement does not match required min_measurement"
			}
		} else if bound, ok := svnBoundOf(mm); !ok {
			return "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)"
		} else if got, ok := canonicalSvn(id.RuntimeMeasurement); !ok {
			return fmt.Sprintf("runtime_measurement %s is not an integer SVN (required min svn %d)", id.shown(unsetRuntime, id.RuntimeMeasurement), bound)
		} else if got < bound {
			return fmt.Sprintf("runtime_measurement svn %d is below required min svn %d", got, bound)
		}
	}
	if op, _ := binding["operator"].(string); op != "" && id.Operator != op {
		return fmt.Sprintf("operator %s is not the bound operator", id.shown(unsetOperator, id.Operator))
	}
	if binding["require_measured_weights"] == true && !id.WeightsMeasured {
		return "weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)"
	}
	if l := bindList(binding["weights_allowlist"]); len(l) > 0 && !listHas(l, id.WeightsDigest) {
		return "weights_digest not in weights_allowlist (model swap / fine-tune?)"
	}
	if l := bindList(binding["system_prompt_allowlist"]); len(l) > 0 && (id.SystemPromptDigest == nil || !listHas(l, *id.SystemPromptDigest)) {
		return "system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)"
	}
	if l := bindList(binding["tool_manifest_allowlist"]); len(l) > 0 && (id.ToolManifestDigest == nil || !listHas(l, *id.ToolManifestDigest)) {
		return "tool_manifest_digest not in tool_manifest_allowlist (tools changed?)"
	}
	return ""
}

// NonceBinds reports whether the document's nonce is the one the PCActn declares in attestation.quote_digest.
func NonceBinds(doc, ctx map[string]any) bool {
	n, ok := doc["nonce"].(string)
	q, qok := ctxMap(ctxMap(ctx, "pcactn"), "attestation")["quote_digest"].(string)
	return ok && qok && n == q
}

func ctxMap(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }

// AttestationRegistry resolves the document whose nonce equals the PCActn's attestation.quote_digest (later duplicates overwrite).
func AttestationRegistry(docs []map[string]any) func(ctx map[string]any) map[string]any {
	by := map[string]map[string]any{}
	for _, d := range docs {
		if n, ok := d["nonce"].(string); ok {
			by[n] = d
		}
	}
	return func(ctx map[string]any) map[string]any {
		if q, ok := ctxMap(ctxMap(ctx, "pcactn"), "attestation")["quote_digest"].(string); ok {
			return by[q]
		}
		return nil
	}
}

// ---- nonce store and entropy gate -------------------------------------------------------------------------------------

// AttestationNonceStore is a single-use store of server-issued nonces. Consume MUST be atomic: true for the first call with a
// nonce, false for every later one (a replay).
type AttestationNonceStore interface{ Consume(nonce string) bool }

// MemoryNonceStoreOptions configure MemoryNonceStore. RetentionMs defaults to DefaultNonceRetentionMs (it must exceed the longest
// time a quote can still pass the nonce-age check); Now defaults to the wall clock.
type MemoryNonceStoreOptions struct {
	RetentionMs int64
	Now         func() int64
}

// MemoryNonceStore is the in-memory single-process AttestationNonceStore. A consumed nonce is never re-accepted inside its
// retention window; when the store is full of retained nonces it refuses new ones (fail closed) instead of evicting a live one.
type MemoryNonceStore struct {
	mu        sync.Mutex
	max       int
	retention int64
	now       func() int64
	seen      map[string]int64
	order     []string // insertion order == time order
}

// NewMemoryNonceStore builds the store; max must be at least 1 and RetentionMs not negative.
func NewMemoryNonceStore(max int, o MemoryNonceStoreOptions) (*MemoryNonceStore, error) {
	if max < 1 {
		return nil, errors.New("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)")
	}
	if o.RetentionMs < 0 {
		return nil, errors.New("memoryNonceStore: retentionMs must be a positive integer (ms)")
	}
	if o.RetentionMs == 0 {
		o.RetentionMs = DefaultNonceRetentionMs
	}
	if o.Now == nil {
		o.Now = func() int64 { return attNowMs() }
	}
	return &MemoryNonceStore{max: max, retention: o.RetentionMs, now: o.Now, seen: map[string]int64{}}, nil
}

func (s *MemoryNonceStore) drop(k string) {
	delete(s.seen, k)
	for i, o := range s.order {
		if o == k {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// Consume implements AttestationNonceStore.
func (s *MemoryNonceStore) Consume(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.now()
	if at, ok := s.seen[nonce]; ok {
		if t-at < s.retention {
			return false // retained: a replay
		}
		s.drop(nonce) // aged out of retention: new again (the freshness check refuses such a quote anyway)
	}
	if len(s.seen) >= s.max {
		for len(s.order) > 0 && t-s.seen[s.order[0]] >= s.retention { // make room only from entries that aged out
			delete(s.seen, s.order[0])
			s.order = s.order[1:]
		}
		if len(s.seen) >= s.max {
			return false // full of live nonces
		}
	}
	s.seen[nonce] = t
	s.order = append(s.order, nonce)
	return true
}

var (
	nonceHexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	nonceB64Re = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// NonceEntropyOk reports whether the nonce plausibly carries at least minBytes (never below 16) bytes of entropy: hex or base64url
// of that length with at least 8 distinct characters. A syntactic floor only: the server must still draw nonces from a CSPRNG.
func NonceEntropyOk(nonce any, minBytes int) bool {
	s, ok := nonce.(string)
	if !ok {
		return false
	}
	need := max(minBytes, MinAttestationNonceBytes)
	hex, b64ok := nonceHexRe.MatchString(s), nonceB64Re.MatchString(s)
	if !hex && !b64ok {
		return false
	}
	bytes := float64(len(s) * 3 / 4)
	if hex {
		bytes = float64(len(s)) / 2
	}
	if bytes < float64(need) {
		return false
	}
	distinct := map[rune]bool{}
	for _, r := range s {
		distinct[r] = true
	}
	return len(distinct) >= 8
}

// ---- verification -------------------------------------------------------------------------------------------------------

// AttestationHardwareVerifier verifies hardware evidence for a document: it must root the evidence in the vendor chain, check the
// measurement registers and confirm the quote's bound value equals AttestationBinding(expected).
type AttestationHardwareVerifier interface {
	VerifyHardware(doc, ctx map[string]any, nowMs int64, expected ExpectedAttestationBinding) HardwareResult
}

// AttestationHardwareFunc adapts a function to AttestationHardwareVerifier.
type AttestationHardwareFunc func(doc, ctx map[string]any, nowMs int64, expected ExpectedAttestationBinding) HardwareResult

// VerifyHardware implements AttestationHardwareVerifier.
func (f AttestationHardwareFunc) VerifyHardware(doc, ctx map[string]any, nowMs int64, expected ExpectedAttestationBinding) HardwareResult {
	return f(doc, ctx, nowMs, expected)
}

// AttestationVerdict is the outcome of VerifyAttestation: Present means a document was supplied; Bound that it was authenticated and
// its quote is bound to holder, grant, epoch and nonce. Identity is set on success.
type AttestationVerdict struct {
	OK, Present, Bound bool
	Reason             string
	Identity           *MeasuredIdentity
}

// VerifyAttestationInput are the inputs of VerifyAttestation.
type VerifyAttestationInput struct {
	Document            map[string]any // nil: none
	Ctx                 map[string]any // "pcactn" and "grant"
	Expected            ExpectedAttestationBinding
	NowMs               float64
	TrustedAttestorKeys []string
	// PqPins maps an attestor key to its pinned PQ key (required for a pure-PQ or hybrid document).
	PqPins           map[string]string
	HardwareVerifier AttestationHardwareVerifier
	MaxNonceAgeMs    *float64
	ClockSkewMs      *float64
}

func nonceAgeReason(issued *float64, now, skew, maxAge float64) string {
	if issued == nil || !finite(*issued) {
		return "server nonce issue time unknown (cannot establish freshness)"
	}
	if now+skew < *issued {
		return "nonce issued in the future"
	}
	if now-*issued > maxAge+skew {
		return "attestation nonce expired (stale quote)"
	}
	return ""
}

// VerifyAttestation verifies a document against the server-supplied expected binding, in the reference's order, and returns the first
// failure: the document is present; the binding is constructible; the PCActn's grant_ref, attestation epoch and quote_digest match
// the expectation; the document nonce is the server nonce; hardware requirements; then, with a hardware verifier, nonce freshness and
// the verifier's ok, bound and measured identity, or, in software mode, the mode, the trusted attestor, the suite, the signature, the
// binding and the validity window (plus nonce age when known); finally the agent_binding match on the established identity.
// It never panics; any error is a closed verdict.
func VerifyAttestation(in VerifyAttestationInput) (v AttestationVerdict) {
	doc := in.Document
	present := doc != nil
	fail := func(r string) AttestationVerdict { return AttestationVerdict{Present: present, Reason: r} }
	defer func() {
		if r := recover(); r != nil {
			v = fail(fmt.Sprintf("attestation verification error (fail closed): %v", r))
		}
	}()
	now, exp := in.NowMs, in.Expected
	if !finite(now) {
		return fail("verifier clock is not a finite time (fail closed)")
	}
	skew := 0.0
	if in.ClockSkewMs != nil && finite(*in.ClockSkewMs) {
		skew = math.Max(0, *in.ClockSkewMs)
	}
	maxAge := float64(MaxAttestationAgeMs)
	if in.MaxNonceAgeMs != nil && finite(*in.MaxNonceAgeMs) && *in.MaxNonceAgeMs > 0 {
		maxAge = math.Min(*in.MaxNonceAgeMs, maxAge)
	}
	ctx := in.Ctx
	pc := ctxMap(ctx, "pcactn")
	att := ctxMap(pc, "attestation")
	ab := map[string]any(nil)
	if env := ReadEnvelope(ctx["grant"]); env != nil {
		ab, _ = env["agent_binding"].(map[string]any)
	}
	hasHw := in.HardwareVerifier != nil
	requireHw := ab["require_hardware"] == true

	if !present {
		return fail("no attestation document for this action")
	}
	wantBinding, err := AttestationBindingB64u(exp)
	if err != nil {
		return fail("attestation binding not constructible: " + err.Error())
	}
	if g, _ := pc["grant_ref"].(string); g != exp.GrantRef || pc["grant_ref"] == nil {
		return fail("attestation binding: PCActn grant_ref differs from expected grant")
	}
	if ep, ok := jsNum(att["epoch"]); !ok || ep != exp.Epoch {
		return fail("attestation binding: PCActn attestation epoch differs from expected epoch")
	}
	if q, ok := att["quote_digest"].(string); !ok || q != exp.Nonce {
		return fail("attestation nonce does not bind to this PCActn")
	}
	if n, ok := doc["nonce"].(string); !ok || n != exp.Nonce {
		return fail("attestation nonce does not match the server-issued nonce")
	}
	if requireHw && !hasHw {
		return fail("agent_binding.require_hardware: no hardware verifier is configured (fail closed)")
	}
	if requireHw && doc["mode"] != "hardware" {
		return fail("agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)")
	}
	var id MeasuredIdentity
	if hasHw {
		if r := nonceAgeReason(exp.NonceIssuedAt, now, skew, maxAge); r != "" {
			return fail(r)
		}
		hw := in.HardwareVerifier.VerifyHardware(doc, ctx, int64(now), exp)
		if !hw.OK {
			why := hw.Reason
			if why == "" {
				why = "invalid"
			}
			return fail("hardware attestation rejected: " + why)
		}
		if !hw.Bound {
			return fail("hardware verifier did not confirm report_data binding")
		}
		if hw.Measured == nil {
			return fail("hardware verifier returned no measured identity")
		}
		id = MeasuredIdentityFromMap(hw.Measured)
	} else {
		if doc["mode"] != "software" {
			return fail(fmt.Sprintf("document mode %v needs a hardwareVerifier", orUndefined(doc["mode"])))
		}
		attestor, _ := doc["attestor"].(string)
		if !listHasStr(in.TrustedAttestorKeys, attestor) || doc["attestor"] == nil {
			return fail("attestor key is not trusted")
		}
		alg, algPresent := doc["alg"]
		if _, ok := resolveSigAlg(alg, algPresent); !ok {
			return fail("attestation declares an unknown signature alg")
		}
		body := make(map[string]any, len(doc))
		for k, val := range doc {
			if k != "sig" && k != "pq_sig" {
				body[k] = val
			}
		}
		cb, cerr := CanonicalBytes(body)
		if cerr != nil { // the reference canonicalizes before it verifies: a refusal there is the fail-closed error, not a bad signature
			return fail("attestation verification error (fail closed): " + cerr.Error())
		}
		_, sigIsStr := doc["sig"].(string)
		if !sigIsStr || !verifyPinnedSuite(alg, algPresent, attestor, doc["pq_pk"], append([]byte(attestDocDomain), cb...), doc["sig"], doc["pq_sig"], in.PqPins) {
			return fail("attestation signature does not verify")
		}
		if b, ok := doc["binding"].(string); !ok || b == "" {
			return fail("attestation is not bound (binding absent)")
		} else if b != wantBinding {
			return fail("attestation binding mismatch (holder/grant/epoch/nonce)")
		}
		iat, ok1 := jsNum(doc["issued_at"])
		end, ok2 := jsNum(doc["expires_at"])
		switch {
		case !ok1 || !ok2 || !finite(iat) || !finite(end) || end < iat:
			return fail("malformed attestation validity window")
		case now+skew < iat:
			return fail("attestation not yet valid")
		case now-skew > end:
			return fail("attestation expired")
		}
		if exp.NonceIssuedAt != nil {
			if r := nonceAgeReason(exp.NonceIssuedAt, now, skew, maxAge); r != "" {
				return fail(r)
			}
		}
		id = MeasuredIdentityFromMap(doc)
	}
	if r := MatchAgentBinding(id, ab); r != "" {
		return fail(r)
	}
	return AttestationVerdict{OK: true, Present: true, Bound: true, Identity: &id}
}

func orUndefined(v any) any {
	if v == nil {
		return "undefined"
	}
	return v
}

func listHasStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// AttestationHookResult is the verdict of the attestation hook: always enforced; Present and Bound let a server fail closed when
// agent_binding is non-empty.
type AttestationHookResult struct {
	Enforced, OK, Present, Bound bool
	Reason                       string
}

// AttestationVerifierOpts configure CreateAttestationVerifier.
type AttestationVerifierOpts struct {
	// NonceStore, when set, consumes the nonce once, only after the attestation verified and bound (a replay is refused). Without it the
	// integrator's ExpectedBinding must consume the nonce itself.
	NonceStore AttestationNonceStore
	// MinNonceBytes is the minimum nonce entropy (default and floor 16). Not applied under InsecureSelfDeclaredNonce.
	MinNonceBytes int
	// TrustedAttestorKeys are the base64url keys trusted to sign software-mode documents.
	TrustedAttestorKeys []string
	PqPins              map[string]string
	// HardwareVerifier, when set, is hardware mode: authenticity is delegated to it instead of the signature.
	HardwareVerifier AttestationHardwareVerifier
	// ResolveDocument finds the document of an action (default: none).
	ResolveDocument func(ctx map[string]any) map[string]any
	// ExpectedBinding supplies the server-issued binding of an action; nil result fails closed.
	ExpectedBinding func(ctx map[string]any) *ExpectedAttestationBinding
	// InsecureSelfDeclaredNonce derives the binding from the PCActn itself (legacy and dev only: replay protection is void).
	InsecureSelfDeclaredNonce  bool
	MaxNonceAgeMs, ClockSkewMs *float64
	// Now is the clock in epoch ms (default the wall clock).
	Now func() int64
}

// AttestationVerifier is the attestation hook built by CreateAttestationVerifier.
type AttestationVerifier struct {
	o     AttestationVerifierOpts
	label AssuranceLabel
}

// CreateAttestationVerifier builds the hook. Its assurance label comes from the configuration, never from the document: software mode
// is "software"; hardware mode is what the hardware verifier declares (unlabelled: unknown); the self-declared-nonce opt-out is unknown.
func CreateAttestationVerifier(o AttestationVerifierOpts) *AttestationVerifier {
	o.TrustedAttestorKeys = append([]string(nil), o.TrustedAttestorKeys...)
	l := AssuranceLabel{Level: "software"}
	switch {
	case o.InsecureSelfDeclaredNonce:
		l = AssuranceLabel{Level: "unknown", Vendor: "insecure-self-declared-nonce"}
	case o.HardwareVerifier != nil:
		if l = labelOf(o.HardwareVerifier); l.Level == "" {
			l = AssuranceLabel{Level: "unknown"}
		}
	}
	return &AttestationVerifier{o: o, label: l}
}

// Assurance implements AssuranceLabeler.
func (v *AttestationVerifier) Assurance() AssuranceLabel { return v.label }

// Verify runs the hook for one action context. It never panics.
func (v *AttestationVerifier) Verify(ctx map[string]any) (res AttestationHookResult) {
	fin := func(a AttestationVerdict) AttestationHookResult {
		return AttestationHookResult{Enforced: true, OK: a.OK, Present: a.Present, Bound: a.Bound, Reason: a.Reason}
	}
	defer func() {
		if r := recover(); r != nil {
			res = fin(AttestationVerdict{Reason: fmt.Sprintf("attestation verification error (fail closed): %v", r)})
		}
	}()
	o := v.o
	var doc map[string]any
	if o.ResolveDocument != nil {
		doc = o.ResolveDocument(ctx)
	}
	var exp *ExpectedAttestationBinding
	if o.ExpectedBinding != nil {
		exp = o.ExpectedBinding(ctx)
	} else if o.InsecureSelfDeclaredNonce {
		pc := ctxMap(ctx, "pcactn")
		att := ctxMap(pc, "attestation")
		leaf := ctxMap(ctx, "grant")
		if chain, ok := pc["cap_chain"].([]any); ok && len(chain) > 0 {
			leaf, _ = chain[len(chain)-1].(map[string]any)
		}
		e := ExpectedAttestationBinding{Epoch: math.NaN()}
		e.HolderPub, _ = leaf["holder"].(string)
		e.GrantRef, _ = pc["grant_ref"].(string)
		e.Nonce, _ = att["quote_digest"].(string)
		if ep, ok := jsNum(att["epoch"]); ok {
			e.Epoch = ep
		}
		exp = &e
	}
	if exp == nil {
		return fin(AttestationVerdict{Present: doc != nil, Reason: "no server-issued attestation nonce/binding available (fail closed)"})
	}
	if !o.InsecureSelfDeclaredNonce && !NonceEntropyOk(exp.Nonce, o.MinNonceBytes) {
		return fin(AttestationVerdict{Present: doc != nil, Reason: "attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)"})
	}
	now := o.Now
	if now == nil {
		now = attNowMs
	}
	vd := VerifyAttestation(VerifyAttestationInput{Document: doc, Ctx: ctx, Expected: *exp, NowMs: float64(now()), TrustedAttestorKeys: o.TrustedAttestorKeys,
		PqPins: o.PqPins, HardwareVerifier: o.HardwareVerifier, MaxNonceAgeMs: o.MaxNonceAgeMs, ClockSkewMs: o.ClockSkewMs})
	if vd.OK && vd.Bound && o.NonceStore != nil && !o.NonceStore.Consume(exp.Nonce) {
		return fin(AttestationVerdict{Present: vd.Present, Reason: "attestation nonce already consumed (replay)"})
	}
	return fin(vd)
}

// ---- multi-root N-of-M ----------------------------------------------------------------------------------------------------

// MultiRootAttestationRoot is one independent attestation root of a multi-root policy: a stable ID, its verifier, whether it MUST
// verify, and an audit-only Suite label.
type MultiRootAttestationRoot struct {
	ID       string
	Verifier AttestationHardwareVerifier
	Required bool
	Suite    string
}

// MultiRootVerifier is an AttestationHardwareVerifier requiring corroboration from at least Threshold independent roots.
type MultiRootVerifier struct {
	roots     []MultiRootAttestationRoot
	threshold int
	label     AssuranceLabel
}

// CreateMultiRootVerifier enforces an N-of-M policy: every root runs; a required root that did not verify (ok, bound, measured)
// denies; fewer than threshold verified roots denies; corroborating roots whose identities contradict deny; otherwise the
// reconciled identity is returned bound. It errors on no roots, a threshold outside [1, len(roots)], an empty or duplicate id.
func CreateMultiRootVerifier(roots []MultiRootAttestationRoot, threshold int) (*MultiRootVerifier, error) {
	if len(roots) == 0 {
		return nil, errors.New("createMultiRootVerifier: at least one attestation root is required")
	}
	if threshold < 1 || threshold > len(roots) {
		return nil, errors.New("createMultiRootVerifier: threshold must be an integer in [1, roots.length]")
	}
	seen := map[string]bool{}
	ids := make([]string, len(roots))
	lr := make([]AttestationRoot, len(roots))
	for i, r := range roots {
		if r.ID == "" {
			return nil, errors.New("createMultiRootVerifier: each root needs a non-empty id")
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("createMultiRootVerifier: duplicate root id '%s'", r.ID)
		}
		seen[r.ID] = true
		ids[i], lr[i] = r.ID, AttestationRoot{Verifier: r.Verifier, Required: r.Required}
	}
	return &MultiRootVerifier{roots: append([]MultiRootAttestationRoot(nil), roots...), threshold: threshold,
		label: AssuranceLabel{Level: MultiRootLevel(lr, threshold), Vendor: "multi-root:" + strings.Join(ids, "+")}}, nil
}

// Assurance implements AssuranceLabeler: the fewest hardware roots any accepted quorum can contain.
func (m *MultiRootVerifier) Assurance() AssuranceLabel { return m.label }

var multiRootFields = []string{"model_id", "weights_digest", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest"}

func identField(id MeasuredIdentity, f int) string {
	switch f {
	case 0:
		return id.ModelID
	case 1:
		return id.WeightsDigest
	case 2:
		return id.RuntimeMeasurement
	case 3:
		return id.Operator
	case 4:
		if id.SystemPromptDigest != nil {
			return *id.SystemPromptDigest
		}
	case 5:
		if id.ToolManifestDigest != nil {
			return *id.ToolManifestDigest
		}
	}
	return ""
}

// VerifyHardware implements AttestationHardwareVerifier.
func (m *MultiRootVerifier) VerifyHardware(doc, ctx map[string]any, nowMs int64, expected ExpectedAttestationBinding) (out HardwareResult) {
	defer func() {
		if r := recover(); r != nil {
			out = hwFail(fmt.Sprintf("multi-root attestation error (fail closed): %v", r))
		}
	}()
	type passed struct {
		idx int
		id  MeasuredIdentity
	}
	var pass []passed
	host := map[string]string{}
	for i, r := range m.roots {
		res := func() (res HardwareResult) {
			defer func() {
				if p := recover(); p != nil {
					res = hwFail(fmt.Sprintf("root '%s' threw (fail closed): %v", r.ID, p))
				}
			}()
			return r.Verifier.VerifyHardware(doc, ctx, nowMs, expected)
		}()
		if !(res.OK && res.Bound && res.Measured != nil) {
			if r.Required {
				why := res.Reason
				if why == "" {
					why = "invalid"
				}
				return hwFail(fmt.Sprintf("required attestation root '%s' failed: %s", r.ID, why))
			}
			continue
		}
		pass = append(pass, passed{i, MeasuredIdentityFromMap(res.Measured)})
		for k, v := range res.HostAsserted {
			host[r.ID+"."+k] = v
		}
	}
	if len(pass) < m.threshold {
		return hwFail(fmt.Sprintf("multi-root attestation below threshold (%d/%d independent roots corroborated)", len(pass), m.threshold))
	}
	chosen := make([]string, len(multiRootFields))
	for f := range multiRootFields {
		who := -1
		for _, p := range pass {
			v := identField(p.id, f)
			switch {
			case v == "":
			case chosen[f] == "":
				chosen[f], who = v, p.idx
			case chosen[f] != v:
				return hwFail(fmt.Sprintf("multi-root attestation identity conflict: roots '%s' and '%s' disagree on %s", m.roots[who].ID, m.roots[p.idx].ID, multiRootFields[f]))
			}
		}
	}
	merged := MeasuredIdentity{ModelID: chosen[0], WeightsDigest: chosen[1], RuntimeMeasurement: chosen[2], Operator: chosen[3]}
	if chosen[4] != "" {
		merged.SystemPromptDigest = &chosen[4]
	}
	if chosen[5] != "" {
		merged.ToolManifestDigest = &chosen[5]
	}
	for _, p := range pass { // measured only when a root that measured it carries the chosen digest
		if chosen[1] != "" && p.id.WeightsMeasured && p.id.WeightsDigest == chosen[1] {
			merged.WeightsMeasured = true
		}
	}
	res := HardwareResult{OK: true, Bound: true, Measured: merged.Map()}
	if len(host) > 0 {
		res.HostAsserted = host
	}
	return res
}

// ---- accountability anchoring ---------------------------------------------------------------------------------------------------

// VerifiedAttestationEvidence is what gets anchored: what was proven, not the raw quote bytes.
type VerifiedAttestationEvidence struct {
	Identity   MeasuredIdentity
	Binding    ExpectedAttestationBinding
	RootIDs    []string // roots that corroborated it; order-insensitive
	Suite      string   // audit label of the attestation suite(s)
	VerifiedAt int64
}

// AttestationEvidenceDigest is the canonical, domain-separated digest of a verified attestation: the commitment leaf appended to
// the transparency ledger. It binds the measured identity and the holder, grant, epoch and nonce.
func AttestationEvidenceDigest(ev VerifiedAttestationEvidence) (string, error) {
	roots := sortedStrings(ev.RootIDs)
	rs := make([]any, len(roots))
	for i, r := range roots {
		rs[i] = r
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	epoch := json.Number(jsNumberLexeme(ev.Binding.Epoch))
	return AttestationDigestBody(map[string]any{
		"domain": AttestAnchorDomain, "holder": ev.Binding.HolderPub, "grant": ev.Binding.GrantRef, "epoch": epoch, "nonce": ev.Binding.Nonce,
		"model_id": ev.Identity.ModelID, "weights_digest": ev.Identity.WeightsDigest, "weights_measured": ev.Identity.WeightsMeasured,
		"runtime_measurement": ev.Identity.RuntimeMeasurement, "operator": ev.Identity.Operator,
		"system_prompt_digest": str(ev.Identity.SystemPromptDigest), "tool_manifest_digest": str(ev.Identity.ToolManifestDigest),
		"roots": rs, "suite": ev.Suite, "verified_at": json.Number(fmt.Sprint(ev.VerifiedAt)),
	})
}

// AttestationDigestBody hashes a ready map with the canonical hash (a helper of AttestationEvidenceDigest).
func AttestationDigestBody(m map[string]any) (string, error) {
	n, err := normObj(m)
	if err != nil {
		return "", err
	}
	return HashCanonical(n)
}

// AttestationAnchorLedger is the transparency ledger an attestation is anchored into: an append-only commitment log with a head.
type AttestationAnchorLedger interface {
	// Head is the current size and root.
	Head() (size int64, root string)
	// AppendCommitment appends an opaque commitment and returns its index.
	AppendCommitment(commit string) (index int64, err error)
	// Principal is the log's principal, recorded in the tree head.
	Principal() string
}

// AttestationAnchorOptions configure AnchorAttestationEvidence.
type AttestationAnchorOptions struct {
	Ledger AttestationAnchorLedger
	// GuardianSeed signs the resulting tree head through SignTreeHead; with a post-quantum Suite the record is post-quantum accountable.
	// Without it the commitment is still appended but no tree head is produced (allowed only when Required is false).
	GuardianSeed []byte
	Suite        *SuiteOpts
	InstanceID   string
	// SignTreeHead signs the head (instance_id, principal, size, root, prev_root, timestamp); nil uses SignTreeHeadWithSeed.
	SignTreeHead func(guardianSeed []byte, head map[string]any, suite *SuiteOpts) (map[string]any, error)
	// Now is the clock for the head timestamp (default the wall clock).
	Now func() int64
	// Required makes anchoring fail closed: a missing ledger, guardian seed or signer, or a failed signature is an error.
	Required bool
}

// AttestationAnchor is the result of anchoring: the log index, the anchored commitment and, when signed, the tree head.
type AttestationAnchor struct {
	Index  int64
	Commit string
	Sth    map[string]any
}

// AnchorAttestationEvidence appends the evidence digest to the ledger as an opaque commitment and, with a guardian seed, signs the
// resulting tree head so the record is vouched for by a (post-quantum capable) signature. It adds after-the-fact accountability, not
// prevention. With Required it fails closed on any missing piece.
func AnchorAttestationEvidence(ev VerifiedAttestationEvidence, o AttestationAnchorOptions) (*AttestationAnchor, error) {
	fail := func(msg string) (*AttestationAnchor, error) {
		return nil, errors.New("attestation anchoring (fail closed): " + msg)
	}
	if o.Ledger == nil {
		return fail("no transparency ledger available")
	}
	if o.SignTreeHead == nil {
		o.SignTreeHead = SignTreeHeadWithSeed
	}
	if o.Required && len(o.GuardianSeed) == 0 {
		return fail("required anchoring needs a guardian secret to sign the tree head")
	}
	commit, err := AttestationEvidenceDigest(ev)
	if err != nil {
		return nil, err
	}
	_, prevRoot := o.Ledger.Head()
	idx, err := o.Ledger.AppendCommitment(commit)
	if err != nil {
		return nil, err
	}
	out := &AttestationAnchor{Index: idx, Commit: commit}
	if len(o.GuardianSeed) > 0 && o.SignTreeHead != nil {
		now := o.Now
		if now == nil {
			now = attNowMs
		}
		size, root := o.Ledger.Head()
		sth, serr := o.SignTreeHead(o.GuardianSeed, map[string]any{"instance_id": o.InstanceID, "principal": o.Ledger.Principal(),
			"size": size, "root": root, "prev_root": prevRoot, "timestamp": now()}, o.Suite)
		if serr != nil {
			if o.Required {
				return fail("tree-head signing failed: " + serr.Error())
			}
		} else {
			out.Sth = sth
		}
	}
	return out, nil
}
