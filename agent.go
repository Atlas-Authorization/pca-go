package pca

// The agent / issuer side of PCA: produce the proofs the verifier in this package checks. Same wire as the TypeScript
// reference (mintGrant, delegate, buildPCActn, signEscalationAnswer, signDischarge, signPassport, signWorkflow, ...),
// BYTE-exact wherever the algorithm is deterministic (Ed25519, canonical JSON, digests, chain structure); the shared
// producer vectors (producer-vectors.json: fixed keys, nonces and timestamps) pin it.
//
// Values are the same JSON shapes the verifier takes (map[string]any, []any, string, bool, nil, json.Number). Every
// producer normalises its inputs through JSON first, so ordinary Go values (ints, float64, structs with json tags) work.
//
// Signing: Ed25519 (crypto/ed25519), and through cloudflare/circl ML-DSA-65 / ML-DSA-87 and SLH-DSA-SHA2-128f / 256s with
// their hybrid and nested-hybrid suites (pure mode, empty context). PQ signing is deterministic like the reference's, so the
// PQ producer vectors compare bytes. fn-dsa-* and less-cat1 are verify-only here (ErrUnsupportedSigner).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// ErrUnsupportedSigner: the suite is registered but this build cannot SIGN with it. The text starts `unsupported_suite: `.
var ErrUnsupportedSigner = errors.New(UnsupportedSuite)

// DefaultTTLMs is the lifetime the agent client stamps on a PCActn (20 minutes).
const DefaultTTLMs int64 = 20 * 60_000

// DefaultRiskPolicy is the risk policy a grant carries when the issuer sets none of its own.
func DefaultRiskPolicy() map[string]any {
	return map[string]any{
		"weights": map[string]any{"alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05},
		"theta1":  0.25, "theta2": 0.6, "kappa": 1, "lambda": 0.0005, "rho": 0.5, "bMax": 1,
	}
}

// ---- normalisation -------------------------------------------------------------------------------------------------------

// NormalizeJSON converts any JSON-encodable Go value into the strict-profile shapes the verifier and the canonicalizer use
// (json.Number, map[string]any, []any). It fails on a value outside the strict profile (unsafe integer, exponent form, ...).
func NormalizeJSON(v any) (any, error) {
	// json.Marshal silently rewrites invalid UTF-8 (a carried lone surrogate) as U+FFFD: refuse it first, as the reference's
	// canonicalizer does, so a producer never signs or hashes a different string than it was given.
	if e := badUTF8(reflect.ValueOf(v), 0); e != "" {
		return nil, fmt.Errorf("canonicalize: %s", e)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return StrictParse(string(b))
}

// badUTF8 finds a string (value or map key) json.Marshal would rewrite: "lone surrogate in string" or "invalid UTF-8".
func badUTF8(v reflect.Value, depth int) string {
	if depth > 10000 || !v.IsValid() {
		return "" // json.Marshal reports the cycle / nothing to check
	}
	str := func(s string) string {
		if utf8.ValidString(s) {
			return ""
		}
		if hasLoneSurrogate(s) {
			return "lone surrogate in string"
		}
		return "invalid UTF-8"
	}
	switch v.Kind() {
	case reflect.String:
		return str(v.String())
	case reflect.Pointer, reflect.Interface:
		return badUTF8(v.Elem(), depth+1) // a nil one's Elem is the invalid Value: ""
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return "" // bytes marshal as base64
		}
		for i := 0; i < v.Len(); i++ {
			if e := badUTF8(v.Index(i), depth+1); e != "" {
				return e
			}
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			if k := it.Key(); k.Kind() == reflect.String {
				if e := str(k.String()); e != "" {
					return e
				}
			}
			if e := badUTF8(it.Value(), depth+1); e != "" {
				return e
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				if e := badUTF8(v.Field(i), depth+1); e != "" {
					return e
				}
			}
		}
	}
	return ""
}

func normObj(v any) (map[string]any, error) {
	n, err := NormalizeJSON(v)
	if err != nil {
		return nil, err
	}
	m, ok := n.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a JSON object")
	}
	return m, nil
}

func normList(v any) ([]any, error) {
	n, err := NormalizeJSON(v)
	if err != nil {
		return nil, err
	}
	if n == nil { // nil or a nil slice marshals to null: no elements
		return []any{}, nil
	}
	l, ok := n.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a JSON array")
	}
	return l, nil
}

func copyMap(m map[string]any) map[string]any {
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// ---- keys ----------------------------------------------------------------------------------------------------------------

// KeyPair is an Ed25519 identity. Public is the base64url key id every artifact names.
type KeyPair struct {
	priv   ed25519.PrivateKey
	Public string
}

// NewKeyPair generates a fresh Ed25519 identity.
func NewKeyPair() (*KeyPair, error) {
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed) // the transient copy of the secret does not outlive the call (KeyPairFromSeed keeps its own)
	rand.Read(seed)   // never fails: since Go 1.24 a failing system RNG crashes the program instead
	return KeyPairFromSeed(seed)
}

// Zero overwrites the private key material this KeyPair holds. The KeyPair cannot sign afterwards (Sign panics on the cleared key,
// as with any invalid key): call it when the identity is retired.
func (k *KeyPair) Zero() { clear(k.priv) }

// KeyPairFromSeed builds the identity of a 32-byte Ed25519 seed.
func KeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("an Ed25519 seed is %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &KeyPair{priv: priv, Public: b64.EncodeToString(priv.Public().(ed25519.PublicKey))}, nil
}

// KeyPairFromSeedB64u is KeyPairFromSeed for a canonical base64url seed.
func KeyPairFromSeedB64u(seed string) (*KeyPair, error) {
	b, ok := DecodeB64uStrict(seed, ed25519.SeedSize)
	if !ok {
		return nil, fmt.Errorf("an Ed25519 seed is 32 canonical base64url bytes")
	}
	return KeyPairFromSeed(b)
}

// Seed returns the 32-byte secret seed.
func (k *KeyPair) Seed() []byte { return k.priv.Seed() }

// Sign returns the deterministic RFC 8032 signature of msg.
func (k *KeyPair) Sign(msg []byte) []byte { return ed25519.Sign(k.priv, msg) }

// PqKeyPair is a post-quantum key pair for the PQ half of a suite. Public is the base64url `pq_pk` a suite binds in.
type PqKeyPair struct {
	prim   pqPrim
	Public string
	sign   func(msg []byte) ([]byte, error)
}

// pqSeedSizes is the seed length of each family: the FIPS 204 xi (32 bytes), or SK.seed || SK.prf || PK.seed for SLH-DSA (3n).
var pqSeedSizes = map[string]int{"ML-DSA-65": mldsa65.SeedSize, "ML-DSA-87": mldsa87.SeedSize, "SLH-DSA-SHA2-128f": 48, "SLH-DSA-SHA2-256s": 96}

// GeneratePqKeyPair generates a key pair for the family "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f" or "SLH-DSA-SHA2-256s".
func GeneratePqKeyPair(family string) (*PqKeyPair, error) {
	n, ok := pqSeedSizes[family]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSigner, family)
	}
	seed := make([]byte, n)
	defer clear(seed)
	// io.ReadFull, not rand.Read: a replaced rand.Reader that fails must be an error, not a crash
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return GeneratePqKeyPairFromSeed(family, seed)
}

// GeneratePqKeyPairFromSeed derives the key pair of a fixed seed, byte for byte the reference's keygen: 32 bytes for ML-DSA
// (FIPS 204 xi), 48 / 96 bytes for SLH-DSA-SHA2-128f / 256s (SK.seed || SK.prf || PK.seed). Signing is deterministic (the
// FIPS 204 deterministic variant with an all-zero rnd; SLH-DSA with opt_rand = PK.seed), so a fixed key signs a fixed message
// to fixed bytes, as the reference does.
func GeneratePqKeyPairFromSeed(family string, seed []byte) (*PqKeyPair, error) {
	n, ok := pqSeedSizes[family]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSigner, family)
	}
	if len(seed) != n {
		return nil, fmt.Errorf("a %s seed is %d bytes", family, n)
	}
	switch family {
	case "ML-DSA-65":
		var xi [mldsa65.SeedSize]byte
		copy(xi[:], seed)
		pk, sk := mldsa65.NewKeyFromSeed(&xi)
		clear(xi[:])
		return &PqKeyPair{prim: pqMlDsa65, Public: b64.EncodeToString(pk.Bytes()), sign: func(m []byte) ([]byte, error) {
			sig := make([]byte, mldsa65.SignatureSize)
			return sig, mldsa65.SignTo(sk, m, nil, false, sig)
		}}, nil
	case "ML-DSA-87":
		var xi [mldsa87.SeedSize]byte
		copy(xi[:], seed)
		pk, sk := mldsa87.NewKeyFromSeed(&xi)
		clear(xi[:])
		return &PqKeyPair{prim: pqMlDsa87, Public: b64.EncodeToString(pk.Bytes()), sign: func(m []byte) ([]byte, error) {
			sig := make([]byte, mldsa87.SignatureSize)
			return sig, mldsa87.SignTo(sk, m, nil, false, sig)
		}}, nil
	}
	id, prim := slhdsa.SHA2_128f, pqSlh128f
	if family == "SLH-DSA-SHA2-256s" {
		id, prim = slhdsa.SHA2_256s, pqSlh256s
	}
	// GenerateKey reads SK.seed, SK.prf, PK.seed in that order: a reader over the seed replays it exactly
	pk, sk, err := slhdsa.GenerateKey(bytes.NewReader(seed), id)
	if err != nil {
		return nil, err
	}
	pb, _ := pk.MarshalBinary() // never fails: a growable cryptobyte builder over a Marshal that returns nil
	return &PqKeyPair{prim: prim, Public: b64.EncodeToString(pb), sign: func(m []byte) ([]byte, error) {
		return slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(m), nil)
	}}, nil
}

// SuiteOpts selects the signature suite of an artifact (zero value: ed25519, byte-identical to the pre-agility wire).
type SuiteOpts struct {
	Alg string
	Pq  *PqKeyPair
}

func (s *SuiteOpts) alg() string {
	if s == nil || s.Alg == "" {
		return "ed25519"
	}
	return s.Alg
}

// SignWithSuite returns the signature parts of msg under the suite: sig, and for a hybrid suite pqSig (over msg, or over
// msg || sig for the nested hybrid). A suite this package cannot sign is refused with ErrUnsupportedSigner.
func SignWithSuite(s *SuiteOpts, ed *KeyPair, msg []byte) (sig, pqSig string, err error) {
	return signWithSuite(s, ed, msg)
}

func signWithSuite(s *SuiteOpts, ed *KeyPair, msg []byte) (sig, pqSig string, err error) {
	alg := s.alg()
	su, ok := resolveSigAlg(alg, true)
	if !ok {
		if isRegisteredSuite(alg) {
			return "", "", fmt.Errorf("%w: %s", ErrUnsupportedSigner, alg)
		}
		return "", "", fmt.Errorf("unknown signature alg %q", alg)
	}
	if su.pq == pqLessCat1 { // verified (with the less tag), never signed here
		return "", "", fmt.Errorf("%w: %s", ErrUnsupportedSigner, alg)
	}
	if !su.needsPqPk {
		if ed == nil {
			return "", "", errors.New("ed25519 needs an Ed25519 key")
		}
		return b64.EncodeToString(ed.Sign(msg)), "", nil
	}
	if s.Pq == nil || s.Pq.prim != su.pq {
		return "", "", fmt.Errorf("%s needs a matching post-quantum key pair", alg)
	}
	if !su.needsPqSig {
		p, err := s.Pq.sign(msg)
		if err != nil {
			return "", "", err
		}
		return b64.EncodeToString(p), "", nil
	}
	if ed == nil {
		return "", "", fmt.Errorf("%s needs an Ed25519 key", alg)
	}
	e := ed.Sign(msg)
	pm := msg
	if su.nested {
		pm = append(append([]byte{}, msg...), e...)
	}
	p, err := s.Pq.sign(pm)
	if err != nil {
		return "", "", err
	}
	return b64.EncodeToString(e), b64.EncodeToString(p), nil
}

// bindSuite adds `alg` and `pq_pk` to a body for a non-default suite (they are signed).
func bindSuite(body map[string]any, s *SuiteOpts) (map[string]any, error) {
	out := copyMap(body)
	if s.alg() == "ed25519" {
		return out, nil
	}
	if s.Pq == nil {
		return nil, fmt.Errorf("%s needs a post-quantum key pair", s.alg())
	}
	out["alg"] = s.alg()
	out["pq_pk"] = s.Pq.Public
	return out, nil
}

// SignArtifact returns body + `sig` (and `alg`/`pq_pk`/`pq_sig` for a non-default suite): the signature covers
// utf8(domain) || strictCanonical(body with alg/pq_pk, without sig/pq_sig).
func SignArtifact(domain string, body map[string]any, ed *KeyPair, s *SuiteOpts) (map[string]any, error) {
	b, err := normObj(body)
	if err != nil {
		return nil, err
	}
	full, err := bindSuite(b, s)
	if err != nil {
		return nil, err
	}
	cb, err := canonBytes(full)
	if err != nil {
		return nil, err
	}
	sig, pqSig, err := signWithSuite(s, ed, append([]byte(domain), cb...))
	if err != nil {
		return nil, err
	}
	full["sig"] = sig
	if pqSig != "" {
		full["pq_sig"] = pqSig
	}
	return full, nil
}

// signBodyFault is a test seam (nil in production): a non-nil error it returns for a domain makes signBody fail as a canonicalization error would.
var signBodyFault func(domain string) error

func signBody(ed *KeyPair, domain string, body any) (string, error) {
	if signBodyFault != nil {
		if e := signBodyFault(domain); e != nil {
			return "", e
		}
	}
	cb, err := canonBytes(body)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(ed.Sign(append([]byte(domain), cb...))), nil
}

// ---- capability chain ----------------------------------------------------------------------------------------------------

const goalDomain = "atlas-pca/goal/v1\x00"

// GoalCommitOf is the salted commitment to the plaintext goal: base64url(sha256(canonical({d, goal, salt}))).
func GoalCommitOf(goal, salt string) (string, error) {
	return HashCanonical(map[string]any{"d": goalDomain, "goal": goal, "salt": salt})
}

// sealDigest is the capability digest (a seam: HashCanonical always yields 32 canonical bytes, so the decode check below is
// otherwise unreachable).
var sealDigest = HashCanonical

func seal(issuer, holder string, caveats []any, parent, holderPq string, ed *KeyPair, s *SuiteOpts) (map[string]any, error) {
	body := map[string]any{"issuer": issuer, "holder": holder, "caveats": caveats, "parent": nil}
	if parent != "" {
		body["parent"] = parent
	}
	if holderPq != "" {
		body["holder_pq"] = holderPq
	}
	signable, err := bindSuite(body, s)
	if err != nil {
		return nil, err
	}
	digest, err := sealDigest(signable)
	if err != nil {
		return nil, err
	}
	raw, ok := DecodeB64uStrict(digest, b32)
	if !ok {
		return nil, errors.New("internal: digest")
	}
	sig, pqSig, err := signWithSuite(s, ed, append([]byte(capDomain), raw...))
	if err != nil {
		return nil, err
	}
	cap := map[string]any{"id": digest, "issuer": issuer, "holder": holder, "caveats": caveats, "body_digest": digest, "sig": sig}
	if parent != "" {
		cap["parent"] = parent
	}
	if holderPq != "" {
		cap["holder_pq"] = holderPq
	}
	if s.alg() != "ed25519" {
		cap["alg"] = s.alg()
		cap["pq_pk"] = s.Pq.Public
		if pqSig != "" {
			cap["pq_sig"] = pqSig
		}
	}
	return cap, nil
}

// MintRoot signs a root capability as the principal. holderPq is the holder's PQ public key (b64u), committed as `holder_pq`.
func MintRoot(principal *KeyPair, holder string, caveats []any, holderPq string, s *SuiteOpts) (map[string]any, error) {
	cs, err := normList(caveats)
	if err != nil {
		return nil, err
	}
	hp := ""
	if holderPq != "" {
		hp = holderPqCommitment(holderPq)
	}
	return seal(principal.Public, holder, cs, "", hp, principal, s)
}

// Delegate returns a child capability: caveats = parent.caveats ++ added (append-only, so never wider), signed by the
// parent's holder (signer). toHolder "" keeps the holder (and its `holder_pq`); otherwise it is rebound to a sub-agent
// (holderPq is that sub-agent's PQ public key, "" for none).
func Delegate(parent map[string]any, signer *KeyPair, toHolder string, added []any, holderPq string, s *SuiteOpts) (map[string]any, error) {
	ph, _ := parent["holder"].(string)
	pcav, err := normList(parent["caveats"])
	if err != nil {
		return nil, err
	}
	add, err := normList(added)
	if err != nil {
		return nil, err
	}
	holder, hp := ph, ""
	if toHolder != "" {
		holder = toHolder
	}
	if holderPq != "" {
		hp = holderPqCommitment(holderPq)
	} else if holder == ph {
		hp, _ = parent["holder_pq"].(string)
	}
	ph2, err := CapHash(parent)
	if err != nil {
		return nil, err
	}
	return seal(ph, holder, append(pcav, add...), ph2, hp, signer, s)
}

// Attenuate is Delegate with the same holder.
func Attenuate(parent map[string]any, added []any, signer *KeyPair, s *SuiteOpts) (map[string]any, error) {
	return Delegate(parent, signer, "", added, "", s)
}

// MintGrantResult is a minted root intent grant with the commitment to its goal.
type MintGrantResult struct {
	Grant      map[string]any
	GoalCommit string
	GoalSalt   string
}

// MintGrant mints the Root Intent Grant: a root capability whose first caveat is the policy envelope (predicates, caveats,
// agent_binding, risk_policy and the optional units / tighten / actions / template_ref / ... members). Only the salted hash
// of goal goes in the grant. salt "" draws 16 random bytes. The optional members are checked as the reference checks them
// (risk_policy, units, tighten, template_ref, actions, provenance, model_polarity); a present member is kept as given, null included.
func MintGrant(principal *KeyPair, holder string, envelope map[string]any, goal, salt, holderPq string, s *SuiteOpts) (*MintGrantResult, error) {
	if goal == "" {
		return nil, errors.New("MintGrant: goal required")
	}
	if salt == "" {
		salt = randNonce()
	}
	e, err := normObj(envelope)
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"predicates", "caveats", "risk_policy"} {
		if e[k] == nil {
			return nil, fmt.Errorf("MintGrant: envelope.%s required", k)
		}
	}
	if msg := riskPolicyError(e["risk_policy"]); msg != "" {
		return nil, errors.New("MintGrant: " + msg)
	}
	if u, has := e["units"]; has {
		if msg := unitTagsError(u); msg != "" {
			return nil, errors.New("MintGrant: " + msg)
		}
	}
	tg, hasTg := e["tighten"]
	if msg := tightenListError(tg, hasTg); msg != "" {
		return nil, errors.New("MintGrant: " + msg)
	}
	if tr, has := e["template_ref"]; has {
		if msg := TemplateRefError(tr); msg != "" {
			return nil, errors.New("MintGrant: " + msg)
		}
	}
	if ac, has := e["actions"]; has {
		if msg := actionPinError(ac); msg != "" {
			return nil, errors.New("MintGrant: " + msg)
		}
	}
	if pe, has := e["provenance"]; has {
		if msg := ProvEnvelopeError(pe); msg != "" {
			return nil, errors.New("MintGrant: " + msg)
		}
	}
	if mp, has := e["model_polarity"]; has && mp != "legacy" {
		return nil, errors.New("MintGrant: model_polarity must be 'legacy' when present")
	}
	commit, err := GoalCommitOf(goal, salt)
	if err != nil {
		return nil, err
	}
	env := map[string]any{"goal_commit": commit, "predicates": e["predicates"], "caveats": e["caveats"], "risk_policy": e["risk_policy"], "type": "envelope"}
	if ab, ok := e["agent_binding"]; ok && ab != nil {
		env["agent_binding"] = ab
	} else {
		env["agent_binding"] = map[string]any{}
	}
	for _, k := range []string{"objective_risk", "progress", "units", "tighten", "model_polarity", "template_ref", "actions", "provenance"} {
		if v, ok := e[k]; ok { // a present null is kept, as the reference keeps it
			env[k] = v
		}
	}
	grant, err := MintRoot(principal, holder, []any{env}, holderPq, s)
	if err != nil {
		return nil, err
	}
	return &MintGrantResult{Grant: grant, GoalCommit: commit, GoalSalt: salt}, nil
}

func numOf(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func riskPolicyError(p any) string {
	m, ok := p.(map[string]any)
	if !ok {
		return "risk_policy must be an object"
	}
	w, ok := m["weights"].(map[string]any)
	if !ok {
		return "risk_policy.weights missing"
	}
	for _, k := range []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta"} {
		if f, ok := numOf(w[k]); !ok || f < 0 {
			return "risk_policy.weights." + k + " must be finite and >= 0"
		}
	}
	v := map[string]float64{}
	for _, k := range []string{"theta1", "theta2", "kappa", "lambda", "rho", "bMax"} {
		f, ok := numOf(m[k])
		if !ok {
			return "risk_policy." + k + " must be finite"
		}
		v[k] = f
	}
	if v["theta1"] < 0 || v["theta2"] < v["theta1"] {
		return "risk_policy requires 0 <= theta1 <= theta2"
	}
	if v["kappa"] <= 0 {
		return "risk_policy.kappa must be > 0"
	}
	if v["lambda"] < 0 || v["rho"] < 0 || v["bMax"] < 0 {
		return "risk_policy lambda/rho/bMax must be >= 0"
	}
	return ""
}

// ---- plan + PCActn -------------------------------------------------------------------------------------------------------

// PlanCommit is the Merkle commitment of a plan.
type PlanCommit struct {
	Root     string
	hs       [][]byte
	ids      []string
	proofFor func(id string) (map[string]any, error)
}

// ProofFor returns the inclusion proof of a plan node.
func (p *PlanCommit) ProofFor(id string) (map[string]any, error) { return p.proofFor(id) }

func prove(hs [][]byte, idx int, out *[]any) {
	if len(hs) == 1 {
		return
	}
	k := split(len(hs))
	if idx < k {
		prove(hs[:k], idx, out)
		*out = append(*out, map[string]any{"side": "R", "hash": b64.EncodeToString(build(hs[k:]))})
	} else {
		prove(hs[k:], idx-k, out)
		*out = append(*out, map[string]any{"side": "L", "hash": b64.EncodeToString(build(hs[:k]))})
	}
}

// CommitPlan commits a plan: nodes are {id, verb, resource, params_digest?, reversibility_class?, pre?, post?}.
func CommitPlan(nodes []map[string]any) (*PlanCommit, error) {
	if len(nodes) == 0 {
		return nil, errors.New("CommitPlan: empty plan")
	}
	seen := map[string]bool{}
	pc := &PlanCommit{}
	for _, raw := range nodes {
		n, err := normObj(raw)
		if err != nil {
			return nil, err
		}
		id, _ := n["id"].(string)
		if seen[id] {
			return nil, fmt.Errorf("CommitPlan: duplicate node id %s", id)
		}
		seen[id] = true
		// n is normalized (canonicalizable within the depth limit) and id is a string: these cannot fail
		cond, _ := conditionsDigest(n["pre"], n["post"])
		leaf, _ := planLeaf(id, n, cond)
		h, _ := leafHash(leaf)
		pc.hs = append(pc.hs, h)
		pc.ids = append(pc.ids, id)
	}
	pc.Root = b64.EncodeToString(build(pc.hs))
	pc.proofFor = func(id string) (map[string]any, error) {
		for i, x := range pc.ids {
			if x == id {
				path := []any{}
				prove(pc.hs, i, &path)
				return map[string]any{"index": i, "size": len(pc.hs), "path": path}, nil
			}
		}
		return nil, fmt.Errorf("CommitPlan: unknown node %s", id)
	}
	return pc, nil
}

// PCActnInput is everything BuildPCActn needs. Params is the action's parameters (committed as their digest). Extra holds the
// optional SIGNED slots by wire name: nonce, caution, rationale_commitment, progress_step, prohibition_evidence, tool_binding,
// intent, intent_session, fresh_at (also provenance / attestation / freshness / risk_claim to replace the empty stubs).
type PCActnInput struct {
	Grant   map[string]any
	Chain   []map[string]any
	Plan    []map[string]any
	NodeID  string
	Params  any
	Counter int64
	Signer  *KeyPair
	Aud     string
	Iat     int64 // 0: now
	Exp     int64 // 0: Iat + TtlMs
	TtlMs   int64 // 0: DefaultTTLMs
	Extra   map[string]any
	Suite   *SuiteOpts
}

// BuildPCActn builds the complete signed PCActn for plan node NodeID (wire format v2).
func BuildPCActn(in PCActnInput) (map[string]any, error) {
	if in.Aud == "" {
		return nil, errors.New("BuildPCActn: aud (audience) is required")
	}
	if in.Signer == nil {
		return nil, errors.New("BuildPCActn: signer required")
	}
	var node map[string]any
	for _, raw := range in.Plan {
		n, err := normObj(raw)
		if err != nil {
			return nil, err
		}
		if id, _ := n["id"].(string); id == in.NodeID {
			node = n
		}
	}
	if node == nil {
		return nil, fmt.Errorf("BuildPCActn: unknown plan node %s", in.NodeID)
	}
	digest, err := ParamsDigest(in.Params)
	if err != nil {
		return nil, err
	}
	if pd, ok := node["params_digest"].(string); ok && pd != digest {
		return nil, fmt.Errorf("BuildPCActn: params do not match plan node %s's params_digest", in.NodeID)
	}
	pc, err := CommitPlan(in.Plan)
	if err != nil {
		return nil, err
	}
	// the node was found in the same (normalized) plan CommitPlan just committed: neither can fail
	proof, _ := pc.ProofFor(in.NodeID)
	cond, _ := conditionsDigest(node["pre"], node["post"])
	rev := defaultRev
	if r, ok := node["reversibility_class"].(string); ok && r != "" {
		rev = r
	}
	iat := in.Iat
	if iat == 0 {
		iat = time.Now().UnixMilli()
	}
	exp := in.Exp
	if exp == 0 {
		ttl := in.TtlMs
		if ttl == 0 {
			ttl = DefaultTTLMs
		}
		exp = iat + ttl
	}
	chain := make([]any, len(in.Chain))
	for i, c := range in.Chain {
		chain[i] = c
	}
	body := map[string]any{
		"ver":         PCActnVer,
		"action":      map[string]any{"verb": node["verb"], "resource": node["resource"], "params_digest": digest, "reversibility_class": rev},
		"grant_ref":   in.Grant["id"],
		"cap_chain":   chain,
		"plan":        map[string]any{"root": pc.Root, "inclusion_proof": proof, "node_id": in.NodeID, "conditions_digest": cond},
		"attestation": map[string]any{"quote_digest": "", "epoch": 0, "model_id": "unattested", "measurement": "", "operator": "unattested"},
		"provenance":  map[string]any{"causal_hash": "", "taint_level": 0, "trusted_refs": []any{}},
		"freshness":   map[string]any{"beacon_ref": "", "epoch": 0, "accumulator_witness": ""},
		"counter":     in.Counter,
		"risk_claim":  map[string]any{"r": 0, "inputs": map[string]any{}},
		"aud":         in.Aud,
		"iat":         iat,
		"exp":         exp,
	}
	for k, v := range in.Extra {
		if v != nil {
			body[k] = v
		}
	}
	nb, err := normObj(body)
	if err != nil {
		return nil, err
	}
	return SignPCActn(nb, in.Signer, in.Suite)
}

// SignPCActn signs a PCActn body (without `sig`) with the leaf holder's key under the suite.
func SignPCActn(body map[string]any, leaf *KeyPair, s *SuiteOpts) (map[string]any, error) {
	full, err := bindSuite(body, s)
	if err != nil {
		return nil, err
	}
	msg, err := ThresholdMessage(full)
	if err != nil {
		return nil, err
	}
	sig, pqSig, err := signWithSuite(s, leaf, msg)
	if err != nil {
		return nil, err
	}
	full["sig"] = sig
	if pqSig != "" {
		full["pq_sig"] = pqSig
	}
	return full, nil
}

// PCAHeaders returns the HTTP headers the native middleware reads: PCA-Action (base64url of the PCActn JSON) and, when given,
// PCA-Discharges (base64url JSON array), PCA-Narrow and PCA-Escalation-Answer (base64url JSON).
func PCAHeaders(pcactn map[string]any, discharges []map[string]any, narrow, escalationAnswer map[string]any) (map[string]string, error) {
	enc := func(v any) (string, error) {
		s, err := Canonicalize(v)
		return b64.EncodeToString([]byte(s)), err
	}
	h := map[string]string{}
	var err error
	if h[PCAHeader], err = enc(pcactn); err != nil {
		return nil, err
	}
	if len(discharges) > 0 {
		l := make([]any, len(discharges))
		for i, d := range discharges {
			l[i] = d
		}
		if h["PCA-Discharges"], err = enc(l); err != nil {
			return nil, err
		}
	}
	if narrow != nil {
		if h["PCA-Narrow"], err = enc(narrow); err != nil {
			return nil, err
		}
	}
	if escalationAnswer != nil {
		if h["PCA-Escalation-Answer"], err = enc(escalationAnswer); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// ---- escalation answer, discharge, narrow ----------------------------------------------------------------------------------

const (
	escalationAnswerDomain = "atlas-pca/escalation-answer/v1\x00"
	dischargeDomain        = "atlas-pca/discharge/v1\x00"
	narrowDomain           = "atlas-pca/narrow/v1\x00"
)

// SignEscalationAnswer is the approving principal's signed answer ("allow" or "deny") to an escalation request. request carries
// policy_digest, action_digest, history_head and (K7) the render_digest the approver saw. nonce "" draws 16 random bytes.
func SignEscalationAnswer(principal *KeyPair, request map[string]any, decision string, iat, expiresAt int64, nonce string, s *SuiteOpts) (map[string]any, error) {
	if decision != "allow" && decision != "deny" {
		return nil, errors.New("decision must be 'allow' or 'deny'")
	}
	if nonce == "" {
		nonce = randNonce()
	}
	body := map[string]any{
		"v": 1, "kind": "pca-escalation-answer", "principal": principal.Public,
		"policy_digest": request["policy_digest"], "action_digest": request["action_digest"], "history_head": request["history_head"],
		"decision": decision, "iat": iat, "expires_at": expiresAt, "nonce": nonce,
	}
	if rd, ok := request["render_digest"].(string); ok && rd != "" {
		body["render_digest"] = rd
	}
	// the signed answer must pass the reference shape check (fail closed: never hand out an answer every verifier refuses)
	a, err := SignArtifact(escalationAnswerDomain, body, principal, s)
	if err != nil {
		return nil, err
	}
	if e := EscalationAnswerShapeError(a); e != "" {
		return nil, errors.New("SignEscalationAnswer: " + e)
	}
	return a, nil
}

func randNonce() string {
	r := make([]byte, 16)
	rand.Read(r) // never fails: since Go 1.24 a failing system RNG crashes the program instead
	return b64.EncodeToString(r)
}

// NeedsDischargeCaveat is a third-party caveat: the verifier's pin labelled issuer (of class issuerClass) must sign a discharge
// whose claims satisfy every require entry ({"claim", "op": eq|neq|gte|lte|in, "value"}).
func NeedsDischargeCaveat(id, issuer, issuerClass, bind string, ttlMs int64, require []any) map[string]any {
	if bind == "" {
		bind = "chain_hop"
	}
	return map[string]any{"type": "needs_discharge", "id": id, "issuer": issuer, "issuer_class": issuerClass, "bind": bind, "ttl_ms": ttlMs, "require": require}
}

// SealedCaveat forbids any hop below the hop that carries it.
func SealedCaveat() map[string]any { return map[string]any{"type": "sealed"} }

// MaxUsesCaveat is a lifetime use count (1..256) backed by the verifier's replay store, expiring at until (epoch ms).
func MaxUsesCaveat(id string, n int, until int64) map[string]any {
	return map[string]any{"type": "max_uses", "id": id, "n": n, "until": until}
}

// DischargeInput describes a discharge of a needs_discharge caveat.
type DischargeInput struct {
	CaveatID     string
	IssuerLabel  string
	CapHash      string // capHash of the hop that carries the caveat
	Bind         string // "chain_hop" (default) or "action"
	ActionDigest string // DischargeActionDigest of the exact PCActn, for bind "action"
	Claims       map[string]any
	Iat          int64
	NotAfter     int64
	Nonce        string
}

// SignDischarge is the pinned third party's discharge.
func SignDischarge(issuer *KeyPair, d DischargeInput, s *SuiteOpts) (map[string]any, error) {
	bind := d.Bind
	if bind == "" {
		bind = "chain_hop"
	}
	nonce := d.Nonce
	if nonce == "" {
		nonce = randNonce()
	}
	body := map[string]any{"v": 1, "kind": "pca-discharge", "caveat_id": d.CaveatID, "issuer": d.IssuerLabel, "cap_hash": d.CapHash, "bind": bind,
		"claims": d.Claims, "iat": d.Iat, "not_after": d.NotAfter, "nonce": nonce}
	if d.ActionDigest != "" {
		body["action_digest"] = d.ActionDigest
	}
	out, err := SignArtifact(dischargeDomain, body, issuer, s)
	if err != nil {
		return nil, err
	}
	if e := DischargeShapeError(out); e != "" {
		return nil, errors.New("SignDischarge: " + e)
	}
	return out, nil
}

// SignNarrow is the leaf holder's self-attenuation, presented beside the PCActn. actionDigest "" applies it to every action until notAfter.
func SignNarrow(holder *KeyPair, leafCapHash string, caveats []any, iat, notAfter int64, actionDigest, nonce string, s *SuiteOpts) (map[string]any, error) {
	if nonce == "" {
		nonce = randNonce()
	}
	body := map[string]any{"v": 1, "kind": "pca-narrow", "cap_hash": leafCapHash, "holder": holder.Public, "caveats": caveats, "iat": iat, "not_after": notAfter, "nonce": nonce}
	if actionDigest != "" {
		body["action_digest"] = actionDigest
	}
	out, err := SignArtifact(narrowDomain, body, holder, s)
	if err != nil {
		return nil, err
	}
	if e := NarrowShapeError(out); e != "" {
		return nil, errors.New("SignNarrow: " + e)
	}
	return out, nil
}

// ---- passport -------------------------------------------------------------------------------------------------------------

// PassportFingerprint is the content address of the identity fields.
func PassportFingerprint(p map[string]any) (string, error) {
	return HashCanonical(map[string]any{
		"d": "atlas-pca/passport/v1", "model_id": p["model_id"], "weights_digest": p["weights_digest"],
		"system_prompt_digest": p["system_prompt_digest"], "tool_manifest_digest": p["tool_manifest_digest"],
		"runtime_measurement": p["runtime_measurement"], "operator": p["operator"], "hardware_rooted": p["hardware_rooted"],
	})
}

// IssuePassport fills `id` from the fingerprint of the identity.
func IssuePassport(identity map[string]any) (map[string]any, error) {
	n, err := normObj(identity)
	if err != nil {
		return nil, err
	}
	id, _ := PassportFingerprint(n) // n is normalized: its identity fields always hash
	n["id"] = id
	return n, nil
}

// SignPassport signs a passport for the agent key subject. iat/nbf 0: the passport's issued_at (nbf: iat). A hardware_rooted
// passport needs evidence (fail closed).
func SignPassport(passport map[string]any, issuer *KeyPair, subject string, iat, nbf, exp int64, evidence map[string]any, s *SuiteOpts) (map[string]any, error) {
	p, err := normObj(passport)
	if err != nil {
		return nil, err
	}
	fp, _ := PassportFingerprint(p) // p is normalized: its identity fields always hash
	if p["id"] != fp {
		return nil, errors.New("SignPassport: passport.id is not the fingerprint of its identity (use IssuePassport)")
	}
	if hw, _ := p["hardware_rooted"].(bool); hw && evidence == nil {
		return nil, errors.New("SignPassport: hardware_rooted requires attestation evidence (fail closed)")
	}
	if iat == 0 {
		n, ok := safeInt(p["issued_at"])
		if !ok {
			return nil, errors.New("SignPassport: passport.issued_at must be a safe integer")
		}
		iat = n
	}
	if nbf == 0 {
		nbf = iat
	}
	if exp <= nbf {
		return nil, errors.New("SignPassport: exp must be after nbf")
	}
	body := map[string]any{"typ": "atlas-pca/passport", "ver": 1, "passport": p, "iss": issuer.Public, "sub": subject, "iat": iat, "nbf": nbf, "exp": exp}
	if evidence != nil {
		ev, err := normObj(evidence)
		if err != nil {
			return nil, err
		}
		if _, has := ev["at"]; !has {
			ev["at"] = iat
		}
		body["evidence"] = ev
	}
	return SignArtifact(passportSigDomain, body, issuer, s)
}

// ---- workflow, receipts, read grants, aggregate grants, fresh_at ----------------------------------------------------------------

const (
	workflowDomain  = "atlas-pca/workflow/v1\x00"
	wfReceiptDomain = "atlas-pca/wf-receipt/v1\x00"
)

// requireSigner normalises body, runs valid (the reference's shape check, "<what>: <malformed>" when it fails) and requires
// body[key] to be the signer.
func requireSigner(body map[string]any, key, public, what string, valid func(map[string]any) bool, malformed string) (map[string]any, error) {
	b, err := normObj(body)
	if err != nil {
		return nil, err
	}
	if !valid(b) {
		return nil, fmt.Errorf("%s: %s", what, malformed)
	}
	if b[key] != public {
		return nil, fmt.Errorf("%s: %s is not the signer", what, key)
	}
	return b, nil
}

// SignWorkflow is the principal's signed workflow commitment ({"body", "sig"}). The body must be well formed and a DAG (unique
// step ids, known dependencies, no cycle, edges along dependencies), and body.principal must be the signer.
func SignWorkflow(principal *KeyPair, body map[string]any) (map[string]any, error) {
	b, err := requireSigner(body, "principal", principal.Public, "SignWorkflow",
		func(b map[string]any) bool { return k5ValidWorkflowBody(b) && k5DagError(b) == "" }, "malformed workflow")
	if err != nil {
		return nil, err
	}
	sig, err := signBody(principal, workflowDomain, b)
	return map[string]any{"body": b, "sig": sig}, err
}

// WfOutput is a receipt output for value (a string, bool or integer); num carries the integer an edge may compare.
func WfOutput(value any, labels []string, unit string, num bool) (map[string]any, error) {
	v, err := NormalizeJSON(value)
	if err != nil {
		return nil, err
	}
	d, ok := WorkflowValueDigest(v)
	if !ok {
		return nil, errors.New("WfOutput: not a scalar")
	}
	var n any
	if nn, isNum := v.(json.Number); isNum && num {
		n = nn
	}
	var u any
	if unit != "" {
		u = unit
	}
	ls := make([]any, 0, len(labels))
	for _, l := range sortedStrings(labels) {
		ls = append(ls, l)
	}
	return map[string]any{"digest": d, "num": n, "unit": u, "labels": ls}, nil
}

// sortedStrings is Array.prototype.sort: UTF-16 code-unit order.
func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	sort.Slice(out, func(i, j int) bool { return utf16Less(out[i], out[j]) })
	return out
}

// SignStepReceipt is the resource server's signed receipt for a workflow step; prev is the previous receipt of the workflow (nil: first).
func SignStepReceipt(rs *KeyPair, workflow map[string]any, step, outcome, paramsDigest string, outputs map[string]any, issuedAt int64, prev map[string]any) (map[string]any, error) {
	wf, err := normObj(workflow)
	if err != nil {
		return nil, err
	}
	wd, ok := WorkflowDigest(wf)
	if !ok {
		return nil, errors.New("SignStepReceipt: malformed workflow")
	}
	seq, ref := any(0), any(nil)
	if prev != nil {
		p, err := normObj(prev)
		if err != nil {
			return nil, err
		}
		ps, _ := safeInt(p["seq"])
		seq = ps + 1
		r, ok := WorkflowReceiptRef(p)
		if !ok {
			return nil, errors.New("SignStepReceipt: malformed previous receipt")
		}
		ref = r
	}
	base := map[string]any{"v": 1, "wf": wd, "step": step, "seq": seq, "prev": ref, "outcome": outcome, "params_digest": paramsDigest,
		"outputs": outputs, "issued_at": issuedAt, "signer": rs.Public}
	nb, err := normObj(base)
	if err != nil {
		return nil, err
	}
	sig, err := signBody(rs, wfReceiptDomain, nb)
	nb["sig"] = sig
	return nb, err
}

// SignReadGrant is the principal's signed read grant ({"body", "sig"}).
func SignReadGrant(principal *KeyPair, body map[string]any) (map[string]any, error) {
	b, err := requireSigner(body, "principal", principal.Public, "SignReadGrant", func(b map[string]any) bool { return k5ValidReadGrantBody(b) }, "malformed grant")
	if err != nil {
		return nil, err
	}
	sig, err := signBody(principal, "atlas-pca/read-grant/v1\x00", b)
	return map[string]any{"body": b, "sig": sig}, err
}

// SignAggregateGrant is the principal's signed aggregate-read grant ({"body", "sig"}).
func SignAggregateGrant(principal *KeyPair, body map[string]any) (map[string]any, error) {
	b, err := requireSigner(body, "principal", principal.Public, "SignAggregateGrant", func(b map[string]any) bool { return k5ValidAggGrantBody(b) }, "malformed grant")
	if err != nil {
		return nil, err
	}
	sig, err := signBody(principal, "atlas-pca/aggregate-grant/v1\x00", b)
	return map[string]any{"body": b, "sig": sig}, err
}

// SignFreshAt signs a consistency token: the high-water mark of the verifier-side state a write produced. state carries
// revocation_epoch, ledger_tree_size, budget_version, policy_revision and policy_digest.
func SignFreshAt(signer *KeyPair, scope string, state map[string]any, issuedAt int64) (map[string]any, error) {
	base := map[string]any{"v": 1, "scope": scope, "revocation_epoch": state["revocation_epoch"], "ledger_tree_size": state["ledger_tree_size"],
		"budget_version": state["budget_version"], "policy_revision": state["policy_revision"], "policy_digest": state["policy_digest"],
		"issued_at": issuedAt, "signer": signer.Public}
	nb, err := normObj(base)
	if err != nil {
		return nil, err
	}
	sig, err := signBody(signer, "atlas-pca/fresh-at/v1\x00", nb)
	nb["sig"] = sig
	return nb, err
}

// ---- the high-level client -----------------------------------------------------------------------------------------------

// Action is one signed action: the PCActn and the headers to send with the request.
type Action struct {
	PCActn  map[string]any
	Headers map[string]string
	NodeID  string
}

// Agent holds a grant (or a delegated chain), keeps the replay counter, picks nonces and builds the headers. Safe for
// concurrent use. Persist the counter (OnCounter) if the process can restart: a lower counter is refused as a replay.
type Agent struct {
	Key       *KeyPair
	Grant     map[string]any
	Chain     []map[string]any
	Aud       string
	TtlMs     int64
	Suite     *SuiteOpts
	OnCounter func(n int64)
	Clock     func() int64

	mu      sync.Mutex
	counter int64
	plan    []map[string]any
}

// NewAgent returns an agent whose chain is the grant alone. counter is the last counter already used.
func NewAgent(key *KeyPair, grant map[string]any, aud string, counter int64) *Agent {
	return &Agent{Key: key, Grant: grant, Chain: []map[string]any{grant}, Aud: aud, TtlMs: DefaultTTLMs, counter: counter,
		Clock: func() int64 { return time.Now().UnixMilli() }}
}

// UsePlan commits to a multi-step plan; Act then signs against the matching node (and its Merkle proof).
func (a *Agent) UsePlan(nodes []map[string]any) { a.plan = nodes }

// Act builds and signs the PCActn for one action. Without a committed plan it commits a one-node plan for the action.
// opts are Extra signed slots (caution, fresh_at, intent, ...).
func (a *Agent) Act(verb, resource string, params any, opts map[string]any) (*Action, error) {
	digest, err := ParamsDigest(params)
	if err != nil {
		return nil, err
	}
	plan, nodeID := a.plan, ""
	if plan == nil {
		nodeID = "n1"
		plan = []map[string]any{{"id": nodeID, "verb": verb, "resource": resource, "params_digest": digest}}
	} else {
		for _, n := range plan {
			if n["verb"] == verb && n["resource"] == resource {
				nodeID, _ = n["id"].(string)
				break
			}
		}
		if nodeID == "" {
			return nil, fmt.Errorf("Act: no node of the committed plan matches %s %s", verb, resource)
		}
	}
	a.mu.Lock()
	a.counter++
	n := a.counter
	if a.OnCounter != nil {
		a.OnCounter(n)
	}
	a.mu.Unlock()
	extra := map[string]any{"nonce": randNonce()}
	for k, v := range opts {
		extra[k] = v
	}
	p, err := BuildPCActn(PCActnInput{Grant: a.Grant, Chain: a.Chain, Plan: plan, NodeID: nodeID, Params: params, Counter: n, Signer: a.Key,
		Aud: a.Aud, Iat: a.Clock(), TtlMs: a.TtlMs, Extra: extra, Suite: a.Suite})
	if err != nil {
		return nil, err
	}
	h, _ := PCAHeaders(p, nil, nil, nil) // p canonicalized when it was signed (only the sig strings were added)
	return &Action{PCActn: p, Headers: h, NodeID: nodeID}, nil
}

// Delegate returns an Ed25519 sub-agent signing with to, holding this chain plus one narrower hop (caveats are only ever
// appended). The hop is signed under this agent's suite. A post-quantum agent's sub-agent needs its own PQ key: use DelegatePq.
func (a *Agent) Delegate(to *KeyPair, caveats []any) (*Agent, error) {
	return a.DelegatePq(to, nil, caveats)
}

// DelegatePq is Delegate for a sub-agent with its own post-quantum key pair toPq (nil: an Ed25519 sub-agent). The hop commits
// toPq as the sub-agent's holder_pq and the sub-agent signs under this agent's suite with toPq, never with this agent's PQ key.
// A PQ agent cannot hand its suite to a sub-agent without one: pass toPq, or the sub-agent signs Ed25519 only.
func (a *Agent) DelegatePq(to *KeyPair, toPq *PqKeyPair, caveats []any) (*Agent, error) {
	var child *SuiteOpts
	holderPq := ""
	if toPq != nil {
		su, ok := resolveSigAlg(a.Suite.alg(), true)
		if !ok || !su.needsPqPk || su.pq != toPq.prim {
			return nil, fmt.Errorf("DelegatePq: the sub-agent's PQ key does not match the suite %s", a.Suite.alg())
		}
		child, holderPq = &SuiteOpts{Alg: a.Suite.alg(), Pq: toPq}, toPq.Public
	}
	cap, err := Delegate(a.Chain[len(a.Chain)-1], a.Key, to.Public, caveats, holderPq, a.Suite)
	if err != nil {
		return nil, err
	}
	return &Agent{Key: to, Grant: a.Grant, Chain: append(append([]map[string]any{}, a.Chain...), cap), Aud: a.Aud, TtlMs: a.TtlMs,
		Suite: child, Clock: a.Clock}, nil
}
