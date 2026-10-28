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
// their hybrid and nested-hybrid suites (pure mode, empty context). PQ signatures are randomised: they are checked by
// cross-verification, not byte equality. fn-dsa-* and less-cat1 are verify-only here (ErrUnsupportedSigner).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

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
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return StrictParse(string(b))
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
	if v == nil {
		return []any{}, nil
	}
	n, err := NormalizeJSON(v)
	if err != nil {
		return nil, err
	}
	if n == nil { // a nil slice marshals to null: no elements
		return []any{}, nil
	}
	l, ok := n.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a JSON array")
	}
	return l, nil
}

func copyMap(m map[string]any) map[string]any {
	o := make(map[string]any, len(m)+2)
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
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return KeyPairFromSeed(seed)
}

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

// GeneratePqKeyPair generates a key pair for the family "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f" or "SLH-DSA-SHA2-256s".
func GeneratePqKeyPair(family string) (*PqKeyPair, error) {
	switch family {
	case "ML-DSA-65":
		pk, sk, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &PqKeyPair{prim: pqMlDsa65, Public: b64.EncodeToString(pk.Bytes()), sign: func(m []byte) ([]byte, error) {
			sig := make([]byte, mldsa65.SignatureSize)
			return sig, mldsa65.SignTo(sk, m, nil, true, sig)
		}}, nil
	case "ML-DSA-87":
		pk, sk, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &PqKeyPair{prim: pqMlDsa87, Public: b64.EncodeToString(pk.Bytes()), sign: func(m []byte) ([]byte, error) {
			sig := make([]byte, mldsa87.SignatureSize)
			return sig, mldsa87.SignTo(sk, m, nil, true, sig)
		}}, nil
	case "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-256s":
		id, prim := slhdsa.SHA2_128f, pqSlh128f
		if family == "SLH-DSA-SHA2-256s" {
			id, prim = slhdsa.SHA2_256s, pqSlh256s
		}
		pk, sk, err := slhdsa.GenerateKey(rand.Reader, id)
		if err != nil {
			return nil, err
		}
		pb, err := pk.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return &PqKeyPair{prim: prim, Public: b64.EncodeToString(pb), sign: func(m []byte) ([]byte, error) {
			return slhdsa.SignRandomized(&sk, rand.Reader, slhdsa.NewMessage(m), nil)
		}}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedSigner, family)
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

// signWithSuite returns the signature parts of msg under the suite: sig, and for a hybrid suite pqSig.
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

func signBody(ed *KeyPair, domain string, body any) (string, error) {
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
	digest, err := HashCanonical(signable)
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
// of goal goes in the grant. salt "" draws 16 random bytes. Shortcut: the optional envelope members are signed as given;
// the verifier refuses a malformed one.
func MintGrant(principal *KeyPair, holder string, envelope map[string]any, goal, salt, holderPq string, s *SuiteOpts) (*MintGrantResult, error) {
	if goal == "" {
		return nil, errors.New("MintGrant: goal required")
	}
	if salt == "" {
		r := make([]byte, 16)
		if _, err := rand.Read(r); err != nil {
			return nil, err
		}
		salt = b64.EncodeToString(r)
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
	for _, k := range []string{"objective_risk", "progress", "units", "tighten", "model_polarity", "template_ref", "actions"} {
		if v, ok := e[k]; ok && v != nil {
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
		cond, err := conditionsDigest(n["pre"], n["post"])
		if err != nil {
			return nil, err
		}
		leaf, err := planLeaf(id, n, cond)
		if err != nil {
			return nil, err
		}
		h, err := leafHash(leaf)
		if err != nil {
			return nil, err
		}
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
	proof, err := pc.ProofFor(in.NodeID)
	if err != nil {
		return nil, err
	}
	cond, err := conditionsDigest(node["pre"], node["post"])
	if err != nil {
		return nil, err
	}
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
	return SignArtifact(escalationAnswerDomain, body, principal, s)
}

func randNonce() string {
	r := make([]byte, 16)
	if _, err := rand.Read(r); err != nil {
		panic(err) // the system RNG failing is not recoverable
	}
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
	return SignArtifact(dischargeDomain, body, issuer, s)
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
	return SignArtifact(narrowDomain, body, holder, s)
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
	id, err := PassportFingerprint(n)
	if err != nil {
		return nil, err
	}
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
	fp, err := PassportFingerprint(p)
	if err != nil {
		return nil, err
	}
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

func requireSigner(body map[string]any, key, public, what string) (map[string]any, error) {
	b, err := normObj(body)
	if err != nil {
		return nil, err
	}
	if b[key] != public {
		return nil, fmt.Errorf("%s: %s is not the signer", what, key)
	}
	return b, nil
}

// SignWorkflow is the principal's signed workflow commitment ({"body", "sig"}); body.principal must be the signer.
func SignWorkflow(principal *KeyPair, body map[string]any) (map[string]any, error) {
	b, err := requireSigner(body, "principal", principal.Public, "SignWorkflow")
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

func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
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
	b, err := requireSigner(body, "principal", principal.Public, "SignReadGrant")
	if err != nil {
		return nil, err
	}
	sig, err := signBody(principal, "atlas-pca/read-grant/v1\x00", b)
	return map[string]any{"body": b, "sig": sig}, err
}

// SignAggregateGrant is the principal's signed aggregate-read grant ({"body", "sig"}).
func SignAggregateGrant(principal *KeyPair, body map[string]any) (map[string]any, error) {
	b, err := requireSigner(body, "principal", principal.Public, "SignAggregateGrant")
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
	h, err := PCAHeaders(p, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return &Action{PCActn: p, Headers: h, NodeID: nodeID}, nil
}

// Delegate returns a sub-agent signing with to, holding this chain plus one narrower hop (caveats are only ever appended).
func (a *Agent) Delegate(to *KeyPair, caveats []any) (*Agent, error) {
	cap, err := Delegate(a.Chain[len(a.Chain)-1], a.Key, to.Public, caveats, "", a.Suite)
	if err != nil {
		return nil, err
	}
	return &Agent{Key: to, Grant: a.Grant, Chain: append(append([]map[string]any{}, a.Chain...), cap), Aud: a.Aud, TtlMs: a.TtlMs,
		Suite: a.Suite, Clock: a.Clock}, nil
}
