package pca

// Attest the mediator, not the weights. The trusted computing base is this small orchestration harness, not an opaque model: the
// model is an UNTRUSTED ORACLE that proposes a candidate action, and the harness enforces plan inclusion, the taint fold and the
// trust budget before any candidate becomes a signed PCActn. The oracle holds no signing key. Also the resource-server hook that
// admits an allowlisted harness measurement.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"
)

// HarnessEnforcedChecks is the ordered manifest of checks the harness enforces before signing; folded into the measurement.
var HarnessEnforcedChecks = []string{"plan_inclusion_before_signing", "taint_provenance_fold", "trust_budget_debit", "pcactn_sign"}

// HarnessVersion is the semantic version of the harness's policy-relevant surface. A bump changes the measurement.
const HarnessVersion = "0.1.0"

// HarnessModelID is the model id stamped into an emitted PCActn's attestation.model_id when attestation is enabled (the mediator,
// not an LLM).
const HarnessModelID = "@atlasauth/pca-harness"

// ComputeHarnessMeasurement is the pure self-measurement: base64url SHA-256 over the harness version, the enforced-checks
// manifest and the risk-policy identity (weights, theta1, theta2, kappa). A policy missing one of those is refused, as the strict
// canonical form refuses an undefined member.
func ComputeHarnessMeasurement(version, enforcedChecks, policy any) (string, error) {
	p, ok := policy.(map[string]any)
	if !ok {
		return "", errors.New("computeHarnessMeasurement: policy is not an object")
	}
	rp := map[string]any{}
	for _, k := range []string{"weights", "theta1", "theta2", "kappa"} {
		v, has := p[k]
		if !has {
			return "", errors.New("canonicalize: unsupported type undefined")
		}
		rp[k] = v
	}
	body, err := NormalizeJSON(map[string]any{"harness": HarnessModelID, "version": version, "enforces": enforcedChecks, "risk_policy": rp})
	if err != nil {
		return "", err
	}
	return HashCanonical(body)
}

// CreateHarnessAttestationVerifier is the resource-server hook: ctx -> {enforced, ok?, reason?} over ctx.pcactn.attestation. Fail
// closed: an empty allowlist accepts nothing; an absent measurement fails unless `required` is false (then not enforced); a
// pinned expectedModelId must match; a present measurement outside the allowlist ALWAYS fails. config: measurements (the
// allowlisted measurement strings), required (default true), expectedModelId (true for the harness id, or a string). The
// measurement's integrity rests on the surrounding verdict requiring the leaf signature to verify.
func CreateHarnessAttestationVerifier(config any) (func(ctx any) map[string]any, error) {
	c, ok := config.(map[string]any)
	if !ok {
		return nil, errors.New("Cannot read properties of null")
	}
	allow := map[string]bool{}
	if l, isList := c["measurements"].([]any); isList {
		for _, m := range l {
			if s, isStr := m.(string); isStr && s != "" {
				allow[s] = true
			}
		}
	}
	required := c["required"] != false
	expected, hasExpected := "", false
	switch em := c["expectedModelId"].(type) {
	case bool:
		if em {
			expected, hasExpected = HarnessModelID, true
		}
	case string:
		if em != "" {
			expected, hasExpected = em, true
		}
	}
	return func(ctx any) map[string]any {
		if len(allow) == 0 {
			return map[string]any{"enforced": true, "ok": false, "reason": "harness attestation configured with an empty measurement allowlist (fail closed)"}
		}
		pc, _ := sbxGet(ctx, "pcactn")
		att, _ := sbxGet(pc, "attestation")
		m, _ := sbxGet(att, "measurement")
		measurement, _ := m.(string)
		if measurement == "" {
			if required {
				return map[string]any{"enforced": true, "ok": false, "reason": "harness attestation required but the PCActn carries no harness measurement (fail closed)"}
			}
			return map[string]any{"enforced": false}
		}
		if hasExpected {
			mid, present := sbxGet(att, "model_id")
			if s, isStr := mid.(string); !isStr || s != expected {
				return map[string]any{"enforced": true, "ok": false,
					"reason": fmt.Sprintf("attestation.model_id '%s' is not the required harness identity '%s'", sbxText(mid, present), expected)}
			}
		}
		if !allow[measurement] {
			return map[string]any{"enforced": true, "ok": false, "reason": "harness measurement is not in the allowlisted set (unattested or unknown mediator)"}
		}
		return map[string]any{"enforced": true, "ok": true}
	}, nil
}

// HarnessOptions configure a Harness. Grant is the principal-signed root capability; Chain the chain ending at the leaf (nil =
// [Grant]); AgentSeed the 32-byte Ed25519 seed of the leaf holder; Plan the committed plan nodes (non-empty); Audience the
// resource-server id; Budget {B, tau, asOf}; Policy a risk policy (nil = the default); BaseRisk overrides of the base risk
// inputs; Now a clock in epoch ms; TtlMs the PCActn lifetime (nil = the default); MeasurementManifest (nil = the enforced
// checks); Nonce a nonce supplier (nil = 16 random bytes as hex); Attestation {operator, epoch?} stamps this harness's
// self-measurement into every emitted PCActn.
type HarnessOptions struct {
	Grant               map[string]any
	Chain               []map[string]any
	AgentSeed           []byte
	Plan                []map[string]any
	Audience            string
	Budget              map[string]any
	Policy              map[string]any
	BaseRisk            map[string]any
	Now                 func() float64
	TtlMs               *int64
	MeasurementManifest []string
	Nonce               func() string
	Attestation         map[string]any
}

// Harness is the attested mediator: it holds the principal's grant, the committed plan, the signing key and the trust budget, and
// wraps an untrusted model oracle. Step is the ONLY path from an oracle proposal to a signed PCActn; it enforces plan inclusion,
// then the taint fold, then the budget, then signs. Safe for concurrent use.
type Harness struct {
	mu        sync.Mutex
	o         HarnessOptions
	chain     []map[string]any
	signer    *KeyPair
	planIndex map[string]map[string]any
	committed *PlanCommit
	policy    map[string]any
	baseRisk  map[string]any
	manifest  []string
	budget    map[string]any
	counter   int64
}

func harnessFin(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// NewHarness validates the options and commits the plan once.
func NewHarness(o HarnessOptions) (*Harness, error) {
	if o.Audience == "" {
		return nil, errors.New("Harness: `audience` is required (the resource-server / instance id PCActns are for)")
	}
	signer, err := KeyPairFromSeed(o.AgentSeed)
	if err != nil {
		return nil, errors.New("Harness: `agentSecret` must be a 32-byte Ed25519 secret key")
	}
	if len(o.Plan) == 0 {
		return nil, errors.New("Harness: `plan` must be a non-empty array (an empty plan authorises nothing)")
	}
	index := map[string]map[string]any{}
	for _, n := range o.Plan {
		id, _ := n["id"].(string)
		index[id] = n
	}
	if len(index) != len(o.Plan) {
		return nil, errors.New("Harness: plan node ids must be unique")
	}
	b, hasB := harnessFin(o.Budget["B"])
	_, hasTau := harnessFin(o.Budget["tau"])
	_, hasAsOf := harnessFin(o.Budget["asOf"])
	if o.Budget == nil || !hasB || b < 0 || !hasTau || !hasAsOf {
		return nil, errors.New("Harness: `budget` must have finite B >= 0, tau and asOf")
	}
	committed, err := CommitPlan(o.Plan)
	if err != nil {
		return nil, err
	}
	h := &Harness{o: o, signer: signer, planIndex: index, committed: committed, budget: o.Budget}
	h.chain = o.Chain
	if h.chain == nil {
		h.chain = []map[string]any{o.Grant}
	}
	h.policy = o.Policy
	if h.policy == nil {
		pol, err := NormalizeJSON(DefaultRiskPolicy())
		if err != nil {
			return nil, err
		}
		h.policy = pol.(map[string]any)
	}
	h.baseRisk = map[string]any{"semanticDistance": jsNumber(0.1), "reversibility": jsNumber(1), "blastRadius": jsNumber(0.1), "taint": jsNumber(0),
		"confidence": jsNumber(1), "age": jsNumber(0)}
	for k, v := range o.BaseRisk {
		h.baseRisk[k] = v
	}
	h.manifest = o.MeasurementManifest
	if h.manifest == nil {
		h.manifest = HarnessEnforcedChecks
	}
	if h.o.Now == nil {
		h.o.Now = func() float64 { return float64(time.Now().UnixMilli()) }
	}
	if h.o.Nonce == nil {
		h.o.Nonce = harnessNonce
	}
	return h, nil
}

// PlanRoot is the committed plan root the principal authorised.
func (h *Harness) PlanRoot() string { return h.committed.Root }

// Budget is the current (leaked-to-last-touch) trust budget.
func (h *Harness) Budget() map[string]any { return h.budget }

// Counter is the number of PCActns this harness has emitted.
func (h *Harness) Counter() int64 { return h.counter }

// HarnessMeasurement is what a remote attestation of the MEDIATOR would cover, in place of the unmeasurable model weights.
func (h *Harness) HarnessMeasurement() (string, error) {
	manifest := make([]any, len(h.manifest))
	for i, m := range h.manifest {
		manifest[i] = m
	}
	return ComputeHarnessMeasurement(HarnessVersion, manifest, h.policy)
}

func harnessRefuse(reason, detail string) map[string]any {
	return map[string]any{"ok": false, "reason": reason, "detail": detail}
}

// harnessJSRound is Math.round: the nearest integer, ties toward +Infinity.
func harnessJSRound(x float64) float64 {
	f := math.Floor(x)
	if x-f >= 0.5 {
		return f + 1
	}
	return f
}

// harnessToFixed is Number.prototype.toFixed(digits) for a non-negative finite value (exact decimal expansion, ties up).
func harnessToFixed(x float64, digits int) string {
	if math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x) >= 1e21 {
		return jsNumberString(x)
	}
	r := new(big.Rat).SetFloat64(x)
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	r.Mul(r, new(big.Rat).SetInt(scale))
	r.Add(r, big.NewRat(1, 2))
	n := new(big.Int).Div(r.Num(), r.Denom())
	s := n.String()
	for len(s) <= digits {
		s = "0" + s
	}
	if digits == 0 {
		return s
	}
	return s[:len(s)-digits] + "." + s[len(s)-digits:]
}

func harnessBudgetMap(b TrustBudget) map[string]any {
	return map[string]any{"B": jsNumber(b.B), "tau": jsNumber(b.Tau), "asOf": jsNumber(b.AsOf)}
}

func (h *Harness) trustBudget() TrustBudget {
	b, _ := jsNum(h.budget["B"])
	tau, _ := jsNum(h.budget["tau"])
	asOf, hasAsOf := jsNum(h.budget["asOf"])
	return TrustBudget{B: b, Tau: tau, AsOf: asOf, HasAsOf: hasAsOf && h.budget["asOf"] != nil}
}

func harnessPolF(p map[string]any, k string) float64 {
	if f, ok := jsNum(p[k]); ok {
		return f
	}
	return math.NaN()
}

// Step asks the untrusted oracle for a candidate {verb, resource, params?, nodeId, inputs?} and, only if it survives the gate,
// emits a signed PCActn: {ok: true, pcactn, inclusionProof, risk, budget}, or a refusal {ok: false, reason: "out_of_plan" |
// "over_budget" | "bad_candidate", detail, requiredT?, budget?}. An oracle that fails, or returns a malformed candidate, is a
// refusal, never an error.
func (h *Harness) Step(propose func() (any, error)) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	candV, err := propose()
	if err != nil {
		return harnessRefuse("bad_candidate", "oracle failed: "+err.Error())
	}
	// (0) the oracle is untrusted: validate the shape before use
	cand, isMap := candV.(map[string]any)
	nodeID, ok1 := cand["nodeId"].(string)
	verb, ok2 := cand["verb"].(string)
	resource, ok3 := cand["resource"].(string)
	if !isMap || !ok1 || !ok2 || !ok3 {
		return harnessRefuse("bad_candidate", "oracle returned a malformed candidate")
	}
	// (1) PLAN INCLUSION: reject out-of-plan BEFORE signing
	node := h.planIndex[nodeID]
	if node == nil {
		return harnessRefuse("out_of_plan", fmt.Sprintf("node '%s' is not in the committed plan", nodeID))
	}
	nv, nvOK := node["verb"]
	nr, nrOK := node["resource"]
	if nv != verb || nr != resource {
		return harnessRefuse("out_of_plan", fmt.Sprintf("action %s %s does not match committed node '%s' (%s %s)", verb, resource, nodeID,
			sbxText(nv, nvOK), sbxText(nr, nrOK)))
	}
	proof, err := h.committed.ProofFor(nodeID)
	if err != nil {
		return harnessRefuse("bad_candidate", "could not build PCActn: "+err.Error())
	}
	// (2) TAINT FOLD: only a well-formed 'trusted' input is trusted; anything else counts as untrusted lineage
	var rawInputs []any
	if iv, has := cand["inputs"]; has {
		l, isList := iv.([]any)
		if !isList {
			return harnessRefuse("bad_candidate", "candidate.inputs is not an array")
		}
		rawInputs = l
	}
	inputs := []any{}
	trustedRefs := []any{}
	taint := 0
	for _, i := range rawInputs {
		im, _ := i.(map[string]any)
		ref, refOK := im["ref"].(string)
		if im != nil && im["provenance"] == "trusted" && refOK {
			inputs = append(inputs, map[string]any{"ref": ref, "provenance": "trusted"})
			trustedRefs = append(trustedRefs, ref)
		} else {
			inputs = append(inputs, map[string]any{"ref": ref, "provenance": "untrusted"})
			taint = 1
		}
	}
	riskInputs := map[string]any{}
	for k, v := range h.baseRisk {
		riskInputs[k] = v
	}
	riskInputs["taint"] = jsNumber(float64(taint))
	in := RiskInputs{SemanticDistance: harnessPolF(riskInputs, "semanticDistance"), Reversibility: harnessPolF(riskInputs, "reversibility"),
		BlastRadius: harnessPolF(riskInputs, "blastRadius"), Taint: float64(taint), Confidence: harnessPolF(riskInputs, "confidence"), Age: harnessPolF(riskInputs, "age")}
	w, _ := h.policy["weights"].(map[string]any)
	weights := RiskWeights{Alpha: harnessPolF(w, "alpha"), Beta: harnessPolF(w, "beta"), Gamma: harnessPolF(w, "gamma"), Delta: harnessPolF(w, "delta"),
		Epsilon: harnessPolF(w, "epsilon"), Zeta: harnessPolF(w, "zeta")}
	// rounded to 6 d.p. so the reported r, the signed risk_claim.r and the budget cost agree and stay canonical
	r := harnessJSRound(RiskScore(in, weights)*1e6) / 1e6
	rt := RequiredThresholdOf(r, harnessPolF(h.policy, "theta1"), harnessPolF(h.policy, "theta2"), node["reversibility_class"] == "irreversible")

	// (3) TRUST BUDGET: meter machine-only actions, leaking to now first
	nowMs := h.o.Now()
	leaked := h.trustBudget().Leak(nowMs, harnessPolF(h.policy, "lambda"))
	c := RiskCost(r, harnessPolF(h.policy, "kappa"))
	if rt.T < 3 && !(leaked.B >= c) {
		// the budget cannot cover even a low-risk in-plan action: escalate to a human, debit nothing, produce no PCActn
		h.budget = harnessBudgetMap(leaked)
		out := harnessRefuse("over_budget", fmt.Sprintf("budget %s < cost %s; step up to a human co-sign", harnessToFixed(leaked.B, 4), harnessToFixed(c, 4)))
		out["requiredT"] = 3
		out["budget"] = h.budget
		return out
	}

	// (4) SIGN
	causal, err := HashCanonical(inputs)
	if err != nil {
		return harnessRefuse("bad_candidate", "could not build PCActn: "+err.Error())
	}
	extra := map[string]any{
		"provenance": map[string]any{"causal_hash": causal, "taint_level": jsNumber(float64(taint)), "trusted_refs": trustedRefs},
		"risk_claim": map[string]any{"r": jsNumber(r), "inputs": normalizeJSONKeep(riskInputs)},
	}
	if h.o.Attestation != nil {
		epoch := any(jsNumber(0))
		if e := h.o.Attestation["epoch"]; e != nil {
			epoch = e
		}
		meas, err := h.HarnessMeasurement()
		if err != nil {
			return harnessRefuse("bad_candidate", "could not build PCActn: "+err.Error())
		}
		extra["attestation"] = map[string]any{"quote_digest": "", "epoch": epoch, "model_id": HarnessModelID, "measurement": meas, "operator": h.o.Attestation["operator"]}
	}
	ttl := DefaultTTLMs
	if h.o.TtlMs != nil {
		ttl = *h.o.TtlMs
	}
	nonce := h.o.Nonce()
	extra["nonce"] = nonce
	iat := int64(nowMs)
	pcactn, err := BuildPCActn(PCActnInput{Grant: h.o.Grant, Chain: h.chain, Plan: h.o.Plan, NodeID: nodeID, Params: cand["params"], Counter: h.counter + 1,
		Signer: h.signer, Aud: h.o.Audience, Iat: iat, Exp: iat + ttl, Extra: extra})
	if err != nil {
		// e.g. params do not match the node's committed params_digest: still never emits an out-of-plan action
		msg := strings.Replace(err.Error(), "BuildPCActn:", "buildPCActn:", 1)
		return harnessRefuse("bad_candidate", "could not build PCActn: "+msg)
	}
	// debit only a metered (machine-only, t < 3) action; commit the counter
	if rt.T < 3 {
		h.budget = harnessBudgetMap(leaked.Debit(c))
	} else {
		h.budget = harnessBudgetMap(leaked)
	}
	h.counter++
	return map[string]any{"ok": true, "pcactn": pcactn, "inclusionProof": proof,
		"risk": map[string]any{"r": jsNumber(r), "inputs": riskInputs, "taint": jsNumber(float64(taint)), "t": rt.T}, "budget": h.budget}
}

// harnessNonce is 16 random bytes as hex.
func harnessNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails: a failing system RNG crashes the program
	return hex.EncodeToString(b)
}
