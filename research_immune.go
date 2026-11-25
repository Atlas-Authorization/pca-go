package pca

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// The behavioural immune system: the per-principal risk baseline, the observation fold, the state validation and the threat read
// the console uses, the policy adaptation and the signed tightening proposal. A heuristic (EWMA and z-score over one principal's
// history): it can be gamed by a slow attacker who drifts the baseline and is no proof that an agent is compromised or benign.
//
// An immune state is {baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}; an observation is {r, at, stepUp?, denied?}.

// ImmuneConfig tunes the observation fold and the threat read.
type ImmuneConfig struct {
	// Alpha is the EWMA weight of the newest sample.
	Alpha float64
	// HalfLifeMs is the half life of the step-up and deny counters.
	HalfLifeMs float64
	// DriftZSat, StepUpSat and DenySat are the values at which each signal saturates to 1.
	DriftZSat, StepUpSat, DenySat float64
}

// DefaultImmuneConfig is the reference tuning.
var DefaultImmuneConfig = ImmuneConfig{Alpha: 0.3, HalfLifeMs: 3_600_000, DriftZSat: 3, StepUpSat: 5, DenySat: 3}

// AdaptConfig bounds the policy adaptation.
type AdaptConfig struct {
	// MaxKappaMult is the largest factor kappa is raised by (at threat score 1).
	MaxKappaMult float64
	// MinThetaMult is the smallest factor the thresholds are lowered to (at threat score 1).
	MinThetaMult float64
}

// DefaultAdaptConfig is the reference bound: kappa x3, theta x0.4.
var DefaultAdaptConfig = AdaptConfig{MaxKappaMult: 3, MinThetaMult: 0.4}

const immuneMaxCount = 1e9

// ImmuneEmptyBaseline is the empty baseline {n: 0, mean: 0, m2: 0}.
func ImmuneEmptyBaseline() map[string]any {
	return map[string]any{"n": jsNumber(0), "mean": jsNumber(0), "m2": jsNumber(0)}
}

// InitialImmuneState is the state of a principal with no history.
func InitialImmuneState() map[string]any {
	return map[string]any{"baseline": ImmuneEmptyBaseline(), "ewma": jsNumber(0), "stepUps": jsNumber(0), "denies": jsNumber(0), "lastAt": jsNumber(0), "seeded": false}
}

func immuneFinNum(x any) float64 {
	if rsFinite(x) {
		return jsF(x)
	}
	return 0
}

// ImmuneUpdateBaseline is the Welford update of a baseline with one risk sample (a non-finite sample counts as 0).
func ImmuneUpdateBaseline(b map[string]any, r float64) map[string]any {
	x := r
	if math.IsNaN(r) || math.IsInf(r, 0) {
		x = 0
	}
	n := jsF(b["n"]) + 1
	delta := x - jsF(b["mean"])
	mean := jsF(b["mean"]) + delta/n
	m2 := jsF(b["m2"]) + float64(delta*(x-mean)) // rounded product: no fused multiply-add
	return map[string]any{"n": rsN(n), "mean": rsN(mean), "m2": rsN(m2)}
}

// ImmuneBaselineStd is the population standard deviation of the baseline (0 until at least 2 samples).
func ImmuneBaselineStd(b map[string]any) float64 {
	n := jsF(b["n"])
	if n >= 2 {
		return math.Sqrt(jsF(b["m2"]) / n)
	}
	return 0
}

// immuneDecayStepsPerHalfLife is the resolution of the decay: elapsed time counts in 1/1024ths of a half-life, rounded down.
const immuneDecayStepsPerHalfLife = 1024

// immuneDecayStep is 2^(-1/1024) as the nearest double (the reference's literal).
const immuneDecayStep = 0.9993233275026507

// immuneDecay is exponential decay by a half-life from operations every platform computes identically: u = floor(1024*dt/halfLife),
// the factor is 0.5 multiplied floor(u/1024) times and then 2^(-1/1024) multiplied (u mod 1024) times, in that order, one IEEE
// multiplication at a time. No pow, exp or log (their last digit differs between libms); the explicit conversions keep arm64 from
// fusing a product into a following sum.
func immuneDecay(count, dtMs, halfLife float64) float64 {
	if dtMs <= 0 || count == 0 {
		return count
	}
	u := math.Floor(float64(dtMs*immuneDecayStepsPerHalfLife) / halfLife)
	if math.IsNaN(u) {
		return math.NaN()
	}
	if u >= immuneDecayStepsPerHalfLife*1100 { // 0.5^1100 underflows
		return count * 0
	}
	k := math.Floor(u / immuneDecayStepsPerHalfLife)
	m := u - float64(k*immuneDecayStepsPerHalfLife)
	f := 1.0
	for i := 0.0; i < k; i++ {
		f = float64(f * 0.5)
	}
	for i := 0.0; i < m; i++ {
		f = float64(f * immuneDecayStep)
	}
	return float64(count * f)
}

// ImmuneObserve folds one observation into the immune state (baseline, recent EWMA, decayed step-up and deny counters).
func ImmuneObserve(state, obs map[string]any) map[string]any {
	return ImmuneObserveWith(state, obs, DefaultImmuneConfig)
}

// ImmuneObserveWith is ImmuneObserve with an explicit tuning.
func ImmuneObserveWith(state, obs map[string]any, cfg ImmuneConfig) map[string]any {
	r := math.Max(0, math.Min(1, immuneFinNum(obs["r"])))
	lastAt := jsF(state["lastAt"])
	at := lastAt
	if rsFinite(obs["at"]) {
		at = jsF(obs["at"])
	}
	seeded := state["seeded"] == true
	dt := 0.0
	if seeded {
		dt = math.Max(0, at-lastAt)
	}
	baseline := ImmuneUpdateBaseline(rsMap(state["baseline"]), r)
	ewma := r
	if seeded {
		ewma = float64(cfg.Alpha*r) + float64((1-cfg.Alpha)*jsF(state["ewma"]))
	}
	stepUps := immuneDecay(jsF(state["stepUps"]), dt, cfg.HalfLifeMs)
	if rsTruthy(obs["stepUp"]) {
		stepUps++
	}
	denies := immuneDecay(jsF(state["denies"]), dt, cfg.HalfLifeMs)
	if rsTruthy(obs["denied"]) {
		denies++
	}
	return map[string]any{"baseline": baseline, "ewma": rsN(ewma), "stepUps": rsN(stepUps), "denies": rsN(denies), "lastAt": rsN(at), "seeded": true}
}

func immuneInRange(x any, lo, hi float64) bool { return rsFinite(x) && jsF(x) >= lo && jsF(x) <= hi }

// ValidateImmuneState returns the reason a state is malformed (non-finite, negative, out of bound), or "" when it is sound.
func ValidateImmuneState(s any) string {
	x := rsMap(s)
	if x == nil {
		if _, isArr := s.([]any); !isArr { // an array is an object whose named members are undefined
			return "state must be an object"
		}
		x = map[string]any{}
	}
	b := rsMap(x["baseline"])
	if b == nil {
		if _, isArr := x["baseline"].([]any); !isArr {
			return "baseline missing"
		}
		b = map[string]any{}
	}
	if n := b["n"]; !immuneInRange(n, 0, immuneMaxCount) || jsF(n) != math.Floor(jsF(n)) || (jsF(n) == 0 && math.Signbit(jsF(n))) {
		return "baseline.n must be an integer in [0, 1e9]"
	}
	if !immuneInRange(b["mean"], 0, 1) {
		return "baseline.mean must be in [0, 1]"
	}
	if !immuneInRange(b["m2"], 0, immuneMaxCount) {
		return "baseline.m2 must be finite and >= 0"
	}
	if !immuneInRange(x["ewma"], 0, 1) {
		return "ewma must be in [0, 1]"
	}
	if !immuneInRange(x["stepUps"], 0, immuneMaxCount) {
		return "stepUps must be finite and >= 0"
	}
	if !immuneInRange(x["denies"], 0, immuneMaxCount) {
		return "denies must be finite and >= 0"
	}
	if !immuneInRange(x["lastAt"], 0, 9007199254740991) {
		return "lastAt must be a finite non-negative time"
	}
	if _, ok := x["seeded"].(bool); !ok {
		return "seeded must be a boolean"
	}
	return ""
}

func immuneThreat(level string, score float64, signals []string, drift, volatility, violation float64) map[string]any {
	sig := make([]any, len(signals))
	for i, s := range signals {
		sig[i] = s
	}
	return map[string]any{"level": level, "score": rsN(score), "signals": sig,
		"components": map[string]any{"drift": rsN(drift), "volatility": rsN(volatility), "violation": rsN(violation)}}
}

// ImmuneAssess is the current threat from the immune state: {level: calm|elevated|high, score, signals, components: {drift, volatility,
// violation}}. The score is the maximum of the drift, step-up volatility and violation signals; levels switch at 0.33 and 0.66. A
// malformed state is the maximal threat.
func ImmuneAssess(state any) map[string]any { return ImmuneAssessWith(state, DefaultImmuneConfig) }

// ImmuneAssessWith is ImmuneAssess with an explicit tuning.
func ImmuneAssessWith(state any, cfg ImmuneConfig) map[string]any {
	if bad := ValidateImmuneState(state); bad != "" {
		return immuneThreat("high", 1, []string{"invalid immune state: " + bad}, 1, 1, 1)
	}
	st := rsMap(state)
	base := rsMap(st["baseline"])
	std := ImmuneBaselineStd(base)
	signals := []string{}
	drift := 0.0
	if jsF(base["n"]) >= 5 && std > 1e-9 {
		z := (jsF(st["ewma"]) - jsF(base["mean"])) / std
		drift = rsClamp01(z / cfg.DriftZSat)
		if drift > 0.33 {
			signals = append(signals, "risk drifted "+rsToFixed(z, 1)+"σ above baseline")
		}
	}
	stepUps, denies := jsF(st["stepUps"]), jsF(st["denies"])
	volatility := rsClamp01(stepUps / cfg.StepUpSat)
	if volatility > 0.33 {
		signals = append(signals, "elevated step-up rate ("+rsToFixed(stepUps, 1)+")")
	}
	violation := rsClamp01(denies / cfg.DenySat)
	if violation > 0.33 {
		signals = append(signals, "repeated policy violations ("+rsToFixed(denies, 1)+")")
	}
	score := math.Max(drift, math.Max(volatility, violation))
	level := "calm"
	if score >= 0.66 {
		level = "high"
	} else if score >= 0.33 {
		level = "elevated"
	}
	return immuneThreat(level, score, signals, drift, volatility, violation)
}

func immuneAdaptation(policy any, changed bool, rationale string) map[string]any {
	return map[string]any{"policy": policy, "changed": changed, "rationale": rationale}
}

// ImmuneAdapt derives the adapted policy for a threat assessment from the BASE policy (never compounded): {policy, changed, rationale}.
// A malformed adaptation, or one that would loosen the base, keeps the base. It errors only when the base is missing under a threat.
func ImmuneAdapt(base any, assessment map[string]any) (map[string]any, error) {
	return ImmuneAdaptWith(base, assessment, DefaultAdaptConfig)
}

// ImmuneAdaptWith is ImmuneAdapt with explicit caps.
func ImmuneAdaptWith(baseIn any, assessment map[string]any, cfg AdaptConfig) (map[string]any, error) {
	base := rsMap(baseIn) // a non-object spreads to nothing
	if base == nil {
		base = map[string]any{}
	}
	s := 1.0 // a non-finite score is the worst case, never calm
	if rsFinite(assessment["score"]) {
		s = rsClamp01(jsF(assessment["score"]))
	}
	if s == 0 {
		return immuneAdaptation(baseIn, false, "calm — baseline policy"), nil
	}
	if baseIn == nil {
		return nil, errors.New("base policy missing")
	}
	kappaMult := 1 + float64((cfg.MaxKappaMult-1)*s)
	thetaMult := 1 - float64((1-cfg.MinThetaMult)*s)
	policy := make(map[string]any, len(base)+4)
	for k, v := range base {
		policy[k] = v
	}
	if w := rsMap(base["weights"]); w != nil {
		cp := make(map[string]any, len(w))
		for k, v := range w {
			cp[k] = v
		}
		policy["weights"] = cp
	} else {
		policy["weights"] = map[string]any{}
	}
	policy["kappa"] = rsN(rsNaNum(base["kappa"]) * kappaMult)
	policy["theta1"] = rsN(rsClamp01(rsNaNum(base["theta1"]) * thetaMult))
	policy["theta2"] = rsN(rsClamp01(rsNaNum(base["theta2"]) * thetaMult))
	bad := validateRiskPolicy(policy)
	if bad == "" {
		v, err := ImmuneNoWidenViolation(base, policy)
		if err != nil {
			return nil, err
		}
		bad = v
	}
	if bad != "" {
		return immuneAdaptation(baseIn, false, "adaptation rejected ("+bad+") — kept baseline"), nil
	}
	sig, _ := assessment["signals"].([]any)
	var why string
	if len(sig) > 0 {
		parts := make([]string, len(sig))
		for i, x := range sig {
			parts[i] = jsValueString(x)
		}
		why = strings.Join(parts, "; ")
	} else {
		why = "threat score " + rsToFixed(s, 2)
	}
	return immuneAdaptation(policy, true, jsValueString(assessment["level"])+": "+why+" → κ ×"+rsToFixed(kappaMult, 2)+", θ ×"+rsToFixed(thetaMult, 2)), nil
}

func immuneSame(a, b any) bool {
	x, okx := jsNum(a)
	y, oky := jsNum(b)
	if okx && oky {
		return x == y
	}
	if okx != oky {
		return false
	}
	return deepEq(a, b)
}

// ImmuneNoWidenViolation returns why adapted is looser than base, or "" when it only tightens (kappa up, thetas down, the rest
// identical). A non-number reads as looser. It errors when base or adapted carries no weights object.
func ImmuneNoWidenViolation(base, adapted map[string]any) (string, error) {
	// null and booleans coerce to numbers in a relational comparison: a value that is not a number is a violation before any comparison
	for _, k := range []string{"kappa", "theta1", "theta2"} {
		if _, isNum := jsNum(adapted[k]); !isNum {
			return "kappa and theta must be numbers", nil
		}
	}
	if !(rsNaNum(adapted["kappa"]) >= rsNaNum(base["kappa"])) {
		return "kappa decreased", nil
	}
	if !(rsNaNum(adapted["theta1"]) <= rsNaNum(base["theta1"])) {
		return "theta1 increased", nil
	}
	if !(rsNaNum(adapted["theta2"]) <= rsNaNum(base["theta2"])) {
		return "theta2 increased", nil
	}
	for _, k := range []string{"lambda", "rho", "bMax"} {
		if !immuneSame(adapted[k], base[k]) {
			return k + " changed", nil
		}
	}
	bw, aw := rsMap(base["weights"]), rsMap(adapted["weights"])
	if bw == nil {
		return "", errors.New("base.weights missing")
	}
	if aw == nil {
		return "", errors.New("adapted.weights missing")
	}
	for _, k := range sortedKeysUtf8(bw) {
		if !immuneSame(aw[k], bw[k]) {
			return "weights." + k + " changed", nil
		}
	}
	return "", nil
}

// ImmuneAssertNoWiden errors unless adapted only tightens base.
func ImmuneAssertNoWiden(base, adapted map[string]any) error {
	v, err := ImmuneNoWidenViolation(base, adapted)
	if err != nil {
		return err
	}
	if v != "" {
		return fmt.Errorf("immune: adaptation widens the policy (%s)", v)
	}
	return nil
}

// TighteningDomain is the signing domain of a tightening proposal.
const TighteningDomain = "atlas-pca/immune-tightening/v1\x00"

func immuneTighteningMessage(claim map[string]any) ([]byte, error) {
	body, err := Canonicalize(claim)
	if err != nil {
		return nil, err
	}
	return append([]byte(TighteningDomain), body...), nil
}

// ImmunePolicyDigest is the digest of a risk policy.
func ImmunePolicyDigest(policy any) (string, error) { return HashCanonicalLenient(policy) }

// ImmuneStateDigest is the digest of an immune state.
func ImmuneStateDigest(state any) (string, error) { return HashCanonicalLenient(state) }

// IssueTighteningProposal derives and signs the tightening for state. It errors on a malformed base, an epoch that is not an integer
// >= 1, a non-finite now or a malformed state (never an unsigned loosening). guardianSecret is the 32-byte Ed25519 seed.
func IssueTighteningProposal(base, state map[string]any, epoch, now any, guardianSecret []byte) (map[string]any, error) {
	if bad := validateRiskPolicy(base); bad != "" {
		return nil, errors.New("issueTighteningProposal: " + bad)
	}
	if !jsIsInt(epoch) || jsF(epoch) < 1 {
		return nil, errors.New("issueTighteningProposal: epoch must be an integer >= 1")
	}
	if !rsFinite(now) {
		return nil, errors.New("issueTighteningProposal: now must be finite")
	}
	key, err := KeyPairFromSeed(guardianSecret)
	if err != nil {
		return nil, err
	}
	ad, err := ImmuneAdapt(base, ImmuneAssess(state))
	if err != nil {
		return nil, err
	}
	baseDigest, err := ImmunePolicyDigest(base)
	if err != nil {
		return nil, err
	}
	stateDigest, err := HashCanonicalLenient(state)
	if err != nil {
		return nil, err
	}
	claim := map[string]any{"v": jsNumber(1), "base_digest": baseDigest, "state_digest": stateDigest, "epoch": epoch, "issued_at": now,
		"policy": ad["policy"], "rationale": ad["rationale"], "guardian": key.Public}
	msg, err := immuneTighteningMessage(claim)
	if err != nil {
		return nil, err
	}
	p := make(map[string]any, len(claim)+1)
	for k, v := range claim {
		p[k] = v
	}
	p["sig"] = B64u(key.Sign(msg))
	return p, nil
}

func immuneRefused(reason string) map[string]any {
	return map[string]any{"ok": false, "reason": reason}
}

// ApplyTightening verifies a proposal and returns {ok: true, policy, epoch} or {ok: false, reason}; it never fails. o holds the pinned
// guardian (b64u, required), lastEpoch, now, maxAgeMs and optionally state (a recompute check).
func ApplyTightening(base, p, o map[string]any) (out map[string]any) {
	defer func() {
		if recover() != nil {
			out = immuneRefused("malformed")
		}
	}()
	one := jsNumber(1)
	if p == nil || !immuneSame(p["v"], one) {
		return immuneRefused("malformed")
	}
	sig, sOk := p["sig"].(string)
	guardian, gOk := p["guardian"].(string)
	if !sOk || !gOk {
		return immuneRefused("malformed")
	}
	if pin, ok := o["guardian"].(string); !ok || pin != guardian {
		return immuneRefused("guardian")
	}
	claim := make(map[string]any, len(p))
	for k, v := range p {
		if k != "sig" {
			claim[k] = v
		}
	}
	msg, err := immuneTighteningMessage(claim)
	if err != nil {
		return immuneRefused("malformed")
	}
	if !VerifyB64u(guardian, msg, sig) {
		return immuneRefused("signature")
	}
	pol := rsMap(p["policy"])
	if validateRiskPolicy(base) != "" || validateRiskPolicy(p["policy"]) != "" {
		return immuneRefused("invalid-policy")
	}
	if pol == nil {
		return immuneRefused("malformed")
	}
	if bd, err := ImmunePolicyDigest(base); err != nil || p["base_digest"] != bd {
		return immuneRefused("base")
	}
	now, at := rsNaNum(o["now"]), rsNaNum(p["issued_at"])
	if math.IsNaN(now) || math.IsInf(now, 0) || math.IsNaN(at) || math.IsInf(at, 0) || at > now || !(now-at <= rsNaNum(o["maxAgeMs"])) {
		return immuneRefused("stale")
	}
	epoch := p["epoch"]
	if !jsIsInt(epoch) || !(rsNaNum(epoch) > rsNaNum(o["lastEpoch"])) {
		return immuneRefused("replayed-epoch")
	}
	if v, err := ImmuneNoWidenViolation(base, pol); err != nil || v != "" {
		return immuneRefused("widens")
	}
	if st := o["state"]; rsTruthy(st) {
		sd, err := HashCanonicalLenient(st)
		if err != nil || p["state_digest"] != sd {
			return immuneRefused("state-mismatch")
		}
		ad, err := ImmuneAdapt(base, ImmuneAssess(st))
		if err != nil {
			return immuneRefused("state-mismatch")
		}
		d1, e1 := ImmunePolicyDigest(ad["policy"])
		d2, e2 := ImmunePolicyDigest(pol)
		if e1 != nil || e2 != nil || d1 != d2 {
			return immuneRefused("state-mismatch")
		}
	}
	return map[string]any{"ok": true, "policy": pol, "epoch": epoch}
}

// ---- durable state ----------------------------------------------------------------------------------------------

// ImmuneStore keeps immune state and the applied epoch for one subject over an atomic key/value store, so a restart keeps the
// history and the replay floor.
type ImmuneStore struct {
	kv         AtomicKV
	sKey, eKey string
}

// CreateImmuneStore opens the immune store of one subject.
func CreateImmuneStore(kv AtomicKV, subject string) *ImmuneStore {
	return &ImmuneStore{kv: kv, sKey: "immune/state/" + subject, eKey: "immune/epoch/" + subject}
}

func immuneDecodeNum(b []byte) any {
	if b == nil {
		return nil
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil
	}
	return v
}

// Get is the stored state, or the initial one.
func (s *ImmuneStore) Get() (map[string]any, error) {
	b, ok, err := s.kv.Get(s.sKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return InitialImmuneState(), nil
	}
	m := rsMap(immuneDecodeNum(b))
	if m == nil {
		return nil, errors.New("immune store: stored state is not an object")
	}
	return m, nil
}

// Observe folds one observation atomically; it errors when the stored state is malformed (it is never silently reset to calm).
func (s *ImmuneStore) Observe(obs map[string]any) (map[string]any, error) {
	var out map[string]any
	var ferr error
	err := s.kv.Update(s.sKey, func(prev []byte) []byte {
		ferr, out = nil, nil
		var cur any = InitialImmuneState()
		if prev != nil {
			cur = immuneDecodeNum(prev)
		}
		if bad := ValidateImmuneState(cur); bad != "" {
			ferr = fmt.Errorf("immune store: stored state invalid (%s)", bad)
			return nil
		}
		out = ImmuneObserve(rsMap(cur), obs)
		b, e := json.Marshal(out)
		if e != nil {
			ferr = e
			return nil
		}
		return b
	})
	if err != nil {
		return nil, err
	}
	if ferr != nil {
		return nil, ferr
	}
	return out, nil
}

// LastEpoch is the epoch floor of the last applied tightening (0 for none).
func (s *ImmuneStore) LastEpoch() (int64, error) {
	b, ok, err := s.kv.Get(s.eKey)
	if err != nil || !ok {
		return 0, err
	}
	if v := immuneDecodeNum(b); rsIsNum(v) {
		return int64(jsF(v)), nil
	}
	return 0, nil
}

// Apply verifies and applies a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win.
// o is as for ApplyTightening without lastEpoch.
func (s *ImmuneStore) Apply(base, p, o map[string]any) (map[string]any, error) {
	out := immuneRefused("malformed")
	err := s.kv.Update(s.eKey, func(prev []byte) []byte {
		oo := make(map[string]any, len(o)+1)
		for k, v := range o {
			oo[k] = v
		}
		oo["lastEpoch"] = jsNumber(0)
		if pv := immuneDecodeNum(prev); rsIsNum(pv) {
			oo["lastEpoch"] = pv
		}
		out = ApplyTightening(base, p, oo)
		if out["ok"] != true {
			return nil
		}
		b, e := json.Marshal(out["epoch"])
		if e != nil {
			return nil
		}
		return b
	})
	return out, err
}
