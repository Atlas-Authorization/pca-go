package pca

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Proof of progress toward committed intent. Authority is faithful pursuit of a committed intent: at grant time the goal (objective,
// potential id, embedder id, metric, epsilon, exploration budget) is hashed into a commitment. Each action then carries a step that
// is either progress (potential(after) <= potential(before) - epsilon) or exploration, whose shortfall is charged to a bounded
// budget. The verifier recomputes every potential from the committed id and the carried states; nothing the prover says about
// potentials is trusted. Invariant (strict): the exploration charges sum to at most the budget.
//
// Every step commits, inside one hash-chained body, to the goal commitment, the action digest, the before and after STATE digests,
// the sequence number and the previous step; a step can be Ed25519-signed by the acting holder. Goals, states and steps are decoded
// JSON values (a goal is a map with objective, potential, embedder?, metric, epsilon, explorationBudget; a step is a map). Hashes
// are the STRICT canonical hash (the wire form): a state with a non-integer of more than 15 significant digits, -0 or a lone
// surrogate has no digest. All quantities are safe integers, so recomputation is bit-exact across implementations. Verification
// never fails with an error: any unexpected failure is the denial "malformed".

const (
	// ProgressVersion is the wire / commitment format version of goals, steps and signed proofs.
	ProgressVersion = 2
	// TrajectoryAnchorDomain tags a trajectory-head anchor leaf.
	TrajectoryAnchorDomain = "atlas-pca/trajectory-anchor/v1"
	// StateAttestationDomain tags a signed state attestation (it ends in one NUL byte).
	StateAttestationDomain = "atlas-pca/progress-state-attestation/v1\x00"

	progressGenesis = "genesis"
)

// Step denials (the reason of a refused step or trajectory).
const (
	DenyGoalMismatch         = "goal-mismatch"
	DenyUnknownPotential     = "unknown-potential"
	DenyEmbedderMismatch     = "embedder-mismatch"
	DenyBadPotential         = "bad-potential"
	DenyExplorationExhausted = "exploration-exhausted"
	DenySeqMismatch          = "seq-mismatch"
	DenyChainBreak           = "chain-break"
	DenyDiscontinuousState   = "discontinuous-state"
	DenyDigestMismatch       = "digest-mismatch"
	DenyStateDigestMismatch  = "state-digest-mismatch"
	DenyPotentialMismatch    = "potential-mismatch"
	DenyModeMismatch         = "mode-mismatch"
	DenyChargeMismatch       = "charge-mismatch"
	DenyBudgetExceeded       = "budget-exceeded"
	DenyMalformed            = "malformed"
	DenyActionMismatch       = "action-mismatch"
	DenyStateMismatch        = "state-mismatch"
	DenyBadSignature         = "bad-signature"
	DenyHolderMismatch       = "holder-mismatch"
	DenyProhibited           = "prohibited"
	DenyUntrustedStateSource = "untrusted-state-source"
	DenyAttestationFailed    = "attestation-failed"
	DenyStateSourceMismatch  = "state-source-mismatch"
)

func progIsObj(v any) bool { _, ok := v.(map[string]any); return ok }

func progGet(v any, k string) (any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	x, has := m[k]
	return x, has
}

func progMember(v any, k string) any { x, _ := progGet(v, k); return x }

// progSafeInt is a JSON number that is a safe integer.
func progSafeInt(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && objSafeInt(f)
}

// progAssertInt is the reference's assertInt: a number that is a safe integer.
func progAssertInt(v any, what string) (float64, error) {
	f, ok := progSafeInt(v)
	if !ok {
		return 0, errors.New(what + ": safe integer required")
	}
	return f, nil
}

// progSnapshot is the deep, canonical, detached copy of a state or objective (the lenient round trip).
func progSnapshot(v any) (any, error) {
	s, err := objCanon(v)
	if err != nil {
		return nil, err
	}
	return ParseJSONLenient([]byte(s))
}

// progErr is a refusal carrying its step denial as the code.
func progErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

func progDenialOf(err error) string {
	var ce *CodedError
	if errors.As(err, &ce) && ce.Code != "" {
		return ce.Code
	}
	return DenyBadPotential
}

// ---- potentials and the registry ---------------------------------------------------------

// PotentialFn maps (objective, state) to a non-negative safe integer: "distance to goal". It must be pure; a failure or a result
// that is no non-negative safe integer is a bad potential.
type PotentialFn func(objective, state any) (float64, error)

// PotentialSpec is a registered potential: the function and the embedder id it is bound to ("" = none; it must equal the goal's).
type PotentialSpec struct {
	Fn       PotentialFn
	Embedder string
}

// PotentialRegistry is the verifier-held registry of version-pinned potentials. Lookups are by own id only, ids cannot be shadowed
// once registered, and the registry can be frozen. An id that is not registered fails closed.
type PotentialRegistry struct {
	m      map[string]PotentialSpec
	frozen bool
}

// NewPotentialRegistry is an empty registry.
func NewPotentialRegistry() *PotentialRegistry {
	return &PotentialRegistry{m: map[string]PotentialSpec{}}
}

// Register adds fn under id (1..128 UTF-16 units); re-registering an id is refused (ids are immutable).
func (r *PotentialRegistry) Register(id string, fn PotentialFn, embedder string) error {
	if r.frozen {
		return errors.New("registry is frozen")
	}
	if n := len(utf16.Encode([]rune(id))); n == 0 || n > 128 {
		return errors.New("potential id: 1..128 chars")
	}
	if fn == nil {
		return errors.New("potential must be a function")
	}
	if _, dup := r.m[id]; dup {
		return fmt.Errorf("potential %s already registered", id)
	}
	r.m[id] = PotentialSpec{Fn: fn, Embedder: embedder}
	return nil
}

// Get resolves a committed id.
func (r *PotentialRegistry) Get(id string) (PotentialSpec, bool) { s, ok := r.m[id]; return s, ok }

// Has reports whether id is registered.
func (r *PotentialRegistry) Has(id string) bool { _, ok := r.m[id]; return ok }

// IDs are the registered ids in UTF-16 code unit order.
func (r *PotentialRegistry) IDs() []string {
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	sortUtf16(out)
	return out
}

// Freeze forbids further registration.
func (r *PotentialRegistry) Freeze() *PotentialRegistry { r.frozen = true; return r }

// PotentialRegistryFrom builds a registry from a record of id to spec.
func PotentialRegistryFrom(rec map[string]PotentialSpec) (*PotentialRegistry, error) {
	r := NewPotentialRegistry()
	ids := make([]string, 0, len(rec))
	for k := range rec {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	for _, k := range ids {
		if err := r.Register(k, rec[k].Fn, rec[k].Embedder); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// NewDefaultPotentialRegistry is a fresh, mutable registry holding the three built-in potentials.
func NewDefaultPotentialRegistry() *PotentialRegistry {
	r := NewPotentialRegistry()
	_ = r.Register("l1-feature-v1", L1FeaturePotential, "")
	_ = r.Register("dag-remaining-v1", DagRemainingPotential, "")
	_ = r.Register("dag-weighted-v1", DagWeightedPotential, "")
	return r
}

// DefaultPotentials is the frozen registry of the built-in potentials (used when none is supplied).
var DefaultPotentials = NewDefaultPotentialRegistry().Freeze()

func progRegistry(r *PotentialRegistry) *PotentialRegistry {
	if r == nil {
		return DefaultPotentials
	}
	return r
}

// L1FeaturePotential is the L1 distance in a committed feature space: objective {target: int[]}, state {x: int[]}.
func L1FeaturePotential(objective, state any) (float64, error) {
	t, tok := progMember(objective, "target").([]any)
	x, xok := progMember(state, "x").([]any)
	if !tok || !xok || len(t) != len(x) {
		return 0, errors.New("l1-feature-v1: bad shape")
	}
	d := 0.0
	for i := range t {
		a, err := progAssertInt(t[i], "target")
		if err != nil {
			return 0, err
		}
		b, err := progAssertInt(x[i], "x")
		if err != nil {
			return 0, err
		}
		d += math.Abs(a - b)
		if !objSafeInt(d) {
			return 0, errors.New("distance: safe integer required")
		}
	}
	return d, nil
}

// progSetKey is the identity of a value inside a JavaScript Set (SameValueZero): a composite value is only equal to itself.
func progSetKey(v any, present bool, n *int) string {
	if !present {
		return "u"
	}
	switch t := v.(type) {
	case nil:
		return "z"
	case string:
		return "s" + t
	case bool:
		return "b" + strconv.FormatBool(t)
	case map[string]any, []any:
		*n++
		return "o" + strconv.Itoa(*n)
	}
	f, ok := jsNum(v)
	if !ok {
		*n++
		return "o" + strconv.Itoa(*n)
	}
	if f == 0 {
		f = 0
	}
	return "n" + jsNumberString(f)
}

// DagRemainingPotential is the task-set remaining work: objective {tasks: [{id, cost}]}, state {done: id[]}.
func DagRemainingPotential(objective, state any) (float64, error) {
	tasks, tok := progMember(objective, "tasks").([]any)
	done, dok := progMember(state, "done").([]any)
	if !tok || !dok {
		return 0, errors.New("dag-remaining-v1: bad shape")
	}
	n := 0
	ids := map[string]bool{}
	taskKey := make([]string, len(tasks))
	for i, t := range tasks {
		if t == nil {
			return 0, errors.New("Cannot read properties of null (reading 'id')")
		}
		id, has := progGet(t, "id")
		taskKey[i] = progSetKey(id, has, &n)
		ids[taskKey[i]] = true
	}
	if len(ids) != len(tasks) {
		return 0, errors.New("dag-remaining-v1: duplicate task id")
	}
	doneSet := map[string]bool{}
	for _, d := range done {
		k := progSetKey(d, true, &n)
		if !ids[k] {
			return 0, fmt.Errorf("dag-remaining-v1: unknown task %s", jsValueString(d))
		}
		doneSet[k] = true
	}
	rem := 0.0
	for i, t := range tasks {
		cost, err := progAssertInt(progMember(t, "cost"), "cost")
		if err != nil {
			return 0, err
		}
		if cost < 0 {
			return 0, errors.New("negative cost")
		}
		if !doneSet[taskKey[i]] {
			rem += cost
		}
		if !objSafeInt(rem) {
			return 0, errors.New("remaining: safe integer required")
		}
	}
	return rem, nil
}

// DagWeightedPotential is the weighted-DAG remaining cost with dependency integrity: objective {tasks: [{id, cost >= 0, deps?: id[]}]}
// (ids unique, deps known, graph acyclic); state {done: id[]} (unique ids, DEPENDENCY-CLOSED: a task may be done only if all its deps
// are). V is the sum of cost over not-done tasks; the closure rule means a state cannot claim an expensive leaf done while skipping
// its prerequisites.
func DagWeightedPotential(objective, state any) (float64, error) {
	tasks, tok := progMember(objective, "tasks").([]any)
	done, dok := progMember(state, "done").([]any)
	if !tok || !dok {
		return 0, errors.New("dag-weighted-v1: bad shape")
	}
	type node struct {
		cost float64
		deps []string
	}
	byID := map[string]node{}
	order := []string{}
	for _, t := range tasks {
		tm, isObj := t.(map[string]any)
		id, isStr := "", false
		if isObj {
			id, isStr = tm["id"].(string)
		}
		if !isObj || !isStr || id == "" {
			return 0, errors.New("dag-weighted-v1: bad task")
		}
		if _, dup := byID[id]; dup {
			return 0, errors.New("dag-weighted-v1: duplicate task id")
		}
		cost, err := progAssertInt(tm["cost"], "cost")
		if err != nil {
			return 0, err
		}
		if cost < 0 {
			return 0, errors.New("negative cost")
		}
		var deps []string
		switch d := tm["deps"].(type) {
		case nil:
		case []any:
			for _, x := range d {
				s, ok := x.(string)
				if !ok {
					return 0, errors.New("dag-weighted-v1: bad deps")
				}
				deps = append(deps, s)
			}
		default:
			return 0, errors.New("dag-weighted-v1: bad deps")
		}
		byID[id] = node{cost, deps}
		order = append(order, id)
	}
	// dependencies must exist, and the graph must be acyclic (Kahn)
	indeg := map[string]int{}
	rev := map[string][]string{}
	for _, id := range order {
		uniq := map[string]bool{}
		for _, d := range byID[id].deps {
			uniq[d] = true
		}
		indeg[id] = len(uniq)
		for d := range uniq {
			if _, known := byID[d]; d == id || !known {
				return 0, fmt.Errorf("dag-weighted-v1: bad dependency %s", d)
			}
			rev[d] = append(rev[d], id)
		}
	}
	var q []string
	for _, id := range order {
		if indeg[id] == 0 {
			q = append(q, id)
		}
	}
	seen := 0
	for len(q) > 0 {
		id := q[len(q)-1]
		q = q[:len(q)-1]
		seen++
		for _, n := range rev[id] {
			indeg[n]--
			if indeg[n] == 0 {
				q = append(q, n)
			}
		}
	}
	if seen != len(byID) {
		return 0, errors.New("dag-weighted-v1: cycle")
	}
	doneSet := map[string]bool{}
	for _, d := range done {
		s, isStr := d.(string)
		if _, known := byID[s]; !isStr || !known {
			return 0, fmt.Errorf("dag-weighted-v1: unknown task %s", jsValueString(d))
		}
		if doneSet[s] {
			return 0, errors.New("dag-weighted-v1: duplicate done")
		}
		doneSet[s] = true
	}
	for d := range doneSet {
		for _, dep := range byID[d].deps {
			if !doneSet[dep] {
				return 0, fmt.Errorf("dag-weighted-v1: %s done before dependency %s", d, dep)
			}
		}
	}
	rem := 0.0
	for _, id := range order {
		if !doneSet[id] {
			rem += byID[id].cost
		}
		if !objSafeInt(rem) {
			return 0, errors.New("remaining: safe integer required")
		}
	}
	return rem, nil
}

// ---- goal commitment ---------------------------------------------------------------------

func progValidateGoal(goal any) error {
	g, ok := goal.(map[string]any)
	if !ok {
		return errors.New("goal must be an object")
	}
	eps, err := progAssertInt(g["epsilon"], "epsilon")
	if err != nil {
		return err
	}
	budget, err := progAssertInt(g["explorationBudget"], "explorationBudget")
	if err != nil {
		return err
	}
	if eps < 1 {
		return errors.New("epsilon must be >= 1")
	}
	if budget < 0 {
		return errors.New("explorationBudget must be >= 0")
	}
	if p, isStr := g["potential"].(string); !isStr || p == "" {
		return errors.New("potential id required")
	}
	if _, isStr := g["metric"].(string); !isStr {
		return errors.New("metric must be a string")
	}
	if e, has := g["embedder"]; has {
		if _, isStr := e.(string); !isStr {
			return errors.New("embedder must be a string")
		}
	}
	return nil
}

// ProgressGoalDigest is the commitment hash of a goal: it binds the objective, potential id, embedder (absent and "" are the same),
// metric, epsilon and budget. It refuses an invalid goal.
func ProgressGoalDigest(goal any) (string, error) {
	if err := progValidateGoal(goal); err != nil {
		return "", err
	}
	g := goal.(map[string]any)
	obj, has := g["objective"]
	if !has {
		return "", errors.New("canonicalize: unsupported type undefined")
	}
	embedder, _ := g["embedder"].(string)
	return HashCanonical(map[string]any{
		"t": "pca-goal", "v": jsNumber(ProgressVersion), "objective": obj, "potential": g["potential"], "embedder": embedder,
		"metric": g["metric"], "epsilon": g["epsilon"], "explorationBudget": g["explorationBudget"],
	})
}

// ProgressCommitGoal commits a goal; the returned goal is a detached canonical snapshot.
func ProgressCommitGoal(goal any) (map[string]any, error) {
	c, err := ProgressGoalDigest(goal)
	if err != nil {
		return nil, err
	}
	snap, err := progSnapshot(goal)
	if err != nil {
		return nil, err
	}
	return map[string]any{"goal": snap, "commitment": c}, nil
}

// ProgressVerifyGoalCommitment: a goal is bound iff it hashes to the commitment the grant carries. It never fails.
func ProgressVerifyGoalCommitment(goal any, commitment any) bool {
	c, isStr := commitment.(string)
	if !isStr {
		return false
	}
	d, err := ProgressGoalDigest(goal)
	return err == nil && d == c
}

// ---- steps, digests, anchors -------------------------------------------------------------

func progStepBodyDigest(body map[string]any) (string, error) {
	m := map[string]any{"t": "pca-progress-step", "v": jsNumber(ProgressVersion)}
	for k, v := range body {
		m[k] = v
	}
	return HashCanonical(m)
}

// ProgressStateDigest commits to a state: the strict hash of {t: "pca-state", state}. States must be canonicalizable JSON.
func ProgressStateDigest(state any) (string, error) {
	return HashCanonical(map[string]any{"t": "pca-state", "state": state})
}

// ProgressTrajectoryHead is the digest of the last step, "genesis" for no steps (the head to publish or anchor). A last step without
// a string digest has no head and gives "".
func ProgressTrajectoryHead(steps []any) string {
	if len(steps) == 0 {
		return progressGenesis
	}
	d, _ := progMember(steps[len(steps)-1], "digest").(string)
	return d
}

// ProgressStepDigest is the digest to place in a PCActn alongside params_digest, binding the proof to the action (the step's own
// digest, nil when it has none). A null step is refused.
func ProgressStepDigest(step any) (any, error) {
	if step == nil {
		return nil, errors.New("Cannot read properties of null (reading 'digest')")
	}
	return progMember(step, "digest"), nil
}

// TrajectoryAnchorCommit is the salted commitment of a trajectory head, the opaque leaf appended to the transparency ledger.
func TrajectoryAnchorCommit(salt, head string) (string, error) {
	if salt == "" || head == "" {
		return "", errors.New("trajectoryAnchorCommit: salt and head must be non-empty strings")
	}
	return HashCanonical(map[string]any{"t": TrajectoryAnchorDomain, "salt": salt, "head": head})
}

// VerifyTrajectoryAnchor is true iff salt and head reproduce the anchored commit. It never fails.
func VerifyTrajectoryAnchor(commit, salt, head string) bool {
	c, err := TrajectoryAnchorCommit(salt, head)
	return err == nil && c == commit
}

// TrajectoryLedger is the transparency ledger a head is anchored in (MerkleLog satisfies it).
type TrajectoryLedger interface {
	AppendCommitment(commit string) (int, error)
	Head() map[string]any
}

// TrajectoryAnchor is an anchored head: the head, the salt the caller MUST retain to later open the anchor, the commitment appended,
// its 0-based ledger index and the ledger head (size, root) AFTER the anchor.
type TrajectoryAnchor struct {
	Head       string
	Salt       string
	Commit     string
	Index      int
	LedgerHead map[string]any
}

// AnchorTrajectoryHead appends the current trajectory head to ledger as a salted commitment, so a rollback of the trajectory is
// externally detectable. salt nil is 16 random bytes (base64url); pass one for deterministic output.
func AnchorTrajectoryHead(ledger TrajectoryLedger, steps []any, salt *string) (TrajectoryAnchor, error) {
	head := ProgressTrajectoryHead(steps)
	s := ""
	if salt != nil {
		s = *salt
	} else {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return TrajectoryAnchor{}, err
		}
		s = B64u(b)
	}
	commit, err := TrajectoryAnchorCommit(s, head)
	if err != nil {
		return TrajectoryAnchor{}, err
	}
	idx, err := ledger.AppendCommitment(commit)
	if err != nil {
		return TrajectoryAnchor{}, err
	}
	return TrajectoryAnchor{Head: head, Salt: s, Commit: commit, Index: idx, LedgerHead: ledger.Head()}, nil
}

func progResolve(goal map[string]any, reg *PotentialRegistry) (PotentialSpec, error) {
	pid, _ := goal["potential"].(string)
	spec, ok := reg.Get(pid)
	if !ok {
		return PotentialSpec{}, progErr(DenyUnknownPotential, "unknown potential "+pid)
	}
	e, _ := goal["embedder"].(string)
	if spec.Embedder != e {
		return PotentialSpec{}, progErr(DenyEmbedderMismatch, "embedder mismatch")
	}
	return spec, nil
}

func progPotentialOf(goal map[string]any, reg *PotentialRegistry, state any) (float64, error) {
	spec, err := progResolve(goal, reg)
	if err != nil {
		return 0, err
	}
	p, err := spec.Fn(goal["objective"], state)
	if err == nil && !objSafeInt(p) {
		err = errors.New("potential: safe integer required")
	}
	if err != nil {
		return 0, progErr(DenyBadPotential, err.Error())
	}
	if p < 0 {
		return 0, progErr(DenyBadPotential, "potential must be >= 0")
	}
	return p, nil
}

// progClassify is the single source of truth for mode and charge. Reaching the goal (after == 0) from a state closer than epsilon
// still counts as progress; anything else short of before - epsilon is exploration, charged the integer shortfall (>= 1).
func progClassify(pb, pa, epsilon float64) (mode string, charge float64, err error) {
	required := pb - epsilon
	if pa <= required || (pa == 0 && pb > 0) {
		return "progress", 0, nil
	}
	charge = pa - required
	if !objSafeInt(charge) {
		return "", 0, progErr(DenyBadPotential, "charge: safe integer required")
	}
	return "exploration", charge, nil
}

func progGoalEpsilon(goal map[string]any) float64 { f, _ := jsNum(goal["epsilon"]); return f }
func progGoalBudget(goal map[string]any) float64  { f, _ := jsNum(goal["explorationBudget"]); return f }

// StepTransition is what a guard sees.
type StepTransition struct {
	Seq          int
	Before       any
	After        any
	ActionDigest string
}

// StepGuard is the negative-authority hook (compose a prohibition set here): return true to ALLOW the transition. It runs in the
// tracker and in the verifier, so a forbidden action cannot be laundered through a good-looking descent.
type StepGuard func(t StepTransition) bool

// StateAttestationVerifier lets the verifier check source-specific evidence (receipt, TEE quote, zk) for a step.
type StateAttestationVerifier func(step map[string]any) bool

// ---- trusted state contract --------------------------------------------------------------

// StateObservation is what a StateSource hands back after an action.
type StateObservation struct {
	State       any    // the observed world state after the action (canonical JSON)
	StateDigest string // must equal ProgressStateDigest(State)
	Source      string // must equal the source's id
	Evidence    any    // source-specific proof
}

// StateObservationRequest is what the tracker asks of a source.
type StateObservationRequest struct {
	ActionDigest   string
	GoalCommitment string
	PriorDigest    string // the state the tracker believes the world is in before the action (continuity anchor)
}

// StateSource is the trust boundary: a production source observes the REAL effect of the action and attests to it. The tracker
// commits to what the source returns; it does not establish the source's honesty. A nil observation is refused.
type StateSource interface {
	ID() string
	Observe(req StateObservationRequest) (*StateObservation, error)
}

// InMemoryStateSource is a StateSource for tests and demos: the "world" is a value mutated through Apply.
type InMemoryStateSource struct {
	cur      any
	n        int
	id       string
	Requests []StateObservationRequest
}

// NewInMemoryStateSource starts the world at initial; id "" is "in-memory".
func NewInMemoryStateSource(initial any, id string) (*InMemoryStateSource, error) {
	if id == "" {
		id = "in-memory"
	}
	s, err := progSnapshot(initial)
	if err != nil {
		return nil, err
	}
	return &InMemoryStateSource{cur: s, id: id}, nil
}

// ID is the source id.
func (s *InMemoryStateSource) ID() string { return s.id }

// Apply mutates the world (what the real action would do).
func (s *InMemoryStateSource) Apply(next any) error {
	c, err := progSnapshot(next)
	if err != nil {
		return err
	}
	s.cur = c
	return nil
}

// Observe returns the current world, with an unsigned evidence record.
func (s *InMemoryStateSource) Observe(req StateObservationRequest) (*StateObservation, error) {
	s.Requests = append(s.Requests, req)
	state, err := progSnapshot(s.cur)
	if err != nil {
		return nil, err
	}
	d, err := ProgressStateDigest(state)
	if err != nil {
		return nil, err
	}
	ev := map[string]any{"kind": "in-memory", "n": jsNumber(float64(s.n)), "prior": req.PriorDigest, "action": req.ActionDigest}
	s.n++
	return &StateObservation{State: state, StateDigest: d, Source: s.id, Evidence: ev}, nil
}

// ---- attested state source ---------------------------------------------------------------

func progAttestationMessage(base map[string]any, alg any, algPresent bool, pqPk any, pqPresent bool) ([]byte, error) {
	bound, ok := BindSuiteFields(base, alg, algPresent, pqPk, pqPresent)
	if !ok {
		return nil, errors.New("unknown signature alg")
	}
	body, err := canonBytes(bound)
	if err != nil {
		return nil, err
	}
	return append([]byte(StateAttestationDomain), body...), nil
}

// VerifyStateAttestation verifies a state attestation's signature under a TRUSTED source public key, bound to its exact statement.
// pqPins maps a trusted key to the pinned post-quantum key (required for a pure post-quantum or hybrid attestation). The legacy
// unpinned-key opt-out is not supported. It never fails.
func VerifyStateAttestation(att any, trustedPublicKey any, pqPins map[string]string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	a, isMap := att.(map[string]any)
	if !isMap {
		return false
	}
	sig, sigOK := a["sig"].(string)
	source, srcOK := a["source"].(string)
	key, keyOK := trustedPublicKey.(string)
	if !sigOK || !srcOK || !keyOK || key == "" {
		return false
	}
	alg, algPresent := a["alg"]
	if _, known := ResolveSigAlg(alg, algPresent); !known {
		return false
	}
	pqPk, pqPresent := a["pq_pk"]
	msg, err := progAttestationMessage(map[string]any{
		"source": source, "goal_commitment": a["goal_commitment"], "action_digest": a["action_digest"],
		"prior_digest": a["prior_digest"], "state_digest": a["state_digest"],
	}, alg, algPresent, pqPk, pqPresent)
	if err != nil {
		return false
	}
	return VerifyPinnedSuite(alg, algPresent, key, pqPk, msg, sig, a["pq_sig"], pqPins)
}

// AttestedStateSourceOpts is what the caller supplies for an AttestedStateSource.
type AttestedStateSourceOpts struct {
	// ID is the source id (the step's state_source; it must be in the verifier's trusted sources).
	ID string
	// SignerSecret is the source's 32-byte Ed25519 seed; it signs each attestation.
	SignerSecret []byte
	// ObserveState observes the REAL post-action world state for a request.
	ObserveState func(req StateObservationRequest) (any, error)
	// Suite is the signature suite (nil is ed25519); for ml-dsa-65 / hybrid it carries the source's ML-DSA key pair.
	Suite *SuiteOpts
}

// AttestedStateSource is a StateSource whose observations carry a VERIFIABLE SIGNED attestation of "state_digest is the state after
// action_digest applied to prior_digest, for this goal, observed by me". Pair it with AttestedStateVerifier and trusted sources.
type AttestedStateSource struct {
	id           string
	PublicKey    string // the source's base64url Ed25519 public key: register it in the verifier's trusted-key map
	key          *KeyPair
	observeState func(StateObservationRequest) (any, error)
	suite        *SuiteOpts
	pqPk         string
	hasPq        bool
	attestations []map[string]any
}

// NewAttestedStateSource validates the options.
func NewAttestedStateSource(o AttestedStateSourceOpts) (*AttestedStateSource, error) {
	if o.ID == "" {
		return nil, errors.New("AttestedStateSource: id is required")
	}
	if o.ObserveState == nil {
		return nil, errors.New("AttestedStateSource: observeState must be a function")
	}
	if _, known := ResolveSigAlg(o.Suite.alg(), true); !known {
		return nil, fmt.Errorf("AttestedStateSource: unknown signature alg '%s'", o.Suite.alg())
	}
	kp, err := KeyPairFromSeed(o.SignerSecret)
	if err != nil {
		return nil, err
	}
	s := &AttestedStateSource{id: o.ID, PublicKey: kp.Public, key: kp, observeState: o.ObserveState, suite: o.Suite}
	s.pqPk, s.hasPq = SuitePqPublicKey(o.Suite)
	return s, nil
}

// ID is the source id.
func (s *AttestedStateSource) ID() string { return s.id }

// Attestations are the signed attestations emitted so far (hand these to AttestedStateVerifier).
func (s *AttestedStateSource) Attestations() []map[string]any {
	return append([]map[string]any(nil), s.attestations...)
}

// Observe observes the state, signs the statement and returns it as the observation's evidence.
func (s *AttestedStateSource) Observe(req StateObservationRequest) (*StateObservation, error) {
	raw, err := s.observeState(req)
	if err != nil {
		return nil, err
	}
	state, err := progSnapshot(raw)
	if err != nil {
		return nil, err
	}
	d, err := ProgressStateDigest(state)
	if err != nil {
		return nil, err
	}
	stmt := map[string]any{
		"source": s.id, "goal_commitment": req.GoalCommitment, "action_digest": req.ActionDigest, "prior_digest": req.PriorDigest, "state_digest": d,
	}
	var pq any
	if s.hasPq {
		pq = s.pqPk
	}
	alg := s.suite.alg()
	msg, err := progAttestationMessage(stmt, alg, alg != DefaultSigAlg, pq, s.hasPq)
	if err != nil {
		return nil, err
	}
	fields, err := SignSuiteArtifact(s.suite, s.key, msg)
	if err != nil {
		return nil, err
	}
	att := map[string]any{}
	for k, v := range stmt {
		att[k] = v
	}
	for k, v := range fields {
		att[k] = v
	}
	s.attestations = append(s.attestations, att)
	return &StateObservation{State: state, StateDigest: d, Source: s.id, Evidence: att}, nil
}

// AttestedStateVerifierOpts is the trusted-key map and the attestations to check steps against.
type AttestedStateVerifierOpts struct {
	// TrustedKeys maps a source id to its trusted base64url Ed25519 public key; a step whose state_source is absent fails closed.
	TrustedKeys map[string]string
	// PqPins pins the post-quantum key by trusted source key (required for a pure post-quantum or hybrid attestation).
	PqPins map[string]string
	// Attestations are the signed attestations to match steps against (entries that are no attestation are skipped).
	Attestations []any
}

// AttestedStateVerifier builds the hook for VerifyProgressStep / VerifyTrajectory. For each step it looks up the trusted key of the
// step's state_source (fail closed if not trusted), finds the attestation matching the step's {action, before to after} digests,
// recomputes the step's evidence_digest from that attestation and requires an exact match (the step must commit to this very
// attestation), and verifies the attestation's signature under the trusted key.
func AttestedStateVerifier(opts AttestedStateVerifierOpts) StateAttestationVerifier {
	key := func(a, p, s string) string { return a + "\x00" + p + "\x00" + s }
	byKey := map[string]map[string]any{}
	for _, x := range opts.Attestations {
		a, isMap := x.(map[string]any)
		if !isMap {
			continue
		}
		act, ok1 := a["action_digest"].(string)
		prior, ok2 := a["prior_digest"].(string)
		state, ok3 := a["state_digest"].(string)
		if ok1 && ok2 && ok3 {
			byKey[key(act, prior, state)] = a
		}
	}
	return func(step map[string]any) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		src, _ := step["state_source"].(string)
		pub, has := opts.TrustedKeys[src]
		if !has || pub == "" {
			return false
		}
		act, _ := step["action_digest"].(string)
		bef, _ := step["before_digest"].(string)
		aft, _ := step["after_digest"].(string)
		att, found := byKey[key(act, bef, aft)]
		if !found || att["source"] != any(src) {
			return false
		}
		h, err := HashCanonical(map[string]any{"t": "pca-evidence", "e": att})
		if err != nil || h != step["evidence_digest"] {
			return false
		}
		return VerifyStateAttestation(att, pub, opts.PqPins)
	}
}

// ---- prover / issuer side ----------------------------------------------------------------

// ProveResult is the outcome of a tracker step: the step with the totals, or the denial (StepUp: exploration exhausted means
// human step-up or denial).
type ProveResult struct {
	OK        bool
	Step      map[string]any
	Spent     float64
	Remaining float64
	Reason    string
	StepUp    bool
}

// TrackerOptions are the tracker's options.
type TrackerOptions struct {
	// Guard is the negative-authority check applied to every transition.
	Guard StepGuard
}

// ProgressTracker is the stateful tracker of one trajectory: it holds the last state, the chain head and the exploration spent. A step
// that would push spent over the budget is REFUSED (no proof is produced, the state does not advance), which is the "forces
// step-up or denial" mechanism. In memory: concurrent agents sharing a goal need atomic escrow.
type ProgressTracker struct {
	seq       int
	head      string
	spent     float64
	cur       any
	curDigest string
	log       []map[string]any
	reg       *PotentialRegistry
	opts      TrackerOptions
	// Goal is the detached snapshot of the committed goal.
	Goal map[string]any
	// Commitment is the goal commitment.
	Commitment string
}

// NewProgressTracker refuses a goal that does not match the commitment and an initial state the potential rejects (the refusal
// carries the denial as its code). registry nil is the frozen default.
func NewProgressTracker(goal any, commitment string, initial any, registry *PotentialRegistry, opts TrackerOptions) (*ProgressTracker, error) {
	if !ProgressVerifyGoalCommitment(goal, commitment) {
		return nil, errors.New("goal does not match commitment")
	}
	snap, err := progSnapshot(goal)
	if err != nil {
		return nil, err
	}
	t := &ProgressTracker{head: progressGenesis, reg: progRegistry(registry), opts: opts, Goal: snap.(map[string]any), Commitment: commitment}
	if t.cur, err = progSnapshot(initial); err != nil {
		return nil, err
	}
	if t.curDigest, err = ProgressStateDigest(t.cur); err != nil {
		return nil, err
	}
	if _, err := progPotentialOf(t.Goal, t.reg, t.cur); err != nil { // fail fast: unknown id / embedder / bad initial state
		return nil, err
	}
	return t, nil
}

// Spent is the total exploration charged so far (always <= the budget).
func (t *ProgressTracker) Spent() float64 { return t.spent }

// Remaining is the budget left.
func (t *ProgressTracker) Remaining() float64 { return progGoalBudget(t.Goal) - t.spent }

// State is the current state.
func (t *ProgressTracker) State() any { return t.cur }

// CurrentStateDigest is the digest of the current state.
func (t *ProgressTracker) CurrentStateDigest() string { return t.curDigest }

// Reached is true when the current state has potential 0.
func (t *ProgressTracker) Reached() (bool, error) {
	p, err := progPotentialOf(t.Goal, t.reg, t.cur)
	return err == nil && p == 0, err
}

// Steps are the proofs issued so far (a copy).
func (t *ProgressTracker) Steps() []map[string]any { return append([]map[string]any(nil), t.log...) }

// Step attempts a step to a self-reported after state. It does not advance on denial.
func (t *ProgressTracker) Step(after any, actionDigest string) ProveResult {
	return t.advance(after, actionDigest, "", "")
}

// StepObserved observes the post-action state from a StateSource and steps to it. The observation's digest and source id are
// checked, and the source id and evidence digest are committed into the step. It does not advance on any denial.
func (t *ProgressTracker) StepObserved(source StateSource, actionDigest string) ProveResult {
	mismatch := ProveResult{Reason: DenyStateSourceMismatch}
	obs, err := source.Observe(StateObservationRequest{ActionDigest: actionDigest, GoalCommitment: t.Commitment, PriorDigest: t.curDigest})
	if err != nil || obs == nil || obs.Source != source.ID() {
		return mismatch
	}
	d, err := ProgressStateDigest(obs.State)
	if err != nil || d != obs.StateDigest {
		return mismatch
	}
	ev, err := HashCanonical(map[string]any{"t": "pca-evidence", "e": obs.Evidence})
	if err != nil {
		return mismatch
	}
	return t.advance(obs.State, actionDigest, source.ID(), ev)
}

func progRunGuard(g StepGuard, tr StepTransition) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return g(tr)
}

func (t *ProgressTracker) advance(afterIn any, actionDigest, stateSource, evidenceDigest string) ProveResult {
	if actionDigest == "" {
		return ProveResult{Reason: DenyMalformed}
	}
	after, err := progSnapshot(afterIn)
	var afterDigest string
	var pb, pa, charge float64
	var mode string
	if err == nil {
		afterDigest, err = ProgressStateDigest(after)
	}
	if err == nil {
		pb, err = progPotentialOf(t.Goal, t.reg, t.cur)
	}
	if err == nil {
		pa, err = progPotentialOf(t.Goal, t.reg, after)
	}
	if err == nil {
		mode, charge, err = progClassify(pb, pa, progGoalEpsilon(t.Goal))
	}
	if err != nil {
		return ProveResult{Reason: progDenialOf(err)}
	}
	if t.opts.Guard != nil && !progRunGuard(t.opts.Guard, StepTransition{Seq: t.seq, Before: t.cur, After: after, ActionDigest: actionDigest}) {
		return ProveResult{Reason: DenyProhibited}
	}
	next := t.spent + charge
	if !objSafeInt(next) || next > progGoalBudget(t.Goal) {
		return ProveResult{Reason: DenyExplorationExhausted, StepUp: true}
	}
	body := map[string]any{
		"goal_commitment": t.Commitment, "seq": jsNumber(float64(t.seq)), "before": t.cur, "after": after,
		"before_digest": t.curDigest, "after_digest": afterDigest, "action_digest": actionDigest, "mode": mode,
		"potential_before": jsNumber(pb), "potential_after": jsNumber(pa), "charge": jsNumber(charge),
		"state_source": stateSource, "evidence_digest": evidenceDigest, "prev": t.head,
	}
	digest, err := progStepBodyDigest(body)
	if err != nil {
		return ProveResult{Reason: DenyBadPotential}
	}
	step := map[string]any{"digest": digest}
	for k, v := range body {
		step[k] = v
	}
	t.log = append(t.log, step)
	t.seq++
	t.head = digest
	t.spent = next
	t.cur = after
	t.curDigest = afterDigest
	return ProveResult{OK: true, Step: step, Spent: t.spent, Remaining: t.Remaining()}
}

// ---- verifier side -----------------------------------------------------------------------

// VerifyStepOptions are the options of VerifyProgressStep.
type VerifyStepOptions struct {
	ExpectedSeq  *float64
	ExpectedPrev *string
	// ExpectedActionDigest requires the step to be bound to this action digest.
	ExpectedActionDigest *string
	// ExpectedBeforeDigest / ExpectedAfterDigest require the step to start from / end at this state digest.
	ExpectedBeforeDigest *string
	ExpectedAfterDigest  *string
	// Registry nil is the frozen default.
	Registry *PotentialRegistry
	// Guard is the negative-authority check re-run by the verifier.
	Guard StepGuard
	// TrustedStateSources, when non-nil, lists the state_source ids allowed ("" / self-reported is refused unless listed).
	TrustedStateSources []string
	// RequireAttestedState nil or true (the default): a step whose after state is self-reported by the prover (state_source "") is
	// refused, whatever TrustedStateSources lists. false accepts it: the proof then shows only that the CLAIMED states descend,
	// not that the world reached them.
	RequireAttestedState *bool
	// Attestation, when set, must return true for the step (evidence check).
	Attestation StateAttestationVerifier
}

// VerifyStepResult is a verified step's charge or the denial.
type VerifyStepResult struct {
	OK     bool
	Charge float64
	Reason string
}

func progFail(reason string) VerifyStepResult { return VerifyStepResult{Reason: reason} }

// progIsStep is the shape of a step: strings, safe integers (negatives pass the shape check and fail later), a mode, and the
// before / after members present (null is present).
func progIsStep(s any) (map[string]any, bool) {
	m, ok := s.(map[string]any)
	if !ok {
		return nil, false
	}
	for _, k := range []string{"goal_commitment", "before_digest", "after_digest", "action_digest", "state_source", "evidence_digest", "prev", "digest"} {
		if _, isStr := m[k].(string); !isStr {
			return nil, false
		}
	}
	if seq, ok := progSafeInt(m["seq"]); !ok || seq < 0 {
		return nil, false
	}
	if m["mode"] != "progress" && m["mode"] != "exploration" {
		return nil, false
	}
	for _, k := range []string{"potential_before", "potential_after", "charge"} {
		if _, ok := progSafeInt(m[k]); !ok {
			return nil, false
		}
	}
	_, hasBefore := m["before"]
	_, hasAfter := m["after"]
	return m, hasBefore && hasAfter
}

func progStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// VerifyProgressStep is the stateless re-check of one step against the committed goal. Pure and deterministic; it never fails with
// an error. Nothing the step claims is trusted: the state digests, both potentials, the mode and the charge are recomputed. The
// first failure wins, in this order: goal commitment, shape, step goal, expected seq / prev / action / before / after, body digest,
// state digests, potentials, potential values, mode, charge, trusted sources, attested-state requirement, guard, attestation hook.
func VerifyProgressStep(goal any, commitment string, step any, opts VerifyStepOptions) (res VerifyStepResult) {
	defer func() {
		if recover() != nil {
			res = progFail(DenyMalformed)
		}
	}()
	if !ProgressVerifyGoalCommitment(goal, commitment) {
		return progFail(DenyGoalMismatch)
	}
	s, ok := progIsStep(step)
	if !ok {
		return progFail(DenyMalformed)
	}
	if progStr(s, "goal_commitment") != commitment {
		return progFail(DenyGoalMismatch)
	}
	if opts.ExpectedSeq != nil {
		if seq, _ := jsNum(s["seq"]); seq != *opts.ExpectedSeq {
			return progFail(DenySeqMismatch)
		}
	}
	if opts.ExpectedPrev != nil && progStr(s, "prev") != *opts.ExpectedPrev {
		return progFail(DenyChainBreak)
	}
	if opts.ExpectedActionDigest != nil && progStr(s, "action_digest") != *opts.ExpectedActionDigest {
		return progFail(DenyActionMismatch)
	}
	if opts.ExpectedBeforeDigest != nil && progStr(s, "before_digest") != *opts.ExpectedBeforeDigest {
		return progFail(DenyStateMismatch)
	}
	if opts.ExpectedAfterDigest != nil && progStr(s, "after_digest") != *opts.ExpectedAfterDigest {
		return progFail(DenyStateMismatch)
	}
	body := make(map[string]any, len(s))
	for k, v := range s {
		if k != "digest" {
			body[k] = v
		}
	}
	bd, err := progStepBodyDigest(body)
	if err != nil {
		return progFail(DenyMalformed)
	}
	if bd != progStr(s, "digest") {
		return progFail(DenyDigestMismatch)
	}
	bs, err := ProgressStateDigest(s["before"])
	if err != nil {
		return progFail(DenyMalformed)
	}
	as, err := ProgressStateDigest(s["after"])
	if err != nil {
		return progFail(DenyMalformed)
	}
	if bs != progStr(s, "before_digest") || as != progStr(s, "after_digest") {
		return progFail(DenyStateDigestMismatch)
	}
	g := goal.(map[string]any)
	reg := progRegistry(opts.Registry)
	pb, err := progPotentialOf(g, reg, s["before"])
	var pa, charge float64
	var mode string
	if err == nil {
		pa, err = progPotentialOf(g, reg, s["after"])
	}
	if err == nil {
		mode, charge, err = progClassify(pb, pa, progGoalEpsilon(g))
	}
	if err != nil {
		return progFail(progDenialOf(err))
	}
	if cpb, _ := jsNum(s["potential_before"]); pb != cpb {
		return progFail(DenyPotentialMismatch)
	}
	if cpa, _ := jsNum(s["potential_after"]); pa != cpa {
		return progFail(DenyPotentialMismatch)
	}
	if s["mode"] != mode {
		return progFail(DenyModeMismatch)
	}
	if cc, _ := jsNum(s["charge"]); cc != charge {
		return progFail(DenyChargeMismatch)
	}
	src := progStr(s, "state_source")
	if opts.TrustedStateSources != nil {
		trusted := false
		for _, t := range opts.TrustedStateSources {
			if t == src {
				trusted = true
			}
		}
		if !trusted {
			return progFail(DenyUntrustedStateSource)
		}
	}
	if (opts.RequireAttestedState == nil || *opts.RequireAttestedState) && src == "" {
		return progFail(DenyUntrustedStateSource)
	}
	seq, _ := jsNum(s["seq"])
	if opts.Guard != nil && !progRunGuard(opts.Guard, StepTransition{Seq: int(seq), Before: s["before"], After: s["after"], ActionDigest: progStr(s, "action_digest")}) {
		return progFail(DenyProhibited)
	}
	if opts.Attestation != nil {
		pass := func() (r bool) {
			defer func() {
				if recover() != nil {
					r = false
				}
			}()
			return opts.Attestation(s)
		}()
		if !pass {
			return progFail(DenyAttestationFailed)
		}
	}
	return VerifyStepResult{OK: true, Charge: charge}
}

// VerifyTrajectoryOptions are the options of VerifyTrajectory (the step options without the per-step expectations).
type VerifyTrajectoryOptions struct {
	Registry             *PotentialRegistry
	Guard                StepGuard
	TrustedStateSources  []string
	RequireAttestedState *bool
	Attestation          StateAttestationVerifier
	// Initial, when HasInitial, requires the first step to start from this state.
	Initial    any
	HasInitial bool
	// InitialDigest is the same by digest (preferred when the state itself is not at hand); it wins over Initial.
	InitialDigest *string
	// ExpectedActionDigests, when non-nil, requires step[i].action_digest == ExpectedActionDigests[i] (and equal length).
	ExpectedActionDigests []string
}

// TrajectoryResult is a verified trajectory, or the denial and the step it was found at (-1 for the whole).
type TrajectoryResult struct {
	OK             bool
	Spent          float64
	Remaining      float64
	Reached        bool
	FinalPotential float64 // -1 if empty and no initial given
	Steps          int
	Head           string
	Reason         string
	At             int
}

func progTrajFail(reason string, at int) TrajectoryResult {
	return TrajectoryResult{Reason: reason, At: at}
}

// VerifyTrajectory verifies a whole trajectory: goal binding, every step re-checked, hash-chained, states contiguous
// (step[i].after_digest == step[i+1].before_digest), starting from Initial if given, per-step action binding if given, and the
// strict global invariant sum(charge) <= explorationBudget. It recomputes the charges itself and never trusts a claimed total.
func VerifyTrajectory(goal any, commitment string, steps any, opts VerifyTrajectoryOptions) TrajectoryResult {
	if !ProgressVerifyGoalCommitment(goal, commitment) {
		return progTrajFail(DenyGoalMismatch, -1)
	}
	list, isList := steps.([]any)
	if !isList {
		return progTrajFail(DenyMalformed, -1)
	}
	if opts.ExpectedActionDigests != nil && len(opts.ExpectedActionDigests) != len(list) {
		at := len(opts.ExpectedActionDigests)
		if len(list) < at {
			at = len(list)
		}
		return progTrajFail(DenyActionMismatch, at)
	}
	var anchor *string
	switch {
	case opts.InitialDigest != nil:
		anchor = opts.InitialDigest
	case opts.HasInitial:
		d, err := ProgressStateDigest(opts.Initial)
		if err != nil {
			return progTrajFail(DenyMalformed, -1)
		}
		anchor = &d
	}
	g := goal.(map[string]any)
	prev := progressGenesis
	spent := 0.0
	finalPotential := -1.0
	if len(list) == 0 && opts.HasInitial {
		p, err := progPotentialOf(g, progRegistry(opts.Registry), opts.Initial)
		if err != nil {
			return progTrajFail(progDenialOf(err), -1)
		}
		finalPotential = p
	}
	budget := progGoalBudget(g)
	for i, s := range list {
		so := VerifyStepOptions{
			Registry: opts.Registry, Guard: opts.Guard, TrustedStateSources: opts.TrustedStateSources,
			RequireAttestedState: opts.RequireAttestedState, Attestation: opts.Attestation,
		}
		seq := float64(i)
		so.ExpectedSeq, so.ExpectedPrev = &seq, &prev
		if opts.ExpectedActionDigests != nil {
			so.ExpectedActionDigest = &opts.ExpectedActionDigests[i]
		}
		r := VerifyProgressStep(goal, commitment, s, so)
		if !r.OK {
			return progTrajFail(r.Reason, i)
		}
		sm := s.(map[string]any)
		if anchor != nil && progStr(sm, "before_digest") != *anchor {
			return progTrajFail(DenyDiscontinuousState, i)
		}
		spent += r.Charge
		if !objSafeInt(spent) || spent > budget {
			return progTrajFail(DenyBudgetExceeded, i)
		}
		a := progStr(sm, "after_digest")
		anchor = &a
		prev = progStr(sm, "digest")
		finalPotential, _ = jsNum(sm["potential_after"])
	}
	return TrajectoryResult{OK: true, Spent: spent, Remaining: budget - spent, Reached: finalPotential == 0, FinalPotential: finalPotential, Steps: len(list), Head: prev}
}

// ---- signed proofs (Ed25519, domain-separated) --------------------------------------------

func progSigMessage(step map[string]any, holder string) ([]byte, error) {
	b := map[string]any{"holder": holder}
	for _, k := range [][2]string{{"goal_commitment", "goal_commitment"}, {"action_digest", "action_digest"}, {"before_digest", "before_digest"},
		{"after_digest", "after_digest"}, {"seq", "seq"}, {"prev", "prev"}, {"step_digest", "digest"}} {
		x, has := step[k[1]]
		if !has {
			return nil, errors.New("SignProgressStep: step." + k[1] + " is required")
		}
		b[k[0]] = x
	}
	return msgOfDB(ProgressSigDomain, b)
}

// SignProgressStepAs signs a step with key, committing holderPublicKey (the key's public half) into the message. The holder is not
// checked against the key: a verifier expecting a holder rejects a mismatch.
func SignProgressStepAs(step map[string]any, key *KeyPair, holderPublicKey string) (map[string]any, error) {
	st, err := normObj(step)
	if err != nil {
		return nil, err
	}
	m, err := progSigMessage(st, holderPublicKey)
	if err != nil {
		return nil, err
	}
	return map[string]any{"step": st, "holder": holderPublicKey, "sig": b64.EncodeToString(key.Sign(m))}, nil
}

// VerifySignedStepOptions are the options of VerifySignedProgressStep. ExpectedActionDigest and ExpectedHolder are REQUIRED: an absent
// one never matches.
type VerifySignedStepOptions struct {
	VerifyStepOptions
	ExpectedHolder *string
}

func progSignedShape(sp any) (map[string]any, string, string, bool) {
	m, ok := sp.(map[string]any)
	if !ok {
		return nil, "", "", false
	}
	holder, hok := m["holder"].(string)
	sig, sok := m["sig"].(string)
	step, stok := progIsStep(m["step"])
	return step, holder, sig, hok && sok && stok
}

func progSigOK(step map[string]any, holder, sig string) bool {
	msg, err := progSigMessage(step, holder)
	return err == nil && VerifyB64u(holder, msg, sig)
}

// VerifySignedProgressStep verifies a signed step offline: the expected holder, the expected action and the goal binding, then the
// signature (strict Ed25519, domain-separated) over the binding fields, THEN the full deterministic step re-check. Rebinding to
// another action, goal, state or holder fails.
func VerifySignedProgressStep(goal any, commitment string, signed any, opts VerifySignedStepOptions) (res VerifyStepResult) {
	defer func() {
		if recover() != nil {
			res = progFail(DenyMalformed)
		}
	}()
	step, holder, sig, ok := progSignedShape(signed)
	if !ok {
		return progFail(DenyMalformed)
	}
	if opts.ExpectedHolder == nil || holder != *opts.ExpectedHolder {
		return progFail(DenyHolderMismatch)
	}
	if opts.ExpectedActionDigest == nil || progStr(step, "action_digest") != *opts.ExpectedActionDigest {
		return progFail(DenyActionMismatch)
	}
	if progStr(step, "goal_commitment") != commitment {
		return progFail(DenyGoalMismatch)
	}
	if !progSigOK(step, holder, sig) {
		return progFail(DenyBadSignature)
	}
	return VerifyProgressStep(goal, commitment, step, opts.VerifyStepOptions)
}

// VerifySignedTrajectoryOptions are the options of VerifySignedTrajectory: ExpectedActionDigests (step[i] must be bound to it) and
// ExpectedHolder (every step must be signed by it) are REQUIRED.
type VerifySignedTrajectoryOptions struct {
	VerifyTrajectoryOptions
	ExpectedHolder *string
}

// VerifySignedTrajectory verifies the signatures on every step (see VerifySignedProgressStep), then the whole trajectory.
func VerifySignedTrajectory(goal any, commitment string, signed any, opts VerifySignedTrajectoryOptions) TrajectoryResult {
	list, isList := signed.([]any)
	if !isList || opts.ExpectedActionDigests == nil {
		return progTrajFail(DenyMalformed, -1)
	}
	if len(opts.ExpectedActionDigests) != len(list) {
		at := len(opts.ExpectedActionDigests)
		if len(list) < at {
			at = len(list)
		}
		return progTrajFail(DenyActionMismatch, at)
	}
	steps := make([]any, len(list))
	for i, sp := range list {
		step, holder, sig, ok := progSignedShape(sp)
		if !ok {
			return progTrajFail(DenyMalformed, i)
		}
		if opts.ExpectedHolder == nil || holder != *opts.ExpectedHolder {
			return progTrajFail(DenyHolderMismatch, i)
		}
		if progStr(step, "action_digest") != opts.ExpectedActionDigests[i] {
			return progTrajFail(DenyActionMismatch, i)
		}
		if !progSigOK(step, holder, sig) {
			return progTrajFail(DenyBadSignature, i)
		}
		steps[i] = sp.(map[string]any)["step"]
	}
	return VerifyTrajectory(goal, commitment, steps, opts.VerifyTrajectoryOptions)
}
