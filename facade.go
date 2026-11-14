package pca

// The facade: CreateAgent compiles human-level inputs (permissions, limits) into the real primitives (a policy envelope, a
// risk policy, a signed Root Intent Grant naming the harness's provenance recorder) and returns a handle that builds one
// proof-carrying action per tool call. Nothing here authorizes anything: the resource server's verifier decides, and every
// field the facade emits is covered by a signature. Same compile-down as the reference facade, byte for byte.

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- catalog --------------------------------------------------------------------------------------------------------------

// CatalogAction is one action definition: the verb `connector.action`, its reversibility class (reversible < rate_limited <
// irreversible), a blast-radius preset in [0, 1], and for money-moving actions the params field that carries the amount.
type CatalogAction struct {
	Connector     string
	Action        string
	Verb          string
	Reversibility string
	BlastRadius   float64
	AmountField   string // "" when the action moves no money
	Resource      string // the default resource matcher; "" is any resource ("*")
	Description   string
	Aliases       []string // other names the definition answers to (`refund` for `stripe.refund`)
	Traits        []string
}

// Catalog resolves verbs (and aliases) to action definitions.
type Catalog struct {
	byVerb map[string]CatalogAction
}

// NewCatalog builds a catalog; a later definition of a verb replaces an earlier one.
func NewCatalog(actions []CatalogAction) *Catalog {
	c := &Catalog{byVerb: map[string]CatalogAction{}}
	for _, a := range actions {
		c.byVerb[a.Verb] = a
	}
	return c
}

// DefaultCatalog is the catalog of the built-in actions.
func DefaultCatalog() *Catalog { return NewCatalog(BuiltinActions) }

// Get returns the definition of a verb.
func (c *Catalog) Get(verb string) (CatalogAction, bool) {
	a, ok := c.byVerb[verb]
	return a, ok
}

// Resolve returns connector.action, else the one action of the connector that has action as an alias (never a guess: two
// aliases of the same name resolve to nothing).
func (c *Catalog) Resolve(connector, action string) (CatalogAction, bool) {
	if a, ok := c.byVerb[connector+"."+action]; ok {
		return a, true
	}
	var hit CatalogAction
	n := 0
	for _, a := range c.byVerb {
		if a.Connector == connector && contains(a.Aliases, action) {
			hit, n = a, n+1
		}
	}
	return hit, n == 1
}

// specFor is the definition of verb; an uncatalogued verb is irreversible with blast radius 0.8.
func specFor(c *Catalog, verb string) CatalogAction {
	if s, ok := c.Get(verb); ok {
		return s
	}
	if dot := strings.IndexByte(verb, '.'); dot > 0 {
		if s, ok := c.Resolve(verb[:dot], verb[dot+1:]); ok {
			return s
		}
	}
	parts := strings.Split(verb, ".")
	action := strings.Join(parts[1:], ".")
	if action == "" {
		action = verb
	}
	return CatalogAction{Connector: parts[0], Action: action, Verb: verb, Reversibility: "irreversible", BlastRadius: 0.8,
		Description: "(uncatalogued) " + verb}
}

// ---- limits -----------------------------------------------------------------------------------------------------------------

// ParsedLimit is a parsed limit string: Unit "usd" ($N) or "count" (N), and PeriodMs the window it named (0: none).
type ParsedLimit struct {
	Amount   float64
	Unit     string
	PeriodMs int64
}

var limitPeriods = map[string]int64{
	"s": 1000, "sec": 1000, "second": 1000, "seconds": 1000,
	"m": 60_000, "min": 60_000, "minute": 60_000, "minutes": 60_000,
	"h": 3_600_000, "hr": 3_600_000, "hour": 3_600_000, "hours": 3_600_000,
	"d": 86_400_000, "day": 86_400_000, "days": 86_400_000,
	"w": 604_800_000, "week": 604_800_000, "weeks": 604_800_000,
	"mo": 2_592_000_000, "month": 2_592_000_000, "months": 2_592_000_000,
}

// MaxLimitLength is the longest limit string accepted, in UTF-16 code units.
const MaxLimitLength = 64

// jsWS and jsTrim (JavaScript's \s and String.prototype.trim) are shared with the action schema and attestation code.
var limitRe = regexp.MustCompile(`^(\$)?[` + jsWS + `]*([0-9]+(?:\.[0-9]+)?)[` + jsWS + `]*(?:/[` + jsWS + `]*([a-zA-Z]+))?$`)

// ParseLimit parses "$500/day", "$500", "10/hour" or "10" (periods s, m, h, d, w, mo and their long forms).
func ParseLimit(s string) (ParsedLimit, error) {
	t := jsTrim(s)
	if t == "" {
		return ParsedLimit{}, errors.New("parseLimit: empty limit")
	}
	if jsLen(s) > MaxLimitLength {
		return ParsedLimit{}, fmt.Errorf("parseLimit: limit is longer than %d characters", MaxLimitLength)
	}
	m := limitRe.FindStringSubmatch(t)
	if m == nil {
		return ParsedLimit{}, fmt.Errorf("parseLimit: cannot parse limit '%s'", s)
	}
	unit := "count"
	if m[1] == "$" {
		unit = "usd"
	}
	amount, err := strconv.ParseFloat(m[2], 64)
	if err != nil || math.IsInf(amount, 0) {
		return ParsedLimit{}, fmt.Errorf("parseLimit: bad amount in '%s'", s)
	}
	out := ParsedLimit{Amount: amount, Unit: unit}
	if m[3] != "" {
		p, ok := limitPeriods[strings.ToLower(m[3])]
		if !ok {
			return ParsedLimit{}, fmt.Errorf("parseLimit: unknown period '%s' in '%s'", m[3], s)
		}
		out.PeriodMs = p
	}
	return out, nil
}

// ---- compile ----------------------------------------------------------------------------------------------------------------

// PolicyOptions is what CompilePolicy compiles.
type PolicyOptions struct {
	// Permissions maps a connector to its granted actions: a parsed JSON object (map[string]any, members in text order) or
	// a map[string][]string (connectors in sorted order).
	Permissions any
	// Limits are keyed by fully qualified verb (`stripe.refund`), bare action (`refund`) or alias; the verb wins.
	Limits      map[string]string
	Catalog     *Catalog       // nil: DefaultCatalog()
	BudgetModel string         // "auto" (or ""), "dollars" or "risk"
	RiskPolicy  map[string]any // members that override the derived risk policy (weights merge member by member)
	Now         int64          // epoch ms for the period windows; 0: the wall clock
}

// CompiledPolicy is the policy envelope material CompilePolicy derives.
type CompiledPolicy struct {
	Predicates     []any
	Caveats        []any
	RiskPolicy     map[string]any
	Actions        []CatalogAction
	BudgetModel    string                 // "dollars" or "risk"
	Limits         map[string]ParsedLimit // per verb, the limits that matched a granted action
	InputLimits    map[string]string
	Approximations []string // limits this offline compiler only approximates (a $N/period is a per-call ceiling plus a lifetime)
}

// revSeverity ranks a reversibility class (reversibilityOrder is shared with the caveat evaluator); -1 for an unknown class.
func revSeverity(cls string) int {
	if i, ok := reversibilityOrder[cls]; ok {
		return i
	}
	return -1
}

type permission struct {
	connector string
	actions   any
}

func permissionsOf(p any) ([]permission, error) {
	switch m := p.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		out := []permission{}
		for _, k := range jsKeys(m) {
			out = append(out, permission{k, m[k]})
		}
		return out, nil
	case map[string][]string:
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		out := []permission{}
		for _, k := range ks {
			out = append(out, permission{k, m[k]})
		}
		return out, nil
	}
	return nil, errors.New("compilePolicy: permissions must be an object")
}

// CompilePolicy compiles permissions and limits into predicates, caveats and a risk policy. Pure: no keys, no signing.
// A "$N" limit becomes a per-call ceiling on the action's amount field; the strictest reversibility class becomes a
// reversibility_max caveat, the shortest limit period the grant lifetime, and every "N/period" limit one rate caveat.
func CompilePolicy(o PolicyOptions) (*CompiledPolicy, error) {
	catalog := o.Catalog
	if catalog == nil {
		catalog = DefaultCatalog()
	}
	now := o.Now
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	perms, err := permissionsOf(o.Permissions)
	if err != nil {
		return nil, err
	}
	actions := []CatalogAction{}
	for _, p := range perms {
		var names []string
		switch l := p.actions.(type) {
		case []string:
			names = l
		case []any:
			for _, x := range l {
				names = append(names, jsValueString(x))
			}
		default:
			return nil, fmt.Errorf("compilePolicy: permissions.%s must be an array", p.connector)
		}
		for _, a := range names {
			actions = append(actions, specFor(catalog, p.connector+"."+a))
		}
	}
	if len(actions) == 0 {
		return nil, errors.New("compilePolicy: no permissions granted")
	}

	limits := map[string]ParsedLimit{}
	limitOrder := []string{}
	limitFor := func(s CatalogAction) (*ParsedLimit, error) {
		raw, found := o.Limits[s.Verb]
		if !found {
			raw, found = o.Limits[s.Action]
		}
		for _, a := range s.Aliases {
			if !found {
				raw, found = o.Limits[a]
			}
		}
		if !found {
			return nil, nil
		}
		pl, err := ParseLimit(raw)
		if err != nil {
			return nil, err
		}
		if _, seen := limits[s.Verb]; !seen {
			limitOrder = append(limitOrder, s.Verb)
		}
		limits[s.Verb] = pl
		return &pl, nil
	}

	predicates := []any{}
	for _, s := range actions {
		lim, err := limitFor(s)
		if err != nil {
			return nil, err
		}
		pred := map[string]any{"verb": s.Verb, "resource": "*"}
		if s.Resource != "" {
			pred["resource"] = s.Resource
		}
		if lim != nil && lim.Unit == "usd" {
			if s.AmountField == "" {
				return nil, fmt.Errorf("compilePolicy: '$' limit on '%s' but the catalog gives that verb no amount field, so the limit could not be enforced", s.Verb)
			}
			f := "action.params." + s.AmountField
			pred["where"] = []any{map[string]any{"field": f, "op": "lte", "value": lim.Amount}, map[string]any{"field": f, "op": "gte", "value": 0}}
		}
		predicates = append(predicates, pred)
	}

	strictest := "reversible"
	hasIrreversible := false
	for _, s := range actions {
		if revSeverity(s.Reversibility) > revSeverity(strictest) {
			strictest = s.Reversibility
		}
		hasIrreversible = hasIrreversible || s.Reversibility == "irreversible"
	}
	caveats := []any{map[string]any{"type": "reversibility_max", "class": strictest}}
	minPeriod := int64(0)
	dollars := []ParsedLimit{}
	for _, v := range limitOrder {
		l := limits[v]
		if l.PeriodMs != 0 && (minPeriod == 0 || l.PeriodMs < minPeriod) {
			minPeriod = l.PeriodMs
		}
		if l.Unit == "usd" {
			dollars = append(dollars, l)
		}
	}
	if minPeriod != 0 {
		caveats = append(caveats, map[string]any{"type": "expires", "at": now + minPeriod})
	}
	for _, v := range limitOrder {
		if l := limits[v]; l.Unit == "count" && l.PeriodMs != 0 {
			caveats = append(caveats, map[string]any{"type": "rate", "max": l.Amount, "per_secs": max(1, int64(math.Round(float64(l.PeriodMs)/1000)))})
		}
	}

	model := o.BudgetModel
	if model != "dollars" && model != "risk" {
		model = "risk"
		if len(dollars) > 0 {
			model = "dollars"
		}
	}
	rp := DefaultRiskPolicy()
	if model == "dollars" && len(dollars) > 0 {
		kappa, bMax := math.Inf(-1), 0.0
		for _, l := range dollars {
			kappa = math.Max(kappa, l.Amount)
			bMax += l.Amount
		}
		if kappa <= 0 {
			kappa = 1
		}
		if bMax <= 0 {
			bMax = 1
		}
		// within-cap actions auto-approve only when nothing granted is irreversible; otherwise the default co-sign tiers stay
		t1, t2 := 1.0, 1.0
		if hasIrreversible {
			t1, t2 = 0.25, 0.6
		}
		rp = map[string]any{"weights": map[string]any{"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0},
			"theta1": t1, "theta2": t2, "kappa": kappa, "lambda": 0, "rho": 0.5, "bMax": bMax}
	}
	if o.RiskPolicy != nil {
		w := copyMap(rp["weights"].(map[string]any))
		if ow, ok := o.RiskPolicy["weights"].(map[string]any); ok {
			for k, v := range ow {
				w[k] = v
			}
		}
		for k, v := range o.RiskPolicy {
			rp[k] = v
		}
		rp["weights"] = w
	}
	rpN, err := normObj(rp)
	if err != nil {
		return nil, err
	}
	if bad := riskPolicyError(rpN); bad != "" {
		return nil, errors.New("compilePolicy: derived risk policy invalid: " + bad)
	}
	predN, err := normList(predicates)
	if err != nil {
		return nil, err
	}
	cavN, _ := normList(caveats) // built from strings and finite numbers: always JSON
	approx := []string{}
	for _, v := range limitOrder {
		if l := limits[v]; l.Unit == "usd" && l.PeriodMs != 0 {
			approx = append(approx, v+": $"+jsNumberString(l.Amount)+"/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap")
		}
	}
	in := map[string]string{}
	for k, v := range o.Limits {
		in[k] = v
	}
	return &CompiledPolicy{Predicates: predN, Caveats: cavN, RiskPolicy: rpN, Actions: actions, BudgetModel: model, Limits: limits,
		InputLimits: in, Approximations: approx}, nil
}

// ---- the agent handle --------------------------------------------------------------------------------------------------------

// AgentOptions is what CreateAgent builds an agent from.
type AgentOptions struct {
	Principal   *KeyPair // the human's key: signs and roots the grant
	Goal        string   // plaintext goal; only its salted commitment goes in the grant
	Permissions any      // see PolicyOptions.Permissions
	Limits      map[string]string
	Holder      *KeyPair // the agent key that signs actions; generated when nil
	// Suite is the holder's signature suite (nil: Ed25519). Under a post-quantum suite its Pq key is committed in the grant as
	// the holder's holder_pq and signs every action with it.
	Suite        *SuiteOpts
	AgentBinding map[string]any
	RiskPolicy   map[string]any // overrides of the derived risk policy
	BudgetModel  string         // "auto" (or ""), "dollars" or "risk"
	Catalog      *Catalog       // nil: DefaultCatalog()
	Aud          string         // default audience of Act
	Now          int64          // epoch ms of minting and the limit windows; 0: the wall clock
	// Provenance overrides the harness's recorder options (mediator "agent-harness", kid "k1", a fresh key and session by
	// default). The recorder's pin goes into the grant's signed envelope; keep its key out of the model's reach.
	Provenance *ProvenanceRecorderOptions
	GoalSalt   string // base64url salt of the goal commitment; "" draws one (set it only to reproduce a grant)
}

// FacadeAgent is the handle CreateAgent returns. Safe for concurrent use.
type FacadeAgent struct {
	Grant           map[string]any
	Chain           []map[string]any
	GoalSalt        string
	Policy          *CompiledPolicy
	Holder          *KeyPair
	PrincipalPublic string
	Budget          TrustBudget // the starting trust budget (B = bMax), metered server-side
	AutonomyBound   float64     // the most this agent can do between human co-signs (bMax / kappa * kappa)
	Provenance      *ProvenanceRecorder

	suite    *SuiteOpts
	catalog  *Catalog
	aud      string
	startNow int64
	mu       sync.Mutex
	counter  int64
}

// ActOptions are the per-call options of Act.
type ActOptions struct {
	Counter *int64   // the replay counter; nil: one more than the highest so far
	Aud     string   // "": the agent's default
	Now     int64    // issued-at in epoch ms; 0: the wall clock
	TtlMs   int64    // 0: DefaultTTLMs
	Nonce   string   // signed when given (no nonce by default)
	Caution *float64 // the agent's own uncertainty in [0, 1]: it can only raise server-side risk
	Risk    *float64 // overrides the claimed risk (else from the amount or the blast radius)
}

// DryRunResult is a local, non-authoritative check of the grant's own predicates and caveats. T is the risk tier the compiled
// policy would assign (1 automatic, 2 guardian co-sign, 3 human).
type DryRunResult struct {
	Allowed bool
	Reason  string
	T       int
}

// ActResult is one built action: the PCActn, its encoded JSON, the headers to send (PCA-Action, and PCA-Provenance when the
// bundle fits a header), the local dry run, and the provenance bundle (send it as PCA-Provenance or the body member
// pca_provenance).
type ActResult struct {
	PCActn     map[string]any
	Encoded    string
	Headers    map[string]string
	DryRun     DryRunResult
	Provenance map[string]any
}

// SubAgentOptions configure SubAgent: Holder (generated when nil), HolderPq for a post-quantum agent (generated when nil), and
// the caveats the new hop adds.
type SubAgentOptions struct {
	Holder       *KeyPair
	HolderPq     *PqKeyPair
	AddedCaveats []any
}

const provHeaderMax = 8192

var pqFamilies = map[pqPrim]string{pqMlDsa65: "ML-DSA-65", pqMlDsa87: "ML-DSA-87", pqSlh128f: "SLH-DSA-SHA2-128f", pqSlh256s: "SLH-DSA-SHA2-256s"}

// CreateAgent compiles the inputs into a signed grant and returns the agent that builds actions under it.
func CreateAgent(o AgentOptions) (*FacadeAgent, error) {
	if o.Principal == nil {
		return nil, errors.New("CreateAgent: principal required")
	}
	catalog := o.Catalog
	if catalog == nil {
		catalog = DefaultCatalog()
	}
	now := o.Now
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	holder := o.Holder
	if holder == nil {
		holder, _ = NewKeyPair() // never fails: a fresh 32-byte seed
	}
	suite, holderPq, err := leafSuite(o.Suite)
	if err != nil {
		return nil, err
	}
	policy, err := CompilePolicy(PolicyOptions{Permissions: o.Permissions, Limits: o.Limits, Catalog: catalog, BudgetModel: o.BudgetModel,
		RiskPolicy: o.RiskPolicy, Now: now})
	if err != nil {
		return nil, err
	}
	ro := ProvenanceRecorderOptions{Mediator: "agent-harness", Kid: "k1"}
	if p := o.Provenance; p != nil {
		if p.Mediator != "" {
			ro.Mediator = p.Mediator
		}
		if p.Kid != "" {
			ro.Kid = p.Kid
		}
		ro.Key, ro.Suite, ro.Session, ro.Now = p.Key, p.Suite, p.Session, p.Now
	}
	rec, err := NewProvenanceRecorder(ro)
	if err != nil {
		return nil, err
	}
	ab := o.AgentBinding
	if ab == nil {
		ab = map[string]any{}
	}
	env := map[string]any{"predicates": policy.Predicates, "caveats": policy.Caveats, "agent_binding": ab, "risk_policy": policy.RiskPolicy,
		"provenance": map[string]any{"mediators": []any{rec.Pin.JSON()}}}
	g, err := MintGrant(o.Principal, holder.Public, env, o.Goal, o.GoalSalt, holderPq, nil)
	if err != nil {
		return nil, err
	}
	return newFacadeAgent(g.Grant, []map[string]any{g.Grant}, g.GoalSalt, policy, holder, o.Principal.Public, catalog, o.Aud, now, rec, suite), nil
}

// leafSuite: nil for Ed25519, else the suite and the PQ public key the grant commits as the holder's holder_pq.
func leafSuite(s *SuiteOpts) (*SuiteOpts, string, error) {
	if s.alg() == "ed25519" {
		return nil, "", nil
	}
	su, ok := resolveSigAlg(s.alg(), true)
	if !ok || !su.needsPqPk || s.Pq == nil || s.Pq.prim != su.pq {
		return nil, "", fmt.Errorf("CreateAgent: the suite %s needs a matching post-quantum key pair the agent can sign with", s.alg())
	}
	return s, s.Pq.Public, nil
}

func newFacadeAgent(grant map[string]any, chain []map[string]any, salt string, policy *CompiledPolicy, holder *KeyPair, principal string,
	catalog *Catalog, aud string, startNow int64, rec *ProvenanceRecorder, suite *SuiteOpts) *FacadeAgent {
	bMax, _ := numOf(policy.RiskPolicy["bMax"])
	kappa, _ := numOf(policy.RiskPolicy["kappa"])
	return &FacadeAgent{Grant: grant, Chain: chain, GoalSalt: salt, Policy: policy, Holder: holder, PrincipalPublic: principal,
		Budget:        TrustBudget{B: bMax, Tau: float64(startNow), AsOf: float64(startNow), HasAsOf: true},
		AutonomyBound: SafetyBound(bMax, kappa) * kappa, Provenance: rec, suite: suite, catalog: catalog, aud: aud, startNow: startNow}
}

// riskFor: the override clamped to [0, 1], else amount / kappa in the dollars model, else the blast radius.
func (a *FacadeAgent) riskFor(spec CatalogAction, params map[string]any, override *float64) float64 {
	clamp := func(x float64) float64 { return math.Max(0, math.Min(1, x)) }
	if override != nil {
		return clamp(*override)
	}
	if a.Policy.BudgetModel == "dollars" && spec.AmountField != "" {
		amt := math.NaN()
		if v, has := params[spec.AmountField]; has {
			amt = jsToNumber(v)
		}
		if kappa, _ := numOf(a.Policy.RiskPolicy["kappa"]); !math.IsNaN(amt) && !math.IsInf(amt, 0) && kappa > 0 {
			return clamp(amt / kappa)
		}
	}
	return clamp(spec.BlastRadius)
}

// jsToNumber is JavaScript's Number(v) for a JSON value.
func jsToNumber(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		return jsStringToNumber(x)
	case []any:
		if len(x) == 0 {
			return 0
		}
		if len(x) == 1 {
			return jsToNumber(jsValueString(x[0]))
		}
		return math.NaN()
	case map[string]any:
		return math.NaN()
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	n, _ := NormalizeJSON(v)
	if f, ok := jsNum(n); ok {
		return f
	}
	return math.NaN()
}

func (a *FacadeAgent) riskPolicy() RiskPolicy {
	f := func(k string) float64 { x, _ := numOf(a.Policy.RiskPolicy[k]); return x }
	return RiskPolicy{Theta1: f("theta1"), Theta2: f("theta2"), Kappa: f("kappa"), Lambda: f("lambda"), Rho: f("rho"), BMax: f("bMax")}
}

// DryRun checks the grant's own predicates and caveats for an action, locally and without authority (the server decides).
// now 0 is the wall clock.
func (a *FacadeAgent) DryRun(verb, resource string, params map[string]any, now int64) DryRunResult {
	spec := specFor(a.catalog, verb)
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	p := map[string]any{}
	if params != nil {
		if n, err := normObj(params); err == nil {
			p = n
		}
	}
	ctx := map[string]any{"action": map[string]any{"verb": verb, "resource": resource, "params": p, "reversibility_class": spec.Reversibility}}
	if ok, reason := envelopePredicates(a.Policy.Predicates, ctx, &regexBudget{}); !ok {
		return DryRunResult{Reason: reason}
	}
	// the local handle has no admitted-action history (the server meters it): an empty history, so a rate caveat can hold
	cctx := map[string]any{"now": now, "blast_radius": spec.BlastRadius, "reversibility_class": spec.Reversibility,
		"delegation_depth": len(a.Chain) - 1, "recent_action_times": []any{}}
	if ok, failed := EvaluateCaveats(a.Policy.Caveats, cctx); !ok {
		return DryRunResult{Reason: "caveat(s) failed: " + strings.Join(failed, ", ")}
	}
	adm := Admit(a.riskFor(spec, p, nil), a.Budget, a.riskPolicy())
	return DryRunResult{Allowed: true, T: adm.T}
}

// Act builds the proof-carrying action for one tool call: a one-node plan (node n0, the catalog's reversibility class, the
// params digest) signed by the holder with a risk claim, and the provenance bundle of the action. It does not authorize.
func (a *FacadeAgent) Act(verb, resource string, params map[string]any, o *ActOptions) (*ActResult, error) {
	if o == nil {
		o = &ActOptions{}
	}
	aud := o.Aud
	if aud == "" {
		aud = a.aud
	}
	if aud == "" {
		return nil, errors.New("Act: aud (resource-server / instance id) is required (pass ActOptions.Aud or AgentOptions.Aud)")
	}
	spec := specFor(a.catalog, verb)
	var pv any
	if params != nil {
		pv = params
	}
	digest, err := ParamsDigest(pv)
	if err != nil {
		return nil, err
	}
	node := map[string]any{"id": "n0", "verb": verb, "resource": resource, "reversibility_class": spec.Reversibility, "params_digest": digest}
	pn := map[string]any{}
	if params != nil {
		pn, _ = normObj(params) // ParamsDigest canonicalized it
	}
	r := a.riskFor(spec, pn, o.Risk)
	a.mu.Lock()
	var counter int64
	if o.Counter != nil {
		counter = *o.Counter
		a.counter = max(a.counter, counter)
	} else {
		a.counter++
		counter = a.counter
	}
	a.mu.Unlock()
	extra := map[string]any{"risk_claim": map[string]any{"r": r, "inputs": map[string]any{"blastRadius": r}}}
	if o.Nonce != "" {
		extra["nonce"] = o.Nonce
	}
	if o.Caution != nil {
		extra["caution"] = *o.Caution
	}
	iat := o.Now
	if iat == 0 {
		iat = time.Now().UnixMilli()
	}
	p, err := BuildPCActn(PCActnInput{Grant: a.Grant, Chain: a.Chain, Plan: []map[string]any{node}, NodeID: "n0", Params: pv, Counter: counter,
		Signer: a.Holder, Aud: aud, Iat: iat, TtlMs: o.TtlMs, Extra: extra, Suite: a.suite})
	if err != nil {
		return nil, err
	}
	bundle, err := a.Provenance.ForAction(Operation{Verb: verb, Resource: resource, Params: pn})
	if err != nil {
		return nil, err
	}
	h, _ := PCAHeaders(p, nil, nil, nil) // p canonicalized when it was signed
	if t, err := Canonicalize(bundle); err == nil {
		if v := b64.EncodeToString([]byte(t)); len(v) <= provHeaderMax {
			h[ProvenanceHeader] = v
		}
	}
	enc, _ := canonicalLenient(p)
	return &ActResult{PCActn: p, Encoded: enc, Headers: h, DryRun: a.DryRun(verb, resource, params, o.Now), Provenance: bundle}, nil
}

// SubAgent returns an agent one hop down: the hop (signed by this agent) rebinds the chain to a new holder (generated when not
// given) with the added caveats, sharing the policy, catalog and provenance recorder. A post-quantum agent's sub-agent gets
// its own PQ key (generated when not given), committed in the hop; it never signs with this agent's PQ key.
func (a *FacadeAgent) SubAgent(o SubAgentOptions) (*FacadeAgent, error) {
	sub := o.Holder
	if sub == nil {
		sub, _ = NewKeyPair() // never fails: a fresh 32-byte seed
	}
	var child *SuiteOpts
	holderPq := ""
	if a.suite != nil {
		pq := o.HolderPq
		if pq == nil {
			var err error
			if pq, err = GeneratePqKeyPair(pqFamilies[a.suite.Pq.prim]); err != nil {
				return nil, err
			}
		}
		if pq.prim != a.suite.Pq.prim {
			return nil, fmt.Errorf("SubAgent: the sub-agent's PQ key does not match the suite %s", a.suite.alg())
		}
		child, holderPq = &SuiteOpts{Alg: a.suite.Alg, Pq: pq}, pq.Public
	}
	hop, err := Delegate(a.Chain[len(a.Chain)-1], a.Holder, sub.Public, o.AddedCaveats, holderPq, a.suite)
	if err != nil {
		return nil, err
	}
	chain := append(append([]map[string]any{}, a.Chain...), hop)
	return newFacadeAgent(a.Grant, chain, a.GoalSalt, a.Policy, sub, a.PrincipalPublic, a.catalog, a.aud, a.startNow, a.Provenance, child), nil
}

// EncodeGrant is the grant's canonical JSON (for transport or inspection).
func (a *FacadeAgent) EncodeGrant() (string, error) { return Canonicalize(a.Grant) }
