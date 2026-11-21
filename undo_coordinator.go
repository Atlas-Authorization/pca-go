package pca

// The undo-window coordinator (0.5): admission, the durable ledger, the human surface and the real rollback (port of the
// reference server undo module; the pure record, token, receipts and store contract are in undo.go and undo_store.go).
//
//	Admit      ELIGIBILITY. An action gets a veto window only when ALL of these hold, else it is irreversible (a plain allow
//	           stays an allow, an escalation stays an escalation): the policy for (operation, grant) does not turn windows off;
//	           the signed reversibility class is `reversible`; the Engine (the verifier's own action definitions) returns a plan
//	           (a CONFIRMED definition, effective class reversible, a confirmed compensating action derivable before the effect
//	           runs); and the compensating action is AUTHORIZED under the original grant (the Policy VM releases it over the
//	           original PCActn's verified chain).
//	Open       writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the `opened`
//	           receipt, mints the one-click undo token and notifies the principal. A window nobody was told about is no window:
//	           a failed notification aborts the record and raises an alert.
//	Veto       a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves open -> vetoed exactly
//	           once and starts the compensation.
//	Compensate re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt
//	           through the Operations store and the Compensate executor. Success: `compensated`, the budget reservation
//	           released with a signed `rollback`. Anything else: `compensation_failed`, the reservation kept and an alert raised
//	           (never silent).
//	FinalizeDue closes the windows whose time is up (open -> finalized) and commits their budget reservations.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// UndoRelayGraceMs: with a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands).
const UndoRelayGraceMs int64 = 60_000

const undoMaxCAS = 64

// UndoPlanCompensation is the compensating action a confirmed definition names.
type UndoPlanCompensation struct {
	Verb      string
	Params    map[string]any
	DefDigest string
	// TargetParam is the compensating definition's resource-id parameter ("" = none).
	TargetParam string
}

// UndoPlan is what the verifier's action definitions say about undoing an operation.
type UndoPlan struct {
	// DefDigest is the digest of the CONFIRMED definition of the original action.
	DefDigest    string
	Compensation UndoPlanCompensation
	// Render and RenderDigest are the canonical render of the original action and H(R): what the principal is shown (nil / "" = none).
	Render       map[string]any
	RenderDigest string
}

// UndoEngine is the source of confirmed reversibility. It must answer from SIGNED, reviewer-confirmed definitions only. A nil
// plan means "not undoable" (irreversible); an error is a refusal (fail closed).
type UndoEngine interface {
	Plan(op Operation, operationID string) (*UndoPlan, error)
}

// UndoPolicy is the per-(operation, grant) window policy.
type UndoPolicy struct {
	// Mode is "always" (default: every eligible action gets a window), "escalations" (only an action that would have asked
	// first) or "off".
	Mode string
	// WindowMs is the veto window (clamped into the coordinator's bounds; never below 30 s); nil = the default.
	WindowMs *float64
	// OnRevocation is "keep" (default: the principal is told and can still veto) or "veto".
	OnRevocation string
}

// UndoWindowAdmission is the result of a successful Admit: everything Open needs.
type UndoWindowAdmission struct {
	ID           string
	OpenedAt     int64
	WindowEnd    int64
	Converted    bool
	Plan         UndoPlan
	Compensation UndoCompensation
	PCActn       map[string]any
	Grant        map[string]any
	Operation    Operation
}

// UndoWindowInfo is what an allowed authorize result carries when the action got a veto window (the decision stays allow).
type UndoWindowInfo struct {
	ID        string
	WindowEnd int64
	// Converted is true when the window replaced a prior approval.
	Converted bool
	// CompensationVerb and CompensationResource name the compensating action.
	CompensationVerb     string
	CompensationResource string
	// Token is the encoded one-click undo token (also delivered to the principal).
	Token string
	// Obligation is the `undo_window` obligation the enforcement point accepts with this allow: report the effect, let the window run.
	Obligation map[string]any
}

// The notice kinds.
const (
	UndoNoticeOpened             = "opened"
	UndoNoticeVetoed             = "vetoed"
	UndoNoticeCompensated        = "compensated"
	UndoNoticeCompensationFailed = "compensation_failed"
	UndoNoticeFinalized          = "finalized"
	UndoNoticeRevoked            = "revoked"
)

// UndoNotice is a message to the principal. Record is the undo record without its pcactn and receipts.
type UndoNotice struct {
	Kind   string
	Record map[string]any
	// Token is set on `opened` only: the encoded token for the one-click undo link.
	Token  string
	Render map[string]any
}

// UndoNotifier tells the principal. Notify reports whether at least one of the principal's channels accepted the notice.
type UndoNotifier interface {
	Notify(n UndoNotice) (delivered bool, reason string)
}

// The alert codes.
const (
	UndoAlertCompensationFailed = "compensation_failed"
	UndoAlertNotifyFailed       = "notify_failed"
	UndoAlertEffectUnknown      = "effect_unknown"
	UndoAlertSlashAfterWindow   = "slash_after_window"
	UndoAlertBudgetSettleFailed = "budget_settle_failed"
	UndoAlertRevokedOpenWindow  = "revoked_open_window"
	UndoAlertCompensationDenied = "compensation_denied"
	UndoAlertVetoRelayFailed    = "veto_relay_failed"
)

// UndoAlert is a failure that needs a human (pager, SIEM). Level is "critical" or "warning".
type UndoAlert struct {
	Level  string
	Code   string
	Record string
	Reason string
}

// UndoCompensationCall is what the compensating-action executor receives.
type UndoCompensationCall struct {
	// Operation is the compensating operation with its target filled in (when the definition names one).
	Operation Operation
	// IdempotencyKey is the key of this attempt (pass it to the downstream call).
	IdempotencyKey string
	// UndoOf is the original operation id; OriginalResult its reported result (HasOriginalResult false: none reported).
	UndoOf            string
	OriginalResult    any
	HasOriginalResult bool
	// Record is the undo record without its pcactn.
	Record map[string]any
}

// UndoBudgetLedger settles the aggregate budget held during a window. Outcome is "settled" or "replayed" on success; anything
// else raises a budget_settle_failed alert.
type UndoBudgetLedger interface {
	Commit(key, id string) (outcome string, err error)
	Release(key, id string, evidence any) (outcome string, err error)
}

// UndoBudget wires a ledger: reservations are committed on finalize, released (with Evidence, when given) on compensation or
// abort. Evidence returns nil for "no evidence": a release carries none unless this func supplies it. reason is "rollback" or
// "effect_not_run".
type UndoBudget struct {
	Ledger   UndoBudgetLedger
	Evidence func(key, id, reason string) any
}

// UndoRelayedVeto is a veto taken by a relay: the principal's token and the time the relay received it. The token is verified
// as of At (so a veto made inside the window counts even when the relay is read after it closed); At is the only thing the
// relay is trusted for, and it can never precede the window's opening or lie in the future.
type UndoRelayedVeto struct {
	ID    string
	Token any
	At    int64
}

// UndoVetoRelay reads the vetoes received somewhere else (the hosted veto endpoint). A relay that cannot be read finalizes NOTHING.
type UndoVetoRelay interface {
	Pending() ([]UndoRelayedVeto, error)
}

// UndoCoordinatorOptions configures CreateUndoCoordinator.
type UndoCoordinatorOptions struct {
	// Store is the durable undo ledger (REQUIRED, Durable() true).
	Store UndoStore
	// Engine gives confirmed reversibility and compensations (REQUIRED).
	Engine UndoEngine
	// SignerSecret is the undo service key, a 32-byte Ed25519 secret (REQUIRED): signs tokens and receipts.
	SignerSecret []byte
	// Audience is this resource server's audience (REQUIRED, bound into the token).
	Audience string
	// ResolveGrant returns the grant by reference, from YOUR store (REQUIRED; the same function Authorize uses).
	ResolveGrant func(grantRef string, pcactn map[string]any) (map[string]any, error)
	// Compensate runs a compensating action (REQUIRED: your connector). Return an error on failure.
	Compensate func(call UndoCompensationCall) (any, error)
	// Operations holds at-most-once records for compensation attempts (REQUIRED; shared and durable in production).
	Operations OperationStore
	// Notifier tells the principal (REQUIRED).
	Notifier UndoNotifier
	// Alert receives a failure that needs a human (REQUIRED). Never silent.
	Alert  func(a UndoAlert)
	Policy func(op Operation, grant map[string]any) (*UndoPolicy, error)
	Window UndoWindowPolicy
	// ResolveTarget is the value of the compensating action's target parameter. Default: effect.result.id when it is a non-empty string.
	ResolveTarget func(rec map[string]any) (target string, ok bool)
	// Budget holds aggregate budgets during the window.
	Budget *UndoBudget
	// PqPins are the verifier-side PQ pins forwarded to the compensation decision.
	PqPins map[string]string
	// EffectTimeoutMs: a vetoed record whose effect was never reported is compensated anyway after this long (default 5 minutes).
	EffectTimeoutMs int64
	// Now is the clock (epoch ms; nil: the wall clock).
	Now func() int64
	// Relay reads vetoes received somewhere else: read before every finalize sweep, and applied with their receipt time.
	Relay UndoVetoRelay
	// InsecureVolatileStore is TESTS ONLY: accept a store whose Durable() is false (every open window is lost on restart).
	InsecureVolatileStore bool
}

// UndoVetoBy says who vetoes: the principal with the one-click Token (At: the time a relay received it), or an authenticated
// Operator of this server. Token wins when set.
type UndoVetoBy struct {
	Token    any
	At       *int64
	Operator *string
}

// UndoVetoResult is the outcome of a veto.
type UndoVetoResult struct {
	OK       bool
	Record   map[string]any
	Replayed bool
	// Code and Reason describe a refusal: a token check code, a transition code, "unknown" or "malformed".
	Code   string
	Reason string
}

// UndoCoordinator is the coordinator handle. It is safe for concurrent use as far as its stores are.
type UndoCoordinator struct {
	opts   UndoCoordinatorOptions
	signer *KeyPair
	// SignerPublic is the undo service key's public half (verifies tokens and receipts elsewhere, e.g. the hosted veto route).
	SignerPublic string
}

// MissingUndoComponents lists the required components opts lacks (empty when the configuration is complete).
func MissingUndoComponents(o UndoCoordinatorOptions) []string {
	var m []string
	if o.Store == nil {
		m = append(m, "store")
	}
	if o.Engine == nil {
		m = append(m, "engine")
	}
	if len(o.SignerSecret) != 32 {
		m = append(m, "signerSecret")
	}
	if o.Audience == "" {
		m = append(m, "audience")
	}
	if o.ResolveGrant == nil {
		m = append(m, "resolveGrant")
	}
	if o.Compensate == nil {
		m = append(m, "compensate")
	}
	if o.Operations == nil {
		m = append(m, "operations")
	}
	if o.Notifier == nil {
		m = append(m, "notifier")
	}
	if o.Alert == nil {
		m = append(m, "alert")
	}
	return m
}

// CreateUndoCoordinator builds the coordinator. It fails with a `config` UndoError for a missing component and `not_durable`
// for a volatile store (fail closed).
func CreateUndoCoordinator(opts UndoCoordinatorOptions) (*UndoCoordinator, error) {
	if missing := MissingUndoComponents(opts); len(missing) > 0 {
		return nil, undoErr("config", "undo coordinator: missing required component(s): "+strings.Join(missing, ", "))
	}
	if !opts.Store.Durable() && !opts.InsecureVolatileStore {
		return nil, undoErr("not_durable", "an undo ledger must be durable: a restart would lose every open window and its compensation")
	}
	signer, err := KeyPairFromSeed(opts.SignerSecret)
	if err != nil {
		return nil, undoErr("signer_missing", err.Error())
	}
	if opts.EffectTimeoutMs == 0 {
		opts.EffectTimeoutMs = 5 * 60_000
	}
	if opts.EffectTimeoutMs < 0 {
		return nil, undoErr("config", "undo coordinator: effectTimeoutMs must be a non-negative number")
	}
	return &UndoCoordinator{opts: opts, signer: signer, SignerPublic: signer.Public}, nil
}

func (c *UndoCoordinator) now() int64 {
	if c.opts.Now != nil {
		return c.opts.Now()
	}
	return time.Now().UnixMilli()
}

func (c *UndoCoordinator) alert(a UndoAlert) {
	defer func() {
		if recover() != nil {
			// an alert sink that panics is itself a failure the operator must see: write it where a host always looks
			fmt.Printf("pca undo alert (%s) for %s: %s\n", a.Code, a.Record, a.Reason)
		}
	}()
	c.opts.Alert(a)
}

func (c *UndoCoordinator) notify(n UndoNotice) (delivered bool, reason string) {
	defer func() {
		if r := recover(); r != nil {
			delivered, reason = false, fmt.Sprint(r)
		}
	}()
	d, why := c.opts.Notifier.Notify(n)
	if d {
		return true, ""
	}
	if why == "" {
		why = "no channel delivered the notice"
	}
	return false, why
}

func undoStrip(r map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range r {
		if k != "pcactn" && k != "receipts" {
			out[k] = v
		}
	}
	return out
}

func undoNum(n int64) any { return jsNumber(float64(n)) }

func undoInt(v any) int64 {
	f, _ := jsNum(v)
	return int64(f)
}

func undoStr(r map[string]any, k string) string { s, _ := r[k].(string); return s }

// undoApplied is the result of one compare-and-swap transition: Record/Applied, or a refusal (Code, Reason).
type undoApplied struct {
	Record  map[string]any
	Applied bool
	Code    string
	Reason  string
}

func (a undoApplied) refused() bool { return a.Code != "" }

// apply applies one event with compare-and-swap retries; checkAt (nil: the clock) is the time a relayed veto is judged at.
func (c *UndoCoordinator) apply(id string, ev map[string]any, checkAt *int64) (undoApplied, error) {
	for i := 0; i < undoMaxCAS; i++ {
		cur, err := c.opts.Store.Get(id)
		if err != nil {
			return undoApplied{}, err
		}
		if cur == nil {
			return undoApplied{Code: "unknown", Reason: "no undo record " + id}, nil
		}
		t := c.now()
		at := t
		if checkAt != nil {
			at = *checkAt
		}
		// a relayed veto is judged as of when the principal made it; its receipt is still written at the current time
		tr := UndoTransition(cur, ev, float64(at))
		switch tr.Outcome {
		case "refused":
			return undoApplied{Code: tr.Code, Reason: tr.Reason}, nil
		case "replayed":
			return undoApplied{Record: tr.Record}, nil
		}
		next, err := WithReceipt(tr.Record, tr.Event, tr.Note, t, c.signer)
		if err != nil {
			return undoApplied{}, err
		}
		ok, err := c.opts.Store.Replace(id, undoInt(cur["ver"]), next)
		if err != nil {
			return undoApplied{}, err
		}
		if ok {
			return undoApplied{Record: next, Applied: true}, nil
		}
	}
	return undoApplied{}, undoErr("conflict_exhausted", "undo record "+id+" kept changing")
}

func (c *UndoCoordinator) must(id string, ev map[string]any) (undoApplied, error) {
	r, err := c.apply(id, ev, nil)
	if err != nil {
		return r, err
	}
	if r.refused() {
		return r, undoErr("invalid", r.Code+": "+r.Reason)
	}
	return r, nil
}

func (c *UndoCoordinator) settleBudget(rec map[string]any, how string) {
	b := c.opts.Budget
	list, _ := rec["budget"].([]any)
	if b == nil || len(list) == 0 {
		return
	}
	id := undoStr(rec, "id")
	for _, x := range list {
		r, _ := x.(map[string]any)
		key, rid := undoStr(r, "key"), undoStr(r, "id")
		func() {
			defer func() {
				if p := recover(); p != nil {
					c.alert(UndoAlert{Level: "warning", Code: UndoAlertBudgetSettleFailed, Record: id, Reason: fmt.Sprintf("%s of %s/%s: %v", how, key, rid, p)})
				}
			}()
			var outcome string
			var err error
			if how == "commit" {
				outcome, err = b.Ledger.Commit(key, rid)
			} else {
				var ev any
				if b.Evidence != nil {
					ev = b.Evidence(key, rid, how)
				}
				outcome, err = b.Ledger.Release(key, rid, ev)
			}
			switch {
			case err != nil:
				c.alert(UndoAlert{Level: "warning", Code: UndoAlertBudgetSettleFailed, Record: id, Reason: fmt.Sprintf("%s of %s/%s: %s", how, key, rid, err.Error())})
			case outcome != "settled" && outcome != "replayed":
				c.alert(UndoAlert{Level: "warning", Code: UndoAlertBudgetSettleFailed, Record: id, Reason: fmt.Sprintf("%s of %s/%s: %s", how, key, rid, outcome)})
			}
		}()
	}
}

func (c *UndoCoordinator) policyOf(op Operation, grant map[string]any) (UndoPolicy, error) {
	if c.opts.Policy == nil {
		return UndoPolicy{}, nil
	}
	p, err := c.opts.Policy(op, grant)
	if err != nil || p == nil {
		return UndoPolicy{}, err
	}
	return *p, nil
}

// compensationAllowed runs the Policy VM on the compensating action under the original chain, at `at` (the admission time).
func (c *UndoCoordinator) compensationAllowed(pc, grant map[string]any, op Operation, at int64) (bool, string) {
	params := op.Params
	if params == nil {
		params = map[string]any{}
	}
	in := map[string]any{
		"grant": grant, "trustedRoot": grant, "chain": pc["cap_chain"],
		"action": map[string]any{"action": map[string]any{"verb": op.Verb, "resource": op.Resource, "params": params}},
		"risk":   map[string]any{}, "budget": map[string]any{"B": undoNum(0), "tau": undoNum(at)}, "now": undoNum(at),
	}
	if c.opts.PqPins != nil {
		pins := map[string]any{}
		for k, v := range c.opts.PqPins {
			pins[k] = v
		}
		in["pqPins"] = pins
	}
	d := DecideNative(in, nil)
	if rel, _ := d["releaseGuardianShare"].(bool); rel {
		return true, ""
	}
	reasons, _ := d["reasons"].([]any)
	for _, r := range reasons {
		if s, ok := r.(string); ok && !strings.HasPrefix(s, "risk input") {
			return false, s
		}
	}
	return false, "the grant does not authorize the compensating action"
}

// UndoAdmitRequest is what Admit decides on.
type UndoAdmitRequest struct {
	PCActn map[string]any
	// Grant is the grant (nil: resolved from the PCActn's grant_ref through ResolveGrant).
	Grant     map[string]any
	Operation Operation
	// Converted is true when the window would replace a prior approval (the guard's decision was escalate).
	Converted bool
}

// Admit decides whether an action gets a veto window. refused is "" on success, else the reason (the action stays irreversible).
func (c *UndoCoordinator) Admit(a UndoAdmitRequest) (adm *UndoWindowAdmission, refused string) {
	defer func() {
		if r := recover(); r != nil {
			adm, refused = nil, fmt.Sprintf("undo admission error (fail closed): %v", r)
		}
	}()
	pc, op := a.PCActn, a.Operation
	if pc == nil || op.Verb == "" && op.Resource == "" && op.Params == nil {
		return nil, "no operation"
	}
	grant := a.Grant
	if grant == nil {
		g, err := c.opts.ResolveGrant(undoStr(pc, "grant_ref"), pc)
		if err != nil {
			return nil, fmt.Sprintf("undo admission error (fail closed): %s", err.Error())
		}
		grant = g
	}
	if grant == nil {
		return nil, "unknown grant"
	}
	pol, perr := c.policyOf(op, grant)
	if perr != nil {
		return nil, fmt.Sprintf("undo admission error (fail closed): %s", perr.Error())
	}
	mode := pol.Mode
	if mode == "" {
		mode = "always"
	}
	if mode == "off" {
		return nil, "policy: undo windows are off"
	}
	if mode == "escalations" && !a.Converted {
		return nil, "policy: windows only replace approvals"
	}
	action, _ := pc["action"].(map[string]any)
	// the stricter of the signed class and the definition applies: an agent signing `irreversible` is taken at its word
	if reversibilityRank(action["reversibility_class"]) != 0 {
		return nil, "the signed class is " + jsValueString(action["reversibility_class"])
	}
	id, err := PCActnDigest(pc)
	if err != nil {
		return nil, fmt.Sprintf("undo admission error (fail closed): %s", err.Error())
	}
	plan, err := c.opts.Engine.Plan(op, id)
	if err != nil {
		return nil, fmt.Sprintf("undo admission error (fail closed): %s", err.Error())
	}
	if plan == nil {
		return nil, "not confirmed reversible, or no confirmed compensating action"
	}
	params := normalizeJSON(plan.Compensation.Params)
	pm, _ := params.(map[string]any)
	if pm == nil {
		pm = map[string]any{}
	}
	comp := UndoCompensation{Verb: plan.Compensation.Verb, Resource: op.Resource, Params: pm, UndoOf: id, DefDigest: plan.Compensation.DefDigest, TargetParam: plan.Compensation.TargetParam}
	t := c.now()
	if ok, why := c.compensationAllowed(pc, grant, Operation{Verb: comp.Verb, Resource: comp.Resource, Params: comp.Params}, t); !ok {
		return nil, "the compensating action is not authorized under the grant: " + why
	}
	var win *float64
	if pol.WindowMs != nil {
		win = pol.WindowMs
	}
	windowMs := ResolveUndoWindow(win, c.opts.Window)
	opParams := normalizeJSON(op.Params)
	opm, _ := opParams.(map[string]any)
	if opm == nil {
		opm = map[string]any{}
	}
	return &UndoWindowAdmission{ID: id, OpenedAt: t, WindowEnd: t + windowMs, Converted: a.Converted, Plan: *plan, Compensation: comp, PCActn: pc, Grant: grant,
		Operation: Operation{Verb: op.Verb, Resource: op.Resource, Params: opm}}, ""
}

func (c *UndoCoordinator) infoOf(rec map[string]any) (UndoWindowInfo, error) {
	tok, err := SignUndoToken(undoTokRecOf(rec), c.signer)
	if err != nil {
		return UndoWindowInfo{}, err
	}
	enc, err := EncodeUndoToken(tok)
	if err != nil {
		return UndoWindowInfo{}, err
	}
	comp, _ := rec["compensation"].(map[string]any)
	we := undoInt(rec["window_end"])
	conv, _ := rec["converted"].(bool)
	id := undoStr(rec, "id")
	return UndoWindowInfo{ID: id, WindowEnd: we, Converted: conv, CompensationVerb: undoStr(comp, "verb"), CompensationResource: undoStr(comp, "resource"), Token: enc,
		Obligation: map[string]any{"kind": "undo_window", "params": map[string]any{"id": id, "window_end": undoNum(we)}, "due": undoNum(we)}}, nil
}

func undoTokRecOf(rec map[string]any) UndoTokenRecord {
	return UndoTokenRecord{ID: undoStr(rec, "id"), Aud: undoStr(rec, "aud"), Principal: undoStr(rec, "principal"),
		CompensationDigest: undoStr(rec, "compensation_digest"), RenderDigest: undoStr(rec, "render_digest"), WindowEnd: undoInt(rec["window_end"])}
}

// UndoBondRef is a bond an optimistic claim holds for a window: a slash with a fraud proof vetoes the record.
type UndoBondRef struct {
	Ref             string
	ChallengeEndsAt int64
}

// Open writes the record durably before the effect runs, signs the `opened` receipt, mints the token and tells the principal.
// A failed notification aborts the record and raises an alert.
func (c *UndoCoordinator) Open(adm *UndoWindowAdmission, bond *UndoBondRef) (UndoWindowInfo, error) {
	pc := adm.PCActn
	chain, _ := pc["cap_chain"].([]any)
	var holder string
	if n := len(chain); n > 0 {
		last, _ := chain[n-1].(map[string]any)
		holder = undoStr(last, "holder")
	}
	windowEnd := adm.WindowEnd
	if bond != nil && bond.ChallengeEndsAt > windowEnd {
		windowEnd = bond.ChallengeEndsAt
	}
	cdig, err := CompensationDigest(adm.Compensation)
	if err != nil {
		return UndoWindowInfo{}, err
	}
	enc, ok := EncodePCActn(pc)
	if !ok {
		return UndoWindowInfo{}, undoErr("invalid", "the PCActn cannot be encoded")
	}
	action, _ := pc["action"].(map[string]any)
	comp := map[string]any{"verb": adm.Compensation.Verb, "resource": adm.Compensation.Resource, "params": normalizeJSON(adm.Compensation.Params),
		"undo_of": adm.Compensation.UndoOf, "def_digest": adm.Compensation.DefDigest}
	if adm.Compensation.TargetParam != "" {
		comp["target_param"] = adm.Compensation.TargetParam
	}
	base := map[string]any{
		"v": undoNum(1), "id": adm.ID, "aud": c.opts.Audience, "grant_ref": undoStr(pc, "grant_ref"), "holder": holder, "principal": undoStr(adm.Grant, "issuer"),
		"action":       map[string]any{"verb": adm.Operation.Verb, "resource": adm.Operation.Resource, "params_digest": action["params_digest"], "def_digest": adm.Plan.DefDigest},
		"compensation": comp, "compensation_digest": cdig,
	}
	if adm.Plan.RenderDigest != "" {
		base["render_digest"] = adm.Plan.RenderDigest
	}
	base["opened_at"] = undoNum(adm.OpenedAt)
	base["window_end"] = undoNum(windowEnd)
	base["converted"] = adm.Converted
	base["state"] = "open"
	base["ver"] = undoNum(0)
	base["pcactn"] = enc
	if bond != nil {
		base["bond_ref"] = bond.Ref
	}
	base["attempt"] = undoNum(0)
	base["receipts"] = []any{}
	note := ""
	if adm.Converted {
		note = "converted"
	}
	rec, err := WithReceipt(base, "opened", note, adm.OpenedAt, c.signer)
	if err != nil {
		return UndoWindowInfo{}, err
	}
	created, existing, err := c.opts.Store.Create(rec)
	if err != nil {
		return UndoWindowInfo{}, err
	}
	if !created {
		// a retry of the same admission returns the same window; anything else is a different action under the same id
		if existing["compensation_digest"] != any(cdig) || existing["state"] != any("open") {
			return UndoWindowInfo{}, undoErr("invalid", fmt.Sprintf("undo record %s already exists with other terms or state %s", adm.ID, jsValueString(existing["state"])))
		}
		return c.infoOf(existing)
	}
	info, err := c.infoOf(rec)
	if err != nil {
		return UndoWindowInfo{}, err
	}
	n := UndoNotice{Kind: UndoNoticeOpened, Record: undoStrip(rec), Token: info.Token}
	if adm.Plan.Render != nil {
		n.Render = adm.Plan.Render
	}
	if delivered, why := c.notify(n); !delivered {
		if _, aerr := c.apply(adm.ID, map[string]any{"kind": "abort", "reason": "notify_failed"}, nil); aerr != nil {
			return UndoWindowInfo{}, aerr
		}
		c.alert(UndoAlert{Level: "critical", Code: UndoAlertNotifyFailed, Record: adm.ID, Reason: "the principal could not be told about the undo window: " + why})
		return UndoWindowInfo{}, undoErr("invalid", "notify_failed: the undo window could not be announced ("+why+")")
	}
	return info, nil
}

// Get returns the record, nil when there is none.
func (c *UndoCoordinator) Get(id string) (map[string]any, error) { return c.opts.Store.Get(id) }

// HoldBudget adds aggregate budget reservations the window holds until it closes.
func (c *UndoCoordinator) HoldBudget(id string, reservations []map[string]string) (map[string]any, error) {
	for i := 0; i < undoMaxCAS; i++ {
		cur, err := c.opts.Store.Get(id)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			return nil, undoErr("invalid", "no undo record "+id)
		}
		if st := undoStr(cur, "state"); st != "open" && st != "vetoed" {
			return nil, undoErr("invalid", "a "+st+" record holds no budget")
		}
		next := undoCopy(cur)
		held, _ := next["budget"].([]any)
		held = append([]any{}, held...)
		for _, r := range reservations {
			held = append(held, map[string]any{"key": r["key"], "id": r["id"]})
		}
		next["budget"] = held
		next["ver"] = undoNum(undoInt(cur["ver"]) + 1)
		ok, err := c.opts.Store.Replace(id, undoInt(cur["ver"]), next)
		if err != nil {
			return nil, err
		}
		if ok {
			return next, nil
		}
	}
	return nil, undoErr("conflict_exhausted", "undo record "+id+" kept changing")
}

// RecordEffect reports the original effect's outcome; a veto that arrived while the effect was running is acted on now.
func (c *UndoCoordinator) RecordEffect(id string, result any, hasResult bool) (map[string]any, error) {
	ev := map[string]any{"kind": "effect"}
	if hasResult {
		ev["result"] = result
	}
	r, err := c.must(id, ev)
	if err != nil {
		return nil, err
	}
	if undoStr(r.Record, "state") == "vetoed" {
		return c.runCompensation(r.Record)
	}
	return r.Record, nil
}

// Abort closes a window whose effect never ran (the held budget is released).
func (c *UndoCoordinator) Abort(id, reason string) (map[string]any, error) {
	r, err := c.must(id, map[string]any{"kind": "abort", "reason": reason})
	if err != nil {
		return nil, err
	}
	if r.Applied {
		c.settleBudget(r.Record, "effect_not_run")
	}
	return r.Record, nil
}

func (c *UndoCoordinator) fail(rec map[string]any, reason, code string) (map[string]any, error) {
	id := undoStr(rec, "id")
	r, err := c.apply(id, map[string]any{"kind": "compensation_failed", "reason": reason}, nil)
	if err != nil {
		return nil, err
	}
	out := r.Record
	if r.refused() {
		cur, err := c.opts.Store.Get(id)
		if err != nil {
			return nil, err
		}
		out = cur
		if out == nil {
			out = rec
		}
	}
	if !r.refused() && r.Applied {
		c.alert(UndoAlert{Level: "critical", Code: code, Record: id, Reason: reason})
		c.notify(UndoNotice{Kind: UndoNoticeCompensationFailed, Record: undoStrip(out)})
	}
	return out, nil
}

func (c *UndoCoordinator) targetOf(rec map[string]any) (string, bool) {
	if c.opts.ResolveTarget != nil {
		return c.opts.ResolveTarget(rec)
	}
	eff, _ := rec["effect"].(map[string]any)
	res, _ := eff["result"].(map[string]any)
	id, ok := res["id"].(string)
	return id, ok && id != ""
}

func (c *UndoCoordinator) runCompensation(rec0 map[string]any) (map[string]any, error) {
	rec := rec0
	if undoStr(rec, "state") != "vetoed" {
		return rec, nil
	}
	t := c.now()
	_, hasEffect := rec["effect"]
	vetoAt := t
	if v, ok := rec["veto"].(map[string]any); ok {
		vetoAt = undoInt(v["at"])
	}
	if !hasEffect && t-vetoAt < c.opts.EffectTimeoutMs {
		return rec, nil // wait for the effect report (RecordEffect resumes)
	}
	id := undoStr(rec, "id")
	pc, perr := DecodePCActn(undoStr(rec, "pcactn"))
	if perr != nil {
		return nil, perr
	}
	grant, err := c.opts.ResolveGrant(undoStr(rec, "grant_ref"), pc)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return c.fail(rec, "the grant is no longer known: the compensation cannot be authorized", UndoAlertCompensationDenied)
	}
	comp, _ := rec["compensation"].(map[string]any)
	srcParams, _ := comp["params"].(map[string]any)
	params := map[string]any{}
	for k, v := range srcParams {
		params[k] = v
	}
	if tp, has := comp["target_param"].(string); has {
		target, ok := c.targetOf(rec)
		if !ok {
			return c.fail(rec, fmt.Sprintf("the target '%s' of the compensation is unknown (no effect result names it)", tp), UndoAlertCompensationFailed)
		}
		params[tp] = target
	}
	op := Operation{Verb: undoStr(comp, "verb"), Resource: undoStr(comp, "resource"), Params: params}
	if ok, why := c.compensationAllowed(pc, grant, op, undoInt(rec["opened_at"])); !ok {
		return c.fail(rec, "the compensating action is not authorized under the grant: "+why, UndoAlertCompensationDenied)
	}
	// at most once per attempt: the operation record is created before the compensator runs
	attempt := rec["attempt"]
	opID, err := HashCanonical(map[string]any{"d": "atlas-pca/undo-compensation-op/v1", "record": id, "attempt": normalizeJSON(attempt)})
	if err != nil {
		return nil, err
	}
	pdig, err := HashCanonical(params)
	if err != nil {
		return nil, err
	}
	orec := OperationRecord{ID: opID, State: OpPending, Verb: op.Verb, Resource: op.Resource, ParamsDigest: pdig, Reversibility: "irreversible", StartedAt: t}
	created, prev, err := c.opts.Operations.Create(orec)
	if err != nil {
		return nil, err
	}
	if !created {
		switch prev.State {
		case OpCommitted:
			r, err := c.apply(id, undoResultEvent("compensated", prev.Result, prev.Result != nil), nil)
			if err != nil {
				return nil, err
			}
			if !r.refused() {
				rec = r.Record
			}
			return c.finishCompensated(rec)
		case OpFailed, OpUncertain:
			return c.fail(rec, fmt.Sprintf("compensation attempt %s %s: %s", jsValueString(attempt), string(prev.State), prev.Error), UndoAlertCompensationFailed)
		case OpAborted:
			r, err := c.apply(id, map[string]any{"kind": "compensation_failed", "reason": "attempt never started"}, nil)
			if err != nil {
				return nil, err
			}
			if r.refused() {
				return rec, nil
			}
			again, err := c.apply(id, map[string]any{"kind": "retry"}, nil)
			if err != nil {
				return nil, err
			}
			if again.refused() {
				return r.Record, nil
			}
			return c.runCompensation(again.Record)
		}
		// pending / executing: another worker holds it, or a crash; stale ones are settled by Recover
		since := prev.ExecutingAt
		if since == 0 {
			since = prev.StartedAt
		}
		if t-since > c.opts.EffectTimeoutMs {
			settled := prev
			if prev.State == OpPending {
				settled.State, settled.Error, settled.FinishedAt = OpAborted, "never started", t
			} else {
				settled.State, settled.Error, settled.FinishedAt = OpUncertain, "no outcome recorded: the compensation may or may not have run", t
			}
			if _, err := c.opts.Operations.Transition(prev.ID, prev.State, settled); err != nil {
				return nil, err
			}
			cur, err := c.opts.Store.Get(id)
			if err != nil {
				return nil, err
			}
			if cur == nil {
				cur = rec
			}
			return c.runCompensation(cur)
		}
		return rec, nil
	}
	// re-read under the record: a concurrent retry or resolution wins
	cur, err := c.opts.Store.Get(id)
	if err != nil {
		return nil, err
	}
	if cur == nil || undoStr(cur, "state") != "vetoed" || !jsLooseEqual(cur["attempt"], attempt) {
		aborted := orec
		aborted.State, aborted.Error, aborted.FinishedAt = OpAborted, "the undo record moved on", c.now()
		if _, err := c.opts.Operations.Transition(opID, OpPending, aborted); err != nil {
			return nil, err
		}
		if cur == nil {
			return rec, nil
		}
		return cur, nil
	}
	running := orec
	running.State, running.ExecutingAt = OpExecuting, c.now()
	moved, err := c.opts.Operations.Transition(opID, OpPending, running)
	if err != nil {
		return nil, err
	}
	if !moved {
		again, err := c.opts.Store.Get(id)
		if err != nil {
			return nil, err
		}
		if again == nil {
			return rec, nil
		}
		return again, nil
	}
	call := UndoCompensationCall{Operation: op, IdempotencyKey: opID, UndoOf: id, Record: undoWithout(cur, "pcactn")}
	if eff, ok := rec["effect"].(map[string]any); ok {
		if r, has := eff["result"]; has {
			call.OriginalResult, call.HasOriginalResult = r, true
		}
	}
	result, cerr := c.runCompensator(call)
	if cerr != nil {
		failed := running
		failed.State, failed.Error, failed.FinishedAt = OpFailed, cerr.Error(), c.now()
		_, _ = c.opts.Operations.Transition(opID, OpExecuting, failed)
		return c.fail(rec, "the compensating action failed: "+cerr.Error(), UndoAlertCompensationFailed)
	}
	done := running
	done.State, done.Result, done.FinishedAt = OpCommitted, result, c.now()
	_, _ = c.opts.Operations.Transition(opID, OpExecuting, done)
	r, err := c.apply(id, undoResultEvent("compensated", result, result != nil), nil)
	if err != nil {
		return nil, err
	}
	if r.refused() {
		cur, err := c.opts.Store.Get(id)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			return rec, nil
		}
		return cur, nil
	}
	return c.finishCompensated(r.Record)
}

func (c *UndoCoordinator) runCompensator(call UndoCompensationCall) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return c.opts.Compensate(call)
}

func undoResultEvent(kind string, result any, has bool) map[string]any {
	ev := map[string]any{"kind": kind}
	if has {
		ev["result"] = result
	}
	return ev
}

func undoWithout(r map[string]any, k string) map[string]any {
	out := map[string]any{}
	for key, v := range r {
		if key != k {
			out[key] = v
		}
	}
	return out
}

// jsLooseEqual compares two JSON scalars by value (numbers by their JavaScript value).
func jsLooseEqual(a, b any) bool {
	if fa, ok := jsNum(a); ok {
		fb, ok2 := jsNum(b)
		return ok2 && fa == fb
	}
	return a == b
}

func (c *UndoCoordinator) finishCompensated(rec map[string]any) (map[string]any, error) {
	if undoStr(rec, "state") == "compensated" {
		c.settleBudget(rec, "rollback")
		c.notify(UndoNotice{Kind: UndoNoticeCompensated, Record: undoStrip(rec)})
	}
	return rec, nil
}

func (c *UndoCoordinator) vetoWith(id string, by UndoVetoBy, direct map[string]any) (res UndoVetoResult) {
	defer func() {
		if r := recover(); r != nil {
			res = UndoVetoResult{Code: "malformed", Reason: fmt.Sprintf("veto error (fail closed): %v", r)}
		}
	}()
	cur, err := c.opts.Store.Get(id)
	if err != nil {
		return UndoVetoResult{Code: "malformed", Reason: "veto error (fail closed): " + err.Error()}
	}
	if cur == nil {
		return UndoVetoResult{Code: "unknown", Reason: "no undo record " + id}
	}
	var v map[string]any
	t := c.now()
	var checkAt *int64
	switch {
	case direct != nil:
		v = undoCopy(direct)
		v["at"] = undoNum(t)
	case by.Token != nil:
		if by.At != nil {
			at := *by.At
			if at > t || at < undoInt(cur["opened_at"]) || at < 0 {
				return UndoVetoResult{Code: "malformed", Reason: "a relayed veto time must lie between the opening of the window and now"}
			}
			t, checkAt = at, &at
		}
		tok := by.Token
		if s, ok := tok.(string); ok {
			tok = DecodeUndoToken(s)
		}
		if chk := UndoTokenCheck(tok, c.SignerPublic, undoTokRecOf(cur), t); chk != "ok" {
			return UndoVetoResult{Code: chk, Reason: "the undo token was refused (" + chk + ")"}
		}
		tm, _ := tok.(map[string]any)
		ev, derr := UndoTokenDigest(tm)
		if derr != nil {
			return UndoVetoResult{Code: "malformed", Reason: "veto error (fail closed): " + derr.Error()}
		}
		v = map[string]any{"at": undoNum(t), "via": "token", "by": undoStr(cur, "principal"), "evidence": ev}
	case by.Operator != nil:
		if *by.Operator == "" {
			return UndoVetoResult{Code: "malformed", Reason: "an operator veto names the operator"}
		}
		v = map[string]any{"at": undoNum(t), "via": "operator", "by": *by.Operator}
	default:
		return UndoVetoResult{Code: "malformed", Reason: "a veto names a token, an operator or a policy"}
	}
	r, err := c.apply(id, map[string]any{"kind": "veto", "veto": v}, checkAt)
	if err != nil {
		return UndoVetoResult{Code: "malformed", Reason: "veto error (fail closed): " + err.Error()}
	}
	if r.refused() {
		return UndoVetoResult{Code: r.Code, Reason: r.Reason}
	}
	if r.Applied {
		c.notify(UndoNotice{Kind: UndoNoticeVetoed, Record: undoStrip(r.Record)})
	}
	done, err := c.runCompensation(r.Record)
	if err != nil {
		return UndoVetoResult{Code: "malformed", Reason: "veto error (fail closed): " + err.Error()}
	}
	return UndoVetoResult{OK: true, Record: done, Replayed: !r.Applied}
}

// Veto vetoes with the one-click token (the principal) or as an authenticated operator of this server.
func (c *UndoCoordinator) Veto(id string, by UndoVetoBy) UndoVetoResult {
	return c.vetoWith(id, by, nil)
}

// SyncRelay applies the relay's pending vetoes now (every FinalizeDue does it too). It fails when the relay cannot be read.
func (c *UndoCoordinator) SyncRelay() ([]UndoVetoResult, error) {
	if c.opts.Relay == nil {
		return nil, nil
	}
	list, err := c.opts.Relay.Pending()
	if err != nil {
		return nil, err
	}
	var out []UndoVetoResult
	for _, x := range list {
		if x.ID == "" {
			continue
		}
		// a forged or late relay entry is refused by the same checks as any veto
		at := x.At
		out = append(out, c.Veto(x.ID, UndoVetoBy{Token: x.Token, At: &at}))
	}
	return out, nil
}

// Compensate runs (or resumes) the compensation of a vetoed record.
func (c *UndoCoordinator) Compensate(id string) (map[string]any, error) {
	cur, err := c.opts.Store.Get(id)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, undoErr("invalid", "no undo record "+id)
	}
	return c.runCompensation(cur)
}

// Retry retries a compensation that failed.
func (c *UndoCoordinator) Retry(id string) (map[string]any, error) {
	r, err := c.must(id, map[string]any{"kind": "retry"})
	if err != nil {
		return nil, err
	}
	return c.runCompensation(r.Record)
}

// FinalizeDue closes the windows whose time is up and returns their ids. With a relay that cannot be read it finalizes nothing.
func (c *UndoCoordinator) FinalizeDue() ([]string, error) {
	var out []string
	if _, err := c.SyncRelay(); err != nil {
		// a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
		c.alert(UndoAlert{Level: "critical", Code: UndoAlertVetoRelayFailed, Record: "*", Reason: "the veto relay could not be read; no window was finalized: " + err.Error()})
		return out, nil
	}
	// with a relay, a veto accepted there just before the window closed may still be in flight: wait out a grace period
	by := c.now() - 1
	if c.opts.Relay != nil {
		by -= UndoRelayGraceMs
	}
	recs, err := c.opts.Store.List(UndoQuery{State: "open", WindowEndedBy: &by})
	if err != nil {
		return out, err
	}
	for _, rec := range recs {
		id := undoStr(rec, "id")
		r, err := c.apply(id, map[string]any{"kind": "finalize"}, nil)
		if err != nil {
			return out, err
		}
		if r.refused() || !r.Applied {
			continue
		}
		out = append(out, id)
		if _, has := r.Record["effect"]; !has {
			c.alert(UndoAlert{Level: "warning", Code: UndoAlertEffectUnknown, Record: id, Reason: "the window closed without an effect report: reconcile the original operation"})
		}
		c.settleBudget(r.Record, "commit")
		c.notify(UndoNotice{Kind: UndoNoticeFinalized, Record: undoStrip(r.Record)})
	}
	return out, nil
}

// Recover resumes every vetoed record's compensation and finalizes the due windows; it returns the ids that moved on.
func (c *UndoCoordinator) Recover() ([]string, error) {
	var out []string
	recs, err := c.opts.Store.List(UndoQuery{State: "vetoed"})
	if err != nil {
		return out, err
	}
	for _, rec := range recs {
		r, err := c.runCompensation(rec)
		if err != nil {
			return out, err
		}
		if undoStr(r, "state") != "vetoed" {
			out = append(out, undoStr(rec, "id"))
		}
	}
	more, err := c.FinalizeDue()
	return append(out, more...), err
}

// OnRevocation handles a grant revoked while windows are open: per policy the principal is told (and can still veto) or the
// window is vetoed. It returns the ids it vetoed.
func (c *UndoCoordinator) OnRevocation(grantRef string) ([]string, error) {
	var out []string
	recs, err := c.opts.Store.List(UndoQuery{State: "open", GrantRef: grantRef})
	if err != nil {
		return out, err
	}
	for _, rec := range recs {
		pc, perr := DecodePCActn(undoStr(rec, "pcactn"))
		if perr != nil {
			return out, perr
		}
		grant, err := c.opts.ResolveGrant(undoStr(rec, "grant_ref"), pc)
		if err != nil {
			return out, err
		}
		var pol UndoPolicy
		if grant != nil {
			act, _ := rec["action"].(map[string]any)
			p, perr := c.policyOf(Operation{Verb: undoStr(act, "verb"), Resource: undoStr(act, "resource")}, grant)
			if perr != nil {
				return out, perr
			}
			pol = p
		}
		id := undoStr(rec, "id")
		if pol.OnRevocation == "veto" {
			if v := c.vetoWith(id, UndoVetoBy{}, map[string]any{"via": "revocation", "by": grantRef}); v.OK {
				out = append(out, id)
			}
		} else {
			c.alert(UndoAlert{Level: "warning", Code: UndoAlertRevokedOpenWindow, Record: id, Reason: fmt.Sprintf("grant %s was revoked while this window is open; the principal can still undo it", grantRef)})
			c.notify(UndoNotice{Kind: UndoNoticeRevoked, Record: undoStrip(rec)})
		}
	}
	return out, nil
}

// UndoBondSlasher slashes a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window).
type UndoBondSlasher interface {
	// SlashBond returns the settlement record (JSON-serialisable).
	SlashBond(claimID string) (settlement map[string]any, err error)
}

// RollbackOnSlash slashes the bond and, only then, vetoes the record the claim held (the fraud-proof veto). It returns the
// settlement and the veto result.
func (c *UndoCoordinator) RollbackOnSlash(bonds UndoBondSlasher, claimID string) (map[string]any, UndoVetoResult, error) {
	settlement, err := bonds.SlashBond(claimID)
	if err != nil {
		return nil, UndoVetoResult{}, err
	}
	evidence, err := HashCanonical(map[string]any{"d": "atlas-pca/undo-slash-ref/v1", "settlement": normalizeJSON(settlement)})
	if err != nil {
		return settlement, UndoVetoResult{}, err
	}
	recs, err := c.opts.Store.List(UndoQuery{State: "open", BondRef: claimID})
	if err != nil {
		return settlement, UndoVetoResult{}, err
	}
	var target map[string]any
	if len(recs) > 0 {
		target = recs[0]
	} else if target, err = c.opts.Store.Get(claimID); err != nil {
		return settlement, UndoVetoResult{}, err
	}
	if target == nil {
		return settlement, UndoVetoResult{Code: "unknown", Reason: "no undo record for bond " + claimID}, nil
	}
	tid := undoStr(target, "id")
	v := c.vetoWith(tid, UndoVetoBy{}, map[string]any{"via": "fraud_proof", "by": claimID, "evidence": evidence})
	if !v.OK {
		c.alert(UndoAlert{Level: "critical", Code: UndoAlertSlashAfterWindow, Record: tid, Reason: "the bond was slashed but the effect could not be rolled back: " + v.Reason})
	}
	return settlement, v, nil
}

// ---- reporting the effect ----------------------------------------------------------------------------------------------

// UndoEffectOutcome is what executing an undo-windowed action produced (an ExecuteOutcome's status and result).
type UndoEffectOutcome struct {
	Status    string
	Result    any
	HasResult bool
}

// ReportUndoEffect executes-and-reports for an allowed Authorize result that carries an undo window: a committed effect is
// recorded (its result names the compensation target), an effect that failed or never started aborts the window (nothing to
// undo; held budget released). Pending / uncertain is unknown: the window keeps running and FinalizeDue alerts if it closes
// without a report.
func ReportUndoEffect(undo *UndoCoordinator, id string, outcome UndoEffectOutcome) (map[string]any, error) {
	switch outcome.Status {
	case "committed":
		return undo.RecordEffect(id, outcome.Result, outcome.HasResult)
	case "failed", "aborted", "refused":
		return undo.Abort(id, "effect_"+outcome.Status)
	}
	r, err := undo.Get(id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, undoErr("invalid", "no undo record "+id)
	}
	return r, nil
}

// ---- the principal's channels ----------------------------------------------------------------------------------------------------

// UndoDelivery is one channel's answer to a notice.
type UndoDelivery struct {
	Kind      string
	Delivered bool
	Reason    string
}

// UndoDispatcher fans a step-up-shaped notice out to the principal's channels (Slack, webhook, email, SMS, push). inboxURL is
// the link the notice carries ("" = none).
type UndoDispatcher interface {
	NotifyAll(req StepUpRequest, inboxURL string) []UndoDelivery
}

// UndoNotifierConfig configures UndoNotifierFromDispatcher.
type UndoNotifierConfig struct {
	// UndoURL builds the one-click undo URL from the encoded token and the record id.
	UndoURL func(token, id string) string
	// InboxURL is the link of every notice but `opened` ("" = none).
	InboxURL string
}

type undoDispatcherNotifier struct {
	d   UndoDispatcher
	cfg UndoNotifierConfig
}

// UndoNotifierFromDispatcher is an UndoNotifier over the approval channels. The notice becomes a step-up-shaped message whose
// link is the one-click undo URL and whose render is the WYSIWYS render of the action.
func UndoNotifierFromDispatcher(d UndoDispatcher, cfg UndoNotifierConfig) UndoNotifier {
	return undoDispatcherNotifier{d, cfg}
}

func (n undoDispatcherNotifier) Notify(notice UndoNotice) (bool, string) {
	r := notice.Record
	act, _ := r["action"].(map[string]any)
	comp, _ := r["compensation"].(map[string]any)
	verb, res := undoStr(act, "verb"), undoStr(act, "resource")
	we := undoInt(r["window_end"])
	until := time.UnixMilli(we).UTC().Format("2006-01-02T15:04:05.000Z")
	var reason string
	switch notice.Kind {
	case UndoNoticeOpened:
		reason = fmt.Sprintf("Already done: %s on %s. You can undo it until %s.", verb, res, until)
	case UndoNoticeVetoed:
		reason = fmt.Sprintf("Undo started for %s on %s.", verb, res)
	case UndoNoticeCompensated:
		reason = fmt.Sprintf("Undone: %s on %s.", verb, res)
	case UndoNoticeCompensationFailed:
		why := "unknown"
		if o, ok := r["outcome"].(map[string]any); ok {
			if s, ok := o["reason"].(string); ok {
				why = s
			}
		}
		reason = fmt.Sprintf("UNDO FAILED for %s on %s: %s. An operator has been alerted.", verb, res, why)
	case UndoNoticeRevoked:
		reason = fmt.Sprintf("The agent's grant was revoked. %s on %s can still be undone until %s.", verb, res, until)
	default:
		reason = fmt.Sprintf("Final: %s on %s can no longer be undone.", verb, res)
	}
	id := undoStr(r, "id")
	req := StepUpRequest{ID: fmt.Sprintf("undo:%s:%s", id, notice.Kind), Verb: verb, Resource: res, Tier: 3, Reason: reason, GoalCommit: "",
		Lineage: GoalLineage{GoalCommit: "", GoalVerified: false, Chain: []LineageNode{{Kind: "action", Label: verb + " " + res, Detail: "undo: " + undoStr(comp, "verb")}}, Because: reason},
		R:       0, RequestedAt: undoInt(r["opened_at"])}
	if notice.Render != nil && undoStr(r, "render_digest") != "" {
		req.Render, req.RenderDigest = notice.Render, undoStr(r, "render_digest")
	}
	link := n.cfg.InboxURL
	if notice.Kind == UndoNoticeOpened && notice.Token != "" && n.cfg.UndoURL != nil {
		link = n.cfg.UndoURL(notice.Token, id)
	}
	out := n.d.NotifyAll(req, link)
	for _, d := range out {
		if d.Delivered {
			return true, ""
		}
	}
	parts := make([]string, len(out))
	for i, d := range out {
		why := d.Reason
		if why == "" {
			why = "not delivered"
		}
		parts[i] = d.Kind + ": " + why
	}
	if len(parts) == 0 {
		return false, "no enabled channel"
	}
	return false, strings.Join(parts, "; ")
}

// ---- the hosted veto relay ----------------------------------------------------------------------------------------------------------

// UndoRelayFetch is the HTTP transport of HostedUndoVetoRelay: a GET with headers; it returns the status and the body.
type UndoRelayFetch func(url string, headers map[string]string) (status int, body []byte, err error)

// HostedUndoVetoRelayConfig configures HostedUndoVetoRelay.
type HostedUndoVetoRelayConfig struct {
	BaseURL   string
	SecretKey string
	// Fetch is the transport (nil: net/http with a 30 s timeout).
	Fetch UndoRelayFetch
	// Limit is the page size, clamped to 1..200 (0 = 200).
	Limit int
}

type hostedUndoRelay struct{ cfg HostedUndoVetoRelayConfig }

// HostedUndoVetoRelay is the relay over a hosted undo ledger: GET {baseUrl}/v1/pca/undo/vetoes with the instance secret key.
// Pass it as UndoCoordinatorOptions.Relay. A non-2xx answer or a malformed body is an error (and so finalizes nothing).
func HostedUndoVetoRelay(cfg HostedUndoVetoRelayConfig) UndoVetoRelay { return hostedUndoRelay{cfg} }

func defaultUndoFetch(url string, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, b, err
}

// Pending implements UndoVetoRelay.
func (h hostedUndoRelay) Pending() ([]UndoRelayedVeto, error) {
	f := h.cfg.Fetch
	if f == nil {
		f = defaultUndoFetch
	}
	limit := h.cfg.Limit
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	url := fmt.Sprintf("%s/v1/pca/undo/vetoes?limit=%d", strings.TrimRight(h.cfg.BaseURL, "/"), limit)
	status, body, err := f(url, map[string]string{"authorization": "Bearer " + h.cfg.SecretKey, "accept": "application/json"})
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, undoErr("invalid", fmt.Sprintf("the veto relay answered %d", status))
	}
	var doc struct {
		Data []struct {
			RecordID any `json:"record_id"`
			Veto     struct {
				Token any `json:"token"`
				At    any `json:"at"`
			} `json:"veto"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.Data == nil {
		return nil, undoErr("invalid", "the veto relay answered without a data list")
	}
	out := make([]UndoRelayedVeto, 0, len(doc.Data))
	for _, row := range doc.Data {
		id, idOk := row.RecordID.(string)
		tok, tokOk := row.Veto.Token.(string)
		at, atOk := row.Veto.At.(float64)
		if !idOk || !tokOk || !atOk {
			return nil, undoErr("invalid", "the veto relay answered a malformed entry")
		}
		out = append(out, UndoRelayedVeto{ID: id, Token: tok, At: int64(at)})
	}
	return out, nil
}

// UndoSignerPublic is the undo service key's public half for a 32-byte secret, for verifying tokens and receipts elsewhere
// (e.g. the hosted veto route).
func UndoSignerPublic(secret []byte) (string, error) {
	k, err := KeyPairFromSeed(secret)
	if err != nil {
		return "", undoErr("signer_missing", "the undo service key must be a 32-byte Ed25519 secret")
	}
	return k.Public, nil
}
