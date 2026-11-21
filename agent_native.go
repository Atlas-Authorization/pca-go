package pca

// Agent-native authority primitives (TypeScript agent-native.ts): uncertainty attestation (caution claims), rationale binding
// (commit / reveal / audit), the semantic firewall builders (tool_schema and predicates caveats, the agent-native caveat
// evaluator), capability introspection (what an attenuated chain permits) and the authority lease.
//
// Pure and deterministic: no clocks (callers pass now), no randomness except the default rationale salt. The verification and
// evaluation functions are total and fail closed (never panic on hostile input); only the authoring helpers (BindRationale,
// ToolSchemaCaveat, PredicatesCaveat, GrantLease) refuse invalid input, so a bad artefact is never minted. Values are the decoded
// JSON of the reference (maps, slices, json.Number or float64 numbers); numbers a function returns are JSON numbers
// (json.Number) written the way JavaScript writes them. SignCaution, SignHeartbeat, ValidateArgSchema and EvaluateToolSchema
// of the same family live in signers_more.go and tool_schema.go.

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
)

// Canonical caveat type names (envelope.ts / predicates.ts) plus the two this module adds, `predicates` and `tool_schema`.
const (
	CaveatEnvelope         = envelopeCaveat
	CaveatExpires          = "expires"
	CaveatNotBefore        = "not_before"
	CaveatRate             = "rate"
	CaveatMaxBlastRadius   = "max_blast_radius"
	CaveatReversibilityMax = "reversibility_max"
	CaveatDelegationDepth  = "delegation_depth"
	// CaveatPredicates is the delegated verb/resource narrowing caveat, {allow: Predicate[]}.
	CaveatPredicates = "predicates"
	// CaveatToolSchema binds tool-call authority to one exact tool, signature and argument schema.
	CaveatToolSchema = "tool_schema"
	// CaveatMaxSpend is the per-action spend ceiling in US dollars, {type: "max_spend", usd}.
	CaveatMaxSpend = "max_spend"
)

// Limits of the caution, rationale, schema and lease artefacts.
const (
	MaxCautionReasonLen  = 64
	MinSaltBytes         = 16
	MinSaltDistinctBytes = 8
	MaxRationaleLen      = 8192
	MaxValueNodes        = MaxSchemaValueNodes
	HeartbeatSkewMs      = 30_000
	MaxLeaseTtlMs        = 7 * 24 * 3_600_000
)

const (
	cautionDomain   = "atlas-pca/caution/v1"
	rationaleDomain = "atlas-pca/rationale/v1"
	heartbeatDomain = "atlas-pca/lease-hb/v2"
)

var (
	cautionClaimKeys = []string{"action_digest", "caution", "reason", "holder", "sig"}
	heartbeatKeys    = []string{"cap_id", "seq", "at", "holder", "lease_issued_at", "sig"}
)

// ---- small helpers -----------------------------------------------------------------------------------------------------

func anObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

// anJ turns a Go struct into its decoded JSON; decoded JSON values pass through unchanged.
func anJ(v any) any {
	switch v.(type) {
	case nil, bool, string, json.Number, float64, int, int64, map[string]any, []any:
		return v
	}
	if n, err := NormalizeJSON(v); err == nil {
		return n
	}
	return v
}

func anNonEmpty(v any) (string, bool) { s, ok := v.(string); return s, ok && s != "" }

func anClamp01(x float64) float64 { return math.Min(1, math.Max(0, x)) }

// anIsInt is Number.isInteger(x) && !Object.is(x, -0) for a decoded JSON value.
func anIsInt(v any) bool {
	f, ok := finNum(v)
	return ok && f == math.Trunc(f) && !(f == 0 && math.Signbit(f))
}

func anMsg(domain string, body map[string]any) ([]byte, error) { return msgOfDB(domain, body) }

// ---- 1. uncertainty attestation ----------------------------------------------------------------------------------------------

func anCautionErr(b map[string]any) string {
	if _, ok := anNonEmpty(b["action_digest"]); !ok {
		return "action_digest required"
	}
	if _, ok := anNonEmpty(b["holder"]); !ok {
		return "holder required"
	}
	if c, ok := finNum(b["caution"]); !ok || c < 0 || c > 1 {
		return "caution must be a finite number in [0,1]"
	}
	if r, has := b["reason"]; has {
		if s, ok := r.(string); !ok || jsLen(s) > MaxCautionReasonLen || !cautionReasonRe.MatchString(s) {
			return "invalid reason"
		}
	}
	return ""
}

// VerifyCaution verifies a caution claim {action_digest, caution, reason?, holder, sig}: a plain object with no member outside
// those five, caution a finite number in [0,1], a valid Ed25519 signature by claim.holder over the domain-separated body,
// bound to expectedActionDigest when given and signed by expectedHolder when given (production callers MUST pass the PCActn's
// holder, otherwise any key may attest). Total: false on anything malformed, never a panic.
func VerifyCaution(claim any, expectedActionDigest, expectedHolder *string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	c, isMap := anObj(anJ(claim))
	if !isMap {
		return false
	}
	sig, isStr := c["sig"].(string)
	if !isStr || !onlyKeys(c, cautionClaimKeys) || anCautionErr(c) != "" {
		return false
	}
	if expectedActionDigest != nil && c["action_digest"] != any(*expectedActionDigest) {
		return false
	}
	if expectedHolder != nil && c["holder"] != any(*expectedHolder) {
		return false
	}
	body := make(map[string]any, len(c))
	for k, v := range c {
		if k != "sig" {
			body[k] = v
		}
	}
	m, err := anMsg(cautionDomain, body)
	if err != nil {
		return false
	}
	return verifyB64u(c["holder"].(string), m, sig)
}

// CombinedCaution is the result of CombineSignedCaution.
type CombinedCaution struct {
	EffectiveRisk float64 `json:"effectiveRisk"`
	Honoured      bool    `json:"honoured"`
	Escalated     bool    `json:"escalated"`
}

// CombineCaution is effectiveRisk = max(agentDeclaredCaution, serverRisk): the result is never below serverRisk, so
// under-reporting gains nothing and a higher declaration raises friction. An unusable declaration (nil, NaN, infinite) is ignored;
// an unusable serverRisk fails closed to 1. Both are clamped to [0,1].
func CombineCaution(agentDeclaredCaution *float64, serverRisk float64) float64 {
	s := 1.0
	if !math.IsNaN(serverRisk) && !math.IsInf(serverRisk, 0) {
		s = anClamp01(serverRisk)
	}
	if agentDeclaredCaution == nil || math.IsNaN(*agentDeclaredCaution) || math.IsInf(*agentDeclaredCaution, 0) {
		return s
	}
	return math.Max(anClamp01(*agentDeclaredCaution), s)
}

// CombineSignedCaution is CombineCaution over a signed claim: only a valid claim bound to actionDigest (and, when given, to
// expectedHolder) is honoured; an invalid, misbound or forged claim degrades to serverRisk, never below it.
func CombineSignedCaution(claim any, actionDigest string, serverRisk float64, expectedHolder *string) CombinedCaution {
	s := 1.0
	if !math.IsNaN(serverRisk) && !math.IsInf(serverRisk, 0) {
		s = anClamp01(serverRisk)
	}
	ok := claim != nil && VerifyCaution(claim, &actionDigest, expectedHolder)
	var declared *float64
	if ok {
		c, _ := anObj(anJ(claim))
		f, _ := finNum(c["caution"])
		declared = &f
	}
	eff := CombineCaution(declared, s)
	return CombinedCaution{EffectiveRisk: eff, Honoured: ok, Escalated: eff > s}
}

// CautionMonotoneResult is the result of CheckCautionMonotone; Counterexample is [declared, server] when OK is false.
type CautionMonotoneResult struct {
	OK             bool      `json:"ok"`
	Counterexample []float64 `json:"counterexample,omitempty"`
}

// CheckCautionMonotone checks the monotonicity property of CombineCaution over the finite members of grid: the result is at
// least the clamped server risk and non-decreasing in the declared value.
func CheckCautionMonotone(grid []float64) CautionMonotoneResult {
	g := make([]float64, 0, len(grid))
	for _, x := range grid {
		if !math.IsNaN(x) && !math.IsInf(x, 0) {
			g = append(g, x)
		}
	}
	for _, s := range g {
		for _, d := range g {
			e := CombineCaution(&d, s)
			if e < anClamp01(s) {
				return CautionMonotoneResult{false, []float64{d, s}}
			}
			for _, d2 := range g {
				if d2 >= d {
					if CombineCaution(&d2, s) < e {
						return CautionMonotoneResult{false, []float64{d2, s}}
					}
				}
			}
		}
	}
	return CautionMonotoneResult{OK: true}
}

// ---- 2. rationale binding ----------------------------------------------------------------------------------------------------

// IsStrongSalt is the entropy floor of a commitment salt: strict base64url (at most 256 characters) that decodes to at least
// MinSaltBytes bytes holding at least MinSaltDistinctBytes distinct byte values. A sanity floor, not a proof of randomness.
func IsStrongSalt(salt any) bool {
	s, ok := salt.(string)
	if !ok || jsLen(s) > 256 || s == "" {
		return false
	}
	b, ok := DecodeB64uStrict(s, -1)
	if !ok || len(b) < MinSaltBytes {
		return false
	}
	var seen [256]bool
	n := 0
	for _, x := range b {
		if !seen[x] {
			seen[x] = true
			n++
		}
	}
	return n >= MinSaltDistinctBytes
}

// RationaleCommitment is the commitment published in the ledger: it binds the action digest, the salt and the rationale.
type RationaleCommitment struct {
	V            int    `json:"v"`
	ActionDigest string `json:"action_digest"`
	Commitment   string `json:"commitment"`
}

// RationaleReveal is what the agent keeps and reveals on audit.
type RationaleReveal struct {
	Rationale string `json:"rationale"`
	Salt      string `json:"salt"`
}

func anCommitDigest(actionDigest, salt, rationale string) (string, error) {
	return HashCanonical(map[string]any{"d": rationaleDomain, "a": actionDigest, "s": salt, "r": rationale})
}

// BindRationale commits to a stated reason for an action. Publish the commitment, KEEP the reveal. salt nil draws 32 random
// bytes; a given salt must pass IsStrongSalt. It refuses (authoring error) an oversized rationale (longer than MaxRationaleLen
// UTF-16 units), a weak salt and a non-canonicalizable action.
func BindRationale(action any, rationale string, salt *string) (RationaleCommitment, RationaleReveal, error) {
	var s string
	if salt == nil {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return RationaleCommitment{}, RationaleReveal{}, err
		}
		s = b64.EncodeToString(b)
	} else {
		s = *salt
	}
	if jsLen(rationale) > MaxRationaleLen {
		return RationaleCommitment{}, RationaleReveal{}, errors.New("bindRationale: rationale too long")
	}
	if !IsStrongSalt(s) {
		return RationaleCommitment{}, RationaleReveal{}, errors.New("bindRationale: salt must be b64u of >=16 bytes with >=8 distinct values")
	}
	ad, err := HashCanonical(anJ(action))
	if err != nil {
		return RationaleCommitment{}, RationaleReveal{}, err
	}
	cd, err := anCommitDigest(ad, s, rationale)
	if err != nil {
		return RationaleCommitment{}, RationaleReveal{}, err
	}
	return RationaleCommitment{V: 1, ActionDigest: ad, Commitment: cd}, RationaleReveal{Rationale: rationale, Salt: s}, nil
}

func anCommitmentOK(c map[string]any) bool {
	v, ok := finNum(c["v"])
	if !ok || v != 1 {
		return false
	}
	_, a := anNonEmpty(c["action_digest"])
	_, b := anNonEmpty(c["commitment"])
	return a && b
}

// VerifyRationale reports whether the reveal opens the commitment, optionally for this very action (pass it as the one optional
// argument; passing nil as that argument means an action of JSON null). A salt below the entropy floor is rejected even if it
// hashes correctly. Total: false on anything malformed.
func VerifyRationale(commitment, reveal any, action ...any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	c, isC := anObj(anJ(commitment))
	r, isR := anObj(anJ(reveal))
	if !isC || !isR || !anCommitmentOK(c) {
		return false
	}
	rat, isStr := r["rationale"].(string)
	if !isStr || jsLen(rat) > MaxRationaleLen || !IsStrongSalt(r["salt"]) {
		return false
	}
	if len(action) > 0 {
		h, err := HashCanonical(anJ(action[0]))
		if err != nil || h != c["action_digest"].(string) {
			return false
		}
	}
	d, err := anCommitDigest(c["action_digest"].(string), r["salt"].(string), rat)
	return err == nil && d == c["commitment"].(string)
}

// RationaleAudit is the outcome of AuditRationale: Verdict is consistent, false_rationale, unopened, wrong_action, malformed or
// judge_error; Slashable is true only when the agent is provably attributable for a false or unrevealed rationale.
type RationaleAudit struct {
	Verdict   string         `json:"verdict"`
	Slashable bool           `json:"slashable"`
	Evidence  map[string]any `json:"evidence"`
}

// RationaleJudge judges a revealed rationale against its action; an error is a failure of the judge, not of the agent.
type RationaleJudge func(rationale string, action any) (bool, error)

// AuditRationale is the after-the-fact audit. The resource server never judges the rationale: an auditor supplies judge. A
// rationale that opens the commitment and is judged false is attributable (slashable); failing to open it on demand is slashable
// too; a failing judge yields judge_error (not slashable). Total: never panics.
func AuditRationale(commitment, action, reveal any, judge RationaleJudge) (res RationaleAudit) {
	cm, isC := anObj(anJ(commitment))
	ev := map[string]any{"commitment": "", "action_digest": ""}
	if isC {
		if s, ok := cm["commitment"].(string); ok {
			ev["commitment"] = s
		}
		if s, ok := cm["action_digest"].(string); ok {
			ev["action_digest"] = s
		}
	}
	malformed := RationaleAudit{Verdict: "malformed", Slashable: false, Evidence: ev}
	defer func() {
		if recover() != nil {
			res = malformed
		}
	}()
	if !isC || !anCommitmentOK(cm) {
		return malformed
	}
	h, err := HashCanonical(anJ(action))
	if err != nil {
		return malformed
	}
	if h != cm["action_digest"].(string) {
		return RationaleAudit{Verdict: "wrong_action", Slashable: false, Evidence: ev}
	}
	rv, isR := anObj(anJ(reveal))
	if !isR || !VerifyRationale(cm, rv, action) {
		return RationaleAudit{Verdict: "unopened", Slashable: true, Evidence: ev}
	}
	rat := rv["rationale"].(string)
	withRat := map[string]any{"commitment": ev["commitment"], "action_digest": ev["action_digest"], "rationale": rat}
	ok, jerr := judge(rat, action)
	if jerr != nil {
		return RationaleAudit{Verdict: "judge_error", Slashable: false, Evidence: withRat}
	}
	if ok {
		return RationaleAudit{Verdict: "consistent", Slashable: false, Evidence: withRat}
	}
	return RationaleAudit{Verdict: "false_rationale", Slashable: true, Evidence: withRat}
}

// ---- 3. semantic firewall ----------------------------------------------------------------------------------------------------

func anBinding(tool, signatureDigest string, schema any) (string, error) {
	return HashCanonical(map[string]any{"tool": tool, "signature_digest": signatureDigest, "schema": schema})
}

// ToolSchemaCaveat builds a `tool_schema` caveat: authority exists only for this exact tool, signature and argument schema.
// toolSignature is the tool name or an object with a string `name`; argSchema must pass ValidateArgSchema. The schema is
// deep-cloned in canonical form, so later mutation of the input cannot alter the caveat. It refuses a missing tool name, an
// invalid schema or anything not canonicalizable.
func ToolSchemaCaveat(toolSignature any, argSchema any) (map[string]any, error) {
	sig := anJ(toolSignature)
	tool := ""
	switch t := sig.(type) {
	case string:
		tool = t
	case map[string]any:
		tool, _ = t["name"].(string)
	}
	if tool == "" {
		return nil, errors.New("toolSchemaCaveat: tool name required")
	}
	schemaIn := anJ(argSchema)
	if e := ValidateArgSchema(schemaIn); e != "" {
		return nil, errors.New("toolSchemaCaveat: " + e)
	}
	text, ok := canonicalLenient(schemaIn)
	if !ok {
		return nil, errors.New("toolSchemaCaveat: schema is not canonicalizable")
	}
	schema, err := ParseJSONLenient([]byte(text))
	if err != nil {
		return nil, err
	}
	sd, err := HashCanonical(sig)
	if err != nil {
		return nil, err
	}
	schD, err := HashCanonical(schema)
	if err != nil {
		return nil, err
	}
	bd, err := anBinding(tool, sd, schema)
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": CaveatToolSchema, "tool": tool, "signature_digest": sd, "schema": schema, "schema_digest": schD, "binding_digest": bd}, nil
}

// EvaluateToolSchemaCall evaluates a tool call {tool, args, toolSignature?, toolSignatureDigest?} (decoded JSON) against a
// `tool_schema` caveat. It fails AUTHORITY, not just validation: the caveat must be self-consistent (valid schema, both digests
// match), the tool and its signature must match, and the possibly nested arguments must satisfy the closed recursive schema.
// Returns (true, "") when admitted, else (false, reason). Total.
func EvaluateToolSchemaCall(caveat any, call any) (ok bool, reason string) {
	defer toolSchemaFailClosed(&ok, &reason)
	toolSchemaFault()
	c, isMap := anObj(anJ(caveat))
	tool, _ := c["tool"].(string)
	if !isMap || c["type"] != any(CaveatToolSchema) || tool == "" {
		return false, "malformed tool_schema caveat"
	}
	if e := ValidateArgSchema(c["schema"]); e != "" {
		return false, "malformed tool_schema caveat: " + e
	}
	sd, err := HashCanonical(c["schema"])
	if err != nil {
		return false, "evaluation error (fail closed)"
	}
	if any(sd) != c["schema_digest"] {
		return false, "schema digest mismatch"
	}
	bd, err := anBinding(tool, jsMemberString(c, "signature_digest"), c["schema"])
	if err != nil {
		return false, "evaluation error (fail closed)"
	}
	if any(bd) != c["binding_digest"] {
		return false, "binding digest mismatch"
	}
	cm, isCall := anObj(anJ(call))
	ct, isStr := cm["tool"].(string)
	args, plain := cm["args"].(map[string]any)
	if !isCall || !isStr || !plain {
		return false, "malformed call"
	}
	if ct != tool {
		return false, "tool " + showArg(ct) + " not authorized"
	}
	if sig, has := cm["toolSignature"]; has {
		h, err := HashCanonical(sig)
		if err != nil {
			return false, "evaluation error (fail closed)"
		}
		if any(h) != c["signature_digest"] {
			return false, "tool signature differs from the authorized signature"
		}
	}
	if d, has := cm["toolSignatureDigest"]; has && !jsStrictEq(d, c["signature_digest"]) {
		return false, "signed tool_binding differs from the authorized tool signature"
	}
	schema := c["schema"].(map[string]any)
	props, _ := schema["props"].(map[string]any)
	n := 0
	if e := checkSchemaObject(props, schema["required"], args, "args", 1, &n); e != "" {
		return false, e
	}
	return true, ""
}

// ToolSchemaEvaluator plugs into the caveat-evaluator extension point: ctx = {toolCall}. Any other caveat type is unsatisfied.
func ToolSchemaEvaluator(caveat any, ctx any) bool {
	x, ok := anObj(anJ(ctx))
	if !ok {
		return false
	}
	if _, ok := anObj(x["toolCall"]); !ok {
		return false
	}
	ok, _ = EvaluateToolSchemaCall(caveat, x["toolCall"])
	return ok
}

// PredicatesCaveat builds the delegated-narrowing caveat {type: "predicates", allow} with allow deep-cloned in canonical form.
func PredicatesCaveat(allow any) (map[string]any, error) {
	text, ok := canonicalLenient(anJ(allow))
	if !ok {
		return nil, errors.New("predicatesCaveat: allow is not canonicalizable")
	}
	clone, err := ParseJSONLenient([]byte(text))
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": CaveatPredicates, "allow": clone}, nil
}

// ActionSpendUsd is the action's spend in USD as `max_spend` reads it: the own action.action.params.amount (finite, >= 0) with an
// own currency, when present, of "usd" or "USD". ok is false when there is no readable spend.
func ActionSpendUsd(action any) (usd float64, ok bool) {
	a, isMap := anObj(anJ(action))
	if !isMap {
		return 0, false
	}
	act, isAct := anObj(a["action"])
	if !isAct {
		return 0, false
	}
	params, isP := anObj(act["params"])
	if !isP {
		return 0, false
	}
	amount, has := params["amount"]
	if !has {
		return 0, false
	}
	f, fin := finNum(amount)
	if !fin || f < 0 {
		return 0, false
	}
	if cur, has := params["currency"]; has && cur != any("usd") && cur != any("USD") {
		return 0, false
	}
	return f, true
}

func anMaxSpendOK(cv, ctx map[string]any) bool {
	lim, ok := finNum(cv["usd"])
	if !ok {
		return false
	}
	spend, has := ActionSpendUsd(ctx["action"])
	return has && spend <= lim
}

// AgentNativeCaveatEvaluator is a superset of the stock envelope caveat evaluator: it adds `predicates` (needs ctx.action, an
// action context {action: {verb, resource, params}}), `max_spend` (needs ctx.action) and `tool_schema` (needs ctx.toolCall). The
// stock context fields are now, blastRadius, reversibilityClass, delegationDepth and recentActionTimes. Anything else is
// unsatisfied (fail closed). Total.
func AgentNativeCaveatEvaluator(caveat any, ctx any) (sat bool) {
	defer func() {
		if recover() != nil {
			sat = false
		}
	}()
	cv, ok1 := anObj(anJ(caveat))
	x, ok2 := anObj(anJ(ctx))
	if !ok1 || !ok2 {
		return false
	}
	switch cv["type"] {
	case any(CaveatToolSchema):
		return ToolSchemaEvaluator(cv, x)
	case any(CaveatPredicates):
		a, isA := anObj(x["action"])
		allow, isArr := cv["allow"].([]any)
		if !isA || !isArr {
			return false
		}
		b := &regexBudget{}
		for _, p := range allow {
			if predicateMatches(p, a, b) {
				return true
			}
		}
		return false
	case any(CaveatMaxSpend):
		return anMaxSpendOK(cv, x)
	}
	now, ok := finNum(x["now"])
	if !ok {
		return false
	}
	typ, _ := cv["type"].(string)
	switch typ {
	case CaveatExpires:
		at, ok := finNum(cv["at"])
		return ok && now < at
	case CaveatNotBefore:
		at, ok := finNum(cv["at"])
		return ok && now >= at
	case CaveatRate:
		mx, ok1 := finNum(cv["max"])
		per, ok2 := finNum(cv["per_secs"])
		times, ok3 := x["recentActionTimes"].([]any)
		if !ok1 || !ok2 || per <= 0 || !ok3 {
			return false
		}
		lo := now - per*1000
		n := 0
		for _, tv := range times {
			if t, ok := finNum(tv); ok && t > lo && t <= now {
				n++
			}
		}
		return float64(n) < mx
	case CaveatMaxBlastRadius:
		mx, ok1 := finNum(cv["max"])
		br, ok2 := finNum(x["blastRadius"])
		return ok1 && ok2 && br <= mx
	case CaveatReversibilityMax:
		lim, ok1 := cv["class"].(string)
		cur, ok2 := x["reversibilityClass"].(string)
		if !ok1 || !ok2 {
			return false
		}
		li, ok1 := reversibilityOrder[lim]
		ci, ok2 := reversibilityOrder[cur]
		return ok1 && ok2 && ci <= li
	case CaveatDelegationDepth:
		mx, ok1 := finNum(cv["max"])
		d, ok2 := finNum(x["delegationDepth"])
		return ok1 && ok2 && d <= mx
	case "budget_alloc":
		lim, ok := finNum(cv["limit"])
		return ok && lim >= 0
	case intentSessionCaveat:
		return intentSessionCaveatError(cv) == ""
	}
	return false
}

// ---- 4. capability introspection ---------------------------------------------------------------------------------------------

type anScope struct {
	verbs, resources []string
	where            []any
}

func (s anScope) json() map[string]any {
	vs := make([]any, len(s.verbs))
	for i, v := range s.verbs {
		vs[i] = v
	}
	rs := make([]any, len(s.resources))
	for i, v := range s.resources {
		rs[i] = v
	}
	w := s.where
	if w == nil {
		w = []any{}
	}
	return map[string]any{"verbs": vs, "resources": rs, "where": w}
}

func anSortedUnique(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sortUtf8(out)
	return out
}

func anHas(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func anIntersectVerbs(a, b []string) []string {
	if anHas(a, "*") {
		return anSortedUnique(b)
	}
	if anHas(b, "*") {
		return anSortedUnique(a)
	}
	var both []string
	for _, x := range a {
		if anHas(b, x) {
			both = append(both, x)
		}
	}
	return anSortedUnique(both)
}

// anInterRes intersects two resource patterns: (value, true) on a result, (_, false) when empty; undecided (a regex) reports
// empty as well, which every caller treats alike.
func anInterRes(a, b string) (string, bool) {
	if a == b {
		return a, true
	}
	if strings.HasPrefix(a, "re:") || strings.HasPrefix(b, "re:") {
		return "", false
	}
	if a == "*" {
		return b, true
	}
	if b == "*" {
		return a, true
	}
	ap, bp := strings.HasSuffix(a, "*"), strings.HasSuffix(b, "*")
	if ap && bp {
		pa, pb := a[:len(a)-1], b[:len(b)-1]
		if jsStartsWith(pb, pa) {
			return b, true
		}
		if jsStartsWith(pa, pb) {
			return a, true
		}
		return "", false
	}
	if ap {
		if jsStartsWith(b, a[:len(a)-1]) {
			return b, true
		}
		return "", false
	}
	if bp {
		if jsStartsWith(a, b[:len(b)-1]) {
			return a, true
		}
		return "", false
	}
	return "", false
}

func anCollapse(list []string) ([]string, bool) {
	lit, hasLit := "", false
	res := map[string]bool{}
	for _, p := range list {
		if strings.HasPrefix(p, "re:") {
			res[p] = true
			continue
		}
		if !hasLit {
			lit, hasLit = p, true
			continue
		}
		r, ok := anInterRes(lit, p)
		if !ok {
			return nil, false
		}
		lit = r
	}
	var out []string
	if hasLit && lit != "*" {
		out = append(out, lit)
	}
	rs := make([]string, 0, len(res))
	for r := range res {
		rs = append(rs, r)
	}
	sortUtf8(rs)
	out = append(out, rs...)
	if len(out) == 0 {
		return []string{"*"}, true
	}
	return out, true
}

func anScopeOfPredicate(p any) (anScope, bool) {
	m, ok := anObj(p)
	if !ok {
		return anScope{}, false
	}
	var verbs []string
	switch v := m["verb"].(type) {
	case string:
		verbs = []string{v}
	case []any:
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return anScope{}, false
			}
			verbs = append(verbs, s)
		}
	default:
		return anScope{}, false
	}
	res := "*"
	if rv, has := m["resource"]; has {
		s, ok := rv.(string)
		if !ok {
			return anScope{}, false
		}
		res = s
	}
	where := []any{}
	if wv, has := m["where"]; has {
		w, ok := wv.([]any)
		if !ok {
			return anScope{}, false
		}
		where = w
	}
	return anScope{verbs: anSortedUnique(verbs), resources: []string{res}, where: where}, true
}

func anIntersectScopes(a, b []anScope) []anScope {
	var order []string
	byKey := map[string]anScope{}
	for _, x := range a {
		for _, y := range b {
			verbs := anIntersectVerbs(x.verbs, y.verbs)
			if len(verbs) == 0 {
				continue
			}
			resources, ok := anCollapse(append(append([]string{}, x.resources...), y.resources...))
			if !ok {
				continue
			}
			where := append(append([]any{}, x.where...), y.where...)
			s := anScope{verbs: verbs, resources: resources, where: where}
			k, err := HashCanonical(s.json())
			if err != nil {
				panic(err)
			}
			if _, seen := byKey[k]; !seen {
				order = append(order, k)
			}
			byKey[k] = s
		}
	}
	sort.Strings(order)
	out := make([]anScope, len(order))
	for i, k := range order {
		out[i] = byKey[k]
	}
	return out
}

func anScopeMatches(s map[string]any, verb, resource string, params map[string]any) bool {
	verbs, ok1 := s["verbs"].([]any)
	resources, ok2 := s["resources"].([]any)
	where, ok3 := s["where"].([]any)
	if !ok1 || !ok2 || !ok3 {
		panic("malformed scope")
	}
	has := func(x string) bool {
		for _, v := range verbs {
			if v == any(x) {
				return true
			}
		}
		return false
	}
	if !has("*") && !has(verb) {
		return false
	}
	act := map[string]any{"verb": verb, "resource": resource}
	if params != nil {
		act["params"] = params
	}
	ctx := map[string]any{"action": act}
	b := &regexBudget{}
	for _, r := range resources {
		if !predicateMatches(map[string]any{"verb": "*", "resource": r}, ctx, b) {
			return false
		}
	}
	if params != nil && len(where) > 0 {
		return predicateMatches(map[string]any{"verb": "*", "where": where}, ctx, b)
	}
	return true
}

func anWellFormedCaveat(cv map[string]any, typ string) bool {
	switch typ {
	case CaveatExpires, CaveatNotBefore:
		_, ok := finNum(cv["at"])
		return ok
	case CaveatRate:
		_, ok1 := finNum(cv["max"])
		per, ok2 := finNum(cv["per_secs"])
		return ok1 && ok2 && per > 0
	case CaveatMaxBlastRadius, CaveatDelegationDepth:
		_, ok := finNum(cv["max"])
		return ok
	case CaveatReversibilityMax:
		c, ok := cv["class"].(string)
		_, known := reversibilityOrder[c]
		return ok && known
	case CaveatPredicates:
		allow, ok := cv["allow"].([]any)
		if !ok {
			return false
		}
		for _, p := range allow {
			if _, ok := anScopeOfPredicate(p); !ok {
				return false
			}
		}
		return true
	case CaveatToolSchema:
		_, ok := anNonEmpty(cv["tool"])
		return ok
	case "budget_alloc":
		l, ok := finNum(cv["limit"])
		return ok && l >= 0
	case CaveatMaxSpend:
		l, ok := finNum(cv["usd"])
		return ok && l >= 0
	}
	return false
}

func anEmptyEnvelope() map[string]any {
	return map[string]any{"ok": false, "hasEnvelope": false, "scopes": []any{}, "verbs": []any{}, "resources": []any{},
		"opaqueResourceConstraints": []any{}, "tools": []any{}, "toolSchemas": []any{}, "unsatisfiable": []any{}, "caveats": []any{},
		"remainingBudgetHints": map[string]any{}}
}

func anStrList(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// DescribeEnvelope computes what an attenuated chain actually permits now, deterministically (now is supplied; nil = unknown).
// The chain is verified first with VerifyChainPolicy (expectedRootIssuer nil = any root; policy is the optional
// {allowedSuites, pqPins, trustedRoot} object); an unverifiable chain gives ok:false with the chain's reason and nothing
// permitted. Caveats are conjunctive and append-only, so the envelope is the intersection across all hops: the set the verifier
// would accept, never wider. A caveat the verifier cannot satisfy (unknown type, malformed fields, a second `envelope`) is listed
// in `unsatisfiable` and nothing is permitted. The result is the JSON object of the reference (scopes, verbs, resources,
// opaqueResourceConstraints, tools, toolSchemas, unsatisfiable, caveats, remainingBudgetHints, reason?); pass it to
// EnvelopePermits and EnvelopePermitsToolCall. Total: never panics.
func DescribeEnvelope(chain any, now *float64, expectedRootIssuer *string, policy any) (out map[string]any) {
	defer func() {
		if recover() != nil {
			out = anEmptyEnvelope()
			out["reason"] = "introspection error (fail closed)"
		}
	}()
	empty := anEmptyEnvelope()
	list, _ := anJ(chain).([]any)
	issuer, haveIssuer := "", expectedRootIssuer != nil
	if haveIssuer {
		issuer = *expectedRootIssuer
	}
	var allowed []string
	var pins map[string]string
	var trusted map[string]any
	if p, ok := anObj(anJ(policy)); ok {
		if a, ok := p["allowedSuites"].([]any); ok {
			allowed = []string{}
			for _, x := range a {
				s, _ := x.(string)
				allowed = append(allowed, s)
			}
		}
		if m, ok := p["pqPins"].(map[string]any); ok {
			pins = map[string]string{}
			for k, v := range m {
				pins[k], _ = v.(string)
			}
		}
		trusted, _ = p["trustedRoot"].(map[string]any)
	}
	if why, ok := VerifyChainPolicy(list, issuer, haveIssuer, allowed, pins, trusted); !ok {
		empty["reason"] = why
		return empty
	}
	root, _ := anObj(list[0])
	leaf, _ := anObj(list[len(list)-1])
	env0 := ReadEnvelope(root)
	env := anEmptyEnvelope()
	env["ok"] = true
	env["hasEnvelope"] = env0 != nil
	env["caveats"] = leaf["caveats"]
	hints := map[string]any{}
	bad := map[string]bool{}
	all := []anScope{{verbs: []string{"*"}, resources: []string{"*"}, where: []any{}}}

	var scopes []anScope
	haveScopes := false
	if env0 != nil {
		var base []anScope
		for _, p := range env0["predicates"].([]any) {
			s, ok := anScopeOfPredicate(p)
			if !ok {
				bad["envelope.predicates"] = true
				continue
			}
			base = append(base, s)
		}
		scopes, haveScopes = anIntersectScopes(base, all), true
	}
	var tools []string
	haveTools := false
	seenEnvelope := false
	var toolSchemas []any
	fnum := func(k string) (float64, bool) { f, ok := hints[k].(float64); return f, ok }

	fold := func(raw any, inEnvelope bool) {
		cv, ok := anObj(raw)
		typ, isStr := cv["type"].(string)
		if !ok || !isStr {
			bad["<malformed>"] = true
			return
		}
		if typ == CaveatEnvelope {
			if seenEnvelope || inEnvelope {
				bad[CaveatEnvelope] = true
			}
			seenEnvelope = true
			return
		}
		if !anWellFormedCaveat(cv, typ) {
			bad[typ] = true
			return
		}
		switch typ {
		case CaveatPredicates:
			var next []anScope
			for _, p := range cv["allow"].([]any) {
				s, _ := anScopeOfPredicate(p)
				next = append(next, s)
			}
			if !haveScopes {
				scopes, haveScopes = all, true
			}
			scopes = anIntersectScopes(scopes, next)
		case CaveatToolSchema:
			toolSchemas = append(toolSchemas, cv)
			tool := cv["tool"].(string)
			consistent := ValidateArgSchema(cv["schema"]) == ""
			if consistent {
				h, err := HashCanonical(cv["schema"])
				if err != nil {
					panic(err)
				}
				consistent = any(h) == cv["schema_digest"]
			}
			if consistent {
				b, err := anBinding(tool, jsMemberString(cv, "signature_digest"), cv["schema"])
				if err != nil {
					panic(err)
				}
				consistent = any(b) == cv["binding_digest"]
			}
			if !consistent {
				tools, haveTools = []string{}, true
				bad[CaveatToolSchema] = true
			} else if !haveTools {
				tools, haveTools = []string{tool}, true
			} else {
				var kept []string
				for _, t := range tools {
					if t == tool {
						kept = append(kept, t)
					}
				}
				tools = kept
			}
		case CaveatExpires:
			at, _ := finNum(cv["at"])
			if cur, has := fnum("expiresAt"); has {
				at = math.Min(cur, at)
			}
			hints["expiresAt"] = at
		case CaveatNotBefore:
			at, _ := finNum(cv["at"])
			if cur, has := fnum("notBefore"); has {
				at = math.Max(cur, at)
			}
			hints["notBefore"] = at
		case CaveatRate:
			m, _ := finNum(cv["max"])
			p, _ := finNum(cv["per_secs"])
			cur, has := hints["maxRate"].(map[string]float64)
			if !has || m/p < cur["max"]/cur["per_secs"] || (m/p == cur["max"]/cur["per_secs"] && m < cur["max"]) {
				hints["maxRate"] = map[string]float64{"max": m, "per_secs": p}
			}
		case CaveatMaxBlastRadius:
			m, _ := finNum(cv["max"])
			if cur, has := fnum("maxBlastRadius"); has {
				m = math.Min(cur, m)
			}
			hints["maxBlastRadius"] = m
		case CaveatReversibilityMax:
			i := reversibilityOrder[cv["class"].(string)]
			j := len(reversibilityOrder)
			if cur, has := hints["reversibilityMax"].(string); has {
				j = reversibilityOrder[cur]
			}
			if i < j {
				for name, idx := range reversibilityOrder {
					if idx == i {
						hints["reversibilityMax"] = name
					}
				}
			}
		case CaveatDelegationDepth:
			m, _ := finNum(cv["max"])
			rem := m - float64(len(list)-1)
			if cur, has := fnum("delegationDepthRemaining"); has {
				rem = math.Min(cur, rem)
			}
			hints["delegationDepthRemaining"] = rem
		case "budget_alloc":
			l, _ := finNum(cv["limit"])
			if cur, has := fnum("budgetAlloc"); has {
				l = math.Min(cur, l)
			}
			hints["budgetAlloc"] = l
		case CaveatMaxSpend:
			l, _ := finNum(cv["usd"])
			if cur, has := fnum("maxSpendUsd"); has {
				l = math.Min(cur, l)
			}
			hints["maxSpendUsd"] = l
		}
	}

	if env0 != nil {
		for _, cv := range env0["caveats"].([]any) {
			fold(cv, true)
		}
	}
	if lc, ok := leaf["caveats"].([]any); ok {
		for _, cv := range lc {
			fold(cv, false)
		}
	}

	opaque := map[string]bool{}
	if haveScopes {
		vs, rs := map[string]bool{}, map[string]bool{}
		scopeJSON := make([]any, len(scopes))
		for i, s := range scopes {
			scopeJSON[i] = s.json()
			for _, v := range s.verbs {
				vs[v] = true
			}
			for _, r := range s.resources {
				rs[r] = true
				if strings.HasPrefix(r, "re:") {
					opaque[r] = true
				}
			}
		}
		env["scopes"] = scopeJSON
		env["verbs"] = anStrList(anKeysOf(vs))
		env["resources"] = anStrList(anKeysOf(rs))
	} else {
		env["scopes"], env["verbs"], env["resources"] = nil, nil, nil
	}
	env["opaqueResourceConstraints"] = anStrList(anKeysOf(opaque))
	if haveTools {
		env["tools"] = anStrList(anSortedUnique(tools))
	} else {
		env["tools"] = nil
	}
	if toolSchemas != nil {
		env["toolSchemas"] = toolSchemas
	}
	unsat := make([]string, 0, len(bad))
	for k := range bad {
		unsat = append(unsat, k)
	}
	sortUtf8(unsat)
	env["unsatisfiable"] = anStrList(unsat)
	if len(unsat) > 0 {
		env["scopes"], env["verbs"], env["resources"], env["tools"] = []any{}, []any{}, []any{}, []any{}
		env["reason"] = "unsatisfiable caveat(s): " + strings.Join(unsat, ", ")
	}
	if at, has := fnum("expiresAt"); has && now != nil && !math.IsNaN(*now) && !math.IsInf(*now, 0) {
		hints["expiresIn"] = at - *now
	}
	outHints := map[string]any{}
	for k, v := range hints {
		switch t := v.(type) {
		case float64:
			outHints[k] = jsNumber(t)
		case map[string]float64:
			outHints[k] = map[string]any{"max": jsNumber(t["max"]), "per_secs": jsNumber(t["per_secs"])}
		default:
			outHints[k] = v
		}
	}
	env["remainingBudgetHints"] = outHints
	return env
}

func anKeysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortUtf8(out)
	return out
}

// EnvelopePermits is the cheap pre-flight an agent can run before attempting. false is DEFINITIVE (the verifier will refuse);
// true means the symbolic envelope allows it. env is the result of DescribeEnvelope. When params is given (non-nil), `where`
// conditions are evaluated too (fail closed); without it, conditional scopes count as "may permit". now nil = not given; a NaN or
// infinite now is refused, expiry is exclusive. Total.
func EnvelopePermits(env any, verb, resource string, now *float64, params map[string]any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	e, isMap := anObj(anJ(env))
	if !isMap {
		return false
	}
	if good, _ := e["ok"].(bool); !good {
		return false
	}
	unsat, isArr := e["unsatisfiable"].([]any)
	if !isArr || len(unsat) > 0 {
		return false
	}
	if e["scopes"] != nil {
		scopes, isArr := e["scopes"].([]any)
		if !isArr {
			return false
		}
		any1 := false
		for _, s := range scopes {
			sm, isM := anObj(s)
			if !isM {
				panic("malformed scope")
			}
			if anScopeMatches(sm, verb, resource, params) {
				any1 = true
				break
			}
		}
		if !any1 {
			return false
		}
	}
	h, _ := anObj(e["remainingBudgetHints"])
	if v, has := h["delegationDepthRemaining"]; has { // a present value that is not a finite number >= 0 refuses
		if r, ok := finNum(v); !ok || !(r >= 0) {
			return false
		}
	}
	if v, has := h["maxSpendUsd"]; has && params != nil {
		lim, limOK := jsNum(v) // an infinite cap is the unbounded one; NaN or a non-number refuses
		spend, got := ActionSpendUsd(map[string]any{"action": map[string]any{"params": params}})
		if !got || !limOK || !(spend <= lim) {
			return false
		}
	}
	if now != nil {
		if math.IsNaN(*now) || math.IsInf(*now, 0) {
			return false
		}
		if v, has := h["expiresAt"]; has {
			if at, ok := finNum(v); !ok || !(*now < at) {
				return false
			}
		}
		if v, has := h["notBefore"]; has {
			if nb, ok := finNum(v); !ok || !(*now >= nb) {
				return false
			}
		}
	}
	return true
}

// EnvelopePermitsToolCall is the pre-flight for a tool call: the tool must be in env.tools (when that is not null) and satisfy
// EVERY `tool_schema` caveat of the chain; the first failure is returned. env is the result of DescribeEnvelope. Total.
func EnvelopePermitsToolCall(env any, call any) (ok bool, reason string) {
	defer func() {
		if recover() != nil {
			ok, reason = false, "evaluation error (fail closed)"
		}
	}()
	e, isMap := anObj(anJ(env))
	if !isMap {
		panic("env is not an object")
	}
	unsat, _ := e["unsatisfiable"].([]any)
	if good, _ := e["ok"].(bool); !good || len(unsat) > 0 {
		if r, has := e["reason"]; has && r != nil {
			return false, jsValueString(r)
		}
		return false, "envelope not usable"
	}
	cm, isCall := anObj(anJ(call))
	if e["tools"] != nil {
		tools, _ := e["tools"].([]any)
		if call == nil {
			panic("call is null")
		}
		tool, isStr := cm["tool"].(string)
		found := false
		for _, t := range tools {
			if isStr && t == any(tool) {
				found = true
			}
		}
		if !found {
			name := "undefined"
			if v, has := cm["tool"]; has {
				name = jsValueString(v)
			}
			return false, "tool " + showArg(name) + " not authorized"
		}
	}
	schemas, _ := e["toolSchemas"].([]any)
	var callArg any = call
	if !isCall {
		callArg = nil
	}
	for _, tc := range schemas {
		if good, why := EvaluateToolSchemaCall(tc, callArg); !good {
			return false, why
		}
	}
	return true, ""
}

// ---- 5. authority lease ------------------------------------------------------------------------------------------------------

// GrantLease issues a lease record {cap_id, holder, issued_at, renewed_at, ttl_ms, renewals, last_seq, expires_at,
// hard_expires_at?, max_renewals?} from {cap_id, holder, now, ttl_ms, hard_expires_at?, max_renewals?}. It refuses (authoring
// error) unless the ids are non-empty, now is finite, 0 < ttl_ms <= MaxLeaseTtlMs, hard_expires_at (if present) is finite and
// after now, and max_renewals (if present) is a non-negative integer. Persist and update the record atomically (row lock or
// compare-and-swap on last_seq); RenewCapabilityLease is a pure function returning the next record.
func GrantLease(args any) (map[string]any, error) {
	a, ok := anObj(anJ(args))
	if !ok {
		return nil, errors.New("grantLease: cap_id and holder required")
	}
	capID, ok1 := anNonEmpty(a["cap_id"])
	holder, ok2 := anNonEmpty(a["holder"])
	if !ok1 || !ok2 {
		return nil, errors.New("grantLease: cap_id and holder required")
	}
	now, okN := finNum(a["now"])
	ttl, okT := finNum(a["ttl_ms"])
	if !okN || !okT || ttl <= 0 || ttl > MaxLeaseTtlMs {
		return nil, errors.New("grantLease: invalid now/ttl_ms")
	}
	hard, hasHard := a["hard_expires_at"]
	var hardF float64
	if hasHard {
		f, ok := finNum(hard)
		if !ok || f <= now {
			return nil, errors.New("grantLease: hard_expires_at must be finite and in the future")
		}
		hardF = f
	}
	mr, hasMR := a["max_renewals"]
	if hasMR && !(anIsInt(mr) && jsF(mr) >= 0) {
		return nil, errors.New("grantLease: invalid max_renewals")
	}
	exp := now + ttl
	if hasHard {
		exp = math.Min(exp, hardF)
	}
	l := map[string]any{"cap_id": capID, "holder": holder, "issued_at": jsNumber(now), "renewed_at": jsNumber(now), "ttl_ms": jsNumber(ttl),
		"renewals": json.Number("0"), "last_seq": json.Number("0"), "expires_at": jsNumber(exp)}
	if hasHard {
		l["hard_expires_at"] = jsNumber(hardF)
	}
	if hasMR {
		l["max_renewals"] = jsNumber(jsF(mr))
	}
	return l, nil
}

func anLeaseErr(v any) string {
	l, ok := anObj(v)
	if !ok {
		return "malformed lease"
	}
	if _, ok := anNonEmpty(l["cap_id"]); !ok {
		return "malformed lease"
	}
	if _, ok := anNonEmpty(l["holder"]); !ok {
		return "malformed lease"
	}
	issued, ok1 := finNum(l["issued_at"])
	renewed, ok2 := finNum(l["renewed_at"])
	ttl, ok3 := finNum(l["ttl_ms"])
	expires, ok4 := finNum(l["expires_at"])
	_ = issued
	if !ok1 || !ok2 || !ok3 || !ok4 || ttl <= 0 || ttl > MaxLeaseTtlMs {
		return "malformed lease"
	}
	for _, k := range []string{"renewals", "last_seq"} {
		if !anIsInt(l[k]) || jsF(l[k]) < 0 {
			return "malformed lease"
		}
	}
	if mr, has := l["max_renewals"]; has && !(anIsInt(mr) && jsF(mr) >= 0) {
		return "malformed lease"
	}
	if hv, has := l["hard_expires_at"]; has {
		hard, ok := finNum(hv)
		if !ok {
			return "malformed lease"
		}
		if expires > hard {
			return "lease exceeds hard expiry"
		}
	}
	if expires > renewed+ttl {
		return "malformed lease"
	}
	return ""
}

// LeaseStatus is the result of LeaseState; ExpiresIn is 0 for every dead state, Reason is set only when not live.
type LeaseStatus struct {
	Live      bool    `json:"live"`
	ExpiresIn float64 `json:"expiresIn"`
	Reason    string  `json:"reason,omitempty"`
}

// LeaseState reports whether a lease is live at now: the record is well-formed, the clock has not rolled back more than
// HeartbeatSkewMs past the last renewal, and now < expires_at. Malformed, NaN or rolled-back means not live (fail closed), with
// a Reason. A lapsed lease has ExpiresIn 0.
func LeaseState(lease any, now float64) LeaseStatus {
	dead := func(r string) LeaseStatus { return LeaseStatus{Live: false, ExpiresIn: 0, Reason: r} }
	if math.IsNaN(now) || math.IsInf(now, 0) {
		return dead("invalid clock")
	}
	l := anJ(lease)
	if e := anLeaseErr(l); e != "" {
		return dead(e)
	}
	m := l.(map[string]any)
	renewed, _ := finNum(m["renewed_at"])
	expires, _ := finNum(m["expires_at"])
	if now < renewed-HeartbeatSkewMs {
		return dead("clock before last renewal")
	}
	in := expires - now
	if in <= 0 {
		return dead("lease lapsed")
	}
	return LeaseStatus{Live: true, ExpiresIn: in}
}

// RenewResult is the result of RenewCapabilityLease: the next lease record, or the reason it was refused.
type RenewResult struct {
	OK     bool           `json:"ok"`
	Lease  map[string]any `json:"lease,omitempty"`
	Reason string         `json:"reason,omitempty"`
}

// RenewCapabilityLease renews a capability lease (the agent-native lease of GrantLease, not the grants LeaseRegistry) on a
// valid, fresh, in-order, holder-signed heartbeat for THIS lease grant. A lease that has already lapsed (or is malformed or
// clock-anomalous) is dead for good: no resurrection by a late heartbeat. Renewal never extends past hard_expires_at, never
// shortens the lease and consumes the renewal budget. The checks run in this order and the reason names the first that fails.
// Pure and total: it never panics.
func RenewCapabilityLease(lease any, hb any, now float64) (res RenewResult) {
	defer func() {
		if recover() != nil {
			res = RenewResult{Reason: "malformed heartbeat"}
		}
	}()
	l := anJ(lease)
	st := LeaseState(l, now)
	if !st.Live {
		if st.Reason == "lease lapsed" {
			return RenewResult{Reason: "lease lapsed"}
		}
		return RenewResult{Reason: "lease not live: " + st.Reason}
	}
	lm := l.(map[string]any)
	h, isMap := anObj(anJ(hb))
	if !isMap || !onlyKeys(h, heartbeatKeys) {
		return RenewResult{Reason: "malformed heartbeat"}
	}
	sig, isStr := h["sig"].(string)
	if !isStr {
		return RenewResult{Reason: "malformed heartbeat"}
	}
	if !jsStrictEq(h["cap_id"], lm["cap_id"]) || !jsStrictEq(h["holder"], lm["holder"]) || !jsStrictEq(h["lease_issued_at"], lm["issued_at"]) {
		return RenewResult{Reason: "heartbeat not for this lease"}
	}
	if !jsIsSafeInteger(h["seq"]) || jsF(h["seq"]) <= jsF(lm["last_seq"]) {
		return RenewResult{Reason: "stale or replayed heartbeat"}
	}
	at, ok := finNum(h["at"])
	if !ok || math.Abs(at-now) > HeartbeatSkewMs {
		return RenewResult{Reason: "heartbeat outside skew window"}
	}
	body := make(map[string]any, len(h))
	for k, v := range h {
		if k != "sig" {
			body[k] = v
		}
	}
	msg, err := anMsg(heartbeatDomain, body)
	if err != nil {
		return RenewResult{Reason: "malformed heartbeat"}
	}
	if !verifyB64u(lm["holder"].(string), msg, sig) {
		return RenewResult{Reason: "bad heartbeat signature"}
	}
	renewals := jsF(lm["renewals"])
	if mr, has := lm["max_renewals"]; has && renewals >= jsF(mr) {
		return RenewResult{Reason: "renewal budget exhausted"}
	}
	ttl, _ := finNum(lm["ttl_ms"])
	exp := now + ttl
	if hv, has := lm["hard_expires_at"]; has {
		exp = math.Min(exp, jsF(hv))
	}
	if math.IsNaN(exp) || math.IsInf(exp, 0) {
		return RenewResult{Reason: "malformed lease"}
	}
	renewedAt, _ := finNum(lm["renewed_at"])
	expiresAt, _ := finNum(lm["expires_at"])
	next := make(map[string]any, len(lm))
	for k, v := range lm {
		next[k] = v
	}
	next["renewals"] = jsNumber(renewals + 1)
	next["last_seq"] = h["seq"]
	next["renewed_at"] = jsNumber(math.Max(now, renewedAt))
	next["expires_at"] = jsNumber(math.Max(exp, expiresAt))
	return RenewResult{OK: true, Lease: next}
}
