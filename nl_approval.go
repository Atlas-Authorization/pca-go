package pca

import (
	"errors"
	"math"
	"sort"
	"time"
)

// The approval half of natural-language policy authoring (generate, then review). The model's completion is injected and its output
// is never trusted: it is parsed strictly and grounded in the catalog (IntentParseNLPolicy), the result is only ever a DRAFT, and it
// becomes loadable policy only after a reviewer whose key YOU pinned signs the exact compiled policy (ApproveNLDraft).
// LoadApprovedPolicy and AgentFromApprovedNL re-derive everything from the draft contents (they trust nothing the draft says about
// itself). GUARANTEED: no model output is enforced without a pinned reviewer's unexpired signature over the exact permissions,
// limits, catalog AND (approval v2) the instruction text, the model id and the prompt that produced the draft, so a reviewer-signed
// draft cannot be attached to another goal text, and a model or prompt change changes the digest; every verb is in the catalog; the
// static analyzer has no error finding. A v1 approval (signed before the binding existed) still loads, flagged
// legacy_unbound_instruction. NOT GUARANTEED: that the model understood the instruction, or that the reviewer read the draft.
// Drafts, approvals and results are decoded JSON values (maps); digests are the lenient canonical hash.

const (
	// NLApprovalDomain is the signing domain of a v1 approval (it ends in one NUL byte).
	NLApprovalDomain = "atlas-pca/nl-approval/v1\x00"
	// NLApprovalDomainV2 is the signing domain of a v2 approval (binds the instruction, model and prompt).
	NLApprovalDomainV2 = "atlas-pca/nl-approval/v2\x00"
	// MaxNLOutputBytes: model output larger than this (UTF-8 bytes) is refused outright.
	MaxNLOutputBytes = 16384
	// MaxNLApprovalTTLMs: an approval may not be valid for longer than this.
	MaxNLApprovalTTLMs = 24 * 3600000

	defaultNLApprovalTTLMs = 3600000
)

// NLCompletion is the injected model: it maps the grounding prompt to the model's text.
type NLCompletion func(prompt string) (string, error)

// PolicyFromNLRequest is the input of PolicyFromNL and DraftPolicyFromNL. Catalog nil is the default catalog; Model identifies the
// model behind Complete (pinned by the draft digest: a different model is a different draft).
type PolicyFromNLRequest struct {
	Instruction string
	Complete    NLCompletion
	Catalog     *IntentNLCatalog
	Model       *string
}

func nlCatalog(c *IntentNLCatalog) *IntentNLCatalog {
	if c == nil {
		return NewIntentNLCatalog(nil)
	}
	return c
}

// NLCatalogDigest is the digest of the catalog vocabulary a draft was grounded against: the lenient hash of the rows [verb,
// reversibility, amountField or null] sorted by verb. It is NOT the digest of ActionCatalogDigest.
func NLCatalogDigest(c *IntentNLCatalog) (string, error) {
	c = nlCatalog(c)
	specs := append([]CatalogAction(nil), c.specs...)
	sort.SliceStable(specs, func(i, j int) bool { return compareUnits(utf16Units(specs[i].Verb), utf16Units(specs[j].Verb)) < 0 })
	rows := make([]any, len(specs))
	for i, s := range specs {
		var amount any
		if s.AmountField != "" {
			amount = s.AmountField
		}
		rows[i] = []any{s.Verb, s.Reversibility, amount}
	}
	return objHash(map[string]any{"v": 1.0, "rows": rows})
}

// NLDraftBinding is the binding a draft for instruction has, all three recomputed from public inputs (the prompt is deterministic):
// {instruction_digest, model (nil: null), prompt_digest}.
func NLDraftBinding(instruction string, c *IntentNLCatalog, model *string) (map[string]any, error) {
	ins, err := objHash(map[string]any{"d": "atlas-pca/nl-instruction/v1", "text": instruction})
	if err != nil {
		return nil, err
	}
	prompt, err := objHash(map[string]any{"d": "atlas-pca/nl-prompt/v1", "text": IntentNLPrompt(instruction, nlCatalog(c))})
	if err != nil {
		return nil, err
	}
	var m any
	if model != nil {
		m = *model
	}
	return map[string]any{"instruction_digest": ins, "model": m, "prompt_digest": prompt}, nil
}

// nlSortedList is `[...v].sort()`: a list's elements, or a string's code points, in default sort order (by their text, UTF-16).
func nlSortedList(v any) ([]any, error) {
	var out []any
	switch t := v.(type) {
	case []any:
		out = append(out, t...)
	case string:
		for _, r := range t {
			out = append(out, string(r))
		}
	default:
		return nil, errors.New("value is not iterable")
	}
	key := func(x any) []uint16 { return utf16Units(jsValueString(x)) }
	sort.SliceStable(out, func(i, j int) bool { return compareUnits(key(out[i]), key(out[j])) < 0 })
	return out, nil
}

func nlSortedPermissions(permissions any) (map[string]any, error) {
	pm, ok := permissions.(map[string]any)
	if !ok {
		if l, isList := permissions.([]any); isList && len(l) == 0 {
			return map[string]any{}, nil
		}
		return nil, errors.New("permissions must be an object")
	}
	out := make(map[string]any, len(pm))
	for k, v := range pm {
		l, err := nlSortedList(v)
		if err != nil {
			return nil, err
		}
		out[k] = l
	}
	return out, nil
}

// NLDraftDigestV2 is the digest an approval v2 signs: the v1 content PLUS {instruction_digest, model, prompt_digest}. Connector and
// action lists are sorted before hashing.
func NLDraftDigestV2(permissions, limits any, catalogDigest any, binding any) (string, error) {
	perms, err := nlSortedPermissions(permissions)
	if err != nil {
		return "", err
	}
	b, _ := binding.(map[string]any)
	return objHash(map[string]any{"v": 2.0, "permissions": perms, "limits": limits, "catalog_digest": catalogDigest,
		"instruction_digest": b["instruction_digest"], "model": b["model"], "prompt_digest": b["prompt_digest"]})
}

// NLDraftDigest is the digest a v1 approval (signed before the binding existed) signs: {permissions, limits, catalog digest}. Kept so
// old approvals still load.
func NLDraftDigest(permissions, limits any, catalogDigest any) (string, error) {
	perms, err := nlSortedPermissions(permissions)
	if err != nil {
		return "", err
	}
	return objHash(map[string]any{"v": 1.0, "permissions": perms, "limits": limits, "catalog_digest": catalogDigest})
}

// nlLints compiles what a policy grants and lints it (empty permissions: no lints).
func nlLints(permissions any, limits any, c *IntentNLCatalog) ([]any, error) {
	pm, _ := permissions.(map[string]any)
	if len(pm) == 0 {
		return []any{}, nil
	}
	lim := map[string]string{}
	switch lm := limits.(type) {
	case map[string]any:
		for k, v := range lm {
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("parseLimit: limit must be a string")
			}
			lim[k] = s
		}
	case nil:
	default:
		return nil, errors.New("limits must be an object")
	}
	cp, err := CompilePolicy(PolicyOptions{Permissions: permissions, Limits: lim, Catalog: c.cat})
	if err != nil {
		return nil, err
	}
	return LintPolicy(cp, c.cat), nil
}

func nlLintErrors(lints []any) bool {
	for _, l := range lints {
		if m, ok := l.(map[string]any); ok && m["level"] == "error" {
			return true
		}
	}
	return false
}

// nlComplete asks the model for the instruction under the catalog's grounding prompt.
func nlComplete(req PolicyFromNLRequest) (*IntentNLCatalog, string, error) {
	c := nlCatalog(req.Catalog)
	if req.Complete == nil {
		return nil, "", errors.New("complete must be a function")
	}
	raw, err := req.Complete(IntentNLPrompt(req.Instruction, c))
	return c, raw, err
}

// nlGround parses raw and lints what it grants, with the connectors in the order the model proposed them.
func nlGround(raw string, c *IntentNLCatalog) (parsed map[string]any, lints []any, err error) {
	var connOrder []string
	parsed, connOrder = ixNlParse(raw, c)
	perms := ixM(parsed["permissions"])
	if len(perms) == 0 {
		return parsed, []any{}, nil
	}
	ordered := map[string]any{}
	for _, cn := range connOrder {
		ordered[cn] = perms[cn]
	}
	recordKeyOrder(ordered, connOrder)
	lints, err = nlLints(ordered, parsed["limits"], c)
	return parsed, lints, err
}

// PolicyFromNL asks the model for a policy, grounds it against the catalog and lints the compiled result: {permissions, limits,
// unknownVerbs, droppedLimits, raw, lints}. A failing model fails the call.
func PolicyFromNL(req PolicyFromNLRequest) (map[string]any, error) {
	c, raw, err := nlComplete(req)
	if err != nil {
		return nil, err
	}
	parsed, lints, err := nlGround(raw, c)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"raw": raw, "lints": lints}
	for k, v := range parsed {
		out[k] = v
	}
	return out, nil
}

// DraftPolicyFromNL asks the model for a DRAFT (never enforced): {status "draft", instruction, permissions, limits, catalog_digest,
// binding, digest, unknownVerbs, droppedLimits, lints, analyzerOk}. A completion over MaxNLOutputBytes, or a failing model, is
// refused.
func DraftPolicyFromNL(req PolicyFromNLRequest) (map[string]any, error) {
	c, raw, err := nlComplete(req)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxNLOutputBytes {
		return nil, errors.New("draftPolicyFromNL: model output exceeds 16384 bytes or is not a string")
	}
	parsed, lints, err := nlGround(raw, c)
	if err != nil {
		return nil, err
	}
	cd, err := NLCatalogDigest(c)
	if err != nil {
		return nil, err
	}
	binding, err := NLDraftBinding(req.Instruction, c, req.Model)
	if err != nil {
		return nil, err
	}
	digest, err := NLDraftDigestV2(parsed["permissions"], parsed["limits"], cd, binding)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"status": "draft", "instruction": req.Instruction, "permissions": parsed["permissions"], "limits": parsed["limits"],
		"catalog_digest": cd, "binding": binding, "digest": digest, "unknownVerbs": parsed["unknownVerbs"], "droppedLimits": parsed["droppedLimits"],
		"lints": lints, "analyzerOk": len(ixM(parsed["permissions"])) > 0 && !nlLintErrors(lints),
	}, nil
}

func nlApprovalMessage(v any, digest, catalogDigest, reviewer, approvedAt, expiresAt any) ([]byte, error) {
	domain := NLApprovalDomain
	if f, _ := jsNum(v); f == 2 {
		domain = NLApprovalDomainV2
	}
	body, err := objCanon(map[string]any{"v": v, "digest": digest, "catalog_digest": catalogDigest, "reviewer": reviewer, "approved_at": approvedAt, "expires_at": expiresAt})
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), body...), nil
}

// NLApprovalOptions are the clock and lifetime of an approval: Now nil is the wall clock, TtlMs nil is one hour.
type NLApprovalOptions struct {
	Now   *float64
	TtlMs *float64
}

// ApproveNLDraft is the human step: sign the exact draft with the reviewer's Ed25519 seed. It refuses a draft the analyzer rejected
// (the loader would refuse it anyway), one that proposed verbs outside the catalog, and a lifetime outside (0, MaxNLApprovalTTLMs].
// The approval is {v: 2, digest, catalog_digest, reviewer, approved_at, expires_at, sig}.
func ApproveNLDraft(draft any, reviewerSecret []byte, opts NLApprovalOptions) (map[string]any, error) {
	d, ok := draft.(map[string]any)
	if !ok {
		return nil, errors.New("Cannot read properties of null (reading 'analyzerOk')")
	}
	if !rsTruthy(d["analyzerOk"]) {
		return nil, errors.New("approveDraft: the draft did not pass the static analyzer")
	}
	switch uv := d["unknownVerbs"].(type) {
	case []any:
		if len(uv) > 0 {
			return nil, errors.New("approveDraft: the draft proposed verbs that are not in the catalog")
		}
	case string:
		if len(uv) > 0 {
			return nil, errors.New("approveDraft: the draft proposed verbs that are not in the catalog")
		}
	case nil:
		return nil, errors.New("Cannot read properties of undefined (reading 'length')")
	}
	now := float64(time.Now().UnixMilli())
	if opts.Now != nil {
		now = *opts.Now
	}
	ttl := float64(defaultNLApprovalTTLMs)
	if opts.TtlMs != nil {
		ttl = *opts.TtlMs
	}
	if !objFinite(now) || !objFinite(ttl) || ttl <= 0 || ttl > MaxNLApprovalTTLMs {
		return nil, errors.New("approveDraft: invalid time or ttl")
	}
	digest, hasD := d["digest"]
	cd, hasC := d["catalog_digest"]
	if !hasD || !hasC {
		return nil, errors.New("canonicalize: unsupported type undefined")
	}
	kp, err := KeyPairFromSeed(reviewerSecret)
	if err != nil {
		return nil, err
	}
	return nlSignApproval(2, digest, cd, kp, now, now+ttl)
}

func nlSignApproval(v int, digest, catalogDigest any, kp *KeyPair, approvedAt, expiresAt float64) (map[string]any, error) {
	msg, err := nlApprovalMessage(jsNumber(float64(v)), digest, catalogDigest, kp.Public, jsNumber(approvedAt), jsNumber(expiresAt))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"v": jsNumber(float64(v)), "digest": digest, "catalog_digest": catalogDigest, "reviewer": kp.Public,
		"approved_at": jsNumber(approvedAt), "expires_at": jsNumber(expiresAt), "sig": EncodeSig(kp.Sign(msg)),
	}, nil
}

// ApproveNLDraftLegacyV1 is the pre-binding approval (v1): it signs the draft WITHOUT the instruction, model or prompt. Only for the
// legacy-load compatibility window.
func ApproveNLDraftLegacyV1(draft any, reviewerSecret []byte, opts NLApprovalOptions) (map[string]any, error) {
	v2, err := ApproveNLDraft(draft, reviewerSecret, opts)
	if err != nil {
		return nil, err
	}
	d := draft.(map[string]any)
	digest, err := NLDraftDigest(d["permissions"], d["limits"], d["catalog_digest"])
	if err != nil {
		return nil, err
	}
	kp, err := KeyPairFromSeed(reviewerSecret)
	if err != nil {
		return nil, err
	}
	a, _ := jsNum(v2["approved_at"])
	e, _ := jsNum(v2["expires_at"])
	return nlSignApproval(1, digest, d["catalog_digest"], kp, a, e)
}

// NLRejection codes of LoadApprovedPolicy.
const (
	NLNoReviewersPinned = "no_reviewers_pinned"
	NLNotADraft         = "not_a_draft"
	NLCatalogMismatch   = "catalog_mismatch"
	NLTamperedDraft     = "tampered_draft"
	NLGoalMismatch      = "goal_mismatch"
	NLUnknownVerbs      = "unknown_verbs"
	NLEmptyPermissions  = "empty_permissions"
	NLAnalyzerError     = "analyzer_error"
	NLMalformedApproval = "malformed_approval"
	NLDigestMismatch    = "digest_mismatch"
	NLReviewerNotPinned = "reviewer_not_pinned"
	NLTTLTooLong        = "ttl_too_long"
	NLNotYetValid       = "not_yet_valid"
	NLExpired           = "expired"
	NLBadSignature      = "bad_signature"
)

// LoadApprovedOptions: Reviewers are the base64url public keys allowed to approve (empty: everything is refused); Catalog nil is the
// default; Now nil is the wall clock (a NaN clock makes the time checks pass: pass a real one).
type LoadApprovedOptions struct {
	Reviewers []string
	Catalog   *IntentNLCatalog
	Now       *float64
}

func nlFail(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }

func nlIsObjectish(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func nlIsInt(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && objSafeInt(f) && !(f == 0 && math.Signbit(f))
}

// LoadApprovedPolicy is the only door from a draft to policy. It recomputes digest, grounding and lints from the draft contents and
// never fails: the result is {ok: true, permissions, limits, reviewer, instruction, legacy_unbound_instruction} or {ok: false,
// reason} with an NLRejection code. instruction is the one the reviewer's signature covers (v2); for a legacy v1 approval it is the
// draft's UNSIGNED claim.
func LoadApprovedPolicy(draft any, approval any, opts LoadApprovedOptions) (res map[string]any) {
	defer func() {
		if recover() != nil {
			res = nlFail(NLMalformedApproval)
		}
	}()
	c := nlCatalog(opts.Catalog)
	now := float64(time.Now().UnixMilli())
	if opts.Now != nil {
		now = *opts.Now
	}
	if len(opts.Reviewers) == 0 {
		return nlFail(NLNoReviewersPinned)
	}
	d, isMap := draft.(map[string]any)
	if !isMap || d["status"] != "draft" || !nlIsObjectish(d["permissions"]) || !nlIsObjectish(d["limits"]) {
		return nlFail(NLNotADraft)
	}
	cd, err := NLCatalogDigest(c)
	if err != nil {
		return nlFail(NLMalformedApproval)
	}
	if d["catalog_digest"] != any(cd) {
		return nlFail(NLCatalogMismatch)
	}
	instruction, isStr := d["instruction"].(string)
	if !isStr {
		return nlFail(NLNotADraft)
	}
	// a pre-binding draft carries no `binding` and a v1 digest: it can only ever match a v1 approval (flagged legacy below)
	rawBinding, hasBinding := d["binding"]
	legacyDraft := !hasBinding
	if !legacyDraft && !nlIsObjectish(rawBinding) {
		return nlFail(NLNotADraft)
	}
	if legacyDraft {
		h, err := NLDraftDigest(d["permissions"], d["limits"], cd)
		if err != nil || d["digest"] != any(h) {
			if err != nil {
				return nlFail(NLMalformedApproval)
			}
			return nlFail(NLTamperedDraft)
		}
	} else {
		// the binding is recomputed from the draft's own instruction; only the model id is taken from the draft
		var model *string
		if bm, ok := rawBinding.(map[string]any); ok {
			if s, isModel := bm["model"].(string); isModel {
				model = &s
			}
		}
		binding, err := NLDraftBinding(instruction, c, model)
		if err != nil {
			return nlFail(NLMalformedApproval)
		}
		bm, _ := rawBinding.(map[string]any)
		if _, hasModel := bm["model"]; !hasModel || bm["instruction_digest"] != binding["instruction_digest"] || bm["prompt_digest"] != binding["prompt_digest"] || bm["model"] != binding["model"] {
			return nlFail(NLTamperedDraft)
		}
		h, err := NLDraftDigestV2(d["permissions"], d["limits"], cd, binding)
		if err != nil {
			return nlFail(NLMalformedApproval)
		}
		if d["digest"] != any(h) {
			return nlFail(NLTamperedDraft)
		}
	}
	// re-ground: every verb must be in the catalog and every limit parse, whatever the draft claims
	for _, e := range ixNlEntries(d["permissions"]) {
		acts, isList := e.val.([]any)
		if !isList {
			return nlFail(NLUnknownVerbs)
		}
		for _, a := range acts {
			s, isStr := a.(string)
			if !isStr {
				return nlFail(NLUnknownVerbs)
			}
			if _, known := c.cat.Get(e.key + "." + s); !known {
				return nlFail(NLUnknownVerbs)
			}
		}
	}
	if uv, isList := d["unknownVerbs"].([]any); isList && len(uv) > 0 {
		return nlFail(NLUnknownVerbs)
	}
	if len(ixNlEntries(d["permissions"])) == 0 {
		return nlFail(NLEmptyPermissions)
	}
	lints, err := nlLints(d["permissions"], d["limits"], c)
	if err != nil {
		return nlFail(NLMalformedApproval)
	}
	if nlLintErrors(lints) {
		return nlFail(NLAnalyzerError)
	}
	a, isApproval := approval.(map[string]any)
	if !isApproval {
		return nlFail(NLMalformedApproval)
	}
	av, _ := jsNum(a["v"])
	_, vNum := jsNum(a["v"])
	approvedAt, okA := nlIsInt(a["approved_at"])
	expiresAt, okE := nlIsInt(a["expires_at"])
	sig, sOK := a["sig"].(string)
	reviewer, rOK := a["reviewer"].(string)
	adigest, dOK := a["digest"].(string)
	acat, cOK := a["catalog_digest"].(string)
	if !vNum || (av != 1 && av != 2) || !sOK || !rOK || !dOK || !cOK || !okA || !okE {
		return nlFail(NLMalformedApproval)
	}
	legacy := av == 1
	if legacyDraft && !legacy {
		return nlFail(NLDigestMismatch) // a v2 approval promises the instruction is bound; a binding-less draft cannot honor that
	}
	want, _ := d["digest"].(string)
	if legacy {
		// v1 signed the digest without the binding: recompute it from the (already verified) contents
		if want, err = NLDraftDigest(d["permissions"], d["limits"], cd); err != nil {
			return nlFail(NLMalformedApproval)
		}
	}
	if adigest != want || acat != cd {
		return nlFail(NLDigestMismatch)
	}
	pinned := false
	for _, r := range opts.Reviewers {
		if r == reviewer {
			pinned = true
		}
	}
	if !pinned {
		return nlFail(NLReviewerNotPinned)
	}
	if ttl := expiresAt - approvedAt; ttl <= 0 || ttl > MaxNLApprovalTTLMs {
		return nlFail(NLTTLTooLong)
	}
	if !(finite(now) && approvedAt <= now) {
		return nlFail(NLNotYetValid)
	}
	if !(finite(now) && now < expiresAt) {
		return nlFail(NLExpired)
	}
	msg, err := nlApprovalMessage(a["v"], a["digest"], a["catalog_digest"], a["reviewer"], a["approved_at"], a["expires_at"])
	if err != nil || !VerifyB64u(reviewer, msg, sig) {
		return nlFail(NLBadSignature)
	}
	return map[string]any{"ok": true, "permissions": d["permissions"], "limits": d["limits"], "reviewer": reviewer, "instruction": instruction, "legacy_unbound_instruction": legacy}
}

// AgentFromApprovedNLRequest is the input of AgentFromApprovedNL.
type AgentFromApprovedNLRequest struct {
	LoadApprovedOptions
	Draft     any
	Approval  any
	Principal *KeyPair
	// Goal is the grant's goal text. It must equal the approved instruction (v2 approvals); a legacy v1 approval cannot check it.
	Goal   string
	Aud    string
	Holder *KeyPair
}

// NLApprovedAgent is an agent minted from an approved draft.
type NLApprovedAgent struct {
	Agent                    *FacadeAgent
	Reviewer                 string
	LegacyUnboundInstruction bool
}

// AgentFromApprovedNL is the ONLY NL-to-agent path: it mints an agent from a draft a pinned reviewer signed. It refuses, with the
// rejection code in the message ("agentFromApprovedNL: <code>"), otherwise.
func AgentFromApprovedNL(req AgentFromApprovedNLRequest) (*NLApprovedAgent, error) {
	loaded := LoadApprovedPolicy(req.Draft, req.Approval, req.LoadApprovedOptions)
	if loaded["ok"] != true {
		return nil, errors.New("agentFromApprovedNL: " + jsValueString(loaded["reason"]))
	}
	legacy, _ := loaded["legacy_unbound_instruction"].(bool)
	if !legacy && req.Goal != loaded["instruction"] {
		return nil, errors.New("agentFromApprovedNL: goal_mismatch")
	}
	limits := map[string]string{}
	if lm, ok := loaded["limits"].(map[string]any); ok {
		for k, v := range lm {
			limits[k], _ = v.(string)
		}
	}
	o := AgentOptions{Principal: req.Principal, Goal: req.Goal, Permissions: loaded["permissions"], Limits: limits, Holder: req.Holder, Aud: req.Aud}
	if req.Catalog != nil {
		o.Catalog = req.Catalog.cat
	}
	if req.Now != nil {
		n := int64(*req.Now)
		o.At = &n
	}
	a, err := CreateAgent(o)
	if err != nil {
		return nil, err
	}
	return &NLApprovedAgent{Agent: a, Reviewer: loaded["reviewer"].(string), LegacyUnboundInstruction: legacy}, nil
}
