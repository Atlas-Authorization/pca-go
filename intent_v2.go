package pca

// The Intent Layer v2 checks of the core verifier (packages/pca/src/intent-v2.ts decideIntentV2), in their normative
// order after `intent` (rule 12; conformance README "Intent Layer v2: the verification pipeline"):
//
//	schema (rule 14) -> intent_session (rule 13) -> layers (V5) -> accumulators (rule 15)
//	-> facts (rule 16) -> provenance (rule 17) -> classes (rule 18)
//
// REPORTING: `schema` iff the PCActn carries intent_session or policy.schema.closed_world is true; `intent_session`
// iff it carries the member or policy.session.require is true; `layers` iff it carries the member and the verifier
// configured `layers`; `accumulators` iff it carries the member; facts / provenance / classes iff it carries the
// member and the W-B unit reports them (the first failing W-B check ends the unit; a rule-17 question fails
// `provenance`). Checks 1-4 are independent. Within each check the first failing step wins. A panic inside a check
// fails that check (fail closed), like the reference's per-check try/catch.

import (
	"fmt"
	"math"
)

// IntentV2Context is the verifier state the v2 checks read (`context.intent_v2` of the conformance vectors):
// {policy?: {session?: {require?, max_revocation_age_s?}, schema?: {closed_world?}}, params?, schema?: {docs, keys},
// session?: {root?, grants?, revocation?: {epoch, proofs}}, layers?: {org?, site?, std?}, wb?: {artifacts?, policy?},
// acc?: {state?, monitors?, receipts?, last_seq?, sequencer_keys?}}. Everything in it is the VERIFIER's (its store, its
// configuration), never the agent's. Build it with IntentV2ContextFromJSON.
type IntentV2Context struct {
	raw map[string]any
	// malformed: a PRESENT context that is not a JSON object; every reportable v2 check fails (as in the reference)
	malformed bool
}

// IntentV2ContextFromJSON builds the context from a decoded JSON object (numbers as json.Number from ParseJSONLenient /
// StrictParse, or float64 / int / int64). Every number is read by its binary64 value. nil (no context) when v is nil: a
// decoded JSON null and an absent member are both nil in Go. Any other non-object (array, string, number, bool) is a
// MALFORMED context, never "no context": every v2 check that would be reported fails, so a misconfigured verifier fails
// closed (it used to be treated as absent, which silently switched v2 enforcement off).
func IntentV2ContextFromJSON(v any) *IntentV2Context {
	if v == nil {
		return nil
	}
	m, ok := normalizeJSON(v).(map[string]any)
	if !ok {
		return &IntentV2Context{malformed: true}
	}
	return &IntentV2Context{raw: m}
}

// IntentV2ContextFromJSONText parses raw JSON text with the lenient loader and applies IntentV2ContextFromJSON.
func IntentV2ContextFromJSONText(text string) (*IntentV2Context, error) {
	v, err := ParseJSONLenient([]byte(text))
	if err != nil {
		return nil, err
	}
	if _, ok := normalizeJSON(v).(map[string]any); !ok {
		return nil, fmt.Errorf("intent_v2 context: not a JSON object")
	}
	return IntentV2ContextFromJSON(v), nil
}

// member is `o?.k` for a JSON value (only plain objects carry the fixed member names the context uses).
func member(o any, k string) (any, bool) {
	m, ok := o.(map[string]any)
	if !ok {
		return nil, false
	}
	v, has := m[k]
	return v, has
}

func memberPath(o any, ks ...string) (any, bool) {
	cur, ok := o, true
	for _, k := range ks {
		if cur == nil {
			return nil, false
		}
		cur, ok = member(cur, k)
		if !ok {
			return nil, false
		}
	}
	return cur, ok
}

type v2Check struct {
	name string
	ok   bool
	why  string
}

type v2Decision struct {
	checks []v2Check
	// env is the predicate env the checks computed (canon, acc, mon, world, prov, class), read by Authorize (TS v2Env)
	env map[string]any
}

type v2Fail string

func (c *IntentV2Context) get(ks ...string) (any, bool) {
	if c == nil {
		return nil, false
	}
	return memberPath(c.raw, ks...)
}

func optObj(v any, has bool) bool {
	if !has {
		return true
	}
	_, ok := v.(map[string]any)
	return ok
}

func optArr(v any, has bool) bool {
	if !has {
		return true
	}
	_, ok := v.([]any)
	return ok
}

// intentV2ContextError is the reference intentV2ContextError: ABSENT members mean empty / default; a member PRESENT
// with null (or of the wrong JSON type) is malformed, including the members passed through to `layers` and W-B.
func intentV2ContextError(c *IntentV2Context) string {
	if c == nil {
		return ""
	}
	if c.malformed {
		return "the v2 verifier context must be an object"
	}
	ctx := c.raw
	pol, polP := ctx["policy"]
	if !optObj(pol, polP) {
		return "policy must be an object"
	}
	if polP {
		// closed member sets; every flag a JSON boolean and every number a safe integer when present (absent = default)
		pm := pol.(map[string]any)
		for k := range pm {
			if k != "session" && k != "schema" && k != "acc" && k != "map" {
				return "policy: unknown member '" + k + "'"
			}
		}
		ps, psP := pm["session"]
		if !optObj(ps, psP) {
			return "policy.session must be an object"
		}
		if psP {
			o := ps.(map[string]any)
			for k := range o {
				if k != "require" && k != "max_revocation_age_s" {
					return "policy.session: unknown member '" + k + "'"
				}
			}
			if r, has := o["require"]; has {
				if _, ok := r.(bool); !ok {
					return "policy.session.require must be a boolean"
				}
			}
			if m, has := o["max_revocation_age_s"]; has && !jsIsNonNeg(m) {
				return "policy.session.max_revocation_age_s must be a non-negative safe integer"
			}
		}
		pc, pcP := pm["schema"]
		if !optObj(pc, pcP) {
			return "policy.schema must be an object"
		}
		if pcP {
			o := pc.(map[string]any)
			for k := range o {
				if k != "closed_world" {
					return "policy.schema: unknown member '" + k + "'"
				}
			}
			if c, has := o["closed_world"]; has {
				if _, ok := c.(bool); !ok {
					return "policy.schema.closed_world must be a boolean"
				}
			}
		}
		pa, paP := pm["acc"]
		if !optObj(pa, paP) {
			return "policy.acc must be an object"
		}
		if paP {
			o := pa.(map[string]any)
			for k, v := range o {
				if k != "max_receipt_age_s" && k != "max_keyset_age_s" {
					return "policy.acc: unknown member '" + k + "'"
				}
				if !jsIsNonNeg(v) {
					return "policy.acc." + k + " must be a non-negative safe integer"
				}
			}
		}
		pmp, pmP := pm["map"]
		if !optObj(pmp, pmP) {
			return "policy.map must be an object"
		}
		if pmP {
			o := pmp.(map[string]any)
			for k := range o {
				if k != "require" && k != "max_residual_risk_ppm" {
					return "policy.map: unknown member '" + k + "'"
				}
			}
			if r, has := o["require"]; has {
				if _, ok := r.(bool); !ok {
					return "policy.map.require must be a boolean"
				}
			}
			if e, has := o["max_residual_risk_ppm"]; has && !jsIsNonNeg(e) {
				return "policy.map.max_residual_risk_ppm must be a non-negative safe integer"
			}
		}
	}
	if v, has := ctx["params"]; !optObj(v, has) {
		return "params must be an object"
	}
	for _, k := range []string{"schema", "session", "acc"} {
		if v, has := ctx[k]; !optObj(v, has) {
			return k + " must be an object"
		}
	}
	if M, has := ctx["map"]; has {
		mm, ok := M.(map[string]any)
		if !ok {
			return "map must be an object"
		}
		if k, ok := firstUnknownKey(mm, []string{"disclosure"}); !ok {
			return "map: unknown member '" + k + "'"
		}
	}
	if L, has := ctx["layers"]; has {
		lm, ok := L.(map[string]any)
		if !ok {
			return "layers must be an object"
		}
		for k, v := range lm {
			if k != "org" && k != "site" && k != "std" {
				return "layers: unknown member '" + k + "'"
			}
			ceil, ok := v.(map[string]any)
			if !ok {
				return "layers." + k + " must be {predicates: [...]}"
			}
			if _, ok := ceil["predicates"].([]any); !ok {
				return "layers." + k + " must be {predicates: [...]}"
			}
		}
	}
	if wb, has := ctx["wb"]; has {
		w, ok := wb.(map[string]any)
		if !ok {
			return "wb must be an object"
		}
		a, aP := w["artifacts"]
		if !optObj(a, aP) {
			return "wb.artifacts must be an object"
		}
		if aP {
			am := a.(map[string]any)
			for _, k := range []string{"facts", "labels", "verdicts"} {
				if v, has := am[k]; !optArr(v, has) {
					return "wb.artifacts." + k + " must be an array"
				}
			}
			if v, has := am["offer_set"]; !optObj(v, has) {
				return "wb.artifacts.offer_set must be an object"
			}
		}
		pv, pP := w["policy"]
		if !optObj(pv, pP) {
			return "wb.policy must be an object"
		}
		if pP {
			pm := pv.(map[string]any)
			wv, wP := pm["world"]
			prv, prP := pm["provenance"]
			if !optObj(wv, wP) || !optObj(prv, prP) {
				return "wb.policy.world / provenance must be objects"
			}
			if v, has := pm["classifiers"]; !optArr(v, has) {
				return "wb.policy.classifiers must be an array"
			}
		}
	}
	return ""
}

func schemaCtxError(c *IntentV2Context) string {
	sc, has := c.get("schema")
	if !has {
		return ""
	}
	m, ok := sc.(map[string]any)
	if !ok {
		return "the schema context must be {docs: [...], keys: [...]}"
	}
	_, d := m["docs"].([]any)
	_, k := m["keys"].([]any)
	if !d || !k {
		return "the schema context must be {docs: [...], keys: [...]}"
	}
	return ""
}

func sessionCtxError(c *IntentV2Context) string {
	se, has := c.get("session")
	if !has {
		return ""
	}
	m, ok := se.(map[string]any)
	if !ok {
		return "the session context must be an object"
	}
	if g, has := m["grants"]; !optArr(g, has) {
		return "the session grants must be an array"
	}
	if r, has := m["revocation"]; !optObj(r, has) {
		return "the session revocation evidence must be an object"
	}
	if r, has := m["revocation_last"]; !optObj(r, has) {
		return "the tracked last revocation epoch must be an object"
	}
	if pp, has := m["pq_pins"]; has {
		pm, ok := pp.(map[string]any)
		if !ok {
			return "the session pq_pins must be an object of strings"
		}
		for _, v := range pm {
			if _, isS := v.(string); !isS {
				return "the session pq_pins must be an object of strings"
			}
		}
	}
	return ""
}

func accCtxError(c *IntentV2Context) string {
	a, has := c.get("acc")
	if !has {
		return ""
	}
	m, ok := a.(map[string]any)
	if !ok {
		return "the accumulator context must be an object"
	}
	for _, k := range []string{"state", "monitors", "last_seq", "keyset_versions"} {
		if v, has := m[k]; !optObj(v, has) {
			return "acc." + k + " must be an object"
		}
	}
	if kv, has := m["keyset_versions"]; has {
		for _, v := range kv.(map[string]any) {
			if e := trackedKeySetError(v); e != "" {
				return "acc.keyset_versions: " + e
			}
		}
	}
	for _, k := range []string{"receipts", "sequencer_keys"} {
		if v, has := m[k]; !optArr(v, has) {
			return "acc." + k + " must be an array"
		}
	}
	if ls, has := m["last_seq"]; has {
		for _, v := range ls.(map[string]any) {
			if !jsIsNonNeg(v) {
				return "acc.last_seq values must be non-negative safe integers"
			}
		}
	}
	return ""
}

// schemaStep is rule 14; returns the matched schema document on success.
func schemaStep(p map[string]any, ctx *IntentV2Context) (doc any, why string) {
	if ce := schemaCtxError(ctx); ce != "" {
		return nil, ce
	}
	docsV, _ := ctx.get("schema", "docs")
	docs, ok := docsV.([]any)
	if !ok || len(docs) == 0 {
		return nil, "this verifier has no action schema configured"
	}
	is, hasIS := p["intent_session"].(map[string]any)
	if hasIS {
		found := false
		for _, d := range docs {
			if dg, ok := actionSchemaDigest(d); ok && dg == is["schema"] {
				doc, found = d, true
				break
			}
		}
		if !found {
			return nil, "intent_session.schema names no schema this verifier accepts"
		}
	} else {
		doc = docs[0]
	}
	keys, kp := ctx.get("schema", "keys")
	if !kp {
		keys = []any{}
	}
	if r := verifyActionSchemaReason(doc, keys); r != "" {
		return nil, "schema does not verify: " + r
	}
	if doc.(map[string]any)["aud"] != p["aud"] {
		return nil, "schema aud does not match the PCActn aud"
	}
	paramsV, _ := ctx.get("params")
	params, ok := paramsV.(map[string]any)
	if !ok {
		return nil, "no plaintext params to check against the schema (closed world needs them)"
	}
	action, _ := p["action"].(map[string]any)
	if pd, ok := hashCanonicalV(params); !ok || pd != action["params_digest"] {
		if !ok {
			panic(v2Fail("params are not strictly canonical"))
		}
		return nil, "params do not hash to action.params_digest"
	}
	verb, _ := action["verb"].(string)
	c, why := conformActionReason(doc, verb, params)
	if !c.OK {
		return nil, "schema_violation: " + c.Code + ": " + why
	}
	return doc, ""
}

// boundRoot: the bound, verified session root (shared by rules 13 and 15).
func boundRoot(is map[string]any, ctx *IntentV2Context, now float64) (map[string]any, string) {
	S, has := ctx.get("session", "root")
	if !has {
		return nil, "no session root for this session"
	}
	if r := sessionRootShape(S); r != "" {
		return nil, "session root: " + r
	}
	// a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals list
	pins, _ := ctx.get("session", "pq_pins")
	if r := verifySessionRoot(S, pins); r != "" {
		return nil, "session root: " + r
	}
	d, ok := sessionRootDigest(S)
	if !ok || d != is["root"] {
		return nil, "intent_session.root is not the digest of the session root"
	}
	s := S.(map[string]any)
	if s["session"] != is["session"] {
		return nil, "the session root names another session"
	}
	if !(now < jsF(s["expires_at"])) {
		return nil, "the session root has expired"
	}
	return s, ""
}

// sessionStep is rule 13.
func sessionStep(p, grant map[string]any, ctx *IntentV2Context, now float64) string {
	maxAgeS, hasMaxAge := ctx.get("policy", "session", "max_revocation_age_s")
	if hasMaxAge && !jsIsNonNeg(maxAgeS) {
		return "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)"
	}
	isV, hasIS := p["intent_session"]
	if !hasIS {
		return "this verifier requires an intent_session but the PCActn carries none"
	}
	if ce := sessionCtxError(ctx); ce != "" {
		return ce
	}
	is := isV.(map[string]any)
	intentV, hasIntent := p["intent"]
	if !hasIntent {
		return "an intent_session needs the envelope.intent binding"
	}
	intent := intentV.(map[string]any)
	S, why := boundRoot(is, ctx, now)
	if why != "" {
		return why
	}
	if S["intent_ref"] != intent["ref"] {
		return "intent.ref is not the session statement"
	}
	sch := S["schema"].(map[string]any)
	if sch["digest"] != is["schema"] {
		return "intent_session.schema is not the session schema"
	}
	if sch["aud"] != p["aud"] {
		return "the session schema is for another audience"
	}
	seq := jsF(is["seq"])
	layers := S["layers"].(map[string]any)
	if seq == 0 && intent["map_digest"] != layers["task"].(map[string]any)["map_digest"] {
		return "a seq-0 action must use the session task map"
	}
	gc, _ := grantSessionCaveat(grant)
	var gcv any
	if gc != nil {
		gcv = gc
	}
	if e := intentSessionCaveatError(gcv); e != "" {
		return "admitting root: " + e
	}
	if gc["session"] != is["session"] || gc["root"] != is["root"] || !jsStrictEq(gc["seq"], is["seq"]) {
		return "the admitting root is bound to another session, root or seq"
	}
	principals := []string{}
	for _, pv := range S["principals"].([]any) {
		principals = append(principals, pv.(map[string]any)["key"].(string))
	}
	isPrincipal := func(v any) bool {
		s, ok := v.(string)
		return ok && contains(principals, s)
	}
	if !isPrincipal(grant["issuer"]) {
		return "the admitting root is not signed by a session principal"
	}
	priorV, _ := ctx.get("session", "grants")
	prior, _ := priorV.([]any) // an array when present (sessionCtxError)
	if float64(len(prior)) < seq {
		return fmt.Sprintf("the verifier does not hold the %s earlier grants of this session", jsValueString(is["seq"]))
	}
	n := int(seq)
	ids := []string{}
	for i := 0; i < n; i++ {
		g, ok := prior[i].(map[string]any)
		if !ok {
			return fmt.Sprintf("session grant %d is not a capability", i)
		}
		gid, ok1 := g["id"].(string)
		_, ok2 := g["issuer"].(string)
		if !ok1 || !ok2 {
			return fmt.Sprintf("session grant %d is not a capability", i)
		}
		alg, algP := g["alg"]
		if e := suiteCapability(alg, algP); e != "" {
			return fmt.Sprintf("session grant %d: %s", i, e)
		}
		c, _ := grantSessionCaveat(g)
		var cv any
		if c != nil {
			cv = c
		}
		if intentSessionCaveatError(cv) != "" || c["session"] != is["session"] || c["root"] != is["root"] || jsF(c["seq"]) != float64(i) {
			return fmt.Sprintf("session grant %d does not belong to this session at seq %d", i, i)
		}
		if !isPrincipal(g["issuer"]) {
			return fmt.Sprintf("session grant %d is not signed by a session principal", i)
		}
		if i > 0 && c["prev"] != prior[i-1].(map[string]any)["id"] {
			return fmt.Sprintf("session grant %d does not chain to grant %d", i, i-1)
		}
		ids = append(ids, deltaRevocationID(gid))
	}
	if n > 0 && gc["prev"] != prior[n-1].(map[string]any)["id"] {
		return fmt.Sprintf("the admitting root does not chain to grant %d", n-1)
	}
	rev, hasRev := S["revocation"].(map[string]any)
	if hasRev || hasMaxAge {
		m := math.Inf(1)
		if hasRev {
			m = math.Min(m, jsF(rev["max_age_s"]))
		}
		if hasMaxAge {
			m = math.Min(m, jsF(maxAgeS))
		}
		if !hasRev {
			return "revocation: the policy requires a revocation epoch but the session root names no revocation authority"
		}
		// only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
		authority := rev["key"].(string)
		pins := map[string]string{}
		if q, ok := rev["pq_pk"].(string); ok {
			pins[authority] = q
		}
		gid, _ := grant["id"].(string)
		all := []any{sessionRevocationID(is["session"].(string)), mapRevocationID(intent["map_digest"].(string))}
		for _, id := range ids {
			all = append(all, id)
		}
		all = append(all, deltaRevocationID(gid))
		if std, ok := layers["std"].(map[string]any); ok {
			all = append(all, profileRevocationID(std["profile"].(string), jsF(std["version"])))
		}
		ev, _ := ctx.get("session", "revocation")
		last, lastP := ctx.get("session", "revocation_last")
		if r := checkSessionRevocation(ev, is["session"], authority, all, jsNumber(now), jsNumber(m*1000), last, lastP, pins); r != "" {
			return "revocation: " + r
		}
	}
	return ""
}

// accStep is rule 15; returns the verifier-computed env.acc / env.mon on success.
func accStep(p map[string]any, ctx *IntentV2Context, now float64) (env map[string]any, why string) {
	is := p["intent_session"].(map[string]any)
	S, why := boundRoot(is, ctx, now)
	if why != "" {
		return nil, why
	}
	if ce := accCtxError(ctx); ce != "" {
		return nil, ce
	}
	if ce := schemaCtxError(ctx); ce != "" {
		return nil, ce
	}
	action, _ := p["action"].(map[string]any)
	verb, _ := action["verb"].(string)
	claims, _ := is["acc"].([]any)
	accs := S["accumulators"].([]any)
	findAcc := func(id any) map[string]any {
		for _, a := range accs {
			if m := a.(map[string]any); m["id"] == id {
				return m
			}
		}
		return nil
	}
	for _, cv := range claims {
		c := cv.(map[string]any)
		a := findAcc(c["id"])
		if a == nil {
			return nil, fmt.Sprintf("claim '%v' names no accumulator of the session", c["id"])
		}
		if a["holder"].(map[string]any)["kind"] == "wallet" {
			return nil, fmt.Sprintf("accumulator '%v' is wallet-held and cannot be claimed at a site", c["id"])
		}
	}
	docsV, _ := ctx.get("schema", "docs")
	docs, _ := docsV.([]any) // an array when present (schemaCtxError)
	var schemaDoc any
	haveSchema := false
	for _, d := range docs {
		if dg, ok := actionSchemaDigest(d); ok && dg == is["schema"] {
			schemaDoc, haveSchema = d, true
			break
		}
	}
	paramsV, _ := ctx.get("params")
	params, paramsOK := paramsV.(map[string]any)
	accEnv := map[string]any{}
	monEnv := map[string]any{}
	stateV, _ := ctx.get("acc", "state")
	state, _ := stateV.(map[string]any) // an object when present (accCtxError); absent reads as empty
	findClaim := func(id any) map[string]any {
		for _, cv := range claims {
			if c := cv.(map[string]any); c["id"] == id {
				return c
			}
		}
		return nil
	}
	for _, av := range accs {
		a := av.(map[string]any)
		id := a["id"].(string)
		holder := a["holder"].(map[string]any)
		hk := holder["kind"]
		if hk == "wallet" {
			continue
		}
		agg := a["agg"].(string)
		sel := a["sel"].(map[string]any)
		if _, has := sel["accumulates_into"]; has && !haveSchema {
			return nil, fmt.Sprintf("accumulator '%s' selects by accumulates_into but the session schema is not available", id)
		}
		selected, throws := accSelects(a, verb, schemaDoc, haveSchema)
		if throws {
			panic(v2Fail("unusable schema entry"))
		}
		claim := findClaim(id)
		pre, hasPre := state[id]
		if !selected {
			if claim != nil {
				return nil, fmt.Sprintf("claim '%s' for an accumulator this action does not feed", id)
			}
			if hk == "site_local" && hasPre {
				if pe := preStateError(agg, pre); pe != "" {
					return nil, fmt.Sprintf("accumulator '%s': %s", id, pe)
				}
				accEnv[id] = map[string]any{"post": jsNumber(preValue(agg, pre.(map[string]any)))}
			}
			continue
		}
		if claim == nil {
			return nil, fmt.Sprintf("no claim for accumulator '%s' that this action feeds", id)
		}
		if !paramsOK {
			return nil, "no plaintext params to compute accumulator values"
		}
		if kv := a["key"]; kv != nil {
			k := kv.(string)
			if _, has := params[k[len("action.params."):]]; !has {
				return nil, fmt.Sprintf("accumulator '%s': the key parameter %s is missing", id, k)
			}
			var kd map[string]any
			if haveSchema {
				ve, th := schemaVerbOf(schemaDoc, verb)
				if th {
					panic(v2Fail("unusable schema entry"))
				}
				if ve != nil {
					pd, has := ve["params"]
					if !has || pd == nil {
						panic(v2Fail("unusable schema entry"))
					}
					pm, _ := pd.(map[string]any)
					x, has := pm[k]
					if m, ok := x.(map[string]any); ok {
						kd = m
					} else if has && x != nil && x != false {
						kd = map[string]any{} // a truthy primitive: `.semantic` is undefined -> TypeError below
					}
				}
			}
			if kd == nil {
				return nil, fmt.Sprintf("accumulator '%s': the key must be a schema-declared identity (not free text)", id)
			}
			sem, ok := kd["semantic"].(string)
			if !ok {
				panic(v2Fail("unusable key declaration"))
			}
			if len(sem) >= 5 && sem[:5] == "text." {
				return nil, fmt.Sprintf("accumulator '%s': the key must be a schema-declared identity (not free text)", id)
			}
		}
		v, ok, th, why := accValueOfReason(a, verb, params, schemaDoc, haveSchema)
		if th {
			panic(v2Fail("unusable schema entry"))
		}
		if !ok {
			return nil, fmt.Sprintf("accumulator '%s': %s", id, why)
		}
		var post float64
		if hk == "site_local" {
			if _, has := claim["receipt"]; has {
				return nil, fmt.Sprintf("accumulator '%s' is site-local: a receipt is not accepted", id)
			}
			if !hasPre {
				return nil, fmt.Sprintf("no state for site-local accumulator '%s'", id)
			}
			if pe := preStateError(agg, pre); pe != "" {
				return nil, fmt.Sprintf("accumulator '%s': %s", id, pe)
			}
			x, ok := combineAcc(agg, pre.(map[string]any), v)
			if !ok {
				return nil, fmt.Sprintf("accumulator '%s' overflows 2^53-1", id)
			}
			post = x
		} else {
			rd, has := claim["receipt"]
			if !has {
				return nil, fmt.Sprintf("accumulator '%s' is sequenced: the claim needs a reservation receipt", id)
			}
			rcV, _ := ctx.get("acc", "receipts")
			rcs, _ := rcV.([]any) // an array when present (accCtxError)
			var rc map[string]any
			for _, x := range rcs {
				if dg, ok := accReceiptDigest(x); ok && dg == rd {
					rc, _ = x.(map[string]any)
					if rc == nil {
						rc = map[string]any{} // a digest-matching non-object: refused by the shape check below
					}
					break
				}
			}
			if rc == nil {
				return nil, fmt.Sprintf("the reservation receipt for '%s' was not presented", id)
			}
			ksV, _ := ctx.get("acc", "sequencer_keys")
			keySets, _ := ksV.([]any) // an array when present (accCtxError)
			fresh := receiptFreshness{maxReceiptAgeMs: defaultMaxReceiptAgeMs, maxKeySetAgeMs: defaultMaxKeySetAgeMs}
			if v, has := ctx.get("policy", "acc", "max_receipt_age_s"); has {
				fresh.maxReceiptAgeMs = jsF(v) * 1000
			}
			if v, has := ctx.get("policy", "acc", "max_keyset_age_s"); has {
				fresh.maxKeySetAgeMs = jsF(v) * 1000
			}
			if kvs, ok := ctx.get("acc", "keyset_versions"); ok {
				if v, has := kvs.(map[string]any)[holder["root"].(string)]; has {
					fresh.tracked, _ = v.(map[string]any)
				}
			}
			if !verifyReceiptAgainstHolder(rc, holder, keySets, now, fresh) {
				if r := receiptSuiteReason(rc, keySets); r != "" {
					return nil, fmt.Sprintf("the reservation receipt for '%s': %s", id, r)
				}
				return nil, fmt.Sprintf("the reservation receipt for '%s' is not signed by a key the session sequencer's root-signed key set lists for its issue time", id)
			}
			if rc["session"] != is["session"] || rc["acc"] != id || rc["aud"] != p["aud"] {
				return nil, fmt.Sprintf("the reservation receipt for '%s' is for another session, accumulator or audience", id)
			}
			if rd, ok := pcactnReservationDigest(p); !ok || rd != rc["pcactn_digest"] {
				if !ok {
					panic(v2Fail("PCActn is not strictly canonical"))
				}
				return nil, fmt.Sprintf("the reservation receipt for '%s' is for another action", id)
			}
			if !(now <= jsF(rc["expires_at"])) {
				return nil, fmt.Sprintf("the reservation receipt for '%s' has expired", id)
			}
			lsV, _ := ctx.get("acc", "last_seq")
			ls, _ := lsV.(map[string]any) // safe integers when present (accCtxError)
			if last, has := ls[id]; has && !(jsF(rc["seq"]) > jsF(last)) {
				return nil, fmt.Sprintf("the reservation receipt for '%s' replays seq %s (last accepted %s)", id, jsValueString(rc["seq"]), jsValueString(last))
			}
			if !receiptArithmeticOk(agg, rc, v.val) {
				return nil, fmt.Sprintf("the reservation receipt for '%s' does not add up", id)
			}
			post = jsF(rc["post"])
		}
		if dm, has := a["domain_max"]; has && post > jsF(dm) {
			return nil, fmt.Sprintf("accumulator '%s' post %s is outside its domain (max %s)", id, jsNumberString(post), jsValueString(dm))
		}
		if !jsStrictEq(claim["post"], jsNumber(post)) {
			return nil, fmt.Sprintf("claimed post %s for '%s' differs from the verifier's %s", jsValueString(claim["post"]), id, jsNumberString(post))
		}
		accEnv[id] = map[string]any{"post": jsNumber(post)}
	}
	monsV, _ := ctx.get("acc", "monitors")
	mons, _ := monsV.(map[string]any) // an object when present (accCtxError)
	for _, mv := range S["monitors"].([]any) {
		m := mv.(map[string]any)
		id := m["id"].(string)
		st, has := mons[id]
		s, isS := st.(string)
		if !has || !isS || !contains(monitorStates(m), s) {
			return nil, fmt.Sprintf("no valid state for monitor '%s'", id)
		}
		monEnv[id] = map[string]any{"state": s}
	}
	return map[string]any{"acc": accEnv, "mon": monEnv}, ""
}

// decideLayerCeilings is the V5 `layers` check: org, then site, then std; an absent ceiling admits everything; a
// ceiling present with null or anything but {predicates: [...]} fails as that ceiling (the pipeline already refuses
// it as a malformed context); a ceiling admits iff one of its predicates matches.
func decideLayerCeilings(layers any, actx map[string]any) string {
	lm, ok := layers.(map[string]any)
	if !ok {
		return "layers: the layers member is malformed (not an object)"
	}
	if !closedMembers(lm, nil, "org", "site", "std") {
		return "layers: unknown member (the layers object is {org?, site?, std?}): fails as the org ceiling"
	}
	for _, k := range []string{"org", "site", "std"} {
		l, has := member(layers, k)
		if !has {
			continue
		}
		preds, isList := member(l, "predicates")
		lmap, _ := l.(map[string]any)
		if _, isArr := preds.([]any); !isList || !isArr || len(lmap) != 1 {
			return "layers: the " + k + " ceiling is malformed (null or not {predicates: [...]})"
		}
		if !evaluatePredicates(preds, actx) {
			return "layers: the action is outside the " + k + " ceiling (a ceiling is never a question)"
		}
	}
	return ""
}

// decideIntentV2 runs the v2 checks in order (never panics: a panic fails the check being evaluated).
func decideIntentV2(p, grant map[string]any, ctx *IntentV2Context, now float64) v2Decision {
	out := v2Decision{env: map[string]any{}}
	_, present := p["intent_session"]
	if ce := intentV2ContextError(ctx); ce != "" {
		// a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
		names := []string{"schema", "intent_session"}
		if present {
			names = append(names, "accumulators")
			if is, _ := p["intent_session"].(map[string]any); is["map_form"] == mapFormCommit {
				names = append(names, "map")
			}
		}
		for _, n := range names {
			out.checks = append(out.checks, v2Check{name: n, why: "malformed v2 context: " + ce})
		}
		return out
	}
	clockOK := jsIsInt(jsNumber(now))
	run := func(name string, f func() string) bool {
		why := func() (w string) {
			defer func() {
				if r := recover(); r != nil {
					w = fmt.Sprintf("%s error (fail closed): %v", name, r)
				}
			}()
			if !clockOK {
				return "the verifier clock is not a safe integer (fail closed)"
			}
			return f()
		}()
		out.checks = append(out.checks, v2Check{name: name, ok: why == "", why: why})
		return why == ""
	}
	action, _ := p["action"].(map[string]any)
	// String(p.action?.verb) / String(p.action?.resource), as the reference builds the action (absent => "undefined")
	verb := jsMemberString(action, "verb")
	resource := jsMemberString(action, "resource")
	var canon map[string]any
	if cw, _ := ctx.get("policy", "schema", "closed_world"); present || cw == true {
		run("schema", func() string {
			doc, why := schemaStep(p, ctx)
			if why != "" {
				return why
			}
			params, _ := ctx.get("params")
			c, ok := canonProjection(doc, verb, params.(map[string]any))
			if !ok {
				panic(v2Fail("canonical projection"))
			}
			canon = c
			out.env["canon"] = c
			return ""
		})
	}
	if rq, _ := ctx.get("policy", "session", "require"); present || rq == true {
		run("intent_session", func() string { return sessionStep(p, grant, ctx, now) })
	}
	paramsV, _ := ctx.get("params")
	params, ok := paramsV.(map[string]any)
	if !ok {
		params = map[string]any{}
	}
	actx := map[string]any{"action": map[string]any{"verb": verb, "resource": resource, "params": params}}
	envForLayers := map[string]any{}
	if canon != nil {
		envForLayers["canon"] = canon
	}
	actx["env"] = envForLayers
	if layers, has := ctx.get("layers"); present && has {
		run("layers", func() string { return decideLayerCeilings(layers, actx) })
	}
	isMap, _ := p["intent_session"].(map[string]any)
	mr, _ := ctx.get("policy", "map", "require")
	mapActive := isMap["map_form"] == mapFormCommit || mr == true
	if !present {
		if mapActive {
			run("map", func() string { return mapStep(p, ctx) })
		}
		return out
	}
	run("accumulators", func() string {
		env, why := accStep(p, ctx, now)
		for k, v := range env {
			out.env[k] = v
		}
		return why
	})
	if mapActive {
		run("map", func() string { return mapStep(p, ctx) })
	}
	is := p["intent_session"].(map[string]any)
	var wb wbResult
	func() {
		defer func() {
			if r := recover(); r != nil {
				out.checks = append(out.checks, v2Check{name: "facts", why: fmt.Sprintf("W-B error (fail closed): %v", r)})
				wb = wbResult{skip: true}
			}
		}()
		artifacts, _ := ctx.get("wb", "artifacts")
		policy, hasPol := ctx.get("wb", "policy")
		if !hasPol {
			policy = map[string]any{}
		}
		aud, _ := p["aud"].(string)
		wb = decideIntentWB(now, aud, is["session"].(string), actx["action"].(map[string]any), is, artifacts, policy)
	}()
	if !wb.skip && wb.outcome != "deny" {
		for _, k := range []string{"world", "prov", "class"} {
			if v, has := wb.env[k]; has && v != nil {
				out.env[k] = v
			}
		}
	}
	if !wb.skip {
		for _, name := range []string{"facts", "provenance", "classes"} {
			c, has := wb.checks[name]
			if !has {
				continue
			}
			switch c {
			case "pass":
				out.checks = append(out.checks, v2Check{name: name, ok: true})
			case "question":
				out.checks = append(out.checks, v2Check{name: name, why: "intent_required: " + wb.reason})
			default:
				out.checks = append(out.checks, v2Check{name: name, why: wb.reason})
			}
		}
	}
	return out
}

const intentGoalV2cPrefix = "pca-intent:v2c:"

// mapStep is rule 19 (`map`, Z0): reported iff intent_session.map_form is "commit" or policy.map.require is true;
// evaluated after accumulators and before W-B.
func mapStep(p map[string]any, ctx *IntentV2Context) string {
	is, _ := p["intent_session"].(map[string]any)
	if is["map_form"] != mapFormCommit {
		return "this verifier requires a committed map (intent_session.map_form \"commit\")"
	}
	intent, ok := p["intent"].(map[string]any)
	if !ok {
		return "a committed map needs the envelope.intent binding"
	}
	disclosure, has := ctx.get("map", "disclosure")
	if !has {
		return "no disclosure of the committed map was presented"
	}
	action, _ := p["action"].(map[string]any)
	params, paramsP := ctx.get("params")
	eps, epsSet := ctx.get("policy", "map", "max_residual_risk_ppm")
	d := decideMapDisclosure(intent["map_digest"], action, params, paramsP, disclosure, jsF(eps), epsSet)
	if !d.ok {
		return d.reason
	}
	return ""
}

// v2Goal: when the PCActn carries a wire-valid intent_session, rule 12 step 2 opens the v2 session goal
// "pca-intent:v2:" + session + ":" + map_digest (rule 13 amends rule 12).
// Over a committed map (intent_session.map_form "commit", rule 19) the goal is "pca-intent:v2c:" + session + ":" + map_commit.
func intentGoalCommitV2(session, mapDigest, goalSalt string, committed bool) (string, error) {
	prefix := intentGoalV2Prefix
	if committed {
		prefix = intentGoalV2cPrefix
	}
	return HashCanonical(map[string]any{"d": intentGoalCommitDomain, "goal": prefix + session + ":" + mapDigest, "salt": goalSalt})
}
