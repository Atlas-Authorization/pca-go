package pca

// Intent Layer v2 W-B (rules 16-18): world facts, relational dimensions and offer sets (oracle-facts.ts,
// offer-set.ts), per-parameter provenance with label receipts and flow rules (param-provenance.ts,
// label-receipts.ts, taint.ts), classifier verdicts (intent-classifier.ts), composed by decideIntentWB
// (intent-env.ts). Every artifact is Ed25519-signed under a VERIFIER-pinned key and committed by reference.

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
)

const (
	factDomain          = "atlas-pca/fact/v1\x00"
	factRefDomain       = "atlas-pca/fact-ref/v1"
	offerSetDomain      = "atlas-pca/offer-set/v1\x00"
	offerSetRefDomain   = "atlas-pca/offer-set-ref/v1"
	labelsDomain        = "atlas-pca/labels/v1\x00"
	labelsRefDomain     = "atlas-pca/labels-ref/v1"
	classifierDomain    = "atlas-pca/intent-classifier/v1\x00"
	classifierRefDomain = "atlas-pca/intent-classifier-ref/v1"
	maxCommittedFacts   = 16
	maxWorlds           = 16
	maxRelational       = 16
	defaultWorldSkewMs  = 60_000
	maxOffers           = 256
	maxOfferAttrs       = 32
	maxQueryKeys        = 32
	maxLabelFields      = 64
	maxProvPaths        = 32
	maxProvRefs         = 8
	maxCommittedLabels  = 16
	maxCommittedClasses = 8
	maxClassifierLabels = 32
	labelRefPrefix      = "pca-labels:"
	publicDataClass     = "public"
	taintedRank         = 2
)

var taintRank = map[string]int{"trusted": 0, "first_party": 1, "tool": 2, "web": 3, "agent": 4}

func isTaintLevel(v any) bool {
	s, ok := v.(string)
	_, known := taintRank[s]
	return ok && known
}

func rankOf(level string) int {
	if r, ok := taintRank[level]; ok {
		return r
	}
	return 4
}

// ---- rule 16: facts, relational dimensions, offer sets ----------------------------------------------------------

func validateFactWire(fv any) bool {
	f, ok := fv.(map[string]any)
	if !ok || !closedMembers(f, []string{"v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"}, suiteMembers...) {
		return false
	}
	if !jsStrictEq(f["v"], jsNumber(1)) || f["kind"] != "pca-fact" {
		return false
	}
	if n, ok := f["name"].(string); !ok || !matchName(n) {
		return false
	}
	if !boundedStr(f["subject"], 256) {
		return false
	}
	if !jsIsInt(f["value"]) && !boundedStr(f["value"], 256) {
		return false
	}
	if !jsIsInt(f["t_obs"]) || jsF(f["t_obs"]) < 0 {
		return false
	}
	if !boundedStr(f["oracle"], 64) {
		return false
	}
	_, ok = f["sig"].(string)
	return ok
}

// validateOfferPolicyError is the reference validateOfferPolicy: "" = well-formed, else the refusal text.
func validateOfferPolicyError(pv any) string {
	p, ok := pv.(map[string]any)
	if !ok {
		return "offers policy must be an object"
	}
	if m := closedMembersMsg(p, "offers", []string{"name", "site_keys", "max_age_ms", "offer_param", "filter"}); m != "" {
		return m
	}
	if _, ok := p["name"].(string); !ok {
		return "offers policy needs a name"
	}
	sk, ok := p["site_keys"].([]any)
	if !ok || len(sk) == 0 {
		return "offers policy needs at least one pinned site key"
	}
	kids := map[string]bool{}
	for _, kv := range sk {
		k, ok := kv.(map[string]any)
		if !ok || !closedMembers(k, []string{"kid", "pk"}, "pq_pk") || !boundedStr(k["kid"], 64) || !isDigestV(k["pk"]) || !pinPqOK(k) || kids[k["kid"].(string)] {
			return "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk"
		}
		kids[k["kid"].(string)] = true
	}
	if !jsIsInt(p["max_age_ms"]) || jsF(p["max_age_ms"]) < 0 {
		return "offers policy: max_age_ms must be a non-negative safe integer"
	}
	if op, ok := p["offer_param"].(string); !ok || !strings.HasPrefix(op, "action.params.") {
		return "offers policy: offer_param must be an action.params.* path"
	}
	f, ok := p["filter"].(map[string]any)
	var q, o map[string]any
	var ok1, ok2 bool
	if ok {
		q, ok1 = f["query"].(map[string]any)
		o, ok2 = f["offer"].(map[string]any)
	}
	if !ok || !closedMembers(f, []string{"query", "offer"}) || !ok1 || !ok2 {
		return "offers policy: filter must be exactly {query: {}, offer: {}}"
	}
	for _, m := range []map[string]any{q, o} {
		for _, v := range m {
			if !isScalarV(v) {
				return "offers policy: filter values must be scalars"
			}
		}
	}
	return ""
}

func validateOfferPolicy(pv any) bool { return validateOfferPolicyError(pv) == "" }

// validateWorldPolicyError is rule 16 step 0 (the reference validateWorldPolicy): "" = well-formed, else the refusal text.
func validateWorldPolicyError(pv any) string {
	p, ok := pv.(map[string]any)
	if !ok {
		return "world policy must be an object"
	}
	if m := closedMembersMsg(p, "policy", nil, "skew_ms", "worlds", "relational", "offers"); m != "" {
		return m
	}
	if s, has := p["skew_ms"]; has && (!jsIsInt(s) || jsF(s) < 0) {
		return "skew_ms must be a non-negative safe integer"
	}
	names := map[string]bool{}
	claim := func(n any) string {
		s, ok := n.(string)
		if !ok || !matchName(s) {
			return "dimension name '" + jsValueString(n) + "' must match ^[a-z][a-z0-9_]{0,63}$"
		}
		if names[s] {
			return "duplicate dimension name '" + s + "'"
		}
		names[s] = true
		return ""
	}
	worlds, ok := arrayOf(p["worlds"], hasKey(p, "worlds"))
	if !ok || len(worlds) > maxWorlds {
		return fmt.Sprintf("worlds must be a list of at most %d", maxWorlds)
	}
	for _, wv := range worlds {
		w, ok := wv.(map[string]any)
		if !ok {
			return "world entry must be an object"
		}
		if m := closedMembersMsg(w, "world", []string{"name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty"}); m != "" {
			return m
		}
		if e := claim(w["name"]); e != "" {
			return e
		}
		wn := jsValueString(w["name"])
		if sp, ok := w["subject_path"].(string); !ok || !strings.HasPrefix(sp, "action.") {
			return "world '" + wn + "': subject_path must be rooted at action."
		}
		if !jsIsInt(w["freshness_ms"]) || jsF(w["freshness_ms"]) < 0 {
			return "world '" + wn + "': freshness_ms must be a non-negative safe integer"
		}
		if !jsIsInt(w["max_faulty"]) || jsF(w["max_faulty"]) < 0 {
			return "world '" + wn + "': max_faulty must be a non-negative safe integer"
		}
		if !jsIsInt(w["min_oracles"]) || jsF(w["min_oracles"]) < 2*jsF(w["max_faulty"])+1 {
			return "world '" + wn + "': min_oracles must be a safe integer >= 2*max_faulty+1"
		}
		oracles, ok := w["oracles"].([]any)
		if !ok || float64(len(oracles)) < jsF(w["min_oracles"]) {
			return "world '" + wn + "': fewer pinned oracles than min_oracles"
		}
		kids := map[string]bool{}
		for _, ov := range oracles {
			o, ok := ov.(map[string]any)
			if !ok || !closedMembers(o, []string{"kid", "pk"}, "pq_pk") || !boundedStr(o["kid"], 64) || !isDigestV(o["pk"]) || !pinPqOK(o) || kids[o["kid"].(string)] {
				return "world '" + wn + "': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
			}
			kids[o["kid"].(string)] = true
		}
	}
	rel, ok := arrayOf(p["relational"], hasKey(p, "relational"))
	if !ok || len(rel) > maxRelational {
		return fmt.Sprintf("relational must be a list of at most %d", maxRelational)
	}
	for _, rv := range rel {
		r, ok := rv.(map[string]any)
		if !ok {
			return "relational entry must be an object"
		}
		if m := closedMembersMsg(r, "relational", []string{"name", "fn", "a", "b"}); m != "" {
			return m
		}
		if e := claim(r["name"]); e != "" {
			return e
		}
		rn := jsValueString(r["name"])
		if r["fn"] != "sub" && r["fn"] != "ratio_ppm" {
			return "relational '" + rn + "': fn must be \"sub\" or \"ratio_ppm\""
		}
		for _, op := range []any{r["a"], r["b"]} {
			s, isS := op.(string)
			ok := isParamPath(op) || isS && strings.HasPrefix(s, "env.world.") && names[s[len("env.world."):]] && s[len("env.world."):] != r["name"]
			if !ok {
				return "relational '" + rn + "': operand '" + jsValueString(op) + "' must be an action.params path or an earlier env.world dimension"
			}
		}
	}
	if o, has := p["offers"]; has {
		if e := validateOfferPolicyError(o); e != "" {
			return e
		}
		return claim(o.(map[string]any)["name"])
	}
	return ""
}

func validateWorldPolicy(pv any) bool { return validateWorldPolicyError(pv) == "" }

func nonEmptyArray(v any) bool {
	a, ok := v.([]any)
	return ok && len(a) > 0
}

func isPlainObj(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

// Activity (README rule 16 "Activity", reference intentWBActive): only a non-empty ARRAY, a STRING offer_set or a
// plain OBJECT policy makes a check active (strict typing; `prov` is active when present, null included).

// intentWorldActive: rule 16 is reported iff committed.facts is a non-empty array, committed.offer_set a string,
// policy.worlds / policy.relational a non-empty array, or policy.offers a plain object.
func intentWorldActive(cf, co, policy any) bool {
	_, offerStr := co.(string)
	w, _ := member(policy, "worlds")
	r, _ := member(policy, "relational")
	o, _ := member(policy, "offers")
	return nonEmptyArray(cf) || offerStr || nonEmptyArray(w) || nonEmptyArray(r) || isPlainObj(o)
}

// intentProvenanceActive: rule 17 is reported iff prov is present (any value), labels is a non-empty array, or the
// provenance policy is a plain object.
func intentProvenanceActive(provPresent bool, labels, policy any) bool {
	return provPresent || nonEmptyArray(labels) || isPlainObj(policy)
}

// classifierCheckActive: rule 18 is reported iff committed or policy.classifiers is a non-empty array.
func classifierCheckActive(committed, classifiers any) bool {
	return nonEmptyArray(committed) || nonEmptyArray(classifiers)
}

// IntentWBActivePrimitive runs primitives.intent_wb_active on {intent_session, policy: {world?, provenance?,
// classifiers?}}: which W-B checks a verifier reports, {facts, provenance, classes}.
func IntentWBActivePrimitive(input any) map[string]any {
	in, _ := normalizeJSON(input).(map[string]any)
	is, _ := in["intent_session"].(map[string]any)
	pol := in["policy"]
	world, _ := member(pol, "world")
	prov, _ := member(pol, "provenance")
	cls, _ := member(pol, "classifiers")
	_, provP := is["prov"]
	return map[string]any{
		"facts":      intentWorldActive(is["facts"], is["offer_set"], world),
		"provenance": intentProvenanceActive(provP, is["labels"], prov),
		"classes":    classifierCheckActive(is["classes"], cls),
	}
}

func subjectOf(action map[string]any, path string) (string, bool) {
	switch path {
	case "action.resource":
		s, ok := action["resource"].(string)
		return s, ok
	case "action.verb":
		s, ok := action["verb"].(string)
		return s, ok
	}
	v, found := resolveParamPath(paramsOrEmpty(action), path)
	s, ok := v.(string)
	return s, found && ok
}

func paramsOrEmpty(action map[string]any) any {
	p, has := action["params"]
	if !has {
		return map[string]any{}
	}
	return p
}

// ratioPpm = floor(a * 10^6 / b) exactly; ok false when b <= 0, a < 0 or the result is not a safe integer.
func ratioPpm(a, b float64) (float64, bool) {
	if !(b > 0) || a < 0 {
		return 0, false
	}
	q := new(big.Int).Mul(big.NewInt(int64(a)), big.NewInt(1_000_000))
	q.Quo(q, big.NewInt(int64(b)))
	if q.Cmp(big.NewInt(maxSafeInt)) > 0 {
		return 0, false
	}
	return float64(q.Int64()), true
}

type worldDecision struct {
	ok           bool
	world        map[string]any
	singleSource []string
	reason       string
}

// decideIntentWorld is rule 16 (never panics; a panic is a failure).
func decideIntentWorld(nowV any, aud, session any, action map[string]any, committedFacts any, cfP bool, committedOffer any, coP bool,
	facts any, factsP bool, offerSet any, osP bool, policyV any, polP bool) (d worldDecision) {
	fail := func(r string) worldDecision { return worldDecision{reason: "facts: " + r} }
	clock := jsIsInt(nowV) // CLOCK: a `now` that is not a safe integer is never coerced: every fact and offer set is stale
	now := jsF(nowV)
	defer func() {
		if recover() != nil {
			d = fail("evaluation error (fail closed)")
		}
	}()
	policy := policyV
	if !polP {
		policy = map[string]any{}
	}
	if pe := validateWorldPolicyError(policy); pe != "" {
		return fail("policy misconfigured (fail closed): " + pe)
	}
	if action == nil {
		return fail("action must be an object")
	}
	if !paramsOK(action) {
		return fail("action.params must be an object")
	}
	pol := policy.(map[string]any)
	skew := float64(defaultWorldSkewMs)
	if s, has := pol["skew_ms"]; has {
		skew = jsF(s)
	}
	cf, ok := arrayOf(committedFacts, cfP)
	if !ok || len(cf) > maxCommittedFacts {
		return fail("committed facts must be a list of at most 16 digests")
	}
	seen := map[string]bool{}
	for _, d := range cf {
		if !isDigestV(d) {
			return fail("a committed fact digest is not canonical base64url (32 bytes)")
		}
		if seen[d.(string)] {
			return fail("duplicate committed fact digest")
		}
		seen[d.(string)] = true
	}
	if coP && !isDigestV(committedOffer) {
		return fail("the committed offer_set is not canonical base64url (32 bytes)")
	}
	supplied, ok := arrayOf(facts, factsP)
	if !ok {
		return fail("facts must be an array")
	}
	if _, isMap := offerSet.(map[string]any); osP && !isMap {
		return fail("offer_set must be an object")
	}
	byRef := map[string]map[string]any{}
	for _, f := range supplied {
		if !validateFactWire(f) {
			continue
		}
		if r, ok := artifactRef(factRefDomain, "f", f); ok {
			byRef[r] = f.(map[string]any)
		}
	}
	worlds, _ := arrayOf(pol["worlds"], hasKey(pol, "worlds"))
	findWorld := func(name any) map[string]any {
		for _, w := range worlds {
			if m := w.(map[string]any); m["name"] == name {
				return m
			}
		}
		return nil
	}
	accepted := []map[string]any{}
	pairs := map[string]bool{}
	for _, dv := range cf {
		fact, ok := byRef[dv.(string)]
		if !ok {
			return fail("a committed fact was not supplied (or is malformed)")
		}
		if se := artifactSuiteError(fact); se != "" {
			return fail("fact signature suite: " + se)
		}
		w := findWorld(fact["name"])
		if w == nil {
			return fail("fact for undeclared world '" + jsValueString(fact["name"]) + "'")
		}
		var pin map[string]any
		for _, o := range w["oracles"].([]any) {
			if m := o.(map[string]any); m["kid"] == fact["oracle"] {
				pin = m
				break
			}
		}
		if pin == nil {
			return fail("oracle '" + jsValueString(fact["oracle"]) + "' is not pinned for world '" + jsValueString(w["name"]) + "'")
		}
		if !verifyArtifactSig(factDomain, fact, pin["pk"], pin["pq_pk"]) {
			return fail("bad oracle signature on a '" + jsValueString(w["name"]) + "' fact")
		}
		subj, ok := subjectOf(action, w["subject_path"].(string))
		if !ok || fact["subject"] != subj {
			return fail("a '" + jsValueString(w["name"]) + "' fact names another subject")
		}
		pair := w["name"].(string) + "\x00" + fact["oracle"].(string)
		if pairs[pair] {
			return fail("two facts from oracle '" + jsValueString(fact["oracle"]) + "' for world '" + jsValueString(w["name"]) + "'")
		}
		pairs[pair] = true
		accepted = append(accepted, fact)
	}
	world := map[string]any{}
	single := []string{}
	for _, wv := range worlds {
		w := wv.(map[string]any)
		name := w["name"].(string)
		fresh := []map[string]any{}
		for _, f := range accepted {
			t := jsF(f["t_obs"])
			if clock && f["name"] == name && t <= now+skew && now-t <= jsF(w["freshness_ms"]) {
				fresh = append(fresh, f)
			}
		}
		if float64(len(fresh)) < jsF(w["min_oracles"]) {
			return fail(fmt.Sprintf("world '%s' has %d fresh fact(s), needs %s", name, len(fresh), jsValueString(w["min_oracles"])))
		}
		nums := []float64{}
		for _, f := range fresh {
			if x, ok := jsNum(f["value"]); ok {
				nums = append(nums, x)
			}
		}
		switch {
		case len(nums) == len(fresh):
			if len(nums) == 0 {
				panic("lowerMedian: empty")
			}
			sort.Float64s(nums)
			world[name] = jsNumber(nums[(len(nums)-1)/2])
		case len(nums) == 0:
			v := fresh[0]["value"]
			for _, f := range fresh {
				if f["value"] != v {
					return fail("world '" + name + "': string facts disagree")
				}
			}
			world[name] = v
		default:
			return fail("world '" + name + "': facts mix integer and string values")
		}
		if jsF(w["min_oracles"]) == 1 {
			single = append(single, name)
		}
	}
	operand := func(path string) (float64, bool) {
		if strings.HasPrefix(path, "env.world.") {
			v := world[path[len("env.world."):]]
			return jsF(v), jsIsInt(v)
		}
		v, found := resolveParamPath(paramsOrEmpty(action), path)
		return jsF(v), found && jsIsInt(v)
	}
	rel, _ := arrayOf(pol["relational"], hasKey(pol, "relational"))
	for _, rv := range rel {
		r := rv.(map[string]any)
		a, okA := operand(r["a"].(string))
		b, okB := operand(r["b"].(string))
		if !okA || !okB {
			return fail("relational '" + jsValueString(r["name"]) + "': an operand is missing or not a safe integer")
		}
		var v float64
		ok := true
		if r["fn"] == "sub" {
			v = a - b
		} else {
			v, ok = ratioPpm(a, b)
		}
		if !ok || !jsIsInt(jsNumber(v)) {
			return fail("relational '" + jsValueString(r["name"]) + "': result undefined or outside the safe integer range")
		}
		world[r["name"].(string)] = jsNumber(v)
	}
	if ov, has := pol["offers"]; has {
		o := ov.(map[string]any)
		excess, why := decideOfferSet(o, committedOffer, coP, offerSet, osP, paramsOrEmpty(action), aud, session, clock, now, skew)
		if why != "" {
			return fail(why)
		}
		world[o["name"].(string)] = jsNumber(excess)
	}
	return worldDecision{ok: true, world: world, singleSource: single}
}

// validateOfferSetWireError is the reference validateOfferSetWire: "" = well-formed, else the refusal text. Members are
// examined in sorted order (Go maps carry no insertion order).
func validateOfferSetWireError(ov any) string {
	o, ok := ov.(map[string]any)
	if !ok {
		return "offer set must be an object"
	}
	if m := closedMembersMsg(o, "offer_set", []string{"v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig"}, suiteMembers...); m != "" {
		return m
	}
	if !jsStrictEq(o["v"], jsNumber(1)) || o["kind"] != "pca-offer-set" {
		return "offer set must be {v: 1, kind: \"pca-offer-set\"}"
	}
	if !boundedStr(o["site"], 256) {
		return "'offer_set.site' must be a non-empty string (<= 256 bytes)"
	}
	if !isDigestV(o["session"]) {
		return "'offer_set.session' must be canonical base64url (32 bytes)"
	}
	q, ok := o["query"].(map[string]any)
	if !ok || len(q) > maxQueryKeys {
		return fmt.Sprintf("'offer_set.query' must be an object with <= %d keys", maxQueryKeys)
	}
	for _, k := range sortedKeysUtf8(q) {
		if !boundedStr(k, 64) || !isScalarV(q[k]) {
			return "'offer_set.query." + k + "' must be a scalar"
		}
	}
	if o["rank"] != "price_asc" {
		return "'offer_set.rank' must be \"price_asc\""
	}
	if _, ok := o["complete"].(bool); !ok {
		return "'offer_set.complete' must be a boolean"
	}
	offers, ok := o["offers"].([]any)
	if !ok || len(offers) == 0 || len(offers) > maxOffers {
		return fmt.Sprintf("'offer_set.offers' must hold 1..%d offers", maxOffers)
	}
	ids := map[string]bool{}
	for i, fv := range offers {
		f, ok := fv.(map[string]any)
		if !ok {
			return fmt.Sprintf("offer %d must be an object", i)
		}
		if !boundedStr(f["offer_id"], 128) {
			return fmt.Sprintf("offer %d: 'offer_id' must be a non-empty string (<= 128 bytes)", i)
		}
		if ids[f["offer_id"].(string)] {
			return fmt.Sprintf("offer %d: duplicate offer_id", i)
		}
		ids[f["offer_id"].(string)] = true
		if !jsIsInt(f["price"]) || jsF(f["price"]) < 0 {
			return fmt.Sprintf("offer %d: 'price' must be a non-negative safe integer", i)
		}
		attrs := []string{}
		for _, k := range sortedKeysUtf8(f) {
			if k != "offer_id" && k != "price" {
				attrs = append(attrs, k)
			}
		}
		if len(attrs) > maxOfferAttrs {
			return fmt.Sprintf("offer %d: more than %d attributes", i, maxOfferAttrs)
		}
		for _, k := range attrs {
			if !boundedStr(k, 64) || !isScalarV(f[k]) {
				return fmt.Sprintf("offer %d: attribute '%s' must be a scalar", i, k)
			}
		}
	}
	if !jsIsInt(o["issued_at"]) || jsF(o["issued_at"]) < 0 {
		return "'offer_set.issued_at' must be a non-negative safe integer"
	}
	if !boundedStr(o["kid"], 64) {
		return "'offer_set.kid' must be a non-empty string (<= 64 bytes)"
	}
	if _, ok = o["sig"].(string); !ok {
		return "'offer_set.sig' must be a string"
	}
	return ""
}

func validateOfferSetWire(ov any) bool { return validateOfferSetWireError(ov) == "" }

func offerMatches(offer map[string]any, f map[string]any) bool {
	for k, v := range f {
		x, has := offer[k]
		if !has || !scalarEqV(x, v) {
			return false
		}
	}
	return true
}

// decideOfferSet: the excess of the chosen offer over the cheapest offer satisfying the filter ("" = ok).
func decideOfferSet(policy map[string]any, committed any, committedP bool, ov any, oP bool, params any, aud, session any, clock bool, now, skew float64) (float64, string) {
	if !committedP {
		return 0, "offers: the PCActn commits no offer set but the policy requires one"
	}
	if !oP {
		return 0, "offers: the committed offer set was not supplied"
	}
	if w := validateOfferSetWireError(ov); w != "" {
		return 0, "offers: " + w
	}
	os := ov.(map[string]any)
	ref, ok := artifactRef(offerSetRefDomain, "o", os)
	if !ok {
		return 0, "offers: the offer set is not strictly canonical"
	}
	if ref != committed {
		return 0, "offers: the supplied offer set does not match the committed reference"
	}
	if se := artifactSuiteError(os); se != "" {
		return 0, "offers: signature suite: " + se
	}
	var key map[string]any
	for _, kv := range policy["site_keys"].([]any) {
		if m := kv.(map[string]any); m["kid"] == os["kid"] {
			key = m
			break
		}
	}
	if key == nil {
		return 0, "offers: signing key '" + jsValueString(os["kid"]) + "' is not pinned"
	}
	if !verifyArtifactSig(offerSetDomain, os, key["pk"], key["pq_pk"]) {
		return 0, "offers: bad site signature"
	}
	if os["site"] != aud {
		return 0, "offers: the offer set was issued for another audience"
	}
	if os["session"] != session {
		return 0, "offers: the offer set is bound to another session"
	}
	if !clock {
		return 0, "offers: no usable clock (now must be a safe integer): the offer set counts as stale"
	}
	issued := jsF(os["issued_at"])
	if issued > now+skew {
		return 0, "offers: the offer set is issued in the future"
	}
	if now-issued > jsF(policy["max_age_ms"]) {
		return 0, "offers: the offer set is stale"
	}
	if os["complete"] != true {
		return 0, "offers: the offer set is not declared complete"
	}
	filter := policy["filter"].(map[string]any)
	fq := filter["query"].(map[string]any)
	for k, v := range os["query"].(map[string]any) {
		x, has := fq[k]
		if !has || !scalarEqV(x, v) {
			return 0, "offers: the search was narrowed beyond the intent filter (coverage)"
		}
	}
	idV, found := resolveParamPath(params, policy["offer_param"])
	id, isS := idV.(string)
	if !found || !isS {
		return 0, "offers: the action names no offer id at the declared parameter"
	}
	var chosen map[string]any
	offers := os["offers"].([]any)
	for _, x := range offers {
		if m := x.(map[string]any); m["offer_id"] == id {
			chosen = m
			break
		}
	}
	if chosen == nil {
		return 0, "offers: the chosen offer is not in the signed offer set"
	}
	fo := filter["offer"].(map[string]any)
	if !offerMatches(chosen, fo) {
		return 0, "offers: the chosen offer does not satisfy the intent filter"
	}
	min := jsF(chosen["price"])
	for _, x := range offers {
		m := x.(map[string]any)
		if offerMatches(m, fo) && jsF(m["price"]) < min {
			min = jsF(m["price"])
		}
	}
	return jsF(chosen["price"]) - min, ""
}

// ---- rule 17: provenance ----------------------------------------------------------------------------------------

func validateLabelsWire(lv any) bool {
	l, ok := lv.(map[string]any)
	if !ok || !closedMembers(l, []string{"v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"}, suiteMembers...) {
		return false
	}
	if !jsStrictEq(l["v"], jsNumber(1)) || l["kind"] != "pca-labels" || !boundedStr(l["site"], 256) || !isDigestV(l["session"]) || !isDigestV(l["response_digest"]) {
		return false
	}
	fields, ok := l["fields"].(map[string]any)
	if !ok || len(fields) == 0 || len(fields) > maxLabelFields {
		return false
	}
	for k, fv := range fields {
		if !boundedStr(k, 256) {
			return false
		}
		f, ok := fv.(map[string]any)
		if !ok || !closedMembers(f, []string{"class", "value_digest"}) {
			return false
		}
		c, ok := f["class"].(string)
		if !ok || jsLen(c) > 128 || !matchDataClass(c) || !isDigestV(f["value_digest"]) {
			return false
		}
	}
	if !jsIsInt(l["issued_at"]) || jsF(l["issued_at"]) < 0 || !boundedStr(l["kid"], 64) {
		return false
	}
	_, ok = l["sig"].(string)
	return ok
}

// validateFlowRulesError: "" = well-formed, else the reference refusal text (patterns examined in sorted order).
func validateFlowRulesError(rv any) string {
	r, ok := rv.(map[string]any)
	if !ok {
		return "flows must be an object"
	}
	for _, p := range sortedKeysUtf8(r) {
		base := p
		if p == "*" {
			base = "x"
		} else if strings.HasSuffix(p, ".*") {
			base = p[:len(p)-2]
		}
		if !matchDataClass(base) {
			return "flow pattern '" + p + "' is not a class, a 'prefix.*' or '*'"
		}
		sinks, ok := r[p].([]any)
		bad := !ok
		for _, s := range sinks {
			if !boundedStr(s, 256) {
				bad = true
			}
		}
		if bad {
			return "flow pattern '" + p + "' needs a list of audiences"
		}
	}
	return ""
}

func validateFlowRules(rv any) bool { return validateFlowRulesError(rv) == "" }

func flowRuleFor(rules map[string]any, cls string) (string, bool) {
	if _, has := rules[cls]; has {
		return cls, true
	}
	best, found := "", false
	for p := range rules {
		if !strings.HasSuffix(p, ".*") {
			continue
		}
		if jsStartsWith(cls, p[:len(p)-1]) && (!found || jsLen(p) > jsLen(best)) {
			best, found = p, true
		}
	}
	if found {
		return best, true
	}
	if _, has := rules["*"]; has {
		return "*", true
	}
	return "", false
}

func flowAllowed(rules map[string]any, cls, origin string, aud any) bool {
	if aud == origin || cls == publicDataClass {
		return true
	}
	p, ok := flowRuleFor(rules, cls)
	if !ok {
		return false
	}
	sinks, ok := rules[p].([]any)
	return ok && containsV(sinks, aud)
}

var taintedModes = []string{"allow", "question", "question_typed", "deny"}

// validateProvenancePolicyError is rule 17 step 0: "" = well-formed, else the reference refusal text.
func validateProvenancePolicyError(pv any) string {
	p, ok := pv.(map[string]any)
	var params map[string]any
	if ok {
		params, ok = p["params"].(map[string]any)
	}
	if !ok {
		return "provenance policy needs a params map"
	}
	if m := closedMembersMsg(p, "policy", []string{"params"}, "registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"); m != "" {
		return m
	}
	for _, k := range sortedKeysUtf8(params) {
		if !isParamPath(k) {
			return "policy param '" + k + "' is not an action.params path"
		}
		if v := params[k]; v != "material" && v != "critical" {
			return "policy param '" + k + "': sensitivity must be material or critical"
		}
	}
	if rv, has := p["registry"]; has {
		r, ok := rv.(map[string]any)
		if !ok {
			return "registry must be an object"
		}
		for _, k := range sortedKeysUtf8(r) {
			if !boundedStr(k, 256) || !isTaintLevel(r[k]) {
				return "registry entry '" + k + "' must map to a taint level"
			}
		}
	}
	if lk, has := p["label_keys"]; has {
		arr, ok := lk.([]any)
		if !ok {
			return "label_keys must be a list"
		}
		for _, kv := range arr {
			k, ok := kv.(map[string]any)
			if !ok || !closedMembers(k, []string{"site", "kid", "pk"}, "pq_pk") || !boundedStr(k["site"], 256) || !boundedStr(k["kid"], 64) || !isDigestV(k["pk"]) || !pinPqOK(k) {
				return "every label key needs site, kid, a 32-byte pk and an optional string pq_pk"
			}
		}
	}
	if c, has := p["critical_max"]; has && !isTaintLevel(c) {
		return "critical_max must be a taint level"
	}
	if m, has := p["material_tainted"]; has && !strIn(m, taintedModes) {
		return "material_tainted must be allow | question | question_typed | deny"
	}
	if m, has := p["critical_tainted"]; has && (m == "allow" || !strIn(m, taintedModes)) {
		return "critical_tainted must be question | question_typed | deny"
	}
	if f, has := p["flows"]; has {
		if e := validateFlowRulesError(f); e != "" {
			return e
		}
	}
	return ""
}

func validateProvenancePolicy(pv any) bool { return validateProvenancePolicyError(pv) == "" }

// validateProvWireError: "" = well-formed `prov`, else the reference refusal text (paths examined in sorted order).
func validateProvWireError(pv any) string {
	prov, ok := pv.(map[string]any)
	if !ok {
		return "'prov' must be an object"
	}
	if len(prov) > maxProvPaths {
		return fmt.Sprintf("'prov' holds more than %d paths", maxProvPaths)
	}
	for _, k := range sortedKeysUtf8(prov) {
		if !matchParamPath(k) || forbiddenSegments[k[len("action.params."):]] {
			return "'prov' key '" + k + "' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)"
		}
		refs, ok := prov[k].([]any)
		if !ok || len(refs) == 0 || len(refs) > maxProvRefs {
			return fmt.Sprintf("'prov.%s' must hold 1..%d refs", k, maxProvRefs)
		}
		for _, r := range refs {
			if !boundedStr(r, 256) {
				return "'prov." + k + "' refs must be non-empty strings (<= 256 bytes)"
			}
		}
	}
	return ""
}

func validateProvWire(pv any) bool { return validateProvWireError(pv) == "" }

type provDecision struct {
	outcome  string // pass | question | deny
	reason   string
	friction string
	labels   map[string]any
	classes  map[string]any
	env      map[string]any
}

// decideParamProvenance is rule 17 (never panics).
func decideParamProvenance(aud, session any, action map[string]any, prov any, provP bool, committedLabels any, clP bool, labels any, labelsP bool, policyV any) (d provDecision) {
	lbl := map[string]any{}
	cls := map[string]any{}
	deny := func(r string) provDecision {
		return provDecision{outcome: "deny", reason: "provenance: " + r, labels: lbl, classes: cls, env: map[string]any{}}
	}
	defer func() {
		if recover() != nil {
			d = deny("evaluation error (fail closed)")
		}
	}()
	if pe := validateProvenancePolicyError(policyV); pe != "" {
		return deny("policy misconfigured (fail closed): " + pe)
	}
	policy := policyV.(map[string]any)
	if !provP {
		prov = map[string]any{}
	}
	if we := validateProvWireError(prov); we != "" {
		return deny(we)
	}
	committed, ok := arrayOf(committedLabels, clP)
	if !ok || len(committed) > maxCommittedLabels {
		return deny("committed labels must be a list of at most 16 digests")
	}
	cset := map[string]bool{}
	for _, d := range committed {
		if !isDigestV(d) || cset[d.(string)] {
			return deny("committed labels must be distinct canonical 32-byte digests")
		}
		cset[d.(string)] = true
	}
	if !paramsOK(action) {
		return deny("action.params must be an object")
	}
	params := paramsOrEmpty(action)
	provMap := prov.(map[string]any)
	paths := make([]string, 0, len(provMap))
	for k := range provMap {
		paths = append(paths, k)
	}
	sort.Strings(paths) // ASCII paths: UTF-16 order == byte order
	for _, p := range paths {
		if _, found := resolveParamPath(params, p); !found {
			return deny("prov names '" + p + "', a parameter the action does not carry")
		}
	}
	for _, a := range paths {
		for _, b := range paths {
			if a != b && strings.HasPrefix(b, a+".") {
				return deny("prov paths '" + a + "' and '" + b + "' overlap")
			}
		}
	}
	supplied, ok := arrayOf(labels, labelsP)
	if !ok {
		return deny("labels must be an array")
	}
	receipts := map[string]map[string]any{}
	for _, r := range supplied {
		if validateLabelsWire(r) {
			if ref, ok := artifactRef(labelsRefDomain, "l", r); ok {
				receipts[ref] = r.(map[string]any)
			}
		}
	}
	reg, _ := policy["registry"].(map[string]any)
	type origin struct{ cls, origin string }
	origins := map[string][]origin{}
	labelKeys, _ := policy["label_keys"].([]any)
	for _, p := range paths {
		value, _ := resolveParamPath(params, p)
		worst := -1
		for _, rv := range provMap[p].([]any) {
			ref := rv.(string)
			level := "agent"
			if !strings.HasPrefix(ref, labelRefPrefix) {
				if l, has := reg[ref]; has && isTaintLevel(l) {
					level = l.(string)
				}
			} else {
				rest := ref[len(labelRefPrefix):]
				i := strings.IndexByte(rest, '#')
				if i < 0 || !isDigestV(rest[:i]) || len(rest[i+1:]) == 0 {
					return deny("malformed label ref on '" + p + "'")
				}
				receiptRef, field := rest[:i], rest[i+1:]
				if !cset[receiptRef] {
					return deny("label ref on '" + p + "' names a receipt the PCActn does not commit")
				}
				rc, ok := receipts[receiptRef]
				if !ok {
					return deny("label receipt for '" + p + "' was not supplied")
				}
				if se := artifactSuiteError(rc); se != "" {
					return deny("label receipt for '" + p + "': signature suite: " + se)
				}
				var key map[string]any
				for _, kv := range labelKeys {
					if m := kv.(map[string]any); m["site"] == rc["site"] && m["kid"] == rc["kid"] {
						key = m
						break
					}
				}
				if key == nil {
					return deny("label receipt for '" + p + "': no pinned label key for site '" + jsValueString(rc["site"]) + "' kid '" + jsValueString(rc["kid"]) + "'")
				}
				if !verifyArtifactSig(labelsDomain, rc, key["pk"], key["pq_pk"]) {
					return deny("label receipt for '" + p + "': bad label receipt signature")
				}
				if rc["session"] != session {
					return deny("label receipt for '" + p + "' is bound to another session")
				}
				fv, has := rc["fields"].(map[string]any)[field]
				if !has {
					return deny("label receipt for '" + p + "' has no field '" + field + "'")
				}
				f := fv.(map[string]any)
				h, ok := hashCanonicalV(value)
				site := rc["site"].(string)
				if ok && h == f["value_digest"] {
					if site == aud {
						level = "first_party"
					} else {
						level = "tool"
					}
				}
				origins[p] = append(origins[p], origin{f["class"].(string), site})
			}
			if rankOf(level) > worst {
				worst = rankOf(level)
			}
		}
		for name, r := range taintRank {
			if r == worst {
				lbl[p] = name
			}
		}
	}
	pparams := policy["params"].(map[string]any)
	ppaths := make([]string, 0, len(pparams))
	for k := range pparams {
		ppaths = append(ppaths, k)
	}
	sort.Strings(ppaths)
	for _, p := range ppaths {
		if _, has := lbl[p]; has {
			continue
		}
		if _, found := resolveParamPath(params, p); found {
			lbl[p] = "agent"
		}
	}
	flows, _ := policy["flows"].(map[string]any)
	opaths := make([]string, 0, len(origins))
	for k := range origins {
		opaths = append(opaths, k)
	}
	sort.Strings(opaths)
	for _, p := range opaths {
		set := map[string]bool{}
		list := []string{}
		for _, o := range origins[p] {
			if !set[o.cls] {
				set[o.cls] = true
				list = append(list, o.cls)
			}
		}
		sortUtf8(list) // UTF-8 byte order (the canonical-ordering rule)
		arr := make([]any, len(list))
		for i, c := range list {
			arr[i] = c
		}
		cls[p] = arr
		for _, o := range origins[p] {
			if !flowAllowed(flows, o.cls, o.origin, aud) {
				return deny("flow: class '" + o.cls + "' from '" + o.origin + "' may not reach '" + audText(aud) + "' (parameter '" + p + "')")
			}
		}
	}
	capLevel := "agent"
	if c, has := policy["critical_max"]; has {
		capLevel = c.(string)
	}
	capRank := rankOf(capLevel)
	lpaths := make([]string, 0, len(lbl))
	for k := range lbl {
		lpaths = append(lpaths, k)
	}
	sort.Strings(lpaths)
	sens := func(p string) string {
		s, _ := pparams[p].(string)
		return s
	}
	for _, p := range lpaths {
		if sens(p) == "critical" && rankOf(lbl[p].(string)) > capRank {
			return deny("critical parameter '" + p + "' has provenance '" + jsValueString(lbl[p]) + "', above the policy maximum '" + jsMemberString(policy, "critical_max") + "'")
		}
	}
	question, typed := false, false
	for _, p := range lpaths {
		s := sens(p)
		if s == "" || rankOf(lbl[p].(string)) < taintedRank {
			continue
		}
		var mode string
		if s == "critical" {
			mode = "question_typed"
			if m, has := policy["critical_tainted"]; has {
				mode = m.(string)
			}
		} else {
			mode = "question"
			if m, has := policy["material_tainted"]; has {
				mode = m.(string)
			}
		}
		if mode == "deny" {
			return deny("tainted " + s + " parameter '" + p + "' (provenance '" + jsValueString(lbl[p]) + "') is denied by policy")
		}
		if mode == "question" || mode == "question_typed" {
			question = true
		}
		if mode == "question_typed" {
			typed = true
		}
	}
	env := map[string]any{}
	for _, p := range lpaths {
		if !setNested(env, p, lbl[p]) {
			return deny("provenance paths overlap at '" + p + "'")
		}
	}
	if question {
		fr := "tap"
		if typed {
			fr = "typed"
		}
		return provDecision{outcome: "question", reason: "provenance: a tainted value needs the principal (lazy question)", friction: fr, labels: lbl, classes: cls, env: env}
	}
	return provDecision{outcome: "pass", labels: lbl, classes: cls, env: env}
}

// ---- read purpose (V14, primitives.intent_read_purpose; label-receipts.ts decideReadPurpose) ----------------------

// IntentReadPurposePrimitive runs primitives.intent_read_purpose on {fields: [{path, class, optional?}], purpose,
// coverage: {purpose: [pattern]}, on_uncovered?}: {outcome, minimise, uncovered}. Malformed input (JSON null anywhere
// included) is {deny, [], []}; coverage[purpose] is an own member; both lists de-duplicated and sorted in UTF-8 byte
// order; outcome allow when nothing required is uncovered, else on_uncovered (default question).
func IntentReadPurposePrimitive(input any) map[string]any {
	malformed := map[string]any{"outcome": "deny", "minimise": []any{}, "uncovered": []any{}}
	in, ok := normalizeJSON(input).(map[string]any)
	if !ok {
		return malformed
	}
	fields, ok1 := in["fields"].([]any)
	purpose, ok2 := in["purpose"].(string)
	coverage, ok3 := in["coverage"].(map[string]any)
	if !ok1 || !ok2 || !ok3 {
		return malformed
	}
	onUncovered := "question"
	if v, has := in["on_uncovered"]; has {
		s, ok := v.(string)
		if !ok || (s != "question" && s != "deny") {
			return malformed
		}
		onUncovered = s
	}
	for _, pv := range coverage {
		pats, ok := pv.([]any)
		if !ok {
			return malformed
		}
		for _, x := range pats {
			if _, ok := x.(string); !ok {
				return malformed
			}
		}
	}
	for _, fv := range fields {
		f, ok := fv.(map[string]any)
		if !ok {
			return malformed
		}
		_, okP := f["path"].(string)
		_, okC := f["class"].(string)
		if !okP || !okC {
			return malformed
		}
		if o, has := f["optional"]; has {
			if _, ok := o.(bool); !ok {
				return malformed
			}
		}
	}
	var patterns []any
	if pv, has := coverage[purpose]; has {
		patterns = pv.([]any)
	}
	covered := func(cls string) bool {
		if cls == publicDataClass {
			return true
		}
		for _, x := range patterns {
			p := x.(string)
			if p == "*" || p == cls || (strings.HasSuffix(p, ".*") && jsStartsWith(cls, p[:len(p)-1])) {
				return true
			}
		}
		return false
	}
	minimise, uncovered := map[string]bool{}, map[string]bool{}
	for _, fv := range fields {
		f := fv.(map[string]any)
		if covered(f["class"].(string)) {
			continue
		}
		if f["optional"] == true {
			minimise[f["path"].(string)] = true
		} else {
			uncovered[f["path"].(string)] = true
		}
	}
	sorted := func(m map[string]bool) []any {
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sortUtf8(ks)
		out := make([]any, len(ks))
		for i, k := range ks {
			out[i] = k
		}
		return out
	}
	outcome := "allow"
	if len(uncovered) > 0 {
		outcome = onUncovered
	}
	return map[string]any{"outcome": outcome, "minimise": sorted(minimise), "uncovered": sorted(uncovered)}
}

// ---- rule 18: classifier verdicts --------------------------------------------------------------------------------

func validateClassifierVerdictWire(vv any) bool {
	v, ok := vv.(map[string]any)
	if !ok || !closedMembers(v, []string{"v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"}, suiteMembers...) {
		return false
	}
	if !jsStrictEq(v["v"], jsNumber(1)) || v["kind"] != "pca-intent-classification" {
		return false
	}
	if c, ok := v["classifier"].(string); !ok || !matchName(c) {
		return false
	}
	if !isDigestV(v["session"]) || !isDigestV(v["content_digest"]) || !boundedStr(v["label"], 64) || !boundedStr(v["measurement"], 256) || !isDigestV(v["judge"]) {
		return false
	}
	_, ok = v["sig"].(string)
	return ok
}

// validateClassifierPolicyError is the reference validateClassifierPolicy: "" = well-formed, else the refusal text.
func validateClassifierPolicyError(pv any) string {
	p, ok := pv.(map[string]any)
	var cs []any
	if ok {
		cs, ok = p["classifiers"].([]any)
	}
	if !ok {
		return "classifier policy needs a classifiers list"
	}
	if m := closedMembersMsg(p, "policy", []string{"classifiers"}); m != "" {
		return m
	}
	ids := map[string]bool{}
	for _, cv := range cs {
		c, ok := cv.(map[string]any)
		if !ok || !closedMembers(c, []string{"id", "param", "labels", "keys", "k"}, "measurements", "pq_keys") {
			return "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}"
		}
		id, ok := c["id"].(string)
		if !ok || !matchName(id) || ids[id] {
			return "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$"
		}
		ids[id] = true
		if !isParamPath(c["param"]) {
			return "classifier '" + id + "': param must be an action.params path"
		}
		labels, ok := c["labels"].([]any)
		if !ok || len(labels) == 0 || len(labels) > maxClassifierLabels {
			return fmt.Sprintf("classifier '%s': labels must hold 1..%d strings", id, maxClassifierLabels)
		}
		badLabels := false
		for _, l := range labels {
			if !boundedStr(l, 64) {
				badLabels = true
			}
		}
		if badLabels || !distinctStrings(labels) {
			return "classifier '" + id + "': labels must be distinct non-empty strings"
		}
		keys, ok := c["keys"].([]any)
		badKeys := !ok || len(keys) == 0
		for _, k := range keys {
			if !isDigestV(k) {
				badKeys = true
			}
		}
		if badKeys || !distinctStrings(keys) {
			return "classifier '" + id + "': keys must be distinct 32-byte keys"
		}
		if !jsIsInt(c["k"]) || jsF(c["k"]) < 1 || jsF(c["k"]) > float64(len(keys)) {
			return fmt.Sprintf("classifier '%s': k must be an integer in [1, %d]", id, len(keys))
		}
		if m, has := c["measurements"]; has {
			arr, ok := m.([]any)
			for _, x := range arr {
				if _, isS := x.(string); !isS {
					ok = false
				}
			}
			if !ok {
				return "classifier '" + id + "': measurements must be a list of strings"
			}
		}
		if pk, has := c["pq_keys"]; has {
			m, ok := pk.(map[string]any)
			for k, v := range m {
				s, isS := v.(string)
				if !containsV(keys, k) || !isS || s == "" {
					ok = false
				}
			}
			if !ok {
				return "classifier '" + id + "': pq_keys must map allowlisted keys to PQ keys"
			}
		}
	}
	return ""
}

func validateClassifierPolicy(pv any) bool { return validateClassifierPolicyError(pv) == "" }

type classDecision struct {
	ok      bool
	classes map[string]any
	reason  string
}

// decideClassifierDimensions is rule 18 (never panics).
func decideClassifierDimensions(session any, action map[string]any, committedV any, cP bool, verdicts any, vP bool, policyV any) (d classDecision) {
	fail := func(r string) classDecision { return classDecision{reason: "classes: " + r} }
	defer func() {
		if recover() != nil {
			d = fail("evaluation error (fail closed)")
		}
	}()
	if pe := validateClassifierPolicyError(policyV); pe != "" {
		return fail("policy misconfigured (fail closed): " + pe)
	}
	cs := policyV.(map[string]any)["classifiers"].([]any)
	committed, ok := arrayOf(committedV, cP)
	if !ok || len(committed) > maxCommittedClasses {
		return fail("committed verdicts must be a list of at most 8 digests")
	}
	seen := map[string]bool{}
	for _, d := range committed {
		if !isDigestV(d) || seen[d.(string)] {
			return fail("committed verdicts must be distinct canonical 32-byte digests")
		}
		seen[d.(string)] = true
	}
	supplied, ok := arrayOf(verdicts, vP)
	if !ok {
		return fail("verdicts must be an array")
	}
	if action == nil {
		return fail("action must be an object")
	}
	byRef := map[string]map[string]any{}
	for _, v := range supplied {
		if !validateClassifierVerdictWire(v) {
			continue
		}
		if r, ok := artifactRef(classifierRefDomain, "c", v); ok {
			byRef[r] = v.(map[string]any)
		}
	}
	if !paramsOK(action) {
		return fail("action.params must be an object")
	}
	params := paramsOrEmpty(action)
	// prototype-free tally: every classifier id and label is an ordinary key
	votes := map[string]map[string]int{}
	pairs := map[string]bool{}
	for _, dv := range committed {
		v, ok := byRef[dv.(string)]
		if !ok {
			return fail("a committed verdict was not supplied (or is malformed)")
		}
		if se := artifactSuiteError(v); se != "" {
			return fail("verdict signature suite: " + se)
		}
		var c map[string]any
		for _, x := range cs {
			if m := x.(map[string]any); m["id"] == v["classifier"] {
				c = m
				break
			}
		}
		if c == nil {
			return fail("verdict for undeclared classifier '" + jsValueString(v["classifier"]) + "'")
		}
		if !containsV(c["keys"].([]any), v["judge"]) {
			return fail("classifier '" + jsValueString(c["id"]) + "': judge key is not on the allowlist")
		}
		var pinPq any
		if pk, ok := c["pq_keys"].(map[string]any); ok {
			pinPq = pk[v["judge"].(string)]
		}
		if !verifyArtifactSig(classifierDomain, v, v["judge"], pinPq) {
			return fail("classifier '" + jsValueString(c["id"]) + "': bad verdict signature")
		}
		if v["session"] != session {
			return fail("classifier '" + jsValueString(c["id"]) + "': verdict bound to another session")
		}
		content, found := resolveParamPath(params, c["param"])
		if !found {
			return fail("classifier '" + jsValueString(c["id"]) + "': the action carries no '" + jsValueString(c["param"]) + "'")
		}
		cb, cerr := canonBytes(content)
		if cerr != nil {
			return fail("evaluation error (fail closed): " + cerr.Error()) // the reference reports the canonicalizer's message
		}
		h := b64.EncodeToString(sha(cb))
		if h != v["content_digest"] {
			return fail("classifier '" + jsValueString(c["id"]) + "': verdict is about other content")
		}
		if !containsV(c["labels"].([]any), v["label"]) {
			return fail("classifier '" + jsValueString(c["id"]) + "': label '" + jsValueString(v["label"]) + "' is not in its label set")
		}
		if m, has := c["measurements"]; has && !containsV(m.([]any), v["measurement"]) {
			return fail("classifier '" + jsValueString(c["id"]) + "': measurement is not pinned")
		}
		id := c["id"].(string)
		pair := id + "\x00" + v["judge"].(string)
		if pairs[pair] {
			return fail("classifier '" + id + "': two verdicts from one judge")
		}
		pairs[pair] = true
		if votes[id] == nil {
			votes[id] = map[string]int{}
		}
		votes[id][v["label"].(string)]++
	}
	classes := map[string]any{}
	for _, cv := range cs {
		c := cv.(map[string]any)
		id := c["id"].(string)
		k := jsF(c["k"])
		winners := []any{}
		for _, lv := range c["labels"].([]any) {
			if float64(votes[id][lv.(string)]) >= k {
				winners = append(winners, lv)
			}
		}
		if len(winners) == 0 {
			return fail("classifier '" + id + "': no label reaches the quorum " + jsLenientNumber(k))
		}
		if len(winners) > 1 {
			return fail(fmt.Sprintf("classifier '%s': ambiguous, %d labels reach the quorum", id, len(winners)))
		}
		classes[id] = winners[0]
	}
	return classDecision{ok: true, classes: classes}
}

// intentWBContextError (absent vs null): artifacts absent or an object whose facts / labels / verdicts are absent or
// arrays and offer_set absent or an object; policy an object whose world / provenance are absent or objects and
// classifiers absent or an array (artifacts nil = absent).
func intentWBContextError(is map[string]any, artifacts any, policy any) string {
	if is == nil {
		return "intent_session must be an object"
	}
	if artifacts != nil {
		a, ok := artifacts.(map[string]any)
		if !ok {
			return "artifacts must be an object"
		}
		if m := closedMembersMsg(a, "artifacts", nil, "facts", "labels", "verdicts", "offer_set"); m != "" {
			return m
		}
		for _, k := range []string{"facts", "labels", "verdicts"} {
			if v, has := a[k]; !optArr(v, has) {
				return "artifacts." + k + " must be an array"
			}
		}
		if v, has := a["offer_set"]; !optObj(v, has) {
			return "artifacts.offer_set must be an object"
		}
	}
	p, ok := policy.(map[string]any)
	if !ok {
		return "policy must be an object"
	}
	if m := closedMembersMsg(p, "policy", nil, "world", "provenance", "classifiers"); m != "" {
		return m
	}
	for _, k := range []string{"world", "provenance"} {
		if v, has := p[k]; !optObj(v, has) {
			return "policy." + k + " must be an object"
		}
	}
	if v, has := p["classifiers"]; !optArr(v, has) {
		return "policy.classifiers must be an array"
	}
	return ""
}

// ---- the W-B unit (intent-env.ts decideIntentWB) ----------------------------------------------------------------

type wbResult struct {
	skip    bool
	checks  map[string]string // pass | question | fail
	reason  string
	outcome string
	env     map[string]any // the predicate env members the unit computed: world, prov, class (authorize)
}

func decideIntentWB(now float64, aud string, session string, action map[string]any, is map[string]any, artifacts any, policy any) wbResult {
	out := wbResult{checks: map[string]string{}, outcome: "admit", env: map[string]any{}}
	if ce := intentWBContextError(is, artifacts, policy); ce != "" {
		out.checks["facts"] = "fail"
		out.reason = "facts: the W-B context is malformed: " + ce
		out.outcome = "deny"
		return out
	}
	world, worldP := member(policy, "world")
	if !worldP {
		world = map[string]any{}
	}
	art := func(k string) (any, bool) {
		if artifacts == nil {
			return nil, false
		}
		return member(artifacts, k)
	}
	facts, factsP := is["facts"]
	offer, offerP := is["offer_set"]
	if intentWorldActive(facts, offer, world) {
		af, afP := art("facts")
		ao, aoP := art("offer_set")
		w := decideIntentWorld(jsNumber(now), aud, session, action, facts, factsP, offer, offerP, af, afP, ao, aoP, world, true)
		if !w.ok {
			out.checks["facts"] = "fail"
			out.reason = w.reason
			out.outcome = "deny"
			return out
		}
		out.checks["facts"] = "pass"
		out.env["world"] = w.world
	}
	prov, provP := is["prov"]
	labels, labelsP := is["labels"]
	provPol, provPolP := member(policy, "provenance")
	if intentProvenanceActive(provP, labels, provPol) {
		pol := provPol
		if !provPolP {
			pol = map[string]any{"params": map[string]any{}}
		}
		al, alP := art("labels")
		p := decideParamProvenance(aud, session, action, prov, provP, labels, labelsP, al, alP, pol)
		if p.outcome == "deny" {
			out.checks["provenance"] = "fail"
			out.reason = p.reason
			out.outcome = "deny"
			return out
		}
		out.env["prov"] = p.env
		if p.outcome == "question" {
			out.checks["provenance"] = "question"
			out.outcome = "question"
			out.reason = p.reason
		} else {
			out.checks["provenance"] = "pass"
		}
	}
	clsV, clsP := member(policy, "classifiers")
	committed, cP := is["classes"]
	if classifierCheckActive(committed, clsV) {
		if !clsP {
			clsV = []any{}
		}
		av, avP := art("verdicts")
		c := decideClassifierDimensions(session, action, committed, cP, av, avP, map[string]any{"classifiers": clsV})
		if !c.ok {
			out.checks["classes"] = "fail"
			out.reason = c.reason
			out.outcome = "deny"
			return out
		}
		out.checks["classes"] = "pass"
		out.env["class"] = c.classes
	}
	return out
}

// ---- conformance primitives ------------------------------------------------------------------------------------

// IntentWorldPrimitive runs primitives.intent_world (rule 16) on its `input`; it returns {ok} and, when ok, {world,
// single_source}.
// The second result is the refusal reason (conformance `expect.reason_contains`).
func IntentWorldPrimitive(input any) (map[string]any, string) {
	in, isMap := normalizeJSON(input).(map[string]any)
	if !isMap {
		return map[string]any{"ok": false}, "facts: input must be an object"
	}
	action, _ := in["action"].(map[string]any)
	committed, _ := in["committed"].(map[string]any)
	if _, has := in["committed"]; has && committed == nil {
		return map[string]any{"ok": false}, "facts: committed must be an object"
	}
	cf, cfP := committed["facts"]
	co, coP := committed["offer_set"]
	f, fP := in["facts"]
	o, oP := in["offer_set"]
	pol, polP := in["policy"]
	now, nowP := in["now"]
	if !nowP {
		now = nil
	}
	w := decideIntentWorld(now, in["aud"], in["session"], action, cf, cfP, co, coP, f, fP, o, oP, pol, polP)
	if !w.ok {
		return map[string]any{"ok": false}, w.reason
	}
	ss := make([]any, len(w.singleSource))
	for i, s := range w.singleSource {
		ss[i] = s
	}
	return map[string]any{"ok": true, "world": w.world, "single_source": ss}, ""
}

// IntentProvenancePrimitive runs primitives.intent_provenance (rule 17): {outcome} and, unless deny, {labels,
// classes} and (question) {friction}.
// The second result is the refusal reason (conformance `expect.reason_contains`).
func IntentProvenancePrimitive(input any) (map[string]any, string) {
	in, inMap := normalizeJSON(input).(map[string]any)
	if !inMap {
		return map[string]any{"outcome": "deny"}, "provenance: input must be an object"
	}
	action, isMap := in["action"].(map[string]any)
	if !isMap {
		return map[string]any{"outcome": "deny"}, "provenance: action must be an object"
	}
	prov, provP := in["prov"]
	cl, clP := in["committed_labels"]
	l, lP := in["labels"]
	pol := in["policy"]
	d := decideParamProvenance(in["aud"], in["session"], action, prov, provP, cl, clP, l, lP, pol)
	out := map[string]any{"outcome": d.outcome}
	if d.outcome != "deny" {
		out["labels"] = d.labels
		out["classes"] = d.classes
	}
	if d.outcome == "question" {
		out["friction"] = d.friction
	}
	return out, d.reason
}

// IntentClassifierPrimitive runs primitives.intent_classifier (rule 18): {ok} and, when ok, {classes}.
// The second result is the refusal reason (conformance `expect.reason_contains`).
func IntentClassifierPrimitive(input any) (map[string]any, string) {
	in, isMap := normalizeJSON(input).(map[string]any)
	if !isMap {
		return map[string]any{"ok": false}, "classes: input must be an object"
	}
	action, _ := in["action"].(map[string]any)
	c, cP := in["committed"]
	v, vP := in["verdicts"]
	d := decideClassifierDimensions(in["session"], action, c, cP, v, vP, in["policy"])
	if !d.ok {
		return map[string]any{"ok": false}, d.reason
	}
	return map[string]any{"ok": true, "classes": d.classes}, ""
}

// IntentSchemaPrimitive runs primitives.intent_schema (rule 14 alone) on {schema, keys, verb, params}: {sig, digest?
// (when sig), conform: {ok, code?, path?}}.
func IntentSchemaPrimitive(input any) map[string]any {
	in, _ := normalizeJSON(input).(map[string]any)
	sig := verifyActionSchema(in["schema"], in["keys"])
	out := map[string]any{"sig": sig}
	if sig {
		if d, ok := actionSchemaDigest(in["schema"]); ok {
			out["digest"] = d
		}
	}
	verb, _ := in["verb"].(string)
	c := conformAction(in["schema"], verb, in["params"])
	conf := map[string]any{"ok": c.OK}
	if !c.OK {
		conf["code"] = c.Code
		if c.Path != "" {
			conf["path"] = c.Path
		}
	}
	out["conform"] = conf
	return out
}

// audText is String(input.aud): the verifier audience is absent (undefined) as a nil Go value.
func audText(aud any) string {
	if aud == nil {
		return "undefined"
	}
	return jsValueString(aud)
}
