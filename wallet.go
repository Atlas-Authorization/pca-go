package pca

// The wallet side of the PCA Intent Layer v2: the principal-signed answer, friction tiers scaled by harm, cell coordinates over
// the wallet's own outcome space, the statistics behind the noise estimates, attention canaries and the approval-fatigue model.
// The trusted card and clarification planning are in wallet_card.go, risk-priced escalation in wallet_pricing.go, population
// priors in wallet_population.go, delivery in wallet_delivery.go and the question channel in wallet_channel.go.
//
// Values that cross the API from a JSON document are plain JSON (map[string]any, []any, string, bool, nil, json.Number); the
// functions follow the reference over hostile values (a reference throw is an error here).

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

const (
	// WalletAnswerSigDomain is the signature domain of a signed intent answer.
	WalletAnswerSigDomain = "atlas-pca/intent-obs/v2\x00"
	// WalletAnswerRefDomain is the content-address domain of a signed answer.
	WalletAnswerRefDomain = "atlas-pca/intent-answer-ref/v1"
	// WalletTypedDomain is the domain of a typed-value digest.
	WalletTypedDomain = "atlas-pca/intent-typed/v1"
	// WalletDeviceChallengeDomain is the domain of a device-tier WebAuthn challenge.
	WalletDeviceChallengeDomain = "atlas-pca/intent-device/v1"
	walletActionDomain          = "atlas-pca/intent-action/v1"
	// WalletMinHoldMs is the shortest hold that counts as a hold.
	WalletMinHoldMs = 2000
)

// WalletFrictionOrder is the friction tiers, weakest first.
var WalletFrictionOrder = []string{"tap", "hold", "typed", "device"}

// WalletProvenanceOrder is the provenance levels, most trusted first.
var WalletProvenanceOrder = []string{"trusted", "first_party", "tool", "web", "agent"}

// WalletFrictionThresholds are the default harm thresholds (hTap, hDevice).
var WalletFrictionThresholds = map[string]any{"hTap": jsNumber(5), "hDevice": jsNumber(100000)}

func walletIndexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

// ---- JSON-value helpers ----------------------------------------------------------------------------------------------------

func wN(i int) any { return jsNumber(float64(i)) }

// wNumEq is `is a number and == n`.
func wNumEq(v any, n float64) bool {
	f, ok := jsNum(v)
	return ok && f == n
}

func wIsFinite(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func wIsNegZero(v any) bool {
	f, ok := jsNum(v)
	return ok && f == 0 && math.Signbit(f)
}

// wPlain is JSON.parse(JSON.stringify(v)): -0 becomes 0, every number takes its canonical lexeme.
func wPlain(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = wPlain(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = wPlain(x)
		}
		return a
	}
	if f, ok := jsNum(v); ok {
		if f == 0 {
			return jsNumber(0)
		}
		return jsNumber(f)
	}
	return v
}

type walletEntry struct {
	k string
	v any
}

// wEntries is Object.entries of a JSON value (strings and arrays yield their indices; null throws).
func wEntries(v any) ([]walletEntry, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make([]walletEntry, 0, len(t))
		for _, k := range jsKeys(t) {
			out = append(out, walletEntry{k, t[k]})
		}
		return out, nil
	case []any:
		out := make([]walletEntry, len(t))
		for i, x := range t {
			out[i] = walletEntry{fmt.Sprint(i), x}
		}
		return out, nil
	case string:
		us := utf16Units(t)
		out := make([]walletEntry, len(us))
		for i, u := range us {
			out[i] = walletEntry{fmt.Sprint(i), string(rune(u))}
		}
		return out, nil
	case nil:
		return nil, errors.New("Cannot convert undefined or null to object")
	}
	return nil, nil
}

// wKeysOf is the member names a map has, in the reference's order.
func wKeysOf(m map[string]any) []string { return jsKeys(m) }

func wHas(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// ---- friction ------------------------------------------------------------------------------------------------------------------

// WalletIsFrictionTier is true for tap, hold, typed and device.
func WalletIsFrictionTier(x any) bool {
	s, ok := x.(string)
	return ok && walletIndexOf(WalletFrictionOrder, s) >= 0
}

// WalletFrictionRank is the rank of a tier, -1 for anything else.
func WalletFrictionRank(t any) int {
	s, ok := t.(string)
	if !ok {
		return -1
	}
	return walletIndexOf(WalletFrictionOrder, s)
}

// WalletMaxFriction is the strongest of the tiers ("tap" for none; an unknown tier never wins).
func WalletMaxFriction(ts ...any) string {
	best := "tap"
	for _, t := range ts {
		if WalletFrictionRank(t) > WalletFrictionRank(best) {
			best = t.(string)
		}
	}
	return best
}

// WalletSatisfiesTier is rank(given) >= rank(required).
func WalletSatisfiesTier(given, required any) bool {
	return WalletFrictionRank(given) >= WalletFrictionRank(required)
}

// WalletIsProvenanceLevel is true for a known provenance level.
func WalletIsProvenanceLevel(x any) bool {
	s, ok := x.(string)
	return ok && walletIndexOf(WalletProvenanceOrder, s) >= 0
}

// WalletWorstProvenance is the least trusted level of a set; "agent" for an empty or unknown set (fail closed). A value that is
// not iterable is refused.
func WalletWorstProvenance(levels any) (string, error) {
	best := -1
	switch t := levels.(type) {
	case []any:
		for _, lv := range t {
			if !WalletIsProvenanceLevel(lv) {
				return "agent", nil
			}
			if i := walletIndexOf(WalletProvenanceOrder, lv.(string)); i > best {
				best = i
			}
		}
	case string:
		if t != "" {
			return "agent", nil // no single character is a level
		}
	default:
		return "", errors.New("levels is not iterable")
	}
	if best < 0 {
		return "agent", nil
	}
	return WalletProvenanceOrder[best], nil
}

// WalletFrictionFor is the friction tier for an action: {tier, rules}. th overrides the default thresholds.
func WalletFrictionFor(inp map[string]any, th map[string]any) (map[string]any, error) {
	if th == nil {
		th = WalletFrictionThresholds
	}
	harm, hasHarm := inp["expectedHarm"]
	hf, isNum := jsNum(harm)
	if !hasHarm || !isNum || math.IsNaN(hf) || math.IsInf(hf, 0) || !(hf >= 0) {
		return map[string]any{"tier": "device", "rules": []any{"harm-unknown"}}, nil
	}
	rules := []any{}
	tier := "tap"
	raise := func(t any, why string) {
		if WalletFrictionRank(t) >= WalletFrictionRank(tier) {
			rules = append(rules, why)
		}
		tier = WalletMaxFriction(tier, t)
	}
	hTap, hDevice := jsF(th["hTap"]), jsF(th["hDevice"])
	rev := inp["reversibility"]
	if rev == "rate_limited" {
		raise("hold", "rate-limited")
	}
	if hf >= hTap {
		raise("hold", "harm>=h_tap")
	}
	if rev == "irreversible" {
		raise("typed", "irreversible")
	}
	tainted := false
	switch prov := inp["provenance"].(type) {
	case nil:
	case []any:
		for _, pv := range prov {
			if pv == nil {
				return nil, errors.New("Cannot read properties of null")
			}
			p, ok := pv.(map[string]any)
			if !ok || p["sensitivity"] != "critical" {
				continue
			}
			w, err := WalletWorstProvenance(p["levels"])
			if err != nil {
				return nil, err
			}
			if w == "web" || w == "agent" {
				tainted = true
				break
			}
		}
	case string:
	default:
		return nil, errors.New("provenance is not iterable")
	}
	if tainted {
		raise("typed", "tainted-critical")
	}
	if jsTruthy(inp["widensCriticalIdentity"]) && rev == "irreversible" {
		raise("device", "critical-irreversible")
	}
	if hf >= hDevice {
		raise("device", "harm>=h_device")
	}
	if jsTruthy(inp["singleSource"]) {
		r := WalletFrictionRank(tier) + 1
		if r > len(WalletFrictionOrder)-1 {
			r = len(WalletFrictionOrder) - 1
		}
		raise(WalletFrictionOrder[r], "single-source")
	}
	if wHas(inp, "siteMin") {
		raise(inp["siteMin"], "site-minimum")
	}
	return map[string]any{"tier": tier, "rules": rules}, nil
}

// ---- helpers (wire) ----------------------------------------------------------------------------------------------------------------

// WalletIsObj is true for a JSON object.
func WalletIsObj(v any) bool { _, ok := v.(map[string]any); return ok }

// WalletIsB64u32 is true for canonical base64url of 32 bytes.
func WalletIsB64u32(v any) bool { return b64uOK(v, 32) }

// WalletCoordsError is why cell coordinates are malformed ("" when well formed).
func WalletCoordsError(c any) string { return cellCoordsError(c) }

// WalletActionDigest is the action digest of an attempted action (what intent_required.action_digest and a JIT consent bind to).
func WalletActionDigest(a any) (string, error) {
	m, _ := a.(map[string]any)
	act := map[string]any{}
	for _, k := range []string{"verb", "resource", "reversibility_class"} {
		v, ok := m[k]
		if !ok {
			return "", errors.New("canonicalize: undefined")
		}
		act[k] = v
	}
	pd, err := ParamsDigest(m["params"])
	if err != nil {
		return "", err
	}
	act["params_digest"] = pd
	return HashCanonical(map[string]any{"d": walletActionDomain, "action": act})
}

// WalletActionValues is the default projection of an attempted action onto Omega paths: the resource and every scalar param.
func WalletActionValues(a any) (map[string]any, error) {
	m, _ := a.(map[string]any)
	values := map[string]any{}
	if res, ok := m["resource"]; ok {
		values["action.resource"] = res
	}
	ents, err := wEntries(m["params"])
	if err != nil {
		return nil, err
	}
	if _, has := m["params"]; !has {
		return nil, errors.New("Cannot convert undefined or null to object")
	}
	for _, e := range ents {
		if _, isStr := e.v.(string); isStr || wIsFinite(e.v) {
			values["action.params."+e.k] = e.v
		}
	}
	out := map[string]any{"values": values}
	if v, ok := m["verb"]; ok {
		out["verb"] = v
	}
	return out, nil
}

// ---- M6: the signed answer ---------------------------------------------------------------------------------------------------------------

var (
	walletAnsKeys = []string{"v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg", "sig"}
	walletUxKeys  = []string{"tier", "rendered_digest", "typed_digest", "hold_ms", "webauthn", "canary", "action_digest", "consent_for_action"}
	walletWaKeys  = []string{"credential_id", "authenticator_data", "client_data_json", "signature"}
)

func walletOnlyKeys(o map[string]any, allowed []string) string {
	for _, k := range wKeysOf(o) {
		if walletIndexOf(allowed, k) < 0 {
			return fmt.Sprintf("unknown member \"%s\"", k)
		}
	}
	return ""
}

func walletPartialError(p any) string {
	m, ok := p.(map[string]any)
	if !ok {
		return "partial.path must be a non-empty string"
	}
	if path, ok := m["path"].(string); !ok || len(path) == 0 {
		return "partial.path must be a non-empty string"
	}
	keys := []string{}
	for _, k := range wKeysOf(m) {
		if k != "path" {
			keys = append(keys, k)
		}
	}
	if len(keys) != 1 {
		return "partial must carry exactly one of upTo / from / except / notFor"
	}
	k := keys[0]
	v := m[k]
	if (k == "upTo" || k == "from") && !jsIsInt(v) {
		return fmt.Sprintf("partial.%s must be an integer", k)
	}
	if k == "except" {
		l, ok := v.([]any)
		good := ok && len(l) > 0
		for _, x := range l {
			good = good && jsIsInt(x)
		}
		if !good {
			return "partial.except must be a non-empty integer array"
		}
	}
	if k == "notFor" {
		l, ok := v.([]any)
		good := ok && len(l) > 0
		for _, x := range l {
			s, isS := x.(string)
			good = good && isS && len(s) > 0
		}
		if !good {
			return "partial.notFor must be a non-empty string array"
		}
	}
	if k != "upTo" && k != "from" && k != "except" && k != "notFor" {
		return fmt.Sprintf("unknown partial member \"%s\"", k)
	}
	return ""
}

// WalletAnswerShapeError is why a signed answer is malformed ("" when well formed).
func WalletAnswerShapeError(av any) string {
	a, ok := av.(map[string]any)
	if !ok {
		return "not an object"
	}
	if e := walletOnlyKeys(a, walletAnsKeys); e != "" {
		return e
	}
	if !wNumEq(a["v"], 2) || a["kind"] != "pca-intent-observation" {
		return "not a pca-intent-observation v2"
	}
	for _, k := range []string{"map_digest", "session", "signer"} {
		if !WalletIsB64u32(a[k]) {
			return k + " is not canonical base64url (32 bytes)"
		}
	}
	if qid, ok := a["question_id"].(string); !ok || !questionIDRe.MatchString(qid) {
		return "question_id must match [A-Za-z0-9_-]{1,64}"
	}
	if verb, ok := a["verb"].(string); !ok || len(verb) == 0 {
		return "verb must be a non-empty string"
	}
	if ce := WalletCoordsError(a["cell"]); ce != "" {
		return "cell: " + ce
	}
	if !(wNumEq(a["y"], 0) || wNumEq(a["y"], 1)) {
		return "y must be 0 or 1"
	}
	if _, has := a["partial"]; has {
		if pe := walletPartialError(a["partial"]); pe != "" {
			return pe
		}
		if !wNumEq(a["y"], 1) {
			return "a partial answer carries y = 1 (yes for the part)"
		}
	}
	if a["source"] != "elicitation" && a["source"] != "clarification" {
		return "source must be elicitation or clarification"
	}
	if obs := jsF(a["observed_at"]); !jsIsInt(a["observed_at"]) || obs < 0 {
		return "observed_at must be a non-negative safe integer"
	}
	if a["alg"] != "ed25519" {
		return "alg must be ed25519"
	}
	ux, ok := a["ux"].(map[string]any)
	if !ok {
		return "ux must be an object"
	}
	if e := walletOnlyKeys(ux, walletUxKeys); e != "" {
		return "ux: " + e
	}
	if !WalletIsFrictionTier(ux["tier"]) {
		return "ux.tier is not a friction tier"
	}
	if !WalletIsB64u32(ux["rendered_digest"]) {
		return "ux.rendered_digest is not canonical base64url (32 bytes)"
	}
	canary, isBool := ux["canary"].(bool)
	if !isBool {
		return "ux.canary must be a boolean"
	}
	if v, has := ux["typed_digest"]; has && !WalletIsB64u32(v) {
		return "ux.typed_digest is not canonical base64url (32 bytes)"
	}
	if v, has := ux["hold_ms"]; has && !(jsIsInt(v) && jsF(v) >= 0) {
		return "ux.hold_ms must be a non-negative integer"
	}
	if v, has := ux["action_digest"]; has && !WalletIsB64u32(v) {
		return "ux.action_digest is not canonical base64url (32 bytes)"
	}
	if v, has := ux["consent_for_action"]; has {
		if _, isB := v.(bool); !isB {
			return "ux.consent_for_action must be a boolean"
		}
	}
	consent := ux["consent_for_action"] == true
	_, hasPartial := a["partial"]
	if consent && (!wHas(ux, "action_digest") || !wNumEq(a["y"], 1) || hasPartial) {
		return "consent_for_action needs action_digest and a plain yes"
	}
	if consent && canary {
		return "a canary never consents to an action"
	}
	if wa, has := ux["webauthn"]; has {
		wm, ok := wa.(map[string]any)
		bad := !ok || walletOnlyKeys(wm, walletWaKeys) != ""
		if !bad {
			for _, k := range walletWaKeys {
				if _, isS := wm[k].(string); !isS {
					bad = true
				}
			}
		}
		if bad {
			return "ux.webauthn is malformed"
		}
	}
	if wNumEq(a["y"], 1) && !canary {
		switch ux["tier"] {
		case "hold":
			if !(jsIsInt(ux["hold_ms"]) && jsF(ux["hold_ms"]) >= WalletMinHoldMs) {
				return fmt.Sprintf("hold tier needs hold_ms >= %d", WalletMinHoldMs)
			}
		case "typed":
			if !wHas(ux, "typed_digest") {
				return "typed tier needs typed_digest"
			}
		case "device":
			if !wHas(ux, "webauthn") {
				return "device tier needs a WebAuthn assertion"
			}
		}
	}
	return ""
}

func walletAnswerBody(a map[string]any) any {
	body := map[string]any{}
	for _, k := range []string{"v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg"} {
		if v, ok := a[k]; ok {
			body[k] = v
		}
	}
	return wPlain(body)
}

func walletDomainMessage(domain string, body any) ([]byte, error) {
	b, err := canonBytes(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), b...), nil
}

// WalletSignIntentAnswer is the wallet side: it signs the principal's answer with the principal key (Ed25519, domain-separated,
// over the canonical body).
func WalletSignIntentAnswer(a map[string]any, principalSeed []byte) (map[string]any, error) {
	kp, err := KeyPairFromSeed(principalSeed)
	if err != nil {
		return nil, err
	}
	base := make(map[string]any, len(a)+4)
	for k, v := range a {
		base[k] = v
	}
	base["v"], base["kind"], base["signer"], base["alg"] = wN(2), "pca-intent-observation", kp.Public, "ed25519"
	body := walletAnswerBody(base).(map[string]any)
	if bad := WalletAnswerShapeError(body); bad != "" {
		return nil, errors.New("signIntentAnswer: " + bad)
	}
	msg, err := walletDomainMessage(WalletAnswerSigDomain, body)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(body)+1)
	for k, v := range body {
		out[k] = v
	}
	out["sig"] = b64.EncodeToString(kp.Sign(msg))
	return out, nil
}

// WalletVerifyIntentAnswer verifies a signed answer; principals (nil = any) restricts the signer to the keys named in the session
// root. It never errors: a failure is {ok: false, reason}.
func WalletVerifyIntentAnswer(av any, principals []string) map[string]any {
	no := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if bad := WalletAnswerShapeError(av); bad != "" {
		return no(bad)
	}
	a := av.(map[string]any)
	if principals != nil && walletIndexOf(principals, a["signer"].(string)) < 0 {
		return no("signer is not a principal of the session")
	}
	sig, ok := a["sig"].(string)
	if !ok {
		return no("bad signature")
	}
	msg, err := walletDomainMessage(WalletAnswerSigDomain, walletAnswerBody(a))
	if err != nil {
		return no("malformed answer: " + err.Error())
	}
	if !verifyB64u(a["signer"].(string), msg, sig) {
		return no("bad signature")
	}
	return map[string]any{"ok": true}
}

// WalletAnswerRef is the content address of a signed answer (evidence bundles and delta grants refer to it).
func WalletAnswerRef(a any) (string, error) {
	return HashCanonical(map[string]any{"d": WalletAnswerRefDomain, "a": a})
}

// WalletTypedDigest is the digest of what the human typed for a question.
func WalletTypedDigest(questionID, normalizedValue string) (string, error) {
	return HashCanonical(map[string]any{"d": WalletTypedDomain, "q": questionID, "v": normalizedValue})
}

// WalletDeviceChallenge is the 32-byte WebAuthn challenge of a device-tier answer: it binds the question, the card the human saw,
// y and the action (actionDigest nil = none).
func WalletDeviceChallenge(questionID, renderedDigest string, y int, actionDigest any) (string, error) {
	return HashCanonical(map[string]any{"d": WalletDeviceChallengeDomain, "q": questionID, "r": renderedDigest, "y": wN(y), "a": actionDigest})
}

// ---- cell coordinates <-> the wallet's own Omega ------------------------------------------------------------------------------------------

var (
	walletAccRe   = regexp.MustCompile(`^env\.acc\.([A-Za-z0-9_.-]+)\.post$`)
	walletMonRe   = regexp.MustCompile(`^env\.mon\.([A-Za-z0-9_.-]+)\.state$`)
	walletProvRe  = regexp.MustCompile(`^env\.prov\.([^\n\r\x{2028}\x{2029}]+)$`)
	walletWorldRe = regexp.MustCompile(`^env\.world\.([A-Za-z0-9_.-]+)$`)
)

// WalletCoordKeyOf is the short coordinate key of a dimension path.
func WalletCoordKeyOf(path string) string {
	if m := walletAccRe.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	if m := walletMonRe.FindStringSubmatch(path); m != nil {
		return "mon:" + m[1]
	}
	if m := walletProvRe.FindStringSubmatch(path); m != nil {
		return "prov:" + m[1]
	}
	if m := walletWorldRe.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	return path
}

// WalletResolved is the result of resolving coordinates: a box of cells of the verb's space, or a refusal.
type WalletResolved struct {
	OK     bool
	VS     *WalletVerb
	Box    [][]int
	Reason string
}

func walletIntegral(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f)
}

func walletJSONStr(s string) string {
	var sb strings.Builder
	lenientString(&sb, s)
	return sb.String()
}

// WalletResolveCoords resolves coordinates to a box of cells of the verb's space. Every dimension must be named exactly once;
// anything the wallet cannot resolve exactly is refused.
func WalletResolveCoords(om *WalletOmega, verb any, coords any) (WalletResolved, error) {
	vs := (*WalletVerb)(nil)
	if vstr, ok := verb.(string); ok {
		vs = om.Verb(vstr)
	}
	if vs == nil {
		return WalletResolved{Reason: fmt.Sprintf("verb %s is not in the wallet's outcome space", jsValueString(verb))}, nil
	}
	byKey := map[string]int{}
	for k := range vs.Dims {
		byKey[vs.Dims[k].Path] = k
		byKey[WalletCoordKeyOf(vs.Dims[k].Path)] = k
	}
	ents, err := wEntries(coords)
	if err != nil {
		return WalletResolved{}, err
	}
	named := map[int]bool{}
	for _, e := range ents {
		k, ok := byKey[e.k]
		if !ok {
			return WalletResolved{Reason: "unknown dimension " + e.k}, nil
		}
		if named[k] {
			return WalletResolved{Reason: "dimension " + vs.Dims[k].Path + " is named twice"}, nil
		}
		named[k] = true
	}
	cm, _ := coords.(map[string]any)
	box := make([][]int, 0, len(vs.Dims))
	for k := range vs.Dims {
		d := &vs.Dims[k]
		c, has := cm[d.Path]
		if !has || c == nil {
			c, has = cm[WalletCoordKeyOf(d.Path)]
		}
		if !has {
			return WalletResolved{Reason: "coordinates leave out dimension " + d.Path}, nil
		}
		if c == nil {
			return WalletResolved{}, errors.New("Cannot read properties of null")
		}
		if d.Kind == "num" {
			l, ok := c.([]any)
			if !ok || len(l) != 2 || !wIsNumber(l[0]) || !wIsNumber(l[1]) {
				return WalletResolved{Reason: "dimension " + d.Path + " is numeric: expected an index range"}, nil
			}
			lo, okLo := walletIntegral(l[0])
			hi, okHi := walletIntegral(l[1])
			if !(okLo && okHi && !wIsNegZero(l[0]) && !wIsNegZero(l[1]) && lo >= 0 && lo <= hi && hi < float64(len(WalletNumCells(d)))) {
				return WalletResolved{Reason: "index range of " + d.Path + " is out of range"}, nil
			}
			ids := []int{}
			for i := int(lo); i <= int(hi); i++ {
				ids = append(ids, i)
			}
			box = append(box, ids)
			continue
		}
		l, ok := c.([]any)
		if !ok {
			return WalletResolved{}, errors.New("c.every is not a function")
		}
		labels := make([]string, len(l))
		for i, x := range l {
			s, isS := x.(string)
			if !isS {
				return WalletResolved{Reason: "dimension " + d.Path + " is categorical: expected a value set"}, nil
			}
			labels[i] = s
		}
		set := map[int]bool{}
		for _, label := range labels {
			hits := []int{}
			for j, v := range d.Values {
				if v.Value == label {
					hits = append(hits, j)
				}
			}
			if len(hits) == 0 {
				return WalletResolved{Reason: fmt.Sprintf("unknown value %s for %s", walletJSONStr(label), d.Path)}, nil
			}
			if len(hits) > 1 {
				return WalletResolved{Reason: fmt.Sprintf("value %s names two cells of %s", walletJSONStr(label), d.Path)}, nil
			}
			set[hits[0]] = true
		}
		ids := make([]int, 0, len(set))
		for i := range set {
			ids = append(ids, i)
		}
		sort.Ints(ids)
		box = append(box, ids)
	}
	return WalletResolved{OK: true, VS: vs, Box: box}, nil
}

// wIsNumber is `is a number` (a JSON number lexeme).
func wIsNumber(v any) bool { _, ok := jsNum(v); return ok }

// WalletCoordsOfBox is the coordinates of a box (the inverse of resolving; numeric sides must be contiguous).
func WalletCoordsOfBox(vs *WalletVerb, box [][]int) (map[string]any, error) {
	out := map[string]any{}
	for k := range vs.Dims {
		d := &vs.Dims[k]
		if k >= len(box) || len(box[k]) == 0 {
			return nil, errors.New("coordsOfBox: empty side")
		}
		ids := box[k]
		if d.Kind == "num" {
			lo, hi := ids[0], ids[0]
			for _, i := range ids {
				if i < lo {
					lo = i
				}
				if i > hi {
					hi = i
				}
			}
			if hi-lo+1 != len(ids) {
				return nil, fmt.Errorf("coordsOfBox: numeric side of %s is not contiguous", d.Path)
			}
			out[d.Path] = []any{wN(lo), wN(hi)}
		} else {
			labels := make([]any, len(ids))
			for j, i := range ids {
				labels[j] = d.Values[i].Value
			}
			out[d.Path] = labels
		}
	}
	return out, nil
}

// WalletCoordsOfCell is the coordinates of a single cell.
func WalletCoordsOfCell(vs *WalletVerb, idx []int) (map[string]any, error) {
	box := make([][]int, len(idx))
	for i, x := range idx {
		box[i] = []int{x}
	}
	return WalletCoordsOfBox(vs, box)
}

// WalletCellInBox is true when the cell lies in the box.
func WalletCellInBox(box [][]int, idx []int) bool {
	if len(box) != len(idx) {
		return false
	}
	for k, ids := range box {
		in := false
		for _, i := range ids {
			if i == idx[k] {
				in = true
			}
		}
		if !in {
			return false
		}
	}
	return true
}

// WalletBoxCells lists the cells of a box (the first dimension varies slowest).
func WalletBoxCells(box [][]int) [][]int {
	out := [][]int{{}}
	for _, ids := range box {
		next := make([][]int, 0, len(out)*len(ids))
		for _, pre := range out {
			for _, i := range ids {
				c := append(append([]int{}, pre...), i)
				next = append(next, c)
			}
		}
		out = next
	}
	return out
}

// WalletBoxSize is the number of cells of a box.
func WalletBoxSize(box [][]int) int {
	n := 1
	for _, ids := range box {
		n *= len(ids)
	}
	return n
}

// WalletCellOfAction is the cell of a concrete action {verb, values} in the wallet's Omega; (nil, nil) when it falls outside it
// (fail closed).
func WalletCellOfAction(om *WalletOmega, a any) (*WalletVerb, []int, error) {
	if a == nil {
		return nil, nil, errors.New("Cannot read properties of null")
	}
	m, _ := a.(map[string]any)
	verb, _ := m["verb"].(string)
	var vs *WalletVerb
	if _, ok := m["verb"].(string); ok {
		vs = om.Verb(verb)
	}
	if vs == nil {
		return nil, nil, nil
	}
	values, has := m["values"]
	switch values.(type) {
	case map[string]any, []any:
	default:
		_ = has
		return nil, nil, errors.New("Cannot use 'in' operator")
	}
	vm, isMap := values.(map[string]any)
	for i := range vs.Dims {
		if !isMap || !wHas(vm, vs.Dims[i].Path) {
			return nil, nil, nil
		}
	}
	idx, ok := WalletCellOf(vs, values)
	if !ok {
		return nil, nil, nil
	}
	return vs, idx, nil
}

// WalletFlatIndex is the flat index of a cell.
func WalletFlatIndex(vs *WalletVerb, idx []int) int {
	f := 0
	for k := range vs.Dims {
		f = f*WalletCellCount(&vs.Dims[k]) + idx[k]
	}
	return f
}

// ---- stats -----------------------------------------------------------------------------------------------------------------------------

var walletLanczos = []float64{676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
	-0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7}

// WalletLnGamma is ln Gamma(x) (Lanczos).
func WalletLnGamma(x float64) float64 {
	if x < 0.5 {
		return math.Log(math.Pi/math.Sin(math.Pi*x)) - WalletLnGamma(1-x)
	}
	z := x - 1
	a := 0.99999999999980993
	t := z + 7.5
	for i := range walletLanczos {
		a += walletLanczos[i] / (z + float64(i) + 1)
	}
	return 0.5*math.Log(2*math.Pi) + (z+0.5)*math.Log(t) - t + math.Log(a)
}

// WalletBetacf is the continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300).
func WalletBetacf(a, b, x float64) float64 {
	const tiny = 1e-300
	qab, qap, qam := a+b, a+1, a-1
	c := 1.0
	d := 1 - (qab*x)/qap
	if math.Abs(d) < tiny {
		d = tiny
	}
	d = 1 / d
	h := d
	for m := 1; m <= 300; m++ {
		mf := float64(m)
		m2 := 2 * mf
		aa := (mf * (b - mf) * x) / ((qam + m2) * (a + m2))
		d = 1 + float64(aa*d)
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		h *= d * c
		aa = (-(a + mf) * (qab + mf) * x) / ((a + m2) * (qap + m2))
		d = 1 + float64(aa*d)
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		dl := d * c
		h *= dl
		if math.Abs(dl-1) < 1e-15 {
			break
		}
	}
	return h
}

// WalletBetaInc is the regularized incomplete beta I_x(a, b), a, b > 0, x in [0, 1].
func WalletBetaInc(x, a, b float64) (float64, error) {
	if !(a > 0 && b > 0) {
		return 0, errors.New("betaInc: a and b must be > 0")
	}
	if x <= 0 {
		return 0, nil
	}
	if x >= 1 {
		return 1, nil
	}
	lbt := WalletLnGamma(a+b) - WalletLnGamma(a) - WalletLnGamma(b) + a*math.Log(x) + b*math.Log(1-x)
	bt := math.Exp(lbt)
	if x < (a+1)/(a+b+2) {
		return (bt * WalletBetacf(a, b, x)) / a, nil
	}
	return 1 - (bt*WalletBetacf(b, a, 1-x))/b, nil
}

// WalletBetaQuantile is the q-quantile of Beta(a, b) by bisection (200 steps).
func WalletBetaQuantile(q, a, b float64) (float64, error) {
	if !(q >= 0 && q <= 1) {
		return 0, errors.New("betaQuantile: q must be in [0, 1]")
	}
	if q == 0 {
		return 0, nil
	}
	if q == 1 {
		return 1, nil
	}
	lo, hi := 0.0, 1.0
	for i := 0; i < 200; i++ {
		mid := (lo + hi) / 2
		v, err := WalletBetaInc(mid, a, b)
		if err != nil {
			return 0, err
		}
		if v < q {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi, nil
}

// WalletBinEnt is the binary entropy in bits.
func WalletBinEnt(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -(p*math.Log2(p) + (1-p)*math.Log2(1-p))
}

// ---- canaries --------------------------------------------------------------------------------------------------------------------------

// WalletNoiseCounts are the canary answer counts.
type WalletNoiseCounts struct {
	FalseYes   int `json:"falseYes"`
	CorrectNo  int `json:"correctNo"`
	FalseNo    int `json:"falseNo"`
	CorrectYes int `json:"correctYes"`
}

// WalletNoisePrior is the Beta prior of the noise estimates.
var WalletNoisePrior = struct{ A, B float64 }{1, 9}

// WalletRecordCanary folds one canary answer into the counts (pure).
func WalletRecordCanary(n WalletNoiseCounts, expected, y int) WalletNoiseCounts {
	if expected == 0 {
		if y == 1 {
			n.FalseYes++
		} else {
			n.CorrectNo++
		}
	} else if y == 0 {
		n.FalseNo++
	} else {
		n.CorrectYes++
	}
	return n
}

// WalletNoiseEstimate is the estimated false-yes / false-no rates.
type WalletNoiseEstimate struct {
	EtaPos      float64 `json:"etaPos"`
	EtaNeg      float64 `json:"etaNeg"`
	EtaPosUpper float64 `json:"etaPosUpper"`
	EtaNegUpper float64 `json:"etaNegUpper"`
	EtaPosCP    float64 `json:"etaPosCP"`
	EtaNegCP    float64 `json:"etaNegCP"`
	Asked       int     `json:"asked"`
}

// WalletEstimateNoise estimates the noise rates; deltaC is the confidence level (the reference default is 0.05).
func WalletEstimateNoise(n WalletNoiseCounts, deltaC float64) (WalletNoiseEstimate, error) {
	if !(deltaC > 0 && deltaC < 1) {
		return WalletNoiseEstimate{}, errors.New("estimateNoise: deltaC must be in (0, 1)")
	}
	ap := WalletNoisePrior.A + float64(n.FalseYes)
	bp := WalletNoisePrior.B + float64(n.CorrectNo)
	an := WalletNoisePrior.A + float64(n.FalseNo)
	bn := WalletNoisePrior.B + float64(n.CorrectYes)
	knownNo := n.FalseYes + n.CorrectNo
	knownYes := n.FalseNo + n.CorrectYes
	e := WalletNoiseEstimate{EtaPos: ap / (ap + bp), EtaNeg: an / (an + bn), Asked: knownNo + knownYes}
	var err error
	if e.EtaPosUpper, err = WalletBetaQuantile(1-deltaC, ap, bp); err != nil {
		return e, err
	}
	if e.EtaNegUpper, err = WalletBetaQuantile(1-deltaC, an, bn); err != nil {
		return e, err
	}
	e.EtaPosCP, e.EtaNegCP = 1, 1
	if knownNo != 0 {
		if e.EtaPosCP, err = ClopperPearsonUpper(float64(n.FalseYes), float64(knownNo), deltaC); err != nil {
			return e, err
		}
	}
	if knownYes != 0 {
		if e.EtaNegCP, err = ClopperPearsonUpper(float64(n.FalseNo), float64(knownYes), deltaC); err != nil {
			return e, err
		}
	}
	return e, nil
}

// WalletCellRef names a cell: a verb and its cell index.
type WalletCellRef struct {
	Verb string `json:"verb"`
	Idx  []int  `json:"idx"`
}

// WalletCellKey is the `verb|i,j,..` key of a cell.
func WalletCellKey(verb string, idx []int) string {
	parts := make([]string, len(idx))
	for i, x := range idx {
		parts[i] = fmt.Sprint(x)
	}
	return verb + "|" + strings.Join(parts, ",")
}

func walletSortUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool { return compareUnits(utf16Units(keys[i]), utf16Units(keys[j])) < 0 })
}

// WalletBoundaryNeighbours are the cells one step outside the confirmed region in exactly one dimension (deterministic order).
func WalletBoundaryNeighbours(om *WalletOmega, confirmed []WalletCellRef) ([]WalletCellRef, error) {
	inside := map[string]bool{}
	for _, c := range confirmed {
		inside[WalletCellKey(c.Verb, c.Idx)] = true
	}
	out := map[string]WalletCellRef{}
	for _, c := range confirmed {
		vs := om.Verb(c.Verb)
		if vs == nil {
			continue
		}
		if len(c.Idx) < len(vs.Dims) {
			return nil, errors.New("boundaryNeighbours: a cell index is too short")
		}
		for k := range vs.Dims {
			d := &vs.Dims[k]
			n := WalletCellCount(d)
			var alts []int
			if d.Kind == "num" {
				alts = []int{c.Idx[k] - 1, c.Idx[k] + 1}
			} else {
				for i := 0; i < n; i++ {
					alts = append(alts, i)
				}
			}
			for _, a := range alts {
				if a < 0 || a >= n || a == c.Idx[k] {
					continue
				}
				idx := append([]int{}, c.Idx...)
				idx[k] = a
				key := WalletCellKey(c.Verb, idx)
				if !inside[key] {
					out[key] = WalletCellRef{Verb: c.Verb, Idx: idx}
				}
			}
		}
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	walletSortUTF16(keys)
	res := make([]WalletCellRef, 0, len(keys))
	for _, k := range keys {
		res = append(res, out[k])
	}
	return res, nil
}

// WalletRand is the injected uniform [0, 1) source; it errors when exhausted (a scripted source).
type WalletRand func() (float64, error)

// WalletCanaryCtx is what pickCanary decides from. KnownNo returns "ceiling" | "veto" | "" for a cell.
type WalletCanaryCtx struct {
	Omega          *WalletOmega
	Confirmed      []WalletCellRef
	KnownNo        func(verb string, idx []int) string
	KnownYes       []WalletCellRef
	Exclude        map[string]bool
	Rand           WalletRand
	Rho            *float64 // nil = 0.1
	LowHarmSession bool
	CanariesSoFar  float64
}

// WalletCanary is a chosen canary: a cell whose answer the wallet already knows.
type WalletCanary struct {
	Verb     string `json:"verb"`
	Idx      []int  `json:"idx"`
	Expected int    `json:"expected"`
	Source   string `json:"source"`
}

// WalletPickCanary decides whether to insert a canary now, and which (nil: no canary this time).
func WalletPickCanary(ctx WalletCanaryCtx) (*WalletCanary, error) {
	rho := 0.1
	if ctx.Rho != nil {
		rho = *ctx.Rho
	}
	if !(rho >= 0 && rho <= 1) {
		return nil, errors.New("pickCanary: rho must be in [0, 1]")
	}
	if ctx.LowHarmSession && ctx.CanariesSoFar >= 1 {
		return nil, nil
	}
	r, err := ctx.Rand()
	if err != nil {
		return nil, err
	}
	if !(r < rho) {
		return nil, nil
	}
	var no, yes []WalletCanary
	nb, err := WalletBoundaryNeighbours(ctx.Omega, ctx.Confirmed)
	if err != nil {
		return nil, err
	}
	for _, c := range nb {
		if ctx.Exclude[WalletCellKey(c.Verb, c.Idx)] {
			continue
		}
		if why := ctx.KnownNo(c.Verb, c.Idx); why != "" {
			no = append(no, WalletCanary{c.Verb, c.Idx, 0, why})
		}
	}
	for _, c := range ctx.KnownYes {
		if !ctx.Exclude[WalletCellKey(c.Verb, c.Idx)] {
			yes = append(yes, WalletCanary{c.Verb, append([]int{}, c.Idx...), 1, "confirmed-yes"})
		}
	}
	if len(no) == 0 && len(yes) == 0 {
		return nil, nil
	}
	pool := no
	if len(no) > 0 && len(yes) > 0 {
		r2, err := ctx.Rand()
		if err != nil {
			return nil, err
		}
		if !(r2 < 0.5) {
			pool = yes
		}
	} else if len(no) == 0 {
		pool = yes
	}
	r3, err := ctx.Rand()
	if err != nil {
		return nil, err
	}
	i := int(math.Floor(r3 * float64(len(pool))))
	if i > len(pool)-1 {
		i = len(pool) - 1
	}
	c := pool[i]
	return &c, nil
}

// ---- approval fatigue --------------------------------------------------------------------------------------------------------------------

// WalletFatigue is the approval-fatigue model.
type WalletFatigue struct {
	BetaF           float64
	EtaStop         float64
	DeltaC          float64
	FreezeOn        string // "mean" | "upper"
	AssumeNoiseFree bool
	Delta           float64
}

// WalletDefaultFatigue is the reference's default model.
var WalletDefaultFatigue = WalletFatigue{BetaF: 0.005, EtaStop: 0.15, DeltaC: 0.05, FreezeOn: "mean", AssumeNoiseFree: false, Delta: 0.05}

const walletBelowHalf = 0.5 - 1e-9

// WalletEtaUnderLoad is eta+ under load: base + betaF * nRecent, capped at 1/2.
func WalletEtaUnderLoad(base, betaF, nRecent float64) (float64, error) {
	if !(base >= 0 && betaF >= 0 && nRecent == math.Trunc(nRecent) && !math.IsInf(nRecent, 0) && nRecent >= 0) {
		return 0, errors.New("etaUnderLoad: bad arguments")
	}
	return math.Min(0.5, base+betaF*nRecent), nil
}

// WalletNoiseState is the noise state used by the admission policy and the freeze.
type WalletNoiseState struct {
	EtaPos    float64 `json:"etaPos"`
	EtaPosBar float64 `json:"etaPosBar"`
	EtaNegBar float64 `json:"etaNegBar"`
	Frozen    bool    `json:"frozen"`
}

// WalletComputeNoiseState is the noise state for the counts and the number of recent questions.
func WalletComputeNoiseState(counts WalletNoiseCounts, nRecent float64, m WalletFatigue) (WalletNoiseState, error) {
	e, err := WalletEstimateNoise(counts, m.DeltaC)
	if err != nil {
		return WalletNoiseState{}, err
	}
	etaPos, err := WalletEtaUnderLoad(e.EtaPos, m.BetaF, nRecent)
	if err != nil {
		return WalletNoiseState{}, err
	}
	etaPosBar, err := WalletEtaUnderLoad(e.EtaPosUpper, m.BetaF, nRecent)
	if err != nil {
		return WalletNoiseState{}, err
	}
	stat := etaPosBar
	if m.FreezeOn == "mean" {
		stat = etaPos
	}
	return WalletNoiseState{EtaPos: etaPos, EtaPosBar: etaPosBar, EtaNegBar: math.Min(0.5, e.EtaNegUpper), Frozen: stat > m.EtaStop}, nil
}

// WalletAdmission is the admission policy the learner uses.
type WalletAdmission struct {
	Tau                       float64 `json:"tau"`
	EtaPos                    float64 `json:"etaPos"`
	EtaNeg                    float64 `json:"etaNeg"`
	DoubleConfirmIrreversible bool    `json:"doubleConfirmIrreversible"`
	FalseAdmitBound           float64 `json:"falseAdmitBound"`
}

// WalletAdmissionPolicy is the admission policy for a noise state.
func WalletAdmissionPolicy(s WalletNoiseState, m WalletFatigue) (WalletAdmission, error) {
	if m.AssumeNoiseFree {
		return WalletAdmission{Tau: 1}, nil
	}
	if !(m.Delta > 0 && m.Delta < 1) {
		return WalletAdmission{}, errors.New("admissionPolicy: delta must be in (0, 1)")
	}
	ep := math.Min(walletBelowHalf, s.EtaPosBar)
	en := math.Min(walletBelowHalf, s.EtaNegBar)
	return WalletAdmission{Tau: 1 - m.Delta, EtaPos: ep, EtaNeg: en, DoubleConfirmIrreversible: ep > 0, FalseAdmitBound: ep * ep}, nil
}

// WalletSlidingWindow is a sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an
// agent cannot split around it by opening sessions). It keeps only timestamps inside the window.
type WalletSlidingWindow struct {
	windowMs float64
	times    []float64
}

// NewWalletSlidingWindow builds a counter; windowMs must be a positive integer (3600000 is the reference default).
func NewWalletSlidingWindow(windowMs float64) (*WalletSlidingWindow, error) {
	if !(windowMs == math.Trunc(windowMs) && windowMs > 0 && !math.IsInf(windowMs, 0)) {
		return nil, errors.New("SlidingWindowCounter: windowMs must be a positive integer")
	}
	return &WalletSlidingWindow{windowMs: windowMs}, nil
}

func (w *WalletSlidingWindow) prune(now float64) {
	if !finite(now) { // an infinite clock must never forget a recorded event
		return
	}
	for len(w.times) > 0 && w.times[0] <= now-w.windowMs {
		w.times = w.times[1:]
	}
}

// Count is the number of events inside the window ending at now.
func (w *WalletSlidingWindow) Count(now float64) int {
	w.prune(now)
	return len(w.times)
}

// TryAdd records one event at now if the count is below cap; false (and nothing recorded) otherwise.
func (w *WalletSlidingWindow) TryAdd(now, limit float64) (bool, error) {
	w.prune(now)
	if !(float64(len(w.times)) < limit) {
		return false, nil
	}
	if len(w.times) > 0 && !(now >= w.times[len(w.times)-1]) {
		return false, errors.New("SlidingWindowCounter: time went backwards")
	}
	if !finite(now) { // an infinite clock records nothing
		return false, nil
	}
	w.times = append(w.times, now)
	return true, nil
}

// WalletConfirmation is one recorded "yes": the screen it was given on and its tier.
type WalletConfirmation struct {
	Screen float64
	Tier   string
}

// WalletDoubleConfirmed is true for two "yes" answers at typed or device tier, on different screens, with at least one other
// screen between them.
func WalletDoubleConfirmed(records []WalletConfirmation) bool {
	strong := []float64{}
	for _, r := range records {
		if r.Tier == "typed" || r.Tier == "device" {
			strong = append(strong, r.Screen)
		}
	}
	sort.Float64s(strong)
	for i := range strong {
		for j := i + 1; j < len(strong); j++ {
			if strong[j]-strong[i] >= 2 {
				return true
			}
		}
	}
	return false
}
