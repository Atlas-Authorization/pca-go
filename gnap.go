package pca

// GNAP (RFC 9635) bridge, the Agent-GNAP profile: GNAP access rights map onto policy-envelope predicates (namespace
// gnap:<type>:<location>), a grant request becomes a root grant (no parent) or an attenuated delegated hop recording its clamped
// rights as an append-only `gnap_access` caveat, the effective authority of a chain is the root envelope intersected with every
// hop's recorded rights, access tokens carry the chain itself, `jwsd` detached-JWS proofs bind requests to the holder key, and a
// continuation resolves through a threshold co-signature folded into the action's PCActn. Every verify path fails closed.
//
// Values are JSON values (map[string]any / []any / string / bool / json.Number), as the reference reads them; a member the
// reference reads off a non-object value is absent, and dereferencing JSON null is an error (the reference throws there).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// GnapError is a malformed request on an issuance path (the verify paths answer {ok:false} instead).
type GnapError struct{ Msg string }

func (e *GnapError) Error() string { return e.Msg }

func gnapErr(format string, a ...any) error { return &GnapError{fmt.Sprintf(format, a...)} }

const (
	// GnapGrantCaveat is the provenance caveat inside a ROOT GNAP grant's policy envelope.
	GnapGrantCaveat = "gnap_grant"
	// GnapAccessCaveat is the caveat appended on each DELEGATED GNAP hop (the rights that hop was granted).
	GnapAccessCaveat = "gnap_access"
	// GnapMaxDetachedJWSChars bounds an accepted detached JWS (UTF-16 code units).
	GnapMaxDetachedJWSChars = 8192
	gnapJwsdTyp             = "gnap-binding-jwsd"
)

// gnapGet is a JavaScript member read: (value, present). Reading a member of JSON null is an error, as in the reference.
func gnapGet(v any, k string) (any, bool, error) {
	switch t := v.(type) {
	case nil:
		return nil, false, fmt.Errorf("cannot read properties of null (reading '%s')", k)
	case map[string]any:
		x, ok := t[k]
		return x, ok, nil
	}
	return nil, false, nil
}

// gnapMember is gnapGet for a value already known not to be null (a missing member reads as absent).
func gnapMember(v any, k string) (any, bool) {
	m, _ := v.(map[string]any)
	x, ok := m[k]
	return x, ok
}

// gnapStrArr is the reference strArr: an array's string elements, or (nil, false) for a non-array.
func gnapStrArr(u any) ([]any, bool) {
	l, ok := u.([]any)
	if !ok {
		return nil, false
	}
	out := []any{}
	for _, x := range l {
		if _, s := x.(string); s {
			out = append(out, x)
		}
	}
	return out, true
}

func gnapAsEd25519(x any) (string, bool) {
	s, ok := x.(string)
	if !ok {
		return "", false
	}
	_, ok = DecodeB64uStrict(s, 32)
	return s, ok
}

// GnapActionResource is the predicate resource for a GNAP (type, location) pair.
func GnapActionResource(typ, location string) string { return "gnap:" + typ + ":" + location }

// ---- access rights ------------------------------------------------------------------------------------------------------------

func gnapTryNormalizeAccessItem(item any) map[string]any {
	if s, ok := item.(string); ok {
		if s == "" {
			return nil
		}
		return map[string]any{"type": s}
	}
	m, ok := item.(map[string]any)
	if !ok {
		return nil
	}
	typ, ok := m["type"].(string)
	if !ok || typ == "" {
		return nil
	}
	out := map[string]any{"type": typ}
	for _, k := range []string{"actions", "locations", "datatypes"} {
		if l, ok := gnapStrArr(m[k]); ok && len(l) > 0 {
			out[k] = l
		}
	}
	if id, ok := m["identifier"].(string); ok {
		out["identifier"] = id
	}
	if l, ok := gnapStrArr(m["privileges"]); ok && len(l) > 0 {
		out["privileges"] = l
	}
	return out
}

// GnapNormalizeAccess normalizes an access array for issuance, refusing any malformed entry.
func GnapNormalizeAccess(items any) ([]any, error) {
	l, ok := items.([]any)
	if !ok {
		return nil, gnapErr("access must be an array")
	}
	out := make([]any, 0, len(l))
	for _, it := range l {
		n := gnapTryNormalizeAccessItem(it)
		if n == nil {
			return nil, gnapErr("malformed access item (needs a non-empty string `type`)")
		}
		out = append(out, n)
	}
	return out, nil
}

// gnapReadAccessArray reads a stored (signed) access array, skipping malformed entries.
func gnapReadAccessArray(u any) []any {
	out := []any{}
	l, _ := u.([]any)
	for _, it := range l {
		if n := gnapTryNormalizeAccessItem(it); n != nil {
			out = append(out, n)
		}
	}
	return out
}

func gnapList(m map[string]any, k string) ([]any, bool) {
	l, ok := m[k].([]any)
	return l, ok && len(l) > 0
}

// GnapAccessToPredicates maps one access right onto predicates (one per location): actions -> verb (absent: "*"), locations ->
// resource (absent: "*"), datatypes / identifier -> `where` conditions on action.params.
func GnapAccessToPredicates(access map[string]any) []any {
	var verb any = "*"
	if a, ok := gnapList(access, "actions"); ok {
		verb = append([]any{}, a...)
	}
	locations := []any{"*"}
	if l, ok := gnapList(access, "locations"); ok {
		locations = l
	}
	var where []map[string]any
	if d, ok := gnapList(access, "datatypes"); ok {
		where = append(where, map[string]any{"field": "action.params.datatype", "op": "in", "value": append([]any{}, d...)})
	}
	if id, ok := access["identifier"].(string); ok {
		where = append(where, map[string]any{"field": "action.params.identifier", "op": "eq", "value": id})
	}
	typ, _ := access["type"].(string)
	out := make([]any, 0, len(locations))
	for _, loc := range locations {
		p := map[string]any{"verb": verb, "resource": GnapActionResource(typ, jsValueString(loc))}
		if len(where) > 0 {
			w := make([]any, len(where))
			for i, c := range where {
				w[i] = copyMap(c)
			}
			p["where"] = w
		}
		out = append(out, p)
	}
	return out
}

func gnapAccessArrayToPredicates(access []any) []any {
	out := []any{}
	for _, a := range access {
		m, _ := a.(map[string]any)
		out = append(out, GnapAccessToPredicates(m)...)
	}
	return out
}

func gnapIncludes(l []any, s any) bool {
	for _, x := range l {
		if jsStrictEq(x, s) {
			return true
		}
	}
	return false
}

func gnapCoversStrings(g, r map[string]any, k string) bool {
	sup, hasSup := g[k]
	if !hasSup {
		return true // the issuer allows all
	}
	sub, hasSub := r[k]
	if !hasSub {
		return false // the request wants all, the issuer has a concrete set
	}
	supL, _ := sup.([]any)
	subL, _ := sub.([]any)
	for _, s := range subL {
		if !gnapIncludes(supL, s) {
			return false
		}
	}
	return true
}

func gnapCoversLocations(g, r map[string]any) bool {
	sup, hasSup := g["locations"]
	if !hasSup {
		return true
	}
	supL, _ := sup.([]any)
	sub, hasSub := r["locations"]
	if !hasSub {
		return gnapIncludes(supL, "*")
	}
	subL, _ := sub.([]any)
	for _, sv := range subL {
		s, _ := sv.(string)
		hit := false
		for _, gv := range supL {
			gs, _ := gv.(string)
			if jsStrictEq(gv, sv) || gs == "*" || strings.HasSuffix(gs, "*") && strings.HasPrefix(s, gs[:len(gs)-1]) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// GnapAccessContains reports whether the issuer's right g fully contains the requested right r.
func GnapAccessContains(g, r map[string]any) bool {
	if !jsStrictEq(g["type"], r["type"]) {
		return false
	}
	if !gnapCoversStrings(g, r, "actions") || !gnapCoversLocations(g, r) || !gnapCoversStrings(g, r, "datatypes") {
		return false
	}
	ri, hasR := r["identifier"]
	gi, hasG := g["identifier"]
	return !(hasR && hasG && !jsStrictEq(gi, ri))
}

// GnapAccessWithin reports whether r is covered by at least one right of the granted set.
func GnapAccessWithin(granted []any, r map[string]any) bool {
	for _, g := range granted {
		gm, _ := g.(map[string]any)
		if GnapAccessContains(gm, r) {
			return true
		}
	}
	return false
}

// GnapClampAccess splits a requested access array into the part within the issuer's authority and the rest.
func GnapClampAccess(issuerGranted, requested []any) (granted, dropped []any) {
	granted, dropped = []any{}, []any{}
	for _, r := range requested {
		rm, _ := r.(map[string]any)
		if GnapAccessWithin(issuerGranted, rm) {
			granted = append(granted, r)
		} else {
			dropped = append(dropped, r)
		}
	}
	return granted, dropped
}

// ---- provenance + granted access --------------------------------------------------------------------------------------------

func gnapReadGrant(root any) map[string]any {
	env := ReadEnvelope(root)
	if env == nil {
		return nil
	}
	cs, _ := env["caveats"].([]any)
	for _, c := range cs {
		cv, _ := c.(map[string]any)
		if cv == nil || cv["type"] != GnapGrantCaveat {
			continue
		}
		clientID, ok1 := cv["client_id"].(string)
		digest, ok2 := cv["request_digest"].(string)
		if !ok1 || !ok2 {
			return nil
		}
		ts := any(jsNumber(0))
		if f, ok := cv["ts"].(json.Number); ok {
			ts = f
		}
		return map[string]any{"type": GnapGrantCaveat, "client_id": clientID, "granted_access": gnapReadAccessArray(cv["granted_access"]),
			"request_digest": digest, "interacted": cv["interacted"] == true, "ts": ts}
	}
	return nil
}

// GnapGrantedAccessOf is the effective granted access of a chain: the leaf's most recent gnap_access caveat, or (root only) the
// root grant's recorded rights. A null hop where the reference dereferences one is an error.
func GnapGrantedAccessOf(chain any) ([]any, error) {
	l, ok := chain.([]any)
	if !ok || len(l) == 0 {
		return []any{}, nil
	}
	cv, _, err := gnapGet(l[len(l)-1], "caveats")
	if err != nil {
		return nil, err
	}
	caveats, _ := cv.([]any)
	for i := len(caveats) - 1; i >= 0; i-- {
		c := caveats[i]
		if t, _ := gnapMember(c, "type"); t == GnapAccessCaveat {
			a, _ := gnapMember(c, "access")
			return gnapReadAccessArray(a), nil
		}
	}
	if g := gnapReadGrant(l[0]); g != nil {
		return g["granted_access"].([]any), nil
	}
	return []any{}, nil
}

// ---- holders ------------------------------------------------------------------------------------------------------------------

// GnapResolveHolder resolves the base64url Ed25519 holder key from the request's client key, or from the override when one is
// passed (any value: a non-key override is refused, as is a declared key proof method other than jwsd).
func GnapResolveHolder(req any, override ...any) (string, error) {
	client, _, err := gnapGet(req, "client")
	if err != nil {
		return "", err
	}
	var declared any
	if _, isStr := client.(string); client != nil && !isStr {
		declared, _ = gnapMember(client, "key")
	}
	if _, isObj := declared.(map[string]any); isObj || isArray(declared) {
		proof, _ := gnapMember(declared, "proof")
		var method any
		switch p := proof.(type) {
		case string:
			method = p
		case map[string]any:
			method = p["method"]
		}
		if method != "jwsd" {
			name := "none"
			if s, ok := method.(string); ok {
				name = s
			}
			return "", gnapErr("unsupported client key proof method: %s (only jwsd is supported)", name)
		}
	}
	if len(override) > 0 {
		h, ok := gnapAsEd25519(override[0])
		if !ok {
			return "", gnapErr("holder override is not a canonical base64url Ed25519 public key")
		}
		return h, nil
	}
	if key, ok := declared.(map[string]any); ok {
		if jwk, ok := key["jwk"].(map[string]any); ok && jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" {
			if x, ok := gnapAsEd25519(jwk["x"]); ok {
				return x, nil
			}
		}
	}
	return "", gnapErr("cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override")
}

func isArray(v any) bool { _, ok := v.([]any); return ok }

// GnapHolderJwk renders a holder key as a GNAP JWK.
func GnapHolderJwk(holder string) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": holder, "use": "sig", "alg": "EdDSA"}
}

func gnapAccessOf(req any) (any, error) {
	at, _ := gnapMember(req, "access_token")
	if m, ok := at.(map[string]any); ok {
		if a, ok := m["access"].([]any); ok {
			return a, nil
		}
	}
	return nil, gnapErr("grant request must carry access_token.access (single-token request)")
}

func gnapRequestDigest(holder string, granted []any, interact any, has bool) (string, error) {
	if !has {
		interact = nil
	}
	return HashCanonical(map[string]any{"d": "atlas-pca/gnap/request/v1", "client_id": holder, "access": granted, "interact": interact})
}

// ---- grant request -> capability --------------------------------------------------------------------------------------------

// GnapGrantOptions configure GnapGrantRequestToCapability. Parent nil (or any falsy value) mints a root grant; otherwise the
// hop is delegated from it (a non-capability parent is refused).
type GnapGrantOptions struct {
	IssuerSecret *KeyPair // the principal (root) or the parent holder's key (delegation)
	IssuerPublic string   // root only
	Parent       any
	IssuerChain  []any // default [Parent]
	NoClamp      bool  // keep requested rights beyond the issuer (default: drop them)
	Holder       any   // explicit holder override (nil: from the request's client key)
	HasHolder    bool
	Interacted   bool
	NowMs        int64 // 0: the wall clock
	Goal         string
	RiskPolicy   map[string]any // nil: DefaultRiskPolicy()
	AgentBinding map[string]any // nil: {}
	Salt         string         // "" draws a random salt
}

// GnapGrantResult is the issued hop, the full chain, the holder and the granted / dropped rights with the provenance caveat.
type GnapGrantResult struct {
	Grant         map[string]any `json:"grant"`
	Chain         []any          `json:"chain"`
	Holder        string         `json:"holder"`
	GrantedAccess []any          `json:"grantedAccess"`
	DroppedAccess []any          `json:"droppedAccess"`
	Provenance    map[string]any `json:"provenance"`
}

// GnapGrantRequestToCapability converts a GNAP grant request into a capability bound to the client key, never wider than the
// issuer: a root grant whose envelope predicates ARE the requested rights, or a delegated hop with a gnap_access caveat.
func GnapGrantRequestToCapability(req any, o GnapGrantOptions) (*GnapGrantResult, error) {
	var holder string
	var err error
	if o.HasHolder {
		holder, err = GnapResolveHolder(req, o.Holder)
	} else {
		holder, err = GnapResolveHolder(req)
	}
	if err != nil {
		return nil, err
	}
	acc, err := gnapAccessOf(req)
	if err != nil {
		return nil, err
	}
	requested, err := GnapNormalizeAccess(acc)
	if err != nil {
		return nil, err
	}
	now := o.NowMs
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	delegated := jsTruthy(o.Parent)
	granted, dropped := requested, []any{}
	issuerChain := o.IssuerChain
	if delegated && issuerChain == nil {
		issuerChain = []any{o.Parent}
	}
	if delegated && !o.NoClamp {
		g, err := GnapGrantedAccessOf(issuerChain)
		if err != nil {
			return nil, err
		}
		granted, dropped = GnapClampAccess(g, requested)
	}
	interact, hasInteract := gnapMember(req, "interact")
	digest, err := gnapRequestDigest(holder, granted, interact, hasInteract)
	if err != nil {
		return nil, err
	}
	if o.IssuerSecret == nil {
		return nil, errors.New("signWithSuite: 'ed25519' requires edSecret")
	}
	if delegated {
		parent, ok := o.Parent.(map[string]any)
		if !ok {
			return nil, gnapErr("parent is not a capability")
		}
		prov := map[string]any{"type": GnapAccessCaveat, "access": granted, "predicates": gnapAccessArrayToPredicates(granted),
			"request_digest": digest, "client_id": holder, "ts": jsNumber(float64(now))}
		child, err := Delegate(parent, o.IssuerSecret, holder, []any{prov}, "", nil)
		if err != nil {
			return nil, err
		}
		return &GnapGrantResult{child, append(append([]any{}, issuerChain...), child), holder, granted, dropped, prov}, nil
	}
	prov := map[string]any{"type": GnapGrantCaveat, "client_id": holder, "granted_access": granted, "request_digest": digest,
		"interacted": o.Interacted, "ts": jsNumber(float64(now))}
	goal := o.Goal
	if goal == "" {
		goal = "gnap:grant:" + holder
	}
	rp := o.RiskPolicy
	if rp == nil {
		rp = DefaultRiskPolicy()
	}
	ab := o.AgentBinding
	if ab == nil {
		ab = map[string]any{}
	}
	env := map[string]any{"predicates": gnapAccessArrayToPredicates(granted), "caveats": []any{prov}, "agent_binding": ab, "risk_policy": rp}
	issuer := o.IssuerSecret
	if o.IssuerPublic != "" && o.IssuerPublic != issuer.Public {
		return nil, gnapErr("issuerPublic is not the public key of issuerSecret")
	}
	m, err := MintGrant(issuer, holder, env, goal, o.Salt, "", nil)
	if err != nil {
		return nil, err
	}
	return &GnapGrantResult{m.Grant, []any{m.Grant}, holder, granted, dropped, prov}, nil
}

// ---- action authorization -----------------------------------------------------------------------------------------------------

// GnapVerifyOptions pin the chain's root: ExpectedRootIssuer (nil: any root) and the verifier-side PQ pins by Ed25519 identity.
type GnapVerifyOptions struct {
	ExpectedRootIssuer *string
	PqPins             map[string]string
}

func (o GnapVerifyOptions) verify(chain []any) (string, bool) {
	exp, has := "", o.ExpectedRootIssuer != nil
	if has {
		exp = *o.ExpectedRootIssuer
	}
	return VerifyChainPolicy(chain, exp, has, nil, o.PqPins, nil)
}

// GnapAuthorizeAction decides whether action ({verb, resource, params?, reversibility_class?}) is authorized by a GNAP-issued
// chain: the chain verifies, the root envelope permits the action, and every gnap_access caveat of the leaf permits it too.
// Returns {allowed, reason?}; fails closed.
func GnapAuthorizeAction(chain any, action any, o GnapVerifyOptions) (map[string]any, error) {
	deny := func(r string) (map[string]any, error) { return map[string]any{"allowed": false, "reason": r}, nil }
	l, ok := chain.([]any)
	if !ok || len(l) == 0 {
		return deny("empty chain")
	}
	if why, ok := o.verify(l); !ok {
		return deny("capability chain invalid: " + why)
	}
	env := ReadEnvelope(l[0])
	if env == nil {
		return deny("root grant carries no policy envelope")
	}
	a := map[string]any{}
	for _, k := range []string{"verb", "resource"} {
		v, has, err := gnapGet(action, k)
		if err != nil {
			return nil, err
		}
		if has {
			a[k] = v
		}
	}
	for _, k := range []string{"params", "reversibility_class"} {
		if v, has := gnapMember(action, k); has {
			a[k] = v
		}
	}
	ctx := map[string]any{"action": a}
	if ok, why := envelopePredicates(env["predicates"], ctx, &regexBudget{}); !ok {
		return deny("root authority denies: " + why)
	}
	leaf, _ := l[len(l)-1].(map[string]any)
	caveats, _ := leaf["caveats"].([]any)
	for _, c := range caveats {
		if t, _ := gnapMember(c, "type"); t != GnapAccessCaveat {
			continue
		}
		acc, _ := gnapMember(c, "access")
		if ok, why := envelopePredicates(gnapAccessArrayToPredicates(gnapReadAccessArray(acc)), ctx, &regexBudget{}); !ok {
			return deny("delegated hop denies: " + why)
		}
	}
	return map[string]any{"allowed": true}, nil
}

// ---- bound token -------------------------------------------------------------------------------------------------------------

var gnapCapOrder = []string{"id", "issuer", "holder", "caveats", "body_digest", "sig", "parent", "holder_pq", "alg", "pq_pk", "pq_sig"}

// gnapStringify is JSON.stringify of a capability chain as the reference holds it: a capability's members in the order the
// reference creates them (any other member after, sorted), every other object (canonical caveats) sorted.
// shortcut: member order of an object that is not a capability is not kept (Go maps carry none); a caller-built chain with
// unsorted non-capability objects encodes differently from the reference. Tokens from GnapGrantRequestToCapability are exact.
func gnapStringify(sb *strings.Builder, v any, capLevel bool) error {
	m, ok := v.(map[string]any)
	if !ok {
		if l, isL := v.([]any); isL {
			sb.WriteByte('[')
			for i, x := range l {
				if i > 0 {
					sb.WriteByte(',')
				}
				if err := gnapStringify(sb, x, capLevel); err != nil {
					return err
				}
			}
			sb.WriteByte(']')
			return nil
		}
		s, ok := canonicalLenient(v)
		if !ok {
			return fmt.Errorf("encodeBoundToken: unserializable %T", v)
		}
		sb.WriteString(s)
		return nil
	}
	keys := sortedKeysUtf8(m)
	if capLevel {
		var ordered []string
		seen := map[string]bool{}
		for _, k := range gnapCapOrder {
			if _, has := m[k]; has {
				ordered, seen[k] = append(ordered, k), true
			}
		}
		for _, k := range keys {
			if !seen[k] {
				ordered = append(ordered, k)
			}
		}
		keys = ordered
	}
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		lenientString(sb, k)
		sb.WriteByte(':')
		if err := gnapStringify(sb, m[k], false); err != nil {
			return err
		}
	}
	sb.WriteByte('}')
	return nil
}

// GnapEncodeBoundToken encodes a capability chain as a GNAP access-token value: base64url(JSON of the chain).
func GnapEncodeBoundToken(chain []any) (string, error) {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, c := range chain {
		if i > 0 {
			sb.WriteByte(',')
		}
		if err := gnapStringify(&sb, c, true); err != nil {
			return "", err
		}
	}
	sb.WriteByte(']')
	return b64.EncodeToString([]byte(wellFormedUTF8(sb.String()))), nil
}

func gnapIsCapabilityShape(x any) bool {
	m, ok := x.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"id", "issuer", "holder", "body_digest", "sig"} {
		if _, ok := m[k].(string); !ok {
			return false
		}
	}
	if _, ok := m["caveats"].([]any); !ok {
		return false
	}
	for _, k := range []string{"parent", "alg", "pq_pk", "pq_sig"} {
		if v, has := m[k]; has {
			if _, ok := v.(string); !ok {
				return false
			}
		}
	}
	return true
}

func gnapDecodeBoundToken(value string) []any {
	raw, ok := DecodeB64uStrict(value, -1)
	if !ok || !utf8.Valid(raw) {
		return nil
	}
	parsed, err := StrictParse(strings.TrimPrefix(string(raw), "\uFEFF")) // the reference's text decoder drops a leading byte-order mark
	if err != nil {
		return nil
	}
	l, ok := parsed.([]any)
	if !ok {
		return nil
	}
	for _, hop := range l {
		if !gnapIsCapabilityShape(hop) {
			return nil
		}
	}
	return l
}

// GnapResponseOptions shape a grant response; a nil pointer member is absent.
type GnapResponseOptions struct {
	ExpiresIn  *int64
	Bearer     bool // emit the token as bearer (key:false) instead of key-bound
	InstanceID *string
	ManageURI  *string
	Continue   map[string]any
}

// GnapCapabilityToGrantResponse renders a capability chain as a GNAP grant response carrying a bound access token.
func GnapCapabilityToGrantResponse(chain any, o GnapResponseOptions) (map[string]any, error) {
	l, ok := chain.([]any)
	if !ok || len(l) == 0 {
		return nil, gnapErr("capabilityToGrantResponse: empty chain")
	}
	value, err := GnapEncodeBoundToken(l)
	if err != nil {
		return nil, err
	}
	access, err := GnapGrantedAccessOf(l)
	if err != nil {
		return nil, err
	}
	token := map[string]any{"value": value, "access": access}
	if o.Bearer {
		token["key"] = false
	} else {
		h, _, err := gnapGet(l[len(l)-1], "holder")
		if err != nil {
			return nil, err
		}
		hs, _ := h.(string)
		token["key"] = GnapHolderJwk(hs)
	}
	if o.ExpiresIn != nil {
		token["expires_in"] = jsNumber(float64(*o.ExpiresIn))
	}
	if o.ManageURI != nil {
		token["manage"] = map[string]any{"uri": *o.ManageURI}
	}
	out := map[string]any{"access_token": token}
	if o.Continue != nil {
		out["continue"] = o.Continue
	}
	if o.InstanceID != nil {
		out["instance_id"] = *o.InstanceID
	}
	return out, nil
}

// GnapVerifyToken verifies an incoming bound token: {ok:true, principal, capability, chain, access} or {ok:false, reason}.
func GnapVerifyToken(value any, o GnapVerifyOptions) map[string]any {
	fail := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	s, ok := value.(string)
	if !ok || s == "" {
		return fail("token value is empty")
	}
	chain := gnapDecodeBoundToken(s)
	if len(chain) == 0 {
		return fail("token is not a decodable PCA capability chain")
	}
	if why, ok := o.verify(chain); !ok {
		return fail("capability chain invalid: " + why)
	}
	access, _ := GnapGrantedAccessOf(chain) // every hop is an object here
	root, leaf := chain[0].(map[string]any), chain[len(chain)-1]
	return map[string]any{"ok": true, "principal": root["issuer"], "capability": leaf, "chain": chain, "access": access}
}

// ---- jwsd detached-JWS proofs ----------------------------------------------------------------------------------------------

type gnapNoContent struct{}

// GnapNoContent is the body of a request that carries no content (its jwsd payload is the empty byte string).
var GnapNoContent = gnapNoContent{}

func gnapAth(v string) string {
	h := sha256.Sum256([]byte(wellFormedUTF8(v)))
	return b64.EncodeToString(h[:])
}

// GnapContentDigest is the jwsd payload (RFC 9635 7.3.3): nothing for GnapNoContent, SHA-256 of a string's UTF-8 or of raw
// bytes as given, else SHA-256 of the strict canonical JSON of the value (after a JSON round trip).
func GnapContentDigest(body any) ([]byte, error) {
	var b []byte
	switch t := body.(type) {
	case gnapNoContent:
		return []byte{}, nil
	case string:
		b = []byte(wellFormedUTF8(t))
	case []byte:
		b = t
	default:
		c, err := Canonicalize(gnapToPlain(body))
		if err != nil {
			return nil, err
		}
		b = []byte(c)
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// gnapToPlain is JSON.parse(JSON.stringify(v)) on a JSON value: numbers take their JavaScript form (-0 becomes 0), a
// non-finite number becomes null.
func gnapToPlain(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = gnapToPlain(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = gnapToPlain(x)
		}
		return a
	case json.Number, float64, int, int64:
		f, ok := jsNum(t)
		if !ok || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil
		}
		if f == 0 {
			return jsNumber(0) // JSON.stringify(-0) is "0"
		}
		return jsNumber(f)
	}
	return v
}

// GnapSignArgs is a jwsd proof request. Created nil = now (epoch seconds); Kid / AccessTokenValue nil = absent.
type GnapSignArgs struct {
	Body             any // GnapNoContent for none
	Key              *KeyPair
	Htm, URI         string
	Created          *float64
	Kid              *string
	AccessTokenValue *string
}

// GnapSignRequest produces a jwsd detached-JWS proof over the body, signed by the client key: {detachedJws, header, holder}.
func GnapSignRequest(a GnapSignArgs) (map[string]any, error) {
	if a.Key == nil {
		return nil, errors.New("signGnapRequest: a client key is required")
	}
	created := float64(time.Now().Unix())
	if a.Created != nil {
		created = *a.Created
	}
	header := map[string]any{"alg": "EdDSA", "typ": gnapJwsdTyp, "htm": jsUpper(a.Htm), "uri": a.URI, "created": jsNumber(created)}
	kv := []any{"alg", "EdDSA", "typ", gnapJwsdTyp, "htm", header["htm"], "uri", a.URI, "created", header["created"]}
	if a.Kid != nil {
		header["kid"] = *a.Kid
		kv = append(kv, "kid", *a.Kid)
	}
	if a.AccessTokenValue != nil {
		header["ath"] = gnapAth(*a.AccessTokenValue)
		kv = append(kv, "ath", header["ath"])
	}
	payload, err := GnapContentDigest(a.Body)
	if err != nil {
		return nil, err
	}
	hj, err := jsonObject(kv...)
	if err != nil {
		return nil, err
	}
	prot := b64.EncodeToString([]byte(wellFormedUTF8(string(hj))))
	sig := a.Key.Sign([]byte(prot + "." + b64.EncodeToString(payload)))
	return map[string]any{"detachedJws": prot + ".." + b64.EncodeToString(sig), "header": header, "holder": a.Key.Public}, nil
}

// jsUpper is String.prototype.toUpperCase.
// shortcut: per-rune upper case (no special casing such as the German sharp s); upgrade if such methods must compare.
func jsUpper(s string) string { return strings.ToUpper(s) }

// GnapVerifyRequestArgs is a jwsd proof to verify. SeenProof is the replay store (called once per otherwise valid proof with
// sha256(detachedJws) and the proof's expiry, epoch seconds; true = replayed; an error = replayed). Without a store,
// ReplayUnchecked must be set explicitly or the call is refused.
type GnapVerifyRequestArgs struct {
	DetachedJWS      any
	Body             any // GnapNoContent for none
	Holder           any
	Htm              any
	URI              any
	MaxAgeSec        *float64 // nil: 300
	Now              time.Time
	AccessTokenValue *string
	SeenProof        func(proofID string, expiresSec float64) (bool, error)
	ReplayUnchecked  bool
}

// GnapVerifyRequest verifies a jwsd proof and binds the request to the holder key: {ok:true, holder, header} or
// {ok:false, reason}. Fails closed on any deviation.
func GnapVerifyRequest(a GnapVerifyRequestArgs) (out map[string]any, err error) {
	if a.SeenProof == nil && !a.ReplayUnchecked {
		return nil, gnapErr("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'")
	}
	fail := func(r string) (map[string]any, error) { return map[string]any{"ok": false, "reason": r}, nil }
	jws, isStr := a.DetachedJWS.(string)
	if isStr && jsLen(jws) > GnapMaxDetachedJWSChars {
		return fail("detached JWS exceeds the size limit")
	}
	if !isStr {
		return fail("malformed jwsd request")
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return fail("not a compact JWS (expected three dot-separated parts)")
	}
	prot, mid, sigSeg := parts[0], parts[1], parts[2]
	holder, ok := gnapAsEd25519(a.Holder)
	if !ok {
		return fail("holder is not a canonical base64url Ed25519 public key")
	}
	digest, err := GnapContentDigest(a.Body)
	if err != nil {
		return fail("malformed jwsd request")
	}
	payload := b64.EncodeToString(digest)
	if mid != "" && mid != payload {
		return fail("not a DETACHED compact JWS")
	}
	header, sig, err := gnapJwsSegments(prot, sigSeg)
	if err != nil {
		return fail("non-canonical detached JWS: " + err.Error())
	}
	if !gnapJoseAccepts(header) {
		return fail("jwsd signature does not verify under the holder key (or body was tampered)")
	}
	pk, _ := DecodeB64uStrict(holder, 32)
	if len(sig) != ed25519.SignatureSize || !VerifyStrict(pk, []byte(prot+"."+payload), sig) {
		return fail("jwsd signature does not verify under the holder key (or body was tampered)")
	}
	if header["typ"] != gnapJwsdTyp {
		return fail("unexpected typ (not gnap-binding-jwsd)")
	}
	htm, ok := header["htm"].(string)
	if !ok {
		return fail("htm does not match the request method")
	}
	wantHtm, ok := a.Htm.(string)
	if !ok {
		return fail("malformed jwsd request")
	}
	if jsUpper(htm) != jsUpper(wantHtm) {
		return fail("htm does not match the request method")
	}
	uri, ok := header["uri"].(string)
	if want, isS := a.URI.(string); !ok || !isS || uri != want {
		return fail("uri does not match the request target")
	}
	cn, ok := header["created"].(json.Number)
	created, okF := jsNum(cn)
	if !ok || !okF || math.IsInf(created, 0) || math.IsNaN(created) {
		return fail("missing or malformed created")
	}
	now := a.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowSec := math.Floor(float64(now.UnixNano()) / 1e9)
	maxAge := 300.0
	if a.MaxAgeSec != nil {
		maxAge = *a.MaxAgeSec
	}
	if !(finite(created) && created <= nowSec+60) {
		return fail("created is in the future")
	}
	if !(finite(created) && nowSec-created <= maxAge) {
		return fail("jwsd proof is stale")
	}
	ath, athIsStr := header["ath"].(string)
	if a.AccessTokenValue != nil && (!athIsStr || ath != gnapAth(*a.AccessTokenValue)) {
		return fail("ath does not bind the named access token")
	}
	if a.SeenProof != nil {
		replayed, err := func() (r bool, err error) {
			defer func() {
				if recover() != nil {
					r = true
				}
			}()
			return a.SeenProof(gnapAth(jws), created+maxAge)
		}()
		if err != nil || replayed {
			return fail("jwsd proof replayed (or the replay store failed)")
		}
	}
	h := map[string]any{"alg": "EdDSA", "typ": gnapJwsdTyp, "htm": htm, "uri": uri, "created": cn}
	if kid, ok := header["kid"].(string); ok {
		h["kid"] = kid
	}
	if athIsStr {
		h["ath"] = ath
	}
	return map[string]any{"ok": true, "holder": holder, "header": h}, nil
}

// gnapJwsSegments is the reference assertCanonicalJwsSegments: both segments non-empty canonical base64url, the protected header
// a strict-JSON object (well-formed UTF-8, no BOM).
func gnapJwsSegments(prot, sig string) (map[string]any, []byte, error) {
	if jsLen(prot)+jsLen(sig) > DefaultMaxJWSBytes {
		return nil, nil, errors.New("non-canonical compact JWS: too-long")
	}
	if prot == "" || sig == "" {
		return nil, nil, errors.New("non-canonical compact JWS: empty-segment")
	}
	hb, err := decodeCanonicalBase64url(prot)
	if err != nil {
		return nil, nil, err
	}
	hv, err := jwsJSONSegment(hb)
	if err != nil {
		return nil, nil, err
	}
	h, ok := hv.(map[string]any)
	if !ok {
		return nil, nil, errors.New("non-canonical compact JWS: not-an-object")
	}
	sb, err := decodeCanonicalBase64url(sig)
	if err != nil {
		return nil, nil, err
	}
	return h, sb, nil
}

// gnapJoseAccepts is the reference JOSE library's protected-header gate for an Ed25519 key: `crit` a non-empty array naming
// only the recognized `b64` (present, boolean; b64:false keeps the signing input, as the payload is passed as text), alg EdDSA.
func gnapJoseAccepts(h map[string]any) bool {
	if c, has := h["crit"]; has {
		l, ok := c.([]any)
		if !ok || len(l) == 0 {
			return false
		}
		for _, x := range l {
			if s, ok := x.(string); !ok || s != "b64" {
				return false
			}
		}
		b, has := h["b64"]
		if _, isB := b.(bool); !has || !isB {
			return false
		}
	}
	return h["alg"] == "EdDSA"
}

// ---- continuation -> step-up ------------------------------------------------------------------------------------------------

// GnapRequestRequiresStepUp decides whether a grant request needs a continuation: interaction requested, an explicit tier
// above 1, or (given the issuer's chain) rights beyond the issuer's authority. tier nil = derived (3 with rights beyond, else 2).
func GnapRequestRequiresStepUp(req any, issuerChain []any, tier any) (map[string]any, error) {
	beyond := []any{}
	if issuerChain != nil {
		g, err := GnapGrantedAccessOf(issuerChain)
		if err != nil {
			return nil, err
		}
		acc, err := gnapAccessOf(req)
		if err != nil {
			return nil, err
		}
		reqd, err := GnapNormalizeAccess(acc)
		if err != nil {
			return nil, err
		}
		for _, r := range reqd {
			if !GnapAccessWithin(g, r.(map[string]any)) {
				beyond = append(beyond, r)
			}
		}
	}
	interact, has, err := gnapGet(req, "interact")
	if err != nil {
		return nil, err
	}
	interactRequested := false
	if has {
		st, _, err := gnapGet(interact, "start")
		if err != nil {
			return nil, err
		}
		l, ok := st.([]any)
		interactRequested = ok && len(l) > 0
	}
	tierGt1 := false
	if f, ok := jsNum(tier); ok {
		tierGt1 = f > 1
	}
	required := interactRequested || len(beyond) > 0 || tierGt1
	if tier == nil {
		tier = jsNumber(2)
		if len(beyond) > 0 {
			tier = jsNumber(3)
		}
	}
	reason := "no step-up required"
	switch {
	case !required:
	case len(beyond) > 0:
		reason = fmt.Sprintf("requested rights exceed the issuer's authority (%d right(s) beyond)", len(beyond))
	case interactRequested:
		reason = "GNAP interaction requested"
	default:
		reason = "tier " + jsValueString(tier) + " step-up required"
	}
	return map[string]any{"required": required, "reason": reason, "beyond": beyond, "tier": tier}, nil
}

// GnapBeginContinuation emits the `continue` handle (a grant response with no token yet) and the step-up it resolves through.
// args: signerSet, t, tier, continueUri, continueToken, wait?, reason?.
func GnapBeginContinuation(args map[string]any) map[string]any {
	cont := map[string]any{"uri": args["continueUri"], "access_token": map[string]any{"value": args["continueToken"], "bound": true}}
	if w, has := args["wait"]; has {
		cont["wait"] = w
	}
	reason, has := args["reason"]
	if !has || reason == nil {
		reason = "tier " + jsValueString(args["tier"]) + " co-signature required to continue"
	}
	return map[string]any{"response": map[string]any{"continue": cont},
		"stepUp": map[string]any{"tier": args["tier"], "t": args["t"], "signerSet": args["signerSet"], "reason": reason, "continueToken": args["continueToken"]}}
}

// gnapSignerSetHash is the reference signerSetHash, lenient on a malformed set (it hashes the String() of what is there).
func gnapSignerSetHash(set any) ([]byte, error) {
	l, _ := set.([]any)
	rows := make([]map[string]any, 0, len(l))
	for _, s := range l {
		pk, _ := gnapMember(s, "publicKey")
		role, _ := gnapMember(s, "role")
		pkS, roleS := "undefined", "undefined"
		if _, has := gnapMember(s, "publicKey"); has {
			pkS = jsValueString(pk)
		}
		if _, has := gnapMember(s, "role"); has {
			roleS = jsValueString(role)
		}
		row := map[string]any{"publicKey": pkS, "role": roleS}
		if pq, ok := gnapMemberStr(s, "pq_pk"); ok {
			row["pq_pk"] = pq
		}
		rows = append(rows, row)
	}
	for i := 1; i < len(rows); i++ { // stable insertion sort by (role, publicKey) in UTF-8 order
		for j := i; j > 0; j-- {
			a, b := rows[j-1], rows[j]
			c := compareUtf8(a["role"].(string), b["role"].(string))
			if c == 0 {
				c = compareUtf8(a["publicKey"].(string), b["publicKey"].(string))
			}
			if c <= 0 {
				break
			}
			rows[j-1], rows[j] = b, a
		}
	}
	arr := make([]any, len(rows))
	for i, r := range rows {
		arr[i] = r
	}
	canon, err := Canonicalize(arr)
	if err != nil {
		return nil, err
	}
	return sha(append([]byte(signersetDomain), canon...)), nil
}

func gnapMemberStr(v any, k string) (string, bool) {
	x, _ := gnapMember(v, k)
	s, ok := x.(string)
	return s, ok
}

// gnapT reads a threshold t: exactly 1, 2 or 3.
func gnapT(t any) (int, bool) {
	f, ok := jsNum(t)
	if _, isB := t.(bool); isB || !ok || f != 1 && f != 2 && f != 3 {
		return 0, false
	}
	return int(f), true
}

func gnapShareMessage(role string, message []byte, set any, t any, alg any) ([]byte, error) {
	tt, ok := gnapT(t)
	if !ok {
		return nil, errors.New("shareMessage: t must be 1, 2 or 3")
	}
	ssh, err := gnapSignerSetHash(set)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(message)
	out := append([]byte(wellFormedUTF8(shareDomainPrefix+role+"\x00")), h[:]...)
	out = append(append(out, ssh...), byte(tt))
	if a, ok := alg.(string); ok && a != "ed25519" && isRegisteredSuite(a) {
		out = append(out, []byte(shareSuiteTag+a)...)
	}
	return out, nil
}

func gnapSignShare(role string, key *KeyPair, message []byte, set any, t any) (map[string]any, error) {
	m, err := gnapShareMessage(role, message, set, t, nil)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, errors.New("signShare: a share needs the role's Ed25519 key")
	}
	return map[string]any{"role": role, "publicKey": key.Public, "sig": b64.EncodeToString(key.Sign(m))}, nil
}

// GnapStepUpShare is one role's step-up co-signature share over a PCActn body, bound to the signer set and t.
func GnapStepUpShare(body map[string]any, role string, key *KeyPair, signerSet any, t any) (map[string]any, error) {
	msg, err := ThresholdMessage(body)
	if err != nil {
		return nil, err
	}
	return gnapSignShare(role, key, msg, signerSet, t)
}

func gnapShow(v any) string {
	switch v.(type) {
	case []any:
		return "<array>"
	case map[string]any:
		return "<object>"
	}
	return jsValueString(v)
}

// gnapVerifyThreshold is the reference verifyThreshold without a leaf baseline: the signer set is validated first (known roles,
// a canonical key per entry, a well-formed pq_pk, one key per role, one role per key), then the DISTINCT registered keys with a
// valid role / set / t-bound share are counted. {ok, count, roles, reason?}; total.
func gnapVerifyThreshold(shares []any, message []byte, set any, t any) map[string]any {
	verdict := func(ok bool, count int, roles []any, reason string) map[string]any {
		v := map[string]any{"ok": ok, "count": jsNumber(float64(count)), "roles": roles}
		if !ok {
			v["reason"] = reason
		}
		return v
	}
	tt, tOK := gnapT(t)
	if !tOK {
		return verdict(false, 0, []any{}, "invalid threshold t="+gnapShow(t)+" (must be 1, 2 or 3)")
	}
	entries, _ := set.([]any)
	reg := map[string]string{}
	pqOf := map[string]*string{}
	seen := map[string]*string{}
	for _, s := range entries {
		m, isObj := s.(map[string]any)
		role, _ := m["role"].(string)
		if !signerRoles[role] {
			role = ""
		}
		pk, _ := m["publicKey"].(string)
		_, keyOK := DecodeB64uStrict(pk, 32)
		keyOK = keyOK && isObj
		if _, isStr := m["publicKey"].(string); !isStr {
			keyOK = false
		}
		pqOK := true
		var pq *string
		if pv, has := m["pq_pk"]; has {
			ps, isS := pv.(string)
			b, ok := DecodeB64uStrict(ps, -1)
			pqOK = isS && ok && pqPkLengths[len(b)]
			if isS {
				pq = &ps
			}
		}
		if role != "" && keyOK && pqOK {
			id := role + "\x00" + pk
			if prev, dup := seen[id]; dup && !gnapSamePq(prev, pq) {
				pqOK = false
			} else {
				seen[id] = pq
			}
		}
		if role == "" || !keyOK {
			return verdict(false, 0, []any{}, "malformed signer set")
		}
		if !pqOK {
			return verdict(false, 0, []any{}, "malformed signer set (pq_pk)")
		}
		if k, has := reg[role]; has && k != pk {
			return verdict(false, 0, []any{}, "signer set registers more than one key for role "+gnapShow(m["role"]))
		}
		for r, k := range reg {
			if k == pk && r != role {
				return verdict(false, 0, []any{}, "signer set registers one key under two roles")
			}
		}
		if _, has := reg[role]; !has {
			reg[role], pqOf[role] = pk, pq
		}
	}
	keys := map[string]bool{}
	roles := []any{}
	reason := ""
	first := func(r string) {
		if reason == "" {
			reason = r
		}
	}
	for _, sv := range shares {
		share, _ := sv.(map[string]any)
		role, ok1 := share["role"].(string)
		pk, ok2 := share["publicKey"].(string)
		if !ok1 || !ok2 {
			first("malformed share")
			continue
		}
		if keys[pk] {
			continue
		}
		want, has := reg[role]
		if !signerRoles[role] || !has {
			first("role " + role + " is not in the signer set")
			continue
		}
		if want != pk {
			first("share for role " + role + " uses a key not registered for that role")
			continue
		}
		algV, algPresent := share["alg"]
		if _, known := resolveSigAlg(algV, algPresent); !known {
			first("share for role " + role + " declares an unknown signature alg")
			continue
		}
		registered := pqOf[role]
		if sp, has := share["pq_pk"]; has {
			if s, ok := sp.(string); !ok || registered == nil || s != *registered {
				first("share for role " + role + " names a pq_pk that is not the key its role registers")
				continue
			}
		}
		good := false
		if signed, err := gnapShareMessage(role, message, set, tt, algV); err == nil {
			edOnly := !algPresent || algV == "ed25519"
			switch {
			case edOnly && registered == nil:
				sig, _ := share["sig"].(string)
				good = verifyB64u(pk, signed, sig)
			case !edOnly && registered != nil:
				good = verifyLeafSuite(algV, algPresent, pk, callerVouchedPqKey(*registered), signed, share["sig"], share["pq_sig"])
			}
		}
		if !good {
			first("invalid signature for role " + role)
			continue
		}
		keys[pk] = true
		roles = append(roles, role)
	}
	count := len(roles)
	if count >= tt {
		return verdict(true, count, roles, "")
	}
	if reason == "" {
		reason = fmt.Sprintf("only %d distinct valid key(s), need %s", count, gnapShow(t))
	}
	return verdict(false, count, roles, reason)
}

func gnapSamePq(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// GnapCosign is one co-signature reached through the continuation.
type GnapCosign struct {
	Role string
	Key  *KeyPair
}

// GnapContinuationArgs resolve a continuation. The agent leaf key signs the PCActn and the agent share; Cosigns are folded in.
type GnapContinuationArgs struct {
	Grant     map[string]any
	Chain     []map[string]any
	Plan      []map[string]any
	NodeID    string
	Params    any
	Counter   int64
	Aud       string
	NowMs     int64 // 0: now
	TtlMs     int64 // 0: the default
	AgentLeaf *KeyPair
	SignerSet any
	T         any
	Cosigns   []GnapCosign
}

// GnapCompleteContinuation builds the action's PCActn, folds the agent share and the step-up co-signatures into its threshold
// and verifies that t is reached: {pcactn, threshold, verdict}.
func GnapCompleteContinuation(a GnapContinuationArgs) (map[string]any, error) {
	if len(a.Chain) == 0 {
		return nil, gnapErr("completeGnapContinuation: empty chain")
	}
	p, err := BuildPCActn(PCActnInput{Grant: a.Grant, Chain: a.Chain, Plan: a.Plan, NodeID: a.NodeID, Params: a.Params, Counter: a.Counter,
		Signer: a.AgentLeaf, Aud: a.Aud, Iat: a.NowMs, TtlMs: a.TtlMs})
	if err != nil {
		return nil, err
	}
	msg, err := ThresholdMessage(p)
	if err != nil {
		return nil, err
	}
	agent, err := gnapSignShare("agent", a.AgentLeaf, msg, a.SignerSet, a.T)
	if err != nil {
		return nil, err
	}
	shares := []any{agent}
	for _, c := range a.Cosigns {
		s, err := gnapSignShare(c.Role, c.Key, msg, a.SignerSet, a.T)
		if err != nil {
			return nil, err
		}
		shares = append(shares, s)
	}
	threshold := map[string]any{"shares": shares}
	verdict := gnapVerifyThreshold(shares, msg, a.SignerSet, a.T)
	full := copyMap(p)
	full["threshold"] = threshold
	return map[string]any{"pcactn": full, "threshold": threshold, "verdict": verdict}, nil
}

// ---- the profile ----------------------------------------------------------------------------------------------------------------

// AgentGnapProfile is the machine-readable Agent-GNAP profile.
func AgentGnapProfile() map[string]any {
	mp := func(g, p, n string) any { return map[string]any{"gnap": g, "pca": p, "note": n} }
	return map[string]any{
		"name": "agent-gnap", "version": "1.0", "rfc": "RFC 9635",
		"summary": "A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is " +
			"issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.",
		"mapping": []any{
			mp("access[].type", "predicate resource namespace gnap:<type>:<location>", "the resource family the rights live in"),
			mp("access[].actions", "predicate.verb (list, or * for any)", "the operations permitted"),
			mp("access[].locations", "predicate.resource (exact or trailing-* prefix)", "the resource targets"),
			mp("access[].datatypes / identifier", "predicate.where on action.params.*", "value-level constraints"),
			mp("client.key.jwk (OKP/Ed25519)", "capability.holder (cnf-bound key)", "the proof-of-possession key"),
			mp("grant request (no prior grant)", "mintGrant → root capability", "envelope predicates = requested access"),
			mp("grant request (delegated hop)", "delegate → child capability + gnap_access caveat", "append-only attenuation"),
			mp("access_token (§3.2)", "a verifiable PCA capability chain (encodeBoundToken)", "bound, self-verifying token"),
			mp("continue (§3.1) + interact (§3.3)", "PCA step-up: FROST/threshold co-signature folded into a PCActn", "tier-2/3 escalation"),
			mp("jwsd detached JWS (§7.3.4)", "request proof binding the body to capability.holder", "verified with jose"),
		},
		"proofMethods": []any{"jwsd"},
		"multiHop": "An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, " +
			"recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the " +
			"intersection of the root policy envelope and every hop; PCA caveats are conjunctive and " +
			"append-only, so no hop can widen — \"never wider than the issuer\" holds across any depth.",
		"stepUp": "A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue " +
			"handle instead of a token. The client returns with the action PCActn plus a guardian/principal " +
			"co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or " +
			"multi-signature) before the action is admitted.",
		"security": []any{
			"Attenuation is structural and append-only: a delegated hop can only ever narrow authority.",
			"Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.",
			"All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.",
			"Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).",
			"Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant.",
		},
	}
}
