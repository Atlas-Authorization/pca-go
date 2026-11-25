package pca

// RS discovery (`/.well-known/pca-configuration`), the `pca_need` encoder and the OAuth scopes derived from a confirmed action:
// ports of the reference discovery.ts, pca-need.ts (encode / challenge side; ValidateA2ANeed / DecodeA2ANeed are the decode side)
// and action-scopes.ts. Documents are JSON values (map[string]any); an absent option (nil) is an absent member.

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// WellKnownPcaPath is where a resource server publishes its discovery document.
const WellKnownPcaPath = "/.well-known/pca-configuration"

// PcaNeedParam is the WWW-Authenticate / A2A parameter that carries an encoded need.
const PcaNeedParam = "pca_need"

// DiscoveryOptions configures BuildDiscoveryDocument. A nil slice or map leaves the member at its default (or absent).
type DiscoveryOptions struct {
	Audience             string
	SignatureSuites      []string
	PcaVersions          []int
	ActionHeader         string // default "PCA-Action"
	RequiredChecks       []string
	Endpoints            map[string]any
	TrustedRoots         []string
	Metadata             map[string]any
	Intent               map[string]any
	ObligationsSupported []string
}

var discoveryDefaultSuites = []string{"ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"}
var discoveryDefaultRequired = []string{"counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"}

// BuildDiscoveryDocument returns the RS discovery document.
func BuildDiscoveryDocument(o DiscoveryOptions) (map[string]any, error) {
	if o.Audience == "" {
		return nil, errors.New("buildDiscoveryDocument: audience is required")
	}
	versions := []any{jsNumber(2)}
	if o.PcaVersions != nil {
		versions = make([]any, len(o.PcaVersions))
		for i, v := range o.PcaVersions {
			versions[i] = jsNumber(float64(v))
		}
	}
	header := o.ActionHeader
	if header == "" {
		header = "PCA-Action"
	}
	doc := map[string]any{
		"audience":         o.Audience,
		"pca_versions":     versions,
		"signature_suites": jsStrList(orStrings(o.SignatureSuites, discoveryDefaultSuites)),
		"action_header":    header,
		"required_checks":  jsStrList(orStrings(o.RequiredChecks, discoveryDefaultRequired)),
	}
	if o.Endpoints != nil {
		doc["endpoints"] = o.Endpoints
	}
	if o.TrustedRoots != nil {
		doc["trusted_roots"] = jsStrList(o.TrustedRoots)
	}
	if o.Metadata != nil {
		doc["metadata"] = o.Metadata
	}
	if o.Intent != nil {
		in, err := ParseDiscoveryIntent(o.Intent)
		if err != nil {
			return nil, err
		}
		doc["intent"] = in
	}
	if o.ObligationsSupported != nil {
		doc["obligations_supported"] = jsStrList(o.ObligationsSupported)
	}
	return doc, nil
}

func orStrings(v, def []string) []string {
	if v == nil {
		return def
	}
	return v
}

// strList copies a string slice into a JSON array value.
func jsStrList(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// isStrArray: a JSON array whose every element is a string.
func isStrArray(v any) bool {
	l, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range l {
		if _, ok := x.(string); !ok {
			return false
		}
	}
	return true
}

func isNumArray(v any) bool {
	l, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range l {
		if _, ok := jsNum(x); !ok {
			return false
		}
	}
	return true
}

// ParseDiscoveryIntent validates the discovery document's `intent` block (closed member set).
func ParseDiscoveryIntent(v any) (map[string]any, error) {
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("parseDiscoveryDocument: intent must be an object")
	}
	for k := range o {
		switch k {
		case "versions", "actions_uri", "schema_keys", "question_relay", "tiers", "evidence_uri":
		default:
			return nil, fmt.Errorf("parseDiscoveryDocument: intent has unknown member '%s'", k)
		}
	}
	vs, ok := o["versions"].([]any)
	if !ok || len(vs) == 0 {
		return nil, errors.New("parseDiscoveryDocument: intent.versions must list 1 and/or 2")
	}
	for _, n := range vs {
		if f, ok := jsNum(n); !ok || (f != 1 && f != 2) {
			return nil, errors.New("parseDiscoveryDocument: intent.versions must list 1 and/or 2")
		}
	}
	out := map[string]any{"versions": append([]any(nil), vs...)}
	for _, k := range []string{"actions_uri", "evidence_uri"} {
		if x, has := o[k]; has {
			if s, ok := x.(string); !ok || s == "" {
				return nil, fmt.Errorf("parseDiscoveryDocument: intent.%s must be a non-empty string", k)
			}
			out[k] = x
		}
	}
	if x, has := o["schema_keys"]; has {
		l, ok := x.([]any)
		if !ok {
			return nil, errors.New("parseDiscoveryDocument: intent.schema_keys must be an array")
		}
		keys := make([]any, len(l))
		for i, e := range l {
			m, ok := e.(map[string]any)
			_, k1 := m["kid"].(string)
			_, k2 := m["alg"].(string)
			_, k3 := m["pk"].(string)
			pq, hasPq := m["pq_pk"]
			_, k4 := pq.(string)
			if !ok || !k1 || !k2 || !k3 || (hasPq && !k4) {
				return nil, errors.New("parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}")
			}
			k := map[string]any{"kid": m["kid"], "alg": m["alg"], "pk": m["pk"]}
			if hasPq {
				k["pq_pk"] = pq
			}
			keys[i] = k
		}
		out["schema_keys"] = keys
	}
	if x, has := o["question_relay"]; has {
		if _, ok := x.(bool); !ok {
			return nil, errors.New("parseDiscoveryDocument: intent.question_relay must be a boolean")
		}
		out["question_relay"] = x
	}
	if x, has := o["tiers"]; has {
		t, ok := x.(map[string]any)
		if !ok {
			return nil, errors.New("parseDiscoveryDocument: intent.tiers must be an object")
		}
		c := make(map[string]any, len(t))
		for k, n := range t {
			if f, ok := jsNum(n); !ok || !jsIsNonNeg(n) || f > 4 {
				return nil, errors.New("parseDiscoveryDocument: intent.tiers values must be integers 0..4")
			}
			c[k] = n
		}
		out["tiers"] = c
	}
	return out, nil
}

// ParseDiscoveryDocument validates a fetched discovery document and returns its known members.
func ParseDiscoveryDocument(value any) (map[string]any, error) {
	v, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("parseDiscoveryDocument: not an object")
	}
	if s, ok := v["audience"].(string); !ok || s == "" {
		return nil, errors.New("parseDiscoveryDocument: missing audience")
	}
	if !isNumArray(v["pca_versions"]) {
		return nil, errors.New("parseDiscoveryDocument: pca_versions must be a number[]")
	}
	if !isStrArray(v["signature_suites"]) {
		return nil, errors.New("parseDiscoveryDocument: signature_suites must be a string[]")
	}
	if s, ok := v["action_header"].(string); !ok || s == "" {
		return nil, errors.New("parseDiscoveryDocument: missing action_header")
	}
	doc := map[string]any{"audience": v["audience"], "pca_versions": v["pca_versions"], "signature_suites": v["signature_suites"], "action_header": v["action_header"]}
	if isStrArray(v["required_checks"]) {
		doc["required_checks"] = v["required_checks"]
	}
	if isJSObject(v["endpoints"]) {
		doc["endpoints"] = v["endpoints"]
	}
	if isStrArray(v["trusted_roots"]) {
		doc["trusted_roots"] = v["trusted_roots"]
	}
	if isJSObject(v["metadata"]) {
		doc["metadata"] = v["metadata"]
	}
	if x, has := v["intent"]; has {
		in, err := ParseDiscoveryIntent(x)
		if err != nil {
			return nil, err
		}
		doc["intent"] = in
	}
	if x, has := v["obligations_supported"]; has {
		if !isStrArray(x) {
			return nil, errors.New("parseDiscoveryDocument: obligations_supported must be a string[]")
		}
		doc["obligations_supported"] = append([]any(nil), x.([]any)...)
	}
	return doc, nil
}

// isJSObject is `x !== null && typeof x === 'object'` (an array counts).
func isJSObject(x any) bool {
	switch x.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

// AcceptsSuite reports whether the discovery document lists the signature suite.
func AcceptsSuite(doc map[string]any, suite string) bool {
	l, _ := doc["signature_suites"].([]any)
	for _, s := range l {
		if s == suite {
			return true
		}
	}
	return false
}

// EncodePcaNeed validates a need and returns its header value (base64url of the strict canonical JSON).
func EncodePcaNeed(need map[string]any) (string, error) {
	if code := ValidateA2ANeed(need); code != "" {
		return "", fmt.Errorf("encodePcaNeed: malformed need (%s)", code)
	}
	c, err := Canonicalize(need)
	if err != nil {
		return "", fmt.Errorf("encodePcaNeed: %w", err)
	}
	enc := b64.EncodeToString([]byte(c))
	if len(enc) > a2aNeedMaxEncoded {
		return "", errors.New("encodePcaNeed: the need is too large for a header")
	}
	return enc, nil
}

var pcaNeedChallenge = regexp.MustCompile(`(?:^|[\s,])pca_need="([^"\\]*)"`)

// PcaNeedFromChallenge extracts and decodes the `pca_need` of a WWW-Authenticate header. found is false when the header carries
// none; otherwise need / code are DecodeA2ANeed's result.
func PcaNeedFromChallenge(header string) (need map[string]any, code string, found bool) {
	m := pcaNeedChallenge.FindStringSubmatch(header)
	if m == nil {
		return nil, "", false
	}
	need, code = DecodeA2ANeed(m[1])
	return need, code, true
}

var scopeToken = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]+$`) // RFC 6749 section 3.3 scope-token

// DeriveActionScopes derives the minimal OAuth scopes of a confirmed action. provider nil skips the provider check; granted nil
// skips the grant check. Returns {ok:true, scopes, provider, def_digest} or {ok:false, code}.
func DeriveActionScopes(action any, provider *string, granted []string) map[string]any {
	fail := func(code string) map[string]any { return map[string]any{"ok": false, "code": code} }
	if !isJSObject(action) {
		return fail("unknown_action")
	}
	a, _ := action.(map[string]any) // an array has no members
	if a["confirmed"] != true {
		return fail("unconfirmed")
	}
	up, _ := a["upstream"].(map[string]any)
	if provider != nil {
		if p, ok := up["provider"].(string); !ok || p != *provider {
			return fail("provider_mismatch")
		}
	}
	min, ok := up["scopes_min"].([]any)
	if !ok || len(min) == 0 {
		return fail("no_scopes")
	}
	set := map[string]bool{}
	for _, x := range min {
		s, ok := x.(string)
		if !ok || len(s) > 256 || !scopeToken.MatchString(s) {
			return fail("bad_scope")
		}
		set[s] = true
	}
	scopes := make([]string, 0, len(set))
	for s := range set {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes) // ASCII only (the scope-token class), so byte order is the reference's code-unit order
	if granted != nil {
		g := map[string]bool{}
		for _, s := range granted {
			g[s] = true
		}
		for _, s := range scopes {
			if !g[s] {
				return fail("exceeds_grant")
			}
		}
	}
	out := map[string]any{"ok": true, "scopes": jsStrList(scopes)}
	if p, has := up["provider"]; has {
		out["provider"] = p
	}
	if d, has := a["def_digest"]; has {
		out["def_digest"] = d
	}
	return out
}
