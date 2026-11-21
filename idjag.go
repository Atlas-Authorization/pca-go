package pca

// ID-JAG (Identity Assertion JWT Authorization Grant, the cross-app access grant): verify the grant an IdP issues to an agent
// acting for a user, project it to a principal and a root capability that carries its scopes and provenance, and build the
// token-exchange / jwt-bearer requests of the flow.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxIDJagChars                = 16384
	IDJagAuthorityCaveat         = "idjag_authority"
	IDJagProvenanceCaveat        = "idjag_provenance"
	GrantTypeTokenExchange       = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantTypeJWTBearer           = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	TokenTypeIDJag               = "urn:ietf:params:oauth:token-type:id-jag"
	TokenTypeIDToken             = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeAccessToken         = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeJWT                 = "urn:ietf:params:oauth:token-type:jwt"
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	idJagTyp                     = "oauth-id-jag+jwt"
)

// VerifyIdJagOptions. Issuer and Audience (the resource app; an ID-JAG is single-audience) are required. StrictDraft (nil =
// true) additionally requires the typ header, client_id == ClientID and a single-use jti through ConsumeJti, which must report
// true for a fresh jti (an error counts as not fresh). The key options are VerifyIdTokenOptions'.
type VerifyIdJagOptions struct {
	Issuer, Audience                  string
	Nonce                             *string
	RequiredScopes                    []string
	ClockToleranceSec, MaxTokenAgeSec *float64
	Algorithms                        []string
	Key                               any
	JwksURI                           *string
	Discover                          bool
	Fetch                             OidcFetch
	StrictDraft                       *bool
	ClientID                          string
	ConsumeJti                        func(jti string, expSec float64) (bool, error)
}

var jsWSRun = regexp.MustCompile(`[` + jsWS + `]+`)

func idJagScopes(scope, scopes any) ([]any, bool) {
	keep := func(l []any) []any {
		out := []any{}
		for _, s := range l {
			if v, ok := s.(string); ok && v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	if s, ok := scope.(string); ok {
		out := []any{}
		for _, p := range jsWSRun.Split(s, -1) {
			if p != "" {
				out = append(out, p)
			}
		}
		return out, true
	}
	if l, ok := scope.([]any); ok {
		return keep(l), true
	}
	if l, ok := scopes.([]any); ok {
		return keep(l), true
	}
	return nil, false
}

func idJagSegment(jwt string, i int) map[string]any {
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[i])
	if err != nil {
		return nil
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		return nil
	}
	m, _ := normalizeJSON(v).(map[string]any)
	return m
}

// VerifyIdJag verifies an ID-JAG and returns the grant: iss, sub, actor (the act claim), agent (act.sub), audience, scopes, iat,
// exp, jti / nonce / cnf when present, and oidcClaims. Every failure is a *CodedError (the OIDC codes plus actor, scope, grant).
func VerifyIdJag(jwt string, o VerifyIdJagOptions) (map[string]any, error) {
	if jwt == "" {
		return nil, oidcErr("invalid_token", "verifyIdJag: jwt must be a non-empty string")
	}
	if jsLen(jwt) > MaxIDJagChars {
		return nil, oidcErr("invalid_token", "verifyIdJag: jwt exceeds the size limit")
	}
	if o.Issuer == "" {
		return nil, oidcErr("config", "verifyIdJag: opts.issuer is required")
	}
	if o.Audience == "" {
		return nil, oidcErr("config", "verifyIdJag: opts.audience is required (ID-JAG is single-audience)")
	}
	strict := o.StrictDraft == nil || *o.StrictDraft
	if strict && o.ConsumeJti == nil {
		return nil, oidcErr("config", "verifyIdJag: strictDraft requires opts.consumeJti (single-use store)")
	}
	if strict && o.ClientID == "" {
		return nil, oidcErr("config", "verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)")
	}
	aud := o.Audience
	base, err := VerifyIdToken(jwt, VerifyIdTokenOptions{Issuer: o.Issuer, Audience: &aud, Nonce: o.Nonce, ClockToleranceSec: o.ClockToleranceSec,
		MaxTokenAgeSec: o.MaxTokenAgeSec, Algorithms: o.Algorithms, Key: o.Key, JwksURI: o.JwksURI, Discover: o.Discover, Fetch: o.Fetch})
	if err != nil {
		var ce *CodedError
		if errors.As(err, &ce) {
			return nil, ce
		}
		return nil, oidcErr("invalid_token", "ID-JAG verification failed")
	}
	audList, isList := base["aud"].([]any)
	if !isList {
		audList = []any{base["aud"]}
	}
	if len(audList) != 1 || audList[0] != o.Audience {
		return nil, oidcErr("audience", "ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)")
	}
	raw := idJagSegment(jwt, 1)
	if raw == nil {
		return nil, oidcErr("invalid_token", "ID-JAG payload could not be decoded")
	}
	act, _ := raw["act"].(map[string]any)
	agent, ok := oidcStr(act["sub"])
	if !ok {
		return nil, oidcErr("actor", `ID-JAG is missing a well-formed "act" (agent) claim with a string "sub"`)
	}
	scopes, ok := idJagScopes(raw["scope"], raw["scopes"])
	if !ok {
		return nil, oidcErr("scope", `ID-JAG is missing the "scope" (or "scopes") claim`)
	}
	have := map[any]bool{}
	for _, s := range scopes {
		have[s] = true
	}
	for _, r := range o.RequiredScopes {
		if !have[r] {
			return nil, oidcErr("scope", fmt.Sprintf(`ID-JAG does not grant the required scope "%s"`, r))
		}
	}
	jti, hasJti := oidcStr(raw["jti"])
	if strict {
		h := idJagSegment(jwt, 0)
		if h["typ"] != idJagTyp {
			return nil, oidcErr("grant", `ID-JAG header typ must be "oauth-id-jag+jwt"`)
		}
		cid, ok := oidcStr(raw["client_id"])
		if !ok {
			return nil, oidcErr("grant", `ID-JAG is missing "client_id"`)
		}
		if cid != o.ClientID {
			return nil, oidcErr("grant", "ID-JAG client_id does not match the expected client")
		}
		if !hasJti {
			return nil, oidcErr("grant", `ID-JAG is missing "jti"`)
		}
		exp, _ := jsNum(base["exp"])
		if fresh, err := o.ConsumeJti(jti, exp); err != nil || !fresh {
			return nil, oidcErr("grant", "ID-JAG jti was already used or the single-use store failed")
		}
	}
	actor := copyMap(act)
	g := map[string]any{"iss": base["iss"], "sub": base["sub"], "actor": actor, "agent": agent, "audience": o.Audience, "scopes": scopes,
		"iat": base["iat"], "exp": base["exp"], "oidcClaims": base}
	if hasJti {
		g["jti"] = jti
	}
	for _, k := range []string{"nonce", "cnf"} {
		if v, has := base[k]; has {
			g[k] = v
		}
	}
	return g, nil
}

// IdJagToPcaPrincipal maps a grant's OIDC claims to a principal (see OidcPrincipal).
func IdJagToPcaPrincipal(grant map[string]any, principalPublic *string) (map[string]any, error) {
	if grant == nil {
		return nil, errors.New("idJagToPcaPrincipal: grant is required")
	}
	claims, _ := grant["oidcClaims"].(map[string]any)
	if claims == nil {
		return nil, errors.New("idJagToPcaPrincipal: grant.oidcClaims is required")
	}
	return OidcPrincipal(claims, principalPublic)
}

// IdJagCapabilityOptions: the principal's Ed25519 seed and its public key (b64u; they must match), the holder (agent) key and
// caveats appended after the ID-JAG ones.
type IdJagCapabilityOptions struct {
	PrincipalSecret []byte
	PrincipalPublic string
	Holder          string
	ExtraCaveats    []any
}

// IdJagToCapability mints the root capability of a verified grant: caveats idjag_authority {scopes, aud}, idjag_provenance {iss,
// sub, agent, aud, iat, exp, jti?}, the oidc_subject caveat and ExtraCaveats. It returns {capability, principal, scopes}.
func IdJagToCapability(grant map[string]any, o IdJagCapabilityOptions) (map[string]any, error) {
	if grant == nil {
		return nil, errors.New("idJagToCapability: grant is required")
	}
	if o.PrincipalSecret == nil {
		return nil, errors.New("idJagToCapability: opts.principalSecret must be a Uint8Array")
	}
	if o.PrincipalPublic == "" {
		return nil, errors.New("idJagToCapability: opts.principalPublic is required")
	}
	if o.Holder == "" {
		return nil, errors.New("idJagToCapability: opts.holder (the agent key) is required")
	}
	pub := o.PrincipalPublic
	principal, err := IdJagToPcaPrincipal(grant, &pub)
	if err != nil {
		return nil, err
	}
	kp, err := KeyPairFromSeed(o.PrincipalSecret)
	if err != nil {
		return nil, fmt.Errorf("idJagToCapability: %w", err)
	}
	if kp.Public != o.PrincipalPublic {
		return nil, errors.New("idJagToCapability: opts.principalSecret is not the key of opts.principalPublic")
	}
	sl, ok := grant["scopes"].([]any)
	if !ok {
		return nil, errors.New("idJagToCapability: grant.scopes must be an array")
	}
	authority := map[string]any{"type": IDJagAuthorityCaveat, "scopes": append([]any{}, sl...), "aud": grant["audience"]}
	prov := map[string]any{"type": IDJagProvenanceCaveat, "iss": grant["iss"], "sub": grant["sub"], "agent": grant["agent"], "aud": grant["audience"],
		"iat": grant["iat"], "exp": grant["exp"]}
	if v, has := grant["jti"]; has {
		prov["jti"] = v
	}
	caveats := append([]any{authority, prov, principal["subjectCaveat"]}, o.ExtraCaveats...)
	capability, err := MintRoot(kp, o.Holder, caveats, "", nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{"capability": capability, "principal": principal, "scopes": append([]any{}, sl...)}, nil
}

// IsIdJagAuthorityCaveat reports whether cv is {type: idjag_authority, scopes: [strings], aud: non-empty string}.
func IsIdJagAuthorityCaveat(cv any) bool {
	m, ok := cv.(map[string]any)
	if !ok || m["type"] != IDJagAuthorityCaveat {
		return false
	}
	l, ok := m["scopes"].([]any)
	if !ok {
		return false
	}
	for _, s := range l {
		if _, ok := s.(string); !ok {
			return false
		}
	}
	_, ok = oidcStr(m["aud"])
	return ok
}

// IsIdJagProvenanceCaveat reports whether cv is {type: idjag_provenance, iss, sub, agent, aud: strings, iat, exp: numbers}.
func IsIdJagProvenanceCaveat(cv any) bool {
	m, ok := cv.(map[string]any)
	if !ok || m["type"] != IDJagProvenanceCaveat {
		return false
	}
	for _, k := range []string{"iss", "sub", "agent", "aud"} {
		if _, ok := m[k].(string); !ok {
			return false
		}
	}
	_, iok := jsNum(m["iat"])
	_, eok := jsNum(m["exp"])
	return iok && eok
}

func idJagReadCaveat(cap any, typ string, valid func(any) bool) (map[string]any, error) {
	m, _ := cap.(map[string]any)
	cv, has := m["caveats"]
	if !has || cv == nil {
		return nil, nil
	}
	l, ok := cv.([]any)
	if !ok {
		return nil, errors.New("capability caveats must be an array")
	}
	for _, c := range l {
		if cm, ok := c.(map[string]any); ok && cm["type"] == typ {
			if valid(cm) {
				return cm, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

// ReadIdJagAuthority returns the capability's first idjag_authority caveat when it is well-formed, nil otherwise (an error for a
// non-array caveats member).
func ReadIdJagAuthority(cap any) (map[string]any, error) {
	return idJagReadCaveat(cap, IDJagAuthorityCaveat, IsIdJagAuthorityCaveat)
}

// ReadIdJagProvenance is ReadIdJagAuthority for the idjag_provenance caveat.
func ReadIdJagProvenance(cap any) (map[string]any, error) {
	return idJagReadCaveat(cap, IDJagProvenanceCaveat, IsIdJagProvenanceCaveat)
}

// ---- request shapes ---------------------------------------------------------------------------------------------------------

// OAuthParam is one form parameter, in order.
type OAuthParam struct{ Name, Value string }

// OAuthFormRequest is a POST of an application/x-www-form-urlencoded body.
type OAuthFormRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Params  map[string]string `json:"params"`
	Body    string            `json:"body"`
}

type formEntry struct {
	k string
	v *string
}

func isArrayIndex(k string) bool {
	n, err := strconv.ParseUint(k, 10, 32)
	return err == nil && n < math.MaxUint32 && strconv.FormatUint(n, 10) == k
}

// formEncode is the application/x-www-form-urlencoded byte serializer (space = "+"; only *-._ and alphanumerics stay as is).
func formEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(wtfToUTF8(s)) { // URLSearchParams encodes a lone surrogate as U+FFFD
		switch {
		case c == ' ':
			b.WriteByte('+')
		case c == '*' || c == '-' || c == '.' || c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// formRequest keeps the non-empty values in object-key order (array-index names first, ascending, then insertion order; an
// extra parameter that repeats a name replaces its value in place).
func formRequest(url string, base []formEntry, extra []OAuthParam) OAuthFormRequest {
	list := append([]formEntry{}, base...)
	for _, p := range extra {
		v := p.Value
		replaced := false
		for i := range list {
			if list[i].k == p.Name {
				list[i].v, replaced = &v, true
			}
		}
		if !replaced {
			list = append(list, formEntry{p.Name, &v})
		}
	}
	var idx, rest []formEntry
	for _, e := range list {
		if e.v == nil || *e.v == "" {
			continue
		}
		if isArrayIndex(e.k) {
			idx = append(idx, e)
		} else {
			rest = append(rest, e)
		}
	}
	sort.SliceStable(idx, func(i, j int) bool {
		a, _ := strconv.ParseUint(idx[i].k, 10, 32)
		b, _ := strconv.ParseUint(idx[j].k, 10, 32)
		return a < b
	})
	params := map[string]string{}
	var body []string
	for _, e := range append(idx, rest...) {
		params[e.k] = *e.v
		body = append(body, formEncode(e.k)+"="+formEncode(*e.v))
	}
	return OAuthFormRequest{URL: url, Method: "POST", Headers: map[string]string{"content-type": "application/x-www-form-urlencoded", "accept": "application/json"},
		Params: params, Body: strings.Join(body, "&")}
}

// idJagScopeParam joins a scope (a space-separated string, or a list) into one parameter; nil when it names nothing.
func idJagScopeParam(scope any) (*string, error) {
	var parts []string
	switch s := scope.(type) {
	case nil:
		return nil, nil
	case string:
		parts = jsWSRun.Split(s, -1)
	case []string:
		parts = s
	case []any:
		for _, x := range s {
			if v, ok := x.(string); ok {
				parts = append(parts, v)
			}
		}
	default:
		return nil, errors.New("scope must be a string or a list of strings")
	}
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	if len(keep) == 0 {
		return nil, nil
	}
	j := strings.Join(keep, " ")
	return &j, nil
}

func strPtr(s string) *string { return &s }

// TokenExchangeRequestOptions build an RFC 8693 token exchange (subject token type defaults to an ID token, requested type to an
// ID-JAG, actor token type to a JWT). Scope is a space-separated string or a list. Empty values are left out.
type TokenExchangeRequestOptions struct {
	TokenEndpoint, SubjectToken                                                string
	SubjectTokenType, ActorToken, ActorTokenType, Audience, Resource, ClientID *string
	RequestedTokenType                                                         *string
	Scope                                                                      any
	Extra                                                                      []OAuthParam
}

// TokenExchangeRequest builds the token-exchange form request.
func TokenExchangeRequest(o TokenExchangeRequestOptions) (*OAuthFormRequest, error) {
	if o.TokenEndpoint == "" {
		return nil, errors.New("tokenExchangeRequest: opts.tokenEndpoint is required")
	}
	if o.SubjectToken == "" {
		return nil, errors.New("tokenExchangeRequest: opts.subjectToken is required")
	}
	or := func(p *string, def string) *string {
		if p != nil {
			return p
		}
		return &def
	}
	scope, err := idJagScopeParam(o.Scope)
	if err != nil {
		return nil, err
	}
	base := []formEntry{{"grant_type", strPtr(GrantTypeTokenExchange)}, {"subject_token", &o.SubjectToken},
		{"subject_token_type", or(o.SubjectTokenType, TokenTypeIDToken)}, {"requested_token_type", or(o.RequestedTokenType, TokenTypeIDJag)},
		{"audience", o.Audience}, {"resource", o.Resource}, {"scope", scope}}
	if o.ActorToken != nil && *o.ActorToken != "" {
		base = append(base, formEntry{"actor_token", o.ActorToken}, formEntry{"actor_token_type", or(o.ActorTokenType, TokenTypeJWT)})
	}
	base = append(base, formEntry{"client_id", o.ClientID})
	r := formRequest(o.TokenEndpoint, base, o.Extra)
	return &r, nil
}

// JwtBearerAssertionOptions build an RFC 7523 jwt-bearer grant presenting an ID-JAG.
type JwtBearerAssertionOptions struct {
	TokenEndpoint, Assertion string
	Scope                    any
	ClientID                 *string
	ClientAssertion          string
	Extra                    []OAuthParam
}

// JwtBearerAssertion builds the jwt-bearer request: {grantType, assertion, scope?, request}.
func JwtBearerAssertion(o JwtBearerAssertionOptions) (map[string]any, error) {
	if o.TokenEndpoint == "" {
		return nil, errors.New("jwtBearerAssertion: opts.tokenEndpoint is required")
	}
	if o.Assertion == "" {
		return nil, errors.New("jwtBearerAssertion: opts.assertion is required")
	}
	scope, err := idJagScopeParam(o.Scope)
	if err != nil {
		return nil, err
	}
	base := []formEntry{{"grant_type", strPtr(GrantTypeJWTBearer)}, {"assertion", &o.Assertion}, {"scope", scope}, {"client_id", o.ClientID}}
	if o.ClientAssertion != "" {
		base = append(base, formEntry{"client_assertion_type", strPtr(ClientAssertionTypeJWTBearer)}, formEntry{"client_assertion", &o.ClientAssertion})
	}
	out := map[string]any{"grantType": GrantTypeJWTBearer, "assertion": o.Assertion, "request": formRequest(o.TokenEndpoint, base, o.Extra)}
	if scope != nil {
		out["scope"] = *scope
	}
	return out, nil
}
