package pca

// Replays the reference oracle of the ID-JAG bridge (testdata/ref-idjag.json.gz). Options arrive JS-typed and are mapped as in
// the OIDC replay; consumeJti {mode: fresh|seen|throw|truthy} is a scripted single-use store. The order of an `extra` object's
// members (which fixes the order of the form body) is read from the raw corpus, as a parsed Go map does not keep it.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
)

// vecRawArgs indexes a corpus's raw case arguments by the canonical form of the parsed arguments.
func vecRawArgs(t *testing.T, file string) map[string][]json.RawMessage {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Args []json.RawMessage `json:"args"`
		} `json:"cases"`
	}
	if err := json.NewDecoder(z).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	out := map[string][]json.RawMessage{}
	for _, c := range doc.Cases {
		var parsed []any
		for _, r := range c.Args {
			v, err := ParseJSONLenient(r)
			if err != nil {
				t.Fatal(err)
			}
			parsed = append(parsed, normalizeJSON(v))
		}
		out[baseCanon(parsed)] = c.Args
	}
	return out
}

// vecObjectKeys lists the members of a raw JSON object in document order.
func vecObjectKeys(raw json.RawMessage) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.Token() // {
	var keys []string
	for d.More() {
		k, _ := d.Token()
		keys = append(keys, k.(string))
		var skip json.RawMessage
		d.Decode(&skip)
	}
	return keys
}

// vecExtra is the reference's `...(opts.extra ?? {})`: an object's members in order, an array's or string's indices; a value
// that is not a string is dropped (as the reference's clean step drops it).
func vecExtra(v any, rawOpts json.RawMessage) []OAuthParam {
	var out []OAuthParam
	str := func(x any) string { s, _ := x.(string); return s }
	switch e := v.(type) {
	case map[string]any:
		var members map[string]json.RawMessage
		json.Unmarshal(rawOpts, &members)
		for _, k := range vecObjectKeys(members["extra"]) {
			out = append(out, OAuthParam{k, str(e[k])})
		}
	case []any:
		for i, x := range e {
			out = append(out, OAuthParam{strconv.Itoa(i), str(x)})
		}
	case string:
		for i, u := range utf16Units(e) {
			out = append(out, OAuthParam{strconv.Itoa(i), string(rune(u))})
		}
	}
	return out
}

func vecPtrIfPresent(m map[string]any, k string) *string {
	v, has := m[k]
	if !has || v == nil {
		return nil
	}
	s, _ := v.(string)
	return &s
}

func idJagVerifyOpts(v any) (VerifyIdJagOptions, error) {
	var o VerifyIdJagOptions
	m, ok := v.(map[string]any)
	if !ok {
		if _, arr := v.([]any); !arr {
			return o, oidcErr("config", "verifyIdJag: opts is required")
		}
	}
	o.Issuer, _ = m["issuer"].(string)
	o.Audience, _ = m["audience"].(string)
	o.ClientID, _ = m["clientId"].(string)
	o.Nonce = oidcStrOpt(m, "nonce")
	if l, ok := m["requiredScopes"].([]any); ok {
		o.RequiredScopes = []string{}
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				s = oidcNoMatch
			}
			o.RequiredScopes = append(o.RequiredScopes, s)
		}
	}
	o.StrictDraft = oidcFalseOnly(m, "strictDraft")
	if x, has := m["algorithms"]; has {
		switch a := x.(type) {
		case string:
			o.Algorithms = []string{}
			for _, r := range a {
				o.Algorithms = append(o.Algorithms, string(r))
			}
		case []any:
			o.Algorithms = []string{}
			for _, e := range a {
				s, ok := e.(string)
				if !ok {
					s = oidcNoMatch
				}
				o.Algorithms = append(o.Algorithms, s)
			}
		default:
			return o, oidcErr("invalid_token", "ID-JAG verification failed")
		}
	}
	if x, has := m["maxTokenAgeSec"]; has && jsTruthy(x) {
		f, ok := jsNum(x)
		if !ok {
			return o, oidcErr("invalid_token", "id token verification failed")
		}
		o.MaxTokenAgeSec = &f
	}
	if x, has := m["clockToleranceSec"]; has {
		f, ok := jsNum(x)
		if !ok {
			return o, oidcErr("invalid_token", "id token verification failed")
		}
		o.ClockToleranceSec = &f
	}
	if x, has := m["jwksUri"]; has {
		s, _ := x.(string)
		o.JwksURI = &s
	}
	o.Discover = m["discover"] == true
	if f, has := m["fetch"]; has {
		o.Fetch = oidcMockFetch(f, nil)
	}
	if cj, ok := m["consumeJti"].(map[string]any); ok {
		if mode, has := cj["mode"]; has {
			o.ConsumeJti = func(string, float64) (bool, error) {
				switch mode {
				case "throw":
					return false, errors.New("store down")
				case "fresh":
					return true, nil
				}
				return false, nil // "seen", and "truthy" (a truthy non-true reply is not fresh)
			}
		}
	}
	if k, has := m["key"]; has {
		if km, ok := k.(map[string]any); ok && km["jwks"] != nil {
			r, err := NewLocalJWKSet(km["jwks"])
			if err != nil {
				return o, err
			}
			o.Key = r
		} else {
			o.Key = k
		}
	}
	return o, nil
}

func TestIdJagVectors(t *testing.T) {
	const file = "ref-idjag.json.gz"
	raw := vecRawArgs(t, "testdata/"+file)
	rawOpts := func(a []any) json.RawMessage {
		if r := raw[baseCanon(a)]; len(r) > 0 {
			return r[0]
		}
		return nil
	}
	replayVectors(t, file, map[string]vecFn{
		"verifyIdJag": func(a []any) (any, error) {
			jwt, _ := vecArg(a, 0).(string)
			if jwt == "" {
				return nil, oidcErr("invalid_token", "verifyIdJag: jwt must be a non-empty string")
			}
			if jsLen(jwt) > MaxIDJagChars {
				return nil, oidcErr("invalid_token", "verifyIdJag: jwt exceeds the size limit")
			}
			o, err := idJagVerifyOpts(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return VerifyIdJag(jwt, o)
		},
		"idJagToPcaPrincipal": func(a []any) (any, error) {
			g, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("grant is required")
			}
			var pub *string
			if len(a) > 1 {
				if a[1] == nil {
					return nil, errors.New("opts is null")
				}
				if x, has := vecObj(a[1])["principalPublic"]; has {
					s, _ := x.(string)
					pub = &s
				}
			}
			return IdJagToPcaPrincipal(g, pub)
		},
		"idJagToCapability": func(a []any) (any, error) {
			g, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("grant is required")
			}
			om, ok := vecArg(a, 1).(map[string]any)
			if !ok {
				return nil, errors.New("opts is required")
			}
			var o IdJagCapabilityOptions
			if b, ok := om["principalSecret"].(map[string]any); ok {
				if s, ok := b["$bytes"].(string); ok {
					o.PrincipalSecret, _ = base64.RawURLEncoding.DecodeString(s)
				}
			}
			o.PrincipalPublic, _ = om["principalPublic"].(string)
			o.Holder, _ = om["holder"].(string)
			o.ExtraCaveats, _ = om["extraCaveats"].([]any)
			return IdJagToCapability(g, o)
		},
		"isIdJagAuthorityCaveat":  func(a []any) (any, error) { return IsIdJagAuthorityCaveat(vecArg(a, 0)), nil },
		"isIdJagProvenanceCaveat": func(a []any) (any, error) { return IsIdJagProvenanceCaveat(vecArg(a, 0)), nil },
		"readIdJagAuthority":      func(a []any) (any, error) { return ReadIdJagAuthority(vecArg(a, 0)) },
		"readIdJagProvenance":     func(a []any) (any, error) { return ReadIdJagProvenance(vecArg(a, 0)) },
		"tokenExchangeRequest": func(a []any) (any, error) {
			m, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("opts is required")
			}
			o := TokenExchangeRequestOptions{SubjectTokenType: vecPtrIfPresent(m, "subjectTokenType"), ActorToken: vecPtrIfPresent(m, "actorToken"),
				ActorTokenType: vecPtrIfPresent(m, "actorTokenType"), Audience: vecPtrIfPresent(m, "audience"), Resource: vecPtrIfPresent(m, "resource"),
				ClientID: vecPtrIfPresent(m, "clientId"), RequestedTokenType: vecPtrIfPresent(m, "requestedTokenType"), Scope: m["scope"],
				Extra: vecExtra(m["extra"], rawOpts(a))}
			o.TokenEndpoint, _ = m["tokenEndpoint"].(string)
			o.SubjectToken, _ = m["subjectToken"].(string)
			return TokenExchangeRequest(o)
		},
		"jwtBearerAssertion": func(a []any) (any, error) {
			m, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("opts is required")
			}
			o := JwtBearerAssertionOptions{Scope: m["scope"], ClientID: vecPtrIfPresent(m, "clientId"), Extra: vecExtra(m["extra"], rawOpts(a))}
			o.TokenEndpoint, _ = m["tokenEndpoint"].(string)
			o.Assertion, _ = m["assertion"].(string)
			o.ClientAssertion, _ = m["clientAssertion"].(string)
			return JwtBearerAssertion(o)
		},
		"constants": func([]any) (any, error) {
			return map[string]any{"MAX_ID_JAG_CHARS": MaxIDJagChars, "IDJAG_AUTHORITY_CAVEAT": IDJagAuthorityCaveat, "IDJAG_PROVENANCE_CAVEAT": IDJagProvenanceCaveat,
				"GRANT_TYPE_TOKEN_EXCHANGE": GrantTypeTokenExchange, "GRANT_TYPE_JWT_BEARER": GrantTypeJWTBearer, "TOKEN_TYPE_ID_JAG": TokenTypeIDJag,
				"TOKEN_TYPE_ID_TOKEN": TokenTypeIDToken, "TOKEN_TYPE_ACCESS_TOKEN": TokenTypeAccessToken, "TOKEN_TYPE_JWT": TokenTypeJWT,
				"CLIENT_ASSERTION_TYPE_JWT_BEARER": ClientAssertionTypeJWTBearer}, nil
		},
	})
}
