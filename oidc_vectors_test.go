package pca

// Replays the reference oracle of the OIDC bridge (testdata/ref-oidc.json.gz). The corpus carries the reference's dynamically
// typed options; the adapters below turn them into the typed Go options (a value of the wrong JS type becomes what the reference
// does with it: an unmatched sentinel, an absent option, or the refusal it raises). Function-valued options travel as specs:
// key {jwks} = NewLocalJWKSet, key {resolver} = CreateOidcJwks, fetch {responses: [...]} = a scripted fetcher (the last reply repeats).

import (
	"encoding/base64"
	"errors"
	"math"
	"testing"
)

const oidcNoMatch = "\x00not-a-string" // a reference option of a non-string type: compared with ===, it never matches

func oidcMockFetch(spec any, calls *[]string) OidcFetch {
	rs, _ := vecObj(spec)["responses"].([]any)
	i := 0
	return func(r OidcFetchRequest) (*OidcFetchResponse, error) {
		if calls != nil {
			*calls = append(*calls, r.URL)
		}
		if len(rs) == 0 {
			return nil, errors.New("no scripted reply")
		}
		x := vecObj(rs[min(i, len(rs)-1)])
		i++
		if jsTruthy(x["throws"]) {
			return nil, errors.New("boom")
		}
		st, _ := jsNum(x["status"])
		h := map[string]string{}
		for k, v := range vecObj(x["headers"]) {
			h[jsLowerASCII(k)], _ = v.(string)
		}
		return &OidcFetchResponse{Status: int(st), Headers: h, Body: vecStr(x, "body")}, nil
	}
}

func jsLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func oidcStrOpt(m map[string]any, k string) *string {
	v, has := m[k]
	if !has {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		s = oidcNoMatch
	}
	return &s
}

func oidcFalseOnly(m map[string]any, k string) *bool {
	if b, ok := m[k].(bool); ok && !b {
		return &b
	}
	return nil
}

// oidcNumOpt: absent = nil; a number = it; another type = NaN (refused by the option check).
func oidcNumOpt(m map[string]any, k string) *float64 {
	v, has := m[k]
	if !has {
		return nil
	}
	f, ok := jsNum(v)
	if !ok {
		f = math.NaN()
	}
	return &f
}

func oidcJwksOpts(m map[string]any) OidcJwksOptions {
	uri, _ := m["jwksUri"].(string)
	return OidcJwksOptions{JwksURI: uri, CacheMaxAgeSec: oidcNumOpt(m, "cacheMaxAgeSec"), CooldownSec: oidcNumOpt(m, "cooldownSec"),
		MaxBytes: oidcNumOpt(m, "maxBytes"), TimeoutMs: oidcNumOpt(m, "timeoutMs"), RequireHttps: oidcFalseOnly(m, "requireHttps")}
}

func oidcVerifyOpts(v any) (VerifyIdTokenOptions, error) {
	var o VerifyIdTokenOptions
	m, ok := v.(map[string]any)
	if !ok {
		if _, arr := v.([]any); !arr {
			return o, oidcErr("config", "verifyIdToken: opts is required")
		}
	}
	o.Issuer, _ = m["issuer"].(string)
	frozen := vecOracleNow() / 1000 // the generator's frozen clock, so a case that depends on the time is replayed at that time
	o.NowSec = &frozen
	switch a := m["audience"].(type) {
	case string:
		o.Audience = &a
	case []any:
		o.Audiences = []string{}
		for _, x := range a {
			s, ok := x.(string)
			if !ok {
				s = oidcNoMatch
			}
			o.Audiences = append(o.Audiences, s)
		}
	}
	o.Nonce, o.AuthorizedParty = oidcStrOpt(m, "nonce"), oidcStrOpt(m, "authorizedParty")
	for _, k := range []string{"accessToken", "code"} {
		if x, has := m[k]; has {
			if _, ok := x.(string); !ok {
				return o, &CodedError{Code: "ERR_INVALID_ARG_TYPE", Msg: "the hashed value must be a string"}
			}
		}
	}
	o.AccessToken, o.Code = oidcStrOpt(m, "accessToken"), oidcStrOpt(m, "code")
	if x, has := m["algorithms"]; has {
		switch a := x.(type) {
		case string: // spread into its characters
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
			return o, errors.New("algorithms is not iterable")
		}
	}
	if x, has := m["maxTokenAgeSec"]; has {
		// the reference's `!(x >= 0)` coerces (true is 1, [] and null are 0): what coerces to NaN or below zero is a config refusal; a
		// truthy non-number that passes the check (true, []) is then rejected by the JWT library as an invalid token; a falsy one is ignored
		if n := jsToNumber(x); !(n >= 0) {
			f := math.NaN()
			o.MaxTokenAgeSec = &f
		} else if f, ok := jsNum(x); ok {
			if jsTruthy(x) {
				o.MaxTokenAgeSec = &f
			}
		} else if jsTruthy(x) {
			return o, oidcErr("invalid_token", "id token verification failed")
		}
	}
	if x, has := m["clockToleranceSec"]; has {
		f, ok := jsNum(x)
		if !ok {
			f = math.NaN() // not a number: the verifier refuses it as a config error
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
	o.RequireHttps = oidcFalseOnly(m, "requireHttps")
	if k, has := m["key"]; has {
		km, isObj := k.(map[string]any)
		switch {
		case isObj && len(km) == 1 && km["$bytes"] != nil:
			b, err := base64.RawURLEncoding.DecodeString(vecStr(km, "$bytes"))
			if err != nil {
				return o, err
			}
			o.Key = b
		case isObj && km["jwks"] != nil:
			r, err := NewLocalJWKSet(km["jwks"])
			if err != nil {
				return o, err
			}
			o.Key = r
		case isObj && km["resolver"] != nil:
			rs := vecObj(km["resolver"])
			jo := oidcJwksOpts(rs)
			jo.Fetch = oidcMockFetch(rs["fetch"], nil)
			r, err := CreateOidcJwks(jo)
			if err != nil {
				return o, err
			}
			o.Key = r
		default:
			o.Key = k
		}
	}
	return o, nil
}

func oidcStep(r OidcKeyResolver, header any) map[string]any {
	k, err := r(vecObj(header))
	if err != nil {
		var ce *CodedError
		if errors.As(err, &ce) && ce.Code == "keys" {
			return map[string]any{"err": "keys"}
		}
		return map[string]any{"err": "other"}
	}
	return map[string]any{"ok": ExportPublicJWK(k)}
}

func oidcDiscoverOpts(v any) (DiscoverOidcOptions, error) {
	var o DiscoverOidcOptions
	if v == nil {
		return o, errors.New("opts is null")
	}
	m := vecObj(v)
	if f, has := m["fetch"]; has {
		o.Fetch = oidcMockFetch(f, nil)
	}
	if x, has := m["maxBytes"]; has {
		f := jsToNumber(x)
		o.MaxBytes = &f
	}
	o.RequireHttps = oidcFalseOnly(m, "requireHttps")
	return o, nil
}

func TestOidcVectors(t *testing.T) {
	replayVectors(t, "ref-oidc.json.gz", map[string]vecFn{
		"verifyIdToken": func(a []any) (any, error) {
			tok, _ := vecArg(a, 0).(string)
			if tok == "" {
				return nil, oidcErr("invalid_token", "verifyIdToken: idToken must be a non-empty string")
			}
			o, err := oidcVerifyOpts(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return VerifyIdToken(tok, o)
		},
		"discoveryUrl": func(a []any) (any, error) {
			s, ok := vecArg(a, 0).(string)
			if !ok {
				return nil, errors.New("issuer is not a string")
			}
			return OidcDiscoveryURL(s), nil
		},
		"discoverOidc": func(a []any) (any, error) {
			o, err := oidcDiscoverOpts(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			iss, _ := vecArg(a, 0).(string)
			return DiscoverOidc(iss, o)
		},
		"discoverOidcCalls": func(a []any) (any, error) {
			op := vecObj(vecArg(a, 1))
			urls := []string{}
			o, _ := oidcDiscoverOpts(op)
			o.Fetch = oidcMockFetch(op["fetch"], &urls)
			iss, _ := vecArg(a, 0).(string)
			outcome := "ok"
			if _, err := DiscoverOidc(iss, o); err != nil {
				outcome = "error"
			}
			return map[string]any{"urls": urls, "outcome": outcome}, nil
		},
		"createOidcJwks": func(a []any) (any, error) {
			s := vecObj(vecArg(a, 0))
			jo := oidcJwksOpts(vecObj(s["opts"]))
			jo.JwksURI, _ = s["jwksUri"].(string)
			clock, fetches := 0.0, 0
			inner := oidcMockFetch(s["fetch"], nil)
			jo.Fetch = func(r OidcFetchRequest) (*OidcFetchResponse, error) { fetches++; return inner(r) }
			jo.Now = func() float64 { return clock }
			r, err := CreateOidcJwks(jo)
			if err != nil {
				return nil, err
			}
			steps := []any{}
			for _, st := range vecArgList(s["steps"]) {
				clock, _ = jsNum(vecObj(st)["atMs"])
				steps = append(steps, oidcStep(r, vecObj(st)["header"]))
			}
			return map[string]any{"steps": steps, "fetches": fetches}, nil
		},
		"createOidcJwksFromIssuer": func(a []any) (any, error) {
			s := vecObj(vecArg(a, 0))
			urls := []string{}
			jo := oidcJwksOpts(vecObj(s["opts"]))
			jo.Fetch = oidcMockFetch(s["fetch"], &urls)
			iss, _ := s["issuer"].(string)
			r, err := CreateOidcJwksFromIssuer(iss, jo)
			if err != nil {
				return nil, err
			}
			return map[string]any{"out": oidcStep(r, s["header"]), "urls": urls}, nil
		},
		"oidcPrincipal": func(a []any) (any, error) {
			c := vecArg(a, 0)
			if c == nil {
				return nil, errors.New("claims is null")
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
			return OidcPrincipal(vecObj(c), pub)
		},
		"isOidcSubjectCaveat": func(a []any) (any, error) { return IsOidcSubjectCaveat(vecArg(a, 0)), nil },
		"constants": func([]any) (any, error) {
			return map[string]any{"DEFAULT_ID_TOKEN_ALGS": DefaultIDTokenAlgs, "DEFAULT_MAX_DISCOVERY_BYTES": DefaultMaxDiscoveryBytes,
				"DEFAULT_JWKS_TIMEOUT_MS": DefaultJwksTimeoutMs, "OIDC_SUBJECT_CAVEAT": OidcSubjectCaveat}, nil
		},
	})
}

func vecArgList(v any) []any { l, _ := v.([]any); return l }
