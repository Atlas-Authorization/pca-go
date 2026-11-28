package pca

// Replays the SPIFFE reference corpus. Adapter conventions follow the corpus header: vo shapes,
// revocation modes ('false' | 'true' | 'at:N' | 'throw' | 'nonbool'; a present null is a non-function value, which a Go func
// field cannot express), recorded calls, key {jwk} | {jwks}, and scripted fetch steps ({$throw} | {$spiffe: code}).

import (
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// spiffeRev decodes {"$bytes": b64url} into bytes (an empty string too); anything else is returned as is.
func spiffeRev(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return v
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return v
	}
	return b
}

func spiffeRevList(v any) any {
	l, ok := v.([]any)
	if !ok {
		return v
	}
	out := make([]any, len(l))
	for i, x := range l {
		out[i] = spiffeRev(x)
	}
	return out
}

// spiffeRevMode: ok false = a present non-function revocation value (not expressible in Go).
func spiffeRevMode(vo map[string]any, calls *[]any) (x func(X509RevocationSubject) (bool, error), j func(JwtRevocationSubject) (bool, error), ok bool) {
	raw, has := vo["revocation"]
	if !has {
		return nil, nil, true
	}
	mode, isStr := raw.(string)
	if !isStr {
		return nil, nil, false
	}
	at := -1.0
	if strings.HasPrefix(mode, "at:") {
		at, _ = parseJSNumberLexeme(mode[3:])
	}
	verdict := func(subject any, pos int) (bool, error) {
		*calls = append(*calls, vecJSON(subject))
		switch {
		case mode == "throw":
			return false, errors.New("backend down")
		case mode == "nonbool":
			return false, errors.New("revocation check did not return a boolean")
		case mode == "true":
			return true, nil
		case at >= 0:
			return float64(pos) == at, nil
		}
		return false, nil
	}
	x = func(s X509RevocationSubject) (bool, error) { return verdict(s, s.Position) }
	j = func(s JwtRevocationSubject) (bool, error) { return verdict(s, -1) }
	return x, j, true
}

func spiffeXO(vo map[string]any, calls *[]any) (VerifyX509SvidOptions, error) {
	o := VerifyX509SvidOptions{TrustDomain: vecStr(vo, "trustDomain")}
	if l, ok := spiffeRevList(vo["roots"]).([]any); ok {
		o.Roots = l
	}
	if f, ok := jsNum(vo["nowMs"]); ok {
		o.Now = time.UnixMilli(int64(f))
	}
	if f, ok := jsNum(vo["maxChainLength"]); ok {
		n := int(f)
		o.MaxChainLength = &n
	}
	x, _, ok := spiffeRevMode(vo, calls)
	if !ok {
		return o, vecSkip("a non-function revocation value: a nil Go func means unset")
	}
	o.Revocation = x
	return o, nil
}

func spiffeJO(vo map[string]any, calls *[]any) (VerifyJwtSvidOptions, error) {
	o := VerifyJwtSvidOptions{TrustDomain: vecStr(vo, "trustDomain")}
	switch a := vo["audience"].(type) {
	case string:
		o.Audience = []string{a}
	case []any:
		o.Audience = vecStrs(vo, "audience")
	}
	if key := vecObj(vo["key"]); key != nil {
		if jwk := vecObj(key["jwk"]); jwk != nil {
			k, err := ImportPublicJWK(jwk)
			if err != nil {
				return o, err
			}
			o.Key = func(map[string]any) (*JOSEKey, error) { return k, nil }
		} else if jwks, has := key["jwks"]; has {
			r, err := NewLocalJWKSet(jwks)
			if err != nil {
				return o, err
			}
			o.Key = r
		}
	}
	if f, ok := jsNum(vo["currentSec"]); ok {
		o.CurrentDate = time.UnixMilli(int64(f * 1000))
	}
	if a, has := vo["algorithms"]; has {
		if _, ok := a.([]any); !ok {
			return o, vecSkip("a non-list algorithms value is a Go type error")
		}
		o.Algorithms = vecStrs(vo, "algorithms")
	}
	o.ClockTolerance = vo["clockTolerance"]
	_, j, ok := spiffeRevMode(vo, calls)
	if !ok {
		return o, vecSkip("a non-function revocation value: a nil Go func means unset")
	}
	o.Revocation = j
	return o, nil
}

func spiffeIDOut(i SpiffeID) map[string]any {
	return map[string]any{"id": i.ID, "trustDomain": i.TrustDomain, "path": i.Path}
}

func spiffeBind(v any) SvidToHolderOptions {
	m := vecObj(v)
	return SvidToHolderOptions{Proof: vecStr(m, "proof"), AcceptUnboundJwtHolder: m["acceptUnboundJwtHolder"] == true}
}

func spiffeHolderKey(v any) any {
	if v == nil {
		return nil
	}
	return spiffeRev(v)
}

func spiffeX509(chain any, vo any) (*X509Svid, []any, error) {
	calls := []any{}
	o, err := spiffeXO(vecObj(vo), &calls)
	if err != nil {
		return nil, nil, err
	}
	s, err := VerifyX509Svid(spiffeRevList(chain), o)
	return s, calls, err
}

func spiffeJwt(token any, vo any) (*JwtSvid, []any, error) {
	calls := []any{}
	o, err := spiffeJO(vecObj(vo), &calls)
	if err != nil {
		return nil, nil, err
	}
	t, ok := token.(string)
	if !ok {
		return nil, nil, vecSkip("a non-string token is a Go type error")
	}
	s, err := VerifyJwtSvid(t, o)
	return s, calls, err
}

func spiffeStepErr(err error) any {
	var ce *CodedError
	if errors.As(err, &ce) && ce.Code != "" {
		return ce.Code
	}
	return nil
}

// spiffeFetch is a scripted fetch: the current step's value, {$throw: text} or {$spiffe: code}; it counts its calls.
func spiffeFetch(cur *any, fetches *int) func() (any, error) {
	return func() (any, error) {
		*fetches++
		if m, ok := (*cur).(map[string]any); ok {
			if t, has := m["$throw"]; has {
				return nil, errors.New(jsValueString(t))
			}
			if c, has := m["$spiffe"].(string); has {
				return nil, &CodedError{Code: c, Msg: "x"}
			}
		}
		return *cur, nil
	}
}

func spiffeWindow(opts map[string]any, k string) float64 {
	if f, ok := jsNum(opts[k]); ok {
		return f
	}
	return math.NaN()
}

func spiffeRevSubjectX(v any) X509RevocationSubject {
	m := vecObj(v)
	p, _ := jsNum(m["position"])
	return X509RevocationSubject{SpiffeID: vecStr(m, "spiffeId"), SerialNumber: vecStr(m, "serialNumber"), Fingerprint256: vecStr(m, "fingerprint256"), Position: int(p), IsLeaf: m["isLeaf"] == true}
}

func spiffeRevSubjectJ(v any) JwtRevocationSubject {
	m := vecObj(v)
	e, _ := jsNum(m["expiresAt"])
	s := JwtRevocationSubject{SpiffeID: vecStr(m, "spiffeId"), ExpiresAt: e, TokenHash: vecStr(m, "tokenHash")}
	if j, ok := m["jti"].(string); ok {
		s.Jti = &j
	}
	return s
}

func TestSpiffeVectors(t *testing.T) {
	replayVectors(t, "ref-spiffe-svid.json.gz", map[string]vecFn{
		"parseSpiffeId": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			id, err := ParseSpiffeID(s)
			return spiffeIDOut(id), err
		},
		"parseX509Svid": func(a []any) (any, error) {
			s, err := ParseX509Svid(spiffeRev(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return map[string]any{"spiffeId": spiffeIDOut(s.SpiffeID), "publicKeyDer": s.PublicKeyDer}, nil
		},
		"verifyX509Svid": func(a []any) (any, error) {
			s, calls, err := spiffeX509(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			out := spiffeIDOut(s.SpiffeID)
			out["publicKeyDer"], out["calls"] = s.PublicKeyDer, calls
			return out, nil
		},
		"verifyJwtSvid": func(a []any) (any, error) {
			s, calls, err := spiffeJwt(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return map[string]any{"spiffeId": spiffeIDOut(s.SpiffeID), "claims": s.Claims, "audience": s.Audience, "expiresAt": s.ExpiresAt, "calls": calls}, nil
		},
		"svidToHolderX509": func(a []any) (any, error) {
			s, _, err := spiffeX509(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return SvidToHolder(s, spiffeHolderKey(vecArg(a, 2)), spiffeBind(vecArg(a, 3)))
		},
		"svidToHolderJwt": func(a []any) (any, error) {
			s, _, err := spiffeJwt(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return SvidToHolder(s, spiffeHolderKey(vecArg(a, 2)), spiffeBind(vecArg(a, 3)))
		},
		"svidToHolderUnverified": func(a []any) (any, error) {
			const id = "spiffe://example.org/workload/db"
			var v any
			switch k, _ := vecArg(a, 0).(string); k {
			case "string":
				v = id
			case "object", "parsed jwt-like":
				p, _ := ParseSpiffeID(id)
				v = map[string]any{"spiffeId": p}
			case "number":
				v = 5
			case "parsed", "parsed built":
				s, err := ParseX509Svid(vecArg(a, 1))
				if err != nil {
					return nil, err
				}
				v = s
			}
			return SvidToHolder(v, "NdQrWOmikoF0DqDFEK2vMLAjX2TEdbAk2yigAcMDoX8", SvidToHolderOptions{})
		},
		"spiffeIdForHolder": func(a []any) (any, error) {
			s, _, err := spiffeX509(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			h, _ := vecArg(a, 2).(string)
			return SpiffeIDForHolder(s, h, spiffeBind(vecArg(a, 3)))
		},
		"workloadDischargePin": func(a []any) (any, error) {
			s, _, err := spiffeX509(vecArg(a, 1), vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			l, _ := vecArg(a, 0).(string)
			return WorkloadDischargePin(l, s)
		},
		"holderToSpiffeId": func(a []any) (any, error) {
			return HolderToSpiffeID(SpiffeHolder{SpiffeID: vecStr(vecObj(vecArg(a, 0)), "spiffeId")})
		},
		"holderBindingMessage": func(a []any) (any, error) {
			x, _ := vecArg(a, 0).(string)
			y, _ := vecArg(a, 1).(string)
			return map[string]any{"$bytes": b64.EncodeToString(HolderBindingMessage(x, y))}, nil
		},
		"spiffeAdmissionEvidence": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 0))
			calls := []any{}
			e := SpiffeEvidence{Kind: vecStr(m, "kind"), Chain: spiffeRevList(m["chain"]), Token: vecStr(m, "token"), Bind: spiffeBind(m["bind"])}
			var err error
			if e.Kind == "x509" {
				e.X509, err = spiffeXO(vecObj(m["verify"]), &calls)
			} else {
				e.Jwt, err = spiffeJO(vecObj(m["verify"]), &calls)
			}
			if err != nil {
				return nil, err
			}
			k, _ := vecArg(a, 1).(string)
			return SpiffeAdmissionEvidence(e, k), nil
		},
		"trustBundleScenario": func(a []any) (any, error) {
			opts := vecObj(vecArg(a, 0))
			var cur any
			fetches := 0
			t := 0.0
			src, err := NewSpiffeTrustBundleSource(SpiffeTrustBundleSourceOptions{Fetch: spiffeFetch(&cur, &fetches), RefreshMs: spiffeWindow(opts, "refreshMs"),
				MaxStaleMs: spiffeWindow(opts, "maxStaleMs"), Now: func() float64 { return t }})
			if err != nil {
				return map[string]any{"ctor": spiffeStepErr(err)}, nil
			}
			out := []any{}
			steps, _ := vecArg(a, 1).([]any)
			for _, st := range steps {
				s := vecObj(st)
				t, _ = jsNum(s["at"])
				cur, fetches = s["fetch"], 0
				if s["op"] == "x509Roots" {
					r, err := src.X509Roots()
					if err != nil {
						out = append(out, map[string]any{"code": spiffeStepErr(err), "fetches": fetches})
					} else {
						out = append(out, map[string]any{"ok": r, "fetches": fetches})
					}
					continue
				}
				h := vecObj(s["header"])
				if h == nil {
					h = map[string]any{"alg": "ES256"}
				}
				if _, err := src.JwtKey(h); err != nil {
					out = append(out, map[string]any{"code": spiffeStepErr(err), "fetches": fetches})
				} else {
					out = append(out, map[string]any{"ok": "key", "fetches": fetches})
				}
			}
			return map[string]any{"steps": out}, nil
		},
		"revocationScenario": func(a []any) (any, error) {
			opts := vecObj(vecArg(a, 0))
			var cur any
			fetches := 0
			t := 0.0
			src, err := NewSpiffeRevocationSource(SpiffeRevocationSourceOptions{Fetch: spiffeFetch(&cur, &fetches), RefreshMs: spiffeWindow(opts, "refreshMs"),
				MaxStaleMs: spiffeWindow(opts, "maxStaleMs"), Now: func() float64 { return t }})
			if err != nil {
				return map[string]any{"ctor": spiffeStepErr(err)}, nil
			}
			out := []any{}
			steps, _ := vecArg(a, 1).([]any)
			for _, st := range steps {
				s := vecObj(st)
				t, _ = jsNum(s["at"])
				cur, fetches = s["fetch"], 0
				var v any
				var err error
				switch s["op"] {
				case "ensureFresh":
					err = src.EnsureFresh()
				case "refresh":
					err = src.Refresh()
				case "x509":
					v, err = src.X509(spiffeRevSubjectX(s["subject"]))
				default:
					v, err = src.Jwt(spiffeRevSubjectJ(s["subject"]))
				}
				if err != nil {
					out = append(out, map[string]any{"code": spiffeStepErr(err), "fetches": fetches})
				} else {
					out = append(out, map[string]any{"ok": v, "fetches": fetches})
				}
			}
			return map[string]any{"steps": out}, nil
		},
		"constants": func([]any) (any, error) {
			return map[string]any{"jwtSvidAlgorithms": JwtSvidAlgorithms}, nil
		},
	})
}
