package pca

// Replays the gateway reference corpus: the request binding, canonical query, path hardening, replay guard, provenance log, the
// decision pipeline over real signed proofs (signature-only mode) and the Envoy / Lambda shapes. Verdict objects and the strict-JSON
// parser's own message are masked (the native verdict lists its own check names).
//
// Not replayed: full-policy mode beyond its missing-component report (the corpus has no state store), the Cloudflare Worker adapter.

import (
	"errors"
	"strings"
	"testing"
)

func gwTestReq(m map[string]any) GatewayRequest {
	r := GatewayRequest{Method: vecStr(m, "method"), Path: vecStr(m, "path"), Query: gwStrPtr(m["query"]), Authority: gwStrPtr(m["authority"]),
		BodySha256: gwStrPtr(m["bodySha256"]), Body: gwStrPtr(m["body"])}
	if h, ok := m["headers"].(map[string]any); ok {
		r.Headers = h
	}
	return r
}

func gwTestBind(v any) *GatewayBindOptions {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	b := &GatewayBindOptions{Authority: m["authority"] == true}
	if x, has := m["body"]; has {
		t := x == true
		b.Body = &t
	}
	return b
}

func gwTestMask(v any) any {
	switch t := v.(type) {
	case string:
		const p = "undecodable PCA-Action header: "
		if i := strings.Index(t, p); i >= 0 && !strings.HasPrefix(t[i+len(p):], "PCA-Action header") {
			return t[:i+len(p)] + "<json>"
		}
		return t
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = gwTestMask(x)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			if s, ok := x.(string); (k == "x-pca-verdict" || k == "pcaVerdict") && ok && s != "" {
				out[k] = "<verdict>"
			} else {
				out[k] = gwTestMask(x)
			}
		}
		if h, ok := out["header"].(map[string]any); ok && h["key"] == "x-pca-verdict" && h["value"] != "" {
			h["value"] = "<verdict>"
		}
		return out
	}
	return v
}

type gwTestGuard func() (bool, error)

func (g gwTestGuard) Claim(string, float64, *float64) (bool, error) { return g() }

func gwTestPolicy(kind any) *GatewayFullPolicy {
	if kind == "body" {
		return &GatewayFullPolicy{ParamsBody: true}
	}
	return &GatewayFullPolicy{ParamsFn: func(GatewayRequest) (map[string]any, error) { return map[string]any{}, nil }}
}

func gwTestOptions(spec map[string]any) GatewayOptions {
	nowF, _ := jsNum(spec["now"])
	now := int64(nowF)
	o := GatewayOptions{Audience: vecStr(spec, "audience"), Now: func() int64 { return now }}
	for _, r := range spec["routes"].([]any) {
		m := r.(map[string]any)
		c := m["capability"].(map[string]any)
		o.Routes = append(o.Routes, GatewayRoute{Method: gwStrPtr(m["method"]), Path: vecStr(m, "path"), Capability: GatewayCapability{Verb: vecStr(c, "verb"), Resource: gwStrPtr(c["resource"])}})
	}
	grants, _ := spec["grants"].(map[string]any)
	o.ResolveGrant = func(ref any, _ map[string]any) map[string]any {
		if s, ok := ref.(string); ok {
			g, _ := grants[s].(map[string]any)
			return g
		}
		return nil
	}
	if br := spec["bindRequest"]; br == "off" {
		o.BindRequestOff = true
	} else {
		o.BindRequest = gwTestBind(br)
	}
	o.UnmatchedRoute = vecStr(spec, "unmatched")
	o.PathPolicy = vecStr(spec, "pathPolicy")
	if rc, ok := spec["requireChecks"].([]any); ok {
		o.RequireChecks = []string{}
		for _, c := range rc {
			o.RequireChecks = append(o.RequireChecks, c.(string))
		}
	}
	if s, ok := spec["realm"].(string); ok {
		o.Realm = &s
	}
	o.InsecureSkipPlanRootCheck = spec["skipPlan"] == true
	if pr, ok := spec["planRoots"].([]any); ok {
		o.AuthorizedPlanRoots = []string{}
		for _, c := range pr {
			o.AuthorizedPlanRoots = append(o.AuthorizedPlanRoots, c.(string))
		}
	}
	switch vecStr(spec, "replay") {
	case "always":
		o.ReplayGuard = gwTestGuard(func() (bool, error) { return true, nil })
	case "false":
		o.ReplayGuard = gwTestGuard(func() (bool, error) { return false, nil })
	case "throws":
		o.ReplayGuard = gwTestGuard(func() (bool, error) { return false, errors.New("store down") })
	case "memory":
		o.ReplayGuard = GatewayMemoryReplayGuard(100000, func() float64 { return float64(now) })
	case "memory-full":
		o.ReplayGuard = GatewayMemoryReplayGuard(1, func() float64 { return float64(now) })
	}
	rev := func(enforced, ok bool, reason *string) {
		o.Revocation = func(_, _ map[string]any, _ int64) (GatewayHookResult, error) {
			return GatewayHookResult{Enforced: enforced, OK: ok, Reason: reason}, nil
		}
	}
	gone := "grant revoked"
	switch vecStr(spec, "revocation") {
	case "ok":
		rev(true, true, nil)
	case "revoked":
		rev(true, false, &gone)
	case "revoked-noreason":
		rev(true, false, nil)
	case "notEnforced":
		rev(false, false, nil)
	case "throws":
		o.Revocation = func(_, _ map[string]any, _ int64) (GatewayHookResult, error) {
			return GatewayHookResult{}, errors.New("rev down")
		}
	}
	cp := func(allow bool, reason string, err error) {
		o.CheckProof = func(GatewayProofContext) (bool, string, error) { return allow, reason, err }
	}
	switch vecStr(spec, "checkProof") {
	case "true", "obj-true":
		cp(true, "", nil)
	case "false", "obj-false":
		cp(false, "", nil)
	case "obj-false-reason":
		cp(false, "over limit", nil)
	case "throws":
		cp(false, "", errors.New("policy down"))
	}
	switch vecStr(spec, "policy") {
	case "sig":
		o.PolicyMode = "signature-only"
	case "bogus":
		o.PolicyMode = "bogus"
	case "full-missing":
		o.PolicyMode = "full"
		o.Full = &GatewayFullPolicy{ParamsBody: true}
	}
	return o
}

func gwTestProject(d GatewayDecision) any {
	m := map[string]any{"allow": d.Allow, "status": d.Status, "code": d.Code, "reason": d.Reason, "headers": gwHeaderAny(d.Headers)}
	if d.Matched != nil {
		r := map[string]any{"verb": d.Matched.Verb}
		if d.Matched.Resource != nil {
			r["resource"] = *d.Matched.Resource
		}
		m["matched"] = r
	}
	if d.PCActn != nil && d.PCActn["grant_ref"] != nil {
		m["grant"] = d.PCActn["grant_ref"]
	}
	if d.Verdict != nil {
		m["verdictAllow"] = d.Verdict.Allow
	}
	return gwTestMask(m)
}

func TestGatewayVectors(t *testing.T) {
	spec0 := func(a []any) map[string]any { return vecObj(vecArg(a, 0)) }
	events := func(s map[string]any) map[string]any { return vecObj(s["events"].([]any)[0]) }
	adapter := func(make func(GatewayOptions) (func(map[string]any) (map[string]any, error), error)) vecFn {
		return func(a []any) (any, error) {
			s := spec0(a)
			h, err := make(gwTestOptions(s))
			if err != nil {
				return map[string]any{"create": err.Error()}, nil
			}
			out, err := h(events(s))
			if err != nil {
				return map[string]any{"threw": err.Error()}, nil
			}
			return gwTestMask(out), nil
		}
	}
	plain := func(make func(GatewayOptions) (func(map[string]any) map[string]any, error)) vecFn {
		return adapter(func(o GatewayOptions) (func(map[string]any) (map[string]any, error), error) {
			h, err := make(o)
			if err != nil {
				return nil, err
			}
			return func(e map[string]any) (map[string]any, error) { return h(e), nil }, nil
		})
	}
	replayVectorsSeeded(t, "ref-gateway.json.gz", map[string]vecFn{
		"canonicalQuery": func(a []any) (any, error) {
			if len(a) > 0 && a[0] == nil { // null (unlike an absent argument) is read: query.startsWith
				return nil, errors.New("Cannot read properties of null (reading 'startsWith')")
			}
			return GatewayCanonicalQuery(gwStrPtr(vecArg(a, 0)))
		},
		"requestBinding": func(a []any) (any, error) {
			return GatewayRequestBinding(gwTestReq(vecObj(vecArg(a, 0))), gwTestBind(vecArg(a, 1)))
		},
		"bindParams": func(a []any) (any, error) { return GatewayBindParams(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))) },
		"ambiguousPathReason": func(a []any) (any, error) {
			if r, ok := GatewayAmbiguousPathReason(vecArg(a, 0).(string)); ok {
				return r, nil
			}
			return nil, nil
		},
		"replayScenario": func(a []any) (any, error) {
			s := spec0(a)
			clock, _ := jsNum(s["clock"])
			max, _ := jsNum(s["max"])
			g := GatewayMemoryReplayGuard(int(max), func() float64 { return clock })
			out := []any{}
			for _, o := range s["ops"].([]any) {
				op := vecObj(o)
				if c, ok := op["setClock"]; ok {
					clock, _ = jsNum(c)
					continue
				}
				exp, _ := jsNum(op["exp"])
				var now *float64
				if n, ok := jsNum(op["now"]); ok {
					now = &n
				}
				ok, err := g.Claim(vecStr(op, "key"), exp, now)
				if err != nil {
					out = append(out, map[string]any{"threw": err.Error()})
				} else {
					out = append(out, ok)
				}
			}
			return out, nil
		},
		"provenanceLogScenario": func(a []any) (any, error) {
			s := spec0(a)
			max, _ := jsNum(s["max"])
			l := GatewayMemoryProvenanceLog(int(max))
			out := []any{}
			for _, o := range s["ops"].([]any) {
				op := vecObj(o)
				if _, ok := op["add"]; ok {
					l.Add(vecStr(op, "session"), vecObj(op["o"]))
					out = append(out, "added")
				} else {
					out = append(out, l.Seen(vecStr(op, "session")))
				}
			}
			return out, nil
		},
		"presentedProvenance": func(a []any) (any, error) {
			m := map[string]any{"method": "POST", "path": "/"}
			for k, v := range vecObj(vecArg(a, 0)) {
				m[k] = v
			}
			v := GatewayPresentedProvenance(gwTestReq(m), gwTestPolicy(vecArg(a, 1)))
			if v == GatewayAbsent {
				return map[string]any{"undef": true}, nil
			}
			return v, nil
		},
		"presentedArtifacts": func(a []any) (any, error) {
			m := map[string]any{"method": "POST", "path": "/"}
			for k, v := range vecObj(vecArg(a, 0)) {
				m[k] = v
			}
			return GatewayPresentedArtifacts(gwTestReq(m), gwTestPolicy(vecArg(a, 1))), nil
		},
		"authorizeScenario": func(a []any) (any, error) {
			s := spec0(a)
			gw, err := GatewayCreate(gwTestOptions(s))
			if err != nil {
				return map[string]any{"create": err.Error()}, nil
			}
			out := []any{}
			for _, r := range s["requests"].([]any) {
				out = append(out, gwTestProject(gw(gwTestReq(vecObj(r)))))
			}
			return out, nil
		},
		"envoyScenario":        plain(GatewayEnvoyExtAuthz),
		"grpcScenario":         plain(GatewayEnvoyGrpcExtAuthz),
		"lambdaScenario":       adapter(GatewayLambdaAuthorizer),
		"lambdaSimpleScenario": adapter(GatewayLambdaSimpleAuthorizer),
	})
}
