package pca

// Replays the reference oracle of the SCIM 2.0 /Agents server, the passport mapping and the push adapters
// (testdata/ref-scim.json.gz). Handler sessions name an options table and push cases a fake fetch; both are rebuilt here.

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const scimT0 = 1_700_000_000_000.0

func scimOpts(name string) ScimHandlerOptions {
	base := func(s string) *string { return &s }
	fixed := func() float64 { return scimT0 }
	yes := func(ScimRequest) bool { return true }
	switch name {
	case "open":
		return ScimHandlerOptions{BaseURL: base("https://scim.acme.com/scim/v2"), Now: fixed, Authenticate: yes}
	case "slash":
		return ScimHandlerOptions{BaseURL: base("https://scim.acme.com/scim/v2///"), Now: fixed, Authenticate: yes}
	case "nobase":
		return ScimHandlerOptions{Now: fixed, AllowUnauthenticated: true}
	case "tick":
		tick := 0.0
		return ScimHandlerOptions{BaseURL: base("https://x.example"), Now: func() float64 { t := scimT0 + 1000*tick; tick++; return t }, Authenticate: yes}
	case "deny", "truthy": // the reference admits only `=== true`
		return ScimHandlerOptions{Now: fixed, Authenticate: func(ScimRequest) bool { return false }}
	case "throwauth":
		return ScimHandlerOptions{Now: fixed, Authenticate: func(ScimRequest) bool { panic("x") }}
	}
	return ScimHandlerOptions{Now: fixed} // noauth / notfn: no authenticate function
}

func vecScimReq(v any) ScimRequest {
	m := vecObj(v)
	meth, has := m["method"]
	r := ScimRequest{Method: jsTemplate(meth, has), Query: asRecord(m["query"]), Body: m["body"]}
	if id, has := m["id"]; has {
		s := jsValueString(id)
		r.ID = &s
	}
	return r
}

type scimFakeClient struct {
	mode  string
	calls []any
}

func (c *scimFakeClient) Do(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.calls = append(c.calls, map[string]any{"url": r.URL.String(), "init": map[string]any{"method": r.Method,
		"headers": map[string]any{"authorization": r.Header.Get("authorization"), "content-type": r.Header.Get("content-type")}, "body": string(b)}})
	status, body := map[string]int{"ok201": 201, "err500": 500, "badjson": 204, "nullbody": 200}[c.mode], map[string]string{"ok201": `{"id":"obj-1"}`, "err500": `{"detail":"x"}`, "badjson": ``, "nullbody": `null`}[c.mode]
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
}

func scimPush(f func(map[string]any, PushTarget) (PushResult, error), agent any, mode string) (any, error) {
	return scimPushTo(f, agent, mode, "https://dir.example/scim/Agents", "TOK")
}

func scimPushTo(f func(map[string]any, PushTarget) (PushResult, error), agent any, mode, endpoint, token string) (any, error) {
	c := &scimFakeClient{mode: mode}
	res, err := f(vecObj(agent), PushTarget{Endpoint: endpoint, Token: token, Client: c})
	if err != nil {
		return nil, err
	}
	return map[string]any{"result": res, "calls": c.calls}, nil
}

func vecScimMeta(v any) ScimMetaInput {
	if f, ok := jsNum(v); ok {
		return ScimMetaInput{Now: func() float64 { return f }}
	}
	m := vecObj(v)
	return ScimMetaInput{BaseURL: vecPtrStr(m, "baseUrl"), Created: vecPtrStr(m, "created"), LastModified: vecPtrStr(m, "lastModified")}
}

func TestScimVectors(t *testing.T) {
	replayVectors(t, "ref-scim.json.gz", map[string]vecFn{
		"scimSession": func(a []any) (any, error) {
			h, err := ScimHandler(NewMemoryAgentStore(), scimOpts(vecStrArg(a, 0)))
			if err != nil {
				return nil, err
			}
			setup, _ := a[1].([]any)
			for _, r := range setup {
				h(vecScimReq(r))
			}
			reqs, _ := a[2].([]any)
			out := make([]any, len(reqs))
			for i, r := range reqs {
				resp := h(vecScimReq(r))
				out[i] = resp
				// the reference's handler never answers 500: any non-SCIM failure (a canonicalization refusal) escapes as a rejected promise
				if body, _ := resp.Body.(map[string]any); resp.Status == 500 {
					return nil, errors.New(vecStr(body, "detail"))
				}
			}
			return out, nil
		},
		"passportFingerprint": func(a []any) (any, error) {
			m, err := passportIdentity(a[0])
			if err != nil {
				return nil, err
			}
			return PassportFingerprint(m)
		},
		"issuePassport": func(a []any) (any, error) {
			m, err := passportIdentity(a[0])
			if err != nil {
				return nil, err
			}
			return IssuePassport(m)
		},
		"passportToScim": func(a []any) (any, error) {
			return PassportToScim(vecObj(a[0]), vecObj(a[1]), vecScimMeta(vecArg(a, 2)))
		},
		"scimToProvisioningRequest": func(a []any) (any, error) { return ScimToProvisioningRequest(a[0]) },
		"parseFilter":               func(a []any) (any, error) { return ParseScimFilter(a[0]) },
		"scimError": func(a []any) (any, error) {
			st, _ := baseI64(a[0])
			b := ScimErrorBody(int(st), vecStrArg(a, 1), vecStrArg(a, 2))
			if len(a) > 2 && a[2] == nil {
				b["scimType"] = nil // an explicit undefined arrives as null; Go has no null string
			}
			return b, nil
		},
		"scimListResponse": func(a []any) (any, error) {
			l, _ := a[0].([]any)
			tot, _ := jsNum(a[1])
			st, _ := jsNum(a[2])
			return ScimListResponse(l, tot, st), nil
		},
		"registry": func(a []any) (any, error) {
			l, _ := a[0].([]any)
			ps := make([]map[string]any, len(l))
			for i, x := range l {
				ps[i] = vecObj(x)
			}
			r := BuildPassportRegistry(ps)
			id := vecStrArg(a, 1)
			var get any
			if p := r.Get(id); p != nil {
				get = p
			}
			return map[string]any{"all": r.All(), "has": r.Has(id), "get": get}, nil
		},
		"toEntraAgentPayload": func(a []any) (any, error) { return ToEntraAgentPayload(vecObj(a[0])), nil },
		"toOktaScimPayload":   func(a []any) (any, error) { return ToOktaScimPayload(vecObj(a[0])), nil },
		"pushToEntra":         func(a []any) (any, error) { return scimPush(PushToEntra, a[1], vecStrArg(a, 2)) },
		"pushToOkta":          func(a []any) (any, error) { return scimPush(PushToOkta, a[1], vecStrArg(a, 2)) },
		"pushProvision": func(a []any) (any, error) {
			// the oracle targets endpoint "e" with token "t" for this one
			return scimPushTo(func(ag map[string]any, t PushTarget) (PushResult, error) {
				return PushProvision(ToEntraAgentPayload(ag), t)
			}, a[0], vecStrArg(a, 1), "e", "t")
		},
	})
}

func TestScimISOStringRange(t *testing.T) {
	for ms, want := range map[float64]string{0: "1970-01-01T00:00:00.000Z", -1: "1969-12-31T23:59:59.999Z", 1.9: "1970-01-01T00:00:00.001Z",
		253402300800000: "+010000-01-01T00:00:00.000Z", -62198755200000: "-000001-01-01T00:00:00.000Z"} {
		if got, err := jsISOString(ms); err != nil || got != want {
			t.Errorf("%v: got %q %v want %q", ms, got, err, want)
		}
	}
	if _, err := jsISOString(8.64e15 + 1); err == nil {
		t.Error("out of range must refuse")
	}
	var se *ScimError
	if _, err := ParseScimFilter("active eq falſe"); !errors.As(err, &se) {
		t.Error("a non-ASCII case fold must not match (the reference regex is not Unicode-aware)")
	}
}
