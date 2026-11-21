package pca

// Replays the reference corpus for the request-in / response-out guard (construction guards and the pre-verification refusals), and
// checks the RoundTripper form against the same refusals.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func fetchTestOpts(resolve string) RequirePCAOptions {
	return RequirePCAOptions{Audience: "rs_fetch", SignatureOnly: true, ResolveGrant: func(string) (map[string]any, error) {
		if resolve == "throws" {
			return nil, errors.New("store down")
		}
		return nil, nil
	}}
}

func fetchTestRequest(spec map[string]any) *http.Request {
	var body io.Reader
	if s, ok := spec["body"].(string); ok {
		body = strings.NewReader(s)
	}
	r := httptest.NewRequest("POST", "http://localhost/refunds", body)
	for k, v := range vecObj(spec["headers"]) {
		r.Header.Set(k, v.(string))
	}
	return r
}

func TestFetchVectors(t *testing.T) {
	replayVectors(t, "ref-fetch.json.gz", map[string]vecFn{
		"constructScenario": func(a []any) (any, error) {
			ok := fetchTestOpts("null")
			switch vecArg(a, 0) {
			case "noaudience":
				ok.Audience = ""
			case "nooperation":
				ok.SignatureOnly = false
			}
			if _, err := WithPCA(ok, http.NotFoundHandler()); err != nil {
				return nil, err
			}
			return map[string]any{"built": true}, nil
		},
		"requestScenario": func(a []any) (any, error) {
			spec := vecObj(vecArg(a, 0))
			ran := false
			h, err := WithPCA(fetchTestOpts(vecStr(spec, "resolve")), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
			if err != nil {
				return nil, err
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, fetchTestRequest(spec))
			var body map[string]any
			if v, err := ParseJSONLenient(rec.Body.Bytes()); err == nil {
				body, _ = v.(map[string]any)
			}
			out := map[string]any{"status": rec.Code, "handlerRan": ran, "decision": nil, "challenge": nil, "contentType": nil, "bodyKeys": nil, "errorIsString": false}
			if d, ok := body["decision"]; ok {
				out["decision"] = d
			}
			if rec.Code == 401 {
				out["challenge"] = strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), `PCA realm="`)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "" {
				out["contentType"] = ct
			}
			if body != nil {
				keys := []any{}
				for k := range body {
					keys = append(keys, k)
				}
				sort.Slice(keys, func(i, j int) bool { return keys[i].(string) < keys[j].(string) })
				out["bodyKeys"] = keys
				_, out["errorIsString"] = body["error"].(string)
			}
			return out, nil
		},
	})
}

type fetchStubTransport struct{ calls int }

func (s *fetchStubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls++
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func TestFetchRoundTripperRefuses(t *testing.T) {
	stub := &fetchStubTransport{}
	rt, err := WithPCARoundTripper(fetchTestOpts("null"), stub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(httptest.NewRequest("POST", "http://localhost/refunds", nil))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 401 || stub.calls != 0 || !strings.Contains(string(b), `"decision":"deny"`) || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), `PCA realm="`) {
		t.Fatalf("status %d calls %d body %s", resp.StatusCode, stub.calls, b)
	}
	if _, err := WithPCARoundTripper(RequirePCAOptions{}, stub); err == nil {
		t.Fatal("a guard without an audience was built")
	}
}
