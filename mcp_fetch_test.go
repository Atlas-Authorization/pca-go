package pca

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type mcpFetchSeen struct{ headers []http.Header }

func (s *mcpFetchSeen) RoundTrip(r *http.Request) (*http.Response, error) {
	s.headers = append(s.headers, r.Header.Clone())
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
}

func mcpFetchPost(t *testing.T, rt http.RoundTripper, body string) {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://x/mcp", strings.NewReader(body))
	res, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(res.Body); string(b) != "{}" {
		t.Fatalf("response body altered: %q", b)
	}
}

func TestMcpPcaFetch(t *testing.T) {
	mk := func() *FacadeAgent {
		ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "refunds", Permissions: map[string][]string{"stripe": {"refund"}}, Limits: map[string]string{"refund": "$500/day"}, Aud: "mcp_test"})
		if err != nil {
			t.Fatal(err)
		}
		return ag
	}
	mapping := func(tool string, args map[string]any) (string, string, bool) {
		if tool == "refund" {
			return "stripe.refund", "charge:" + adapterJsString(args["chargeId"]), true
		}
		return "", "", false
	}
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"refund","arguments":{"chargeId":"ch_1","amount":42}}}`

	ag := mk()
	seen := &mcpFetchSeen{}
	rt, err := McpPcaFetch(ag, mapping, "", seen)
	if err != nil {
		t.Fatal(err)
	}
	mcpFetchPost(t, rt, call)
	mcpFetchPost(t, rt, call)
	h1, h2 := seen.headers[0].Get(PCAHeader), seen.headers[1].Get(PCAHeader)
	if h1 == "" || h2 == "" || h1 == h2 {
		t.Fatalf("expected two distinct proofs: %q %q", h1, h2)
	}
	raw, _ := DecodePCAHeader(h1)
	p, err := ParsePCActn(raw)
	if err != nil {
		t.Fatal(err)
	}
	act := p["action"].(map[string]any)
	if act["verb"] != "stripe.refund" || act["resource"] != "charge:ch_1" || p["aud"] != "mcp_test" {
		t.Fatalf("proof not bound to the call: %v", p)
	}
	if want, _ := ParamsDigest(map[string]any{"chargeId": "ch_1", "amount": 42}); act["params_digest"] != want {
		t.Fatalf("params digest %v want %v", act["params_digest"], want)
	}
	if seen.headers[0].Get(ProvenanceHeader) == "" {
		t.Fatal("provenance bundle did not ride with the proof")
	}
	rs := ag.Provenance.Receipts()
	if last := rs[len(rs)-1]; last["origin"] != "tool" || last["source"] != "refund" {
		t.Fatalf("response not recorded as tool output: %v", last)
	}

	// everything else passes through unchanged
	seen2 := &mcpFetchSeen{}
	rt2, _ := McpPcaFetch(mk(), mapping, "", seen2)
	for _, b := range []string{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, `{"method":"tools/call","params":{"name":"other","arguments":{}}}`, `not json`,
		`[{"method":"tools/call","params":{"name":"refund"}}]`} {
		mcpFetchPost(t, rt2, b)
	}
	req, _ := http.NewRequest("GET", "http://x/mcp", nil)
	if _, err := rt2.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	for i, h := range seen2.headers {
		if h.Get(PCAHeader) != "" {
			t.Fatalf("request %d carried a proof", i)
		}
	}

	// audience override
	seen3 := &mcpFetchSeen{}
	rt3, _ := McpPcaFetch(mk(), mapping, "other_server", seen3)
	mcpFetchPost(t, rt3, call)
	raw3, _ := DecodePCAHeader(seen3.headers[0].Get(PCAHeader))
	p3, _ := ParsePCActn(raw3)
	if p3["aud"] != "other_server" {
		t.Fatalf("aud %v", p3["aud"])
	}
}
