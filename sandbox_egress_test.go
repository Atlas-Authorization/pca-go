package pca

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func egressTestAdmit(t *testing.T, p *EgressPolicy, tmpl map[string]any) {
	t.Helper()
	params := map[string]any{"q": "1"}
	digest, err := HashCanonical(params)
	if err != nil {
		t.Fatal(err)
	}
	op := map[string]any{"verb": "http.get", "resource": "upstream", "params": params}
	res := map[string]any{"allow": true, "operation": map[string]any{"verb": "http.get", "resource": "upstream", "params_digest": digest, "id": "op1"}}
	if err := p.Admit(res, op, func(any) any { return tmpl }, nil); err != nil {
		t.Fatal(err)
	}
}

func egressTestProxy(t *testing.T, allowPrivate bool, tmpl map[string]any) (*httptest.Server, *SandboxReceiptLog) {
	t.Helper()
	pol := NewEgressPolicy(func() float64 { return 1 })
	egressTestAdmit(t, pol, tmpl)
	log := NewSandboxReceiptLog(func() float64 { return 1 }, nil)
	px, err := NewEgressProxy(EgressProxyOptions{Policy: pol, Log: log, AllowPrivate: allowPrivate})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(px)
	t.Cleanup(s.Close)
	return s, log
}

func egressTestGet(t *testing.T, proxy *httptest.Server, target string) *http.Response {
	t.Helper()
	pu, _ := url.Parse(proxy.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestEgressProxyForwardsAdmittedAndRefusesTheRest(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") }))
	defer up.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	pn, _ := net.LookupPort("tcp", port)
	tmpl := map[string]any{"method": "GET", "scheme": "http", "host": "127.0.0.1", "port": jsNumber(float64(pn)), "path": "/ok", "query": "q=1"}
	px, log := egressTestProxy(t, true, tmpl)
	resp := egressTestGet(t, px, up.URL+"/ok?q=1")
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != 200 || string(b) != "hello" {
		t.Fatalf("admitted request: %d %q", resp.StatusCode, b)
	}
	if resp2 := egressTestGet(t, px, up.URL+"/other?q=1"); resp2.StatusCode != 403 {
		t.Fatalf("a request outside the admission must be refused, got %d", resp2.StatusCode)
	}
	if resp3 := egressTestGet(t, px, up.URL+"/ok?q=1"); resp3.StatusCode != 403 {
		t.Fatalf("a spent admission must be refused, got %d", resp3.StatusCode)
	}
	if len(log.Entries) != 3 || log.Entries[0]["outcome"] != "ok" || log.Entries[1]["outcome"] != "refused" {
		t.Fatalf("receipts: %v", log.Entries)
	}
}

func TestEgressProxyRefusesPrivateUpstream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret") }))
	defer up.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	pn, _ := net.LookupPort("tcp", port)
	tmpl := map[string]any{"method": "GET", "scheme": "http", "host": "127.0.0.1", "port": jsNumber(float64(pn)), "path": "/s"}
	px, log := egressTestProxy(t, false, tmpl)
	resp := egressTestGet(t, px, up.URL+"/s")
	if resp.StatusCode != 502 {
		t.Fatalf("a loopback upstream must be refused with 502, got %d", resp.StatusCode)
	}
	if len(log.Entries) != 1 || log.Entries[0]["outcome"] != "error" || log.Entries[0]["reason"] != "upstream:EACCES" {
		t.Fatalf("receipts: %v", log.Entries)
	}
}
