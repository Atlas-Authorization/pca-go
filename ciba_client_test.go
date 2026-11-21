package pca

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCibaClientFlow(t *testing.T) {
	var mu sync.Mutex
	var tokenCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = r.ParseForm()
		if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:s%20x")); r.Header.Get("Authorization") != want {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/bc" {
			if r.Form.Get("login_hint") != "u@example.com" || !strings.Contains(r.Form.Get("scope"), "openid") {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_request"}`))
				return
			}
			w.Write([]byte(`{"auth_req_id":"abc","expires_in":120}`))
			return
		}
		tokenCalls++
		switch tokenCalls {
		case 1:
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"slow_down"}`))
		case 2:
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"authorization_pending"}`))
		default:
			w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
		}
	}))
	defer srv.Close()
	var clock int64 = 1_000_000
	c, err := NewCibaClient(CibaClientConfig{BackchannelAuthenticationEndpoint: srv.URL + "/bc", TokenEndpoint: srv.URL + "/tok",
		ClientID: "cid", ClientSecret: "s x", AllowInsecureHTTP: true, Now: func() int64 { return clock },
		Sleep: func(ctx context.Context, d time.Duration) error { clock += d.Milliseconds(); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	hint := "u@example.com"
	flow, err := c.Initiate(context.Background(), map[string]any{"verb": "pay", "resource": "acct", "tier": 3.0, "id": "s1", "goalCommit": "gc1"},
		CibaInitiateOptions{CibaRequestOptions: CibaRequestOptions{LoginHint: &hint}})
	if err != nil {
		t.Fatal(err)
	}
	if flow.AuthReqID != "abc" || flow.IntervalSec != 5 || flow.Delivery != "poll" {
		t.Fatalf("flow %+v", flow)
	}
	p := c.Poller(flow)
	r, err := p.Wait(context.Background())
	if err != nil || r.Status != "approved" || r.Tokens.AccessToken != "at" {
		t.Fatalf("got %+v %v", r, err)
	}
	if p.IntervalSec() != 10 {
		t.Fatalf("slow_down must add 5s, got %v", p.IntervalSec())
	}
	r2, _ := p.Poll(context.Background())
	if r2.Status != "approved" || tokenCalls != 3 {
		t.Fatal("settled flow must not be re-sent")
	}
}

func TestCibaClientRefusals(t *testing.T) {
	if _, err := NewCibaClient(CibaClientConfig{BackchannelAuthenticationEndpoint: "http://x/bc", TokenEndpoint: "https://x/t"}); err == nil {
		t.Fatal("http endpoint must be refused")
	}
	c, _ := NewCibaClient(CibaClientConfig{BackchannelAuthenticationEndpoint: "https://x/bc", TokenEndpoint: "https://x/t"})
	if _, err := c.Initiate(context.Background(), map[string]any{}, CibaInitiateOptions{}); err == nil {
		t.Fatal("no hint must be refused")
	}
}
