package pca

import (
	"errors"
	"strings"
	"testing"
)

func TestFetchMaaCertsFailsClosed(t *testing.T) {
	iss := "https://x.attest.azure.net"
	serve := func(r MaaFetchResponse, err error) FetchMaaCertsOptions {
		return FetchMaaCertsOptions{Fetch: func(string, int64, int64) (MaaFetchResponse, error) { return r, err }}
	}
	ok := MaaFetchResponse{Status: 200, ContentLength: -1, Body: []byte(`{"keys":[{"kid":"k1","kty":"RSA","x5c":["AAAA"]}]}`)}
	if _, err := FetchMaaCerts(iss, FetchMaaCertsOptions{}); err == nil {
		t.Fatal("no transport must refuse")
	}
	for _, bad := range []string{"http://x.attest.azure.net", iss + "/", iss + "/path", ""} {
		if _, err := FetchMaaCerts(bad, serve(ok, nil)); err == nil {
			t.Fatalf("issuer %q must refuse", bad)
		}
	}
	refusals := map[string]FetchMaaCertsOptions{
		"transport error": serve(MaaFetchResponse{}, errors.New("down")),
		"HTTP 500":        serve(MaaFetchResponse{Status: 500, ContentLength: -1, Body: ok.Body}, nil),
		"redirected":      serve(MaaFetchResponse{Status: 200, URL: "https://evil.example/certs", ContentLength: -1, Body: ok.Body}, nil),
		"not JSON":        serve(MaaFetchResponse{Status: 200, ContentLength: -1, Body: []byte("<html>")}, nil),
		"no keys":         serve(MaaFetchResponse{Status: 200, ContentLength: -1, Body: []byte(`{"k":[]}`)}, nil),
		"invalid UTF-8":   serve(MaaFetchResponse{Status: 200, ContentLength: -1, Body: []byte{0xff, 0xfe}}, nil),
	}
	big := serve(MaaFetchResponse{Status: 200, ContentLength: -1, Body: []byte(`{"keys":[]}` + strings.Repeat(" ", 64))}, nil)
	big.MaxBytes = 32
	refusals["oversize"] = big
	for name, o := range refusals {
		if _, err := FetchMaaCerts(iss, o); err == nil {
			t.Fatalf("%s must refuse", name)
		}
	}
	jwks, err := FetchMaaCerts(iss, serve(ok, nil))
	if err != nil || len(jwks.Keys) != 1 || jwks.Keys[0].Kid == nil || *jwks.Keys[0].Kid != "k1" {
		t.Fatalf("a well-formed answer: %+v %v", jwks, err)
	}
}

func TestCorroborateMaaKeySetsRefusals(t *testing.T) {
	iss := "https://x.attest.azure.net"
	empty := &MaaJwks{}
	if r := CorroborateMaaKeySets(nil, 1, iss, 1000, nil); r.Ok || r.Code != "malformed" {
		t.Fatalf("k < 2: %+v", r)
	}
	if r := CorroborateMaaKeySets(nil, 2, "http://x", 1000, nil); r.Ok || r.Code != "malformed" {
		t.Fatalf("issuer: %+v", r)
	}
	if r := CorroborateMaaKeySets([]MaaVantageObservation{{Vantage: "a", Issuer: "https://other.example", Jwks: empty}}, 2, iss, 1000, nil); r.Ok || r.Code != "malformed" {
		t.Fatalf("another issuer: %+v", r)
	}
	if r := CorroborateMaaKeySets([]MaaVantageObservation{{Vantage: "a", Issuer: iss, Jwks: empty}}, 2, iss, 1000, nil); r.Ok || r.Code != "no-valid-keys" {
		t.Fatalf("no valid key: %+v", r)
	}
	if r := CorroborateMaaKeySets(nil, 2, iss, 1000, nil); r.Ok || r.Code != "insufficient-vantages" {
		t.Fatalf("no vantage: %+v", r)
	}
	junk := "AAAA"
	ev := EvaluateMaaJwks(&MaaJwks{Keys: []MaaJwk{{Kid: &junk, X5c: []string{"AAAA"}}}}, iss, &MaaKeyPolicy{TrustedIssuers: []string{iss}}, 1000)
	if len(ev.Accepted) != 0 {
		t.Fatalf("a key that is no certificate must be rejected: %+v", ev)
	}
}

func TestMaaKeyTrustWithoutNetworkFailsClosed(t *testing.T) {
	iss := "https://x.attest.azure.net"
	store := CreateMemoryMaaKeyStateStore()
	trust, err := NewMaaKeyTrust(MaaKeyTrustOptions{Policy: MaaKeyPolicy{TrustedIssuers: []string{iss}}, Store: store,
		Fetch: func(string, int64, int64) (MaaFetchResponse, error) { return MaaFetchResponse{}, errors.New("down") }})
	if err != nil {
		t.Fatal(err)
	}
	if r := trust.GetTrustAnchors(iss, 1000, nil); r.Ok || len(r.RootSpkiSha256) != 0 {
		t.Fatalf("no cache and no network must refuse: %+v", r)
	}
	if r := trust.GetTrustAnchors("https://unlisted.example", 1000, nil); r.Ok {
		t.Fatalf("an unlisted issuer must refuse: %+v", r)
	}
}
