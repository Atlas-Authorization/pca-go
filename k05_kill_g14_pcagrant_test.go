package pca

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// g14: the pca_grant URL charset and length bounds, the presentation check's -1 index on every refusal, and Protect's
// defaults versus caller-set Authorize fields.

func TestK05KillG14PcaGrantURL(t *testing.T) {
	for c := 0; c < 256; c++ {
		b := byte(c)
		want := b >= 0x21 && b <= 0x7e && b != '#' && b != '\\'
		if got := PcaGrantHTTPSURL("https://a/" + string([]byte{b})); got != want {
			t.Errorf("byte %#02x: %v, want %v", b, got, want)
		}
	}
	for u, want := range map[string]bool{
		"https://a": true, "https://@a": false, "https://a@b/": false, "https://a/@": true, "https:/": false, "https://": false,
		"https:///a": false, "https://?a": false, "http://abc": false,
		"https://a/" + strings.Repeat("x", 2038): true, "https://a/" + strings.Repeat("x", 2039): false,
	} {
		if got := PcaGrantHTTPSURL(u); got != want {
			t.Errorf("PcaGrantHTTPSURL(len %d %.20q) = %v, want %v", len(u), u, got, want)
		}
	}
	if PcaGrantHTTPSURL(1) {
		t.Error("a non-string is a URL")
	}
}

func TestK05KillG14PcaGrantPresentation(t *testing.T) {
	d1, err := PcaGrantChainDigest([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	detail := func(n string, digest string, locs []any) map[string]any {
		m := map[string]any{"type": "pca_grant", "chain_len": json.Number(n), "chain_digest": digest}
		if locs != nil {
			m["locations"] = locs
		}
		return m
	}
	check := func(name string, details []map[string]any, resource string, ids []string, proof bool, wantI int, wantCode string) {
		t.Helper()
		if i, code := CheckPcaGrantPresentation(details, resource, ids, proof); i != wantI || code != wantCode {
			t.Errorf("%s: %d %q, want %d %q", name, i, code, wantI, wantCode)
		}
	}
	ok := detail("1", d1, nil)
	check("no detail", nil, "https://r/", []string{"a"}, true, -1, "no_detail")
	check("no proof", []map[string]any{ok}, "https://r/", []string{"a"}, false, -1, "proof_required")
	// a detail longer than the presented chain is skipped (never sliced past the chain)
	check("chain too short", []map[string]any{detail("3", d1, nil)}, "https://r/", []string{"a"}[:1:1], true, -1, "chain_mismatch")
	check("wrong location", []map[string]any{detail("1", d1, []any{"https://x/"})}, "https://r/", []string{"a"}, true, -1, "wrong_location")
	check("second detail passes", []map[string]any{detail("3", d1, nil), ok}, "https://r/", []string{"a"}, true, 1, "")
}

func g14ptOperation(*http.Request, []byte) (*Operation, error) { return nil, nil }

func TestK05KillG14ProtectDefaults(t *testing.T) {
	// no Authorize: every default is filled in
	p := Protect(ProtectOptions{Audience: "aud"})
	az := p.Options.Authorize
	if az == nil || az.StateStore == nil || az.Plan != PlanSingleStep || az.IsRevoked == nil || az.Operation != nil {
		t.Fatalf("defaults: %+v", az)
	}
	if revoked, err := az.IsRevoked(nil, map[string]any{"id": "g"}); revoked || err != nil {
		t.Errorf("default revocation: %v %v", revoked, err)
	}
	// caller-set Authorize fields win over the defaults
	mine := errors.New("mine")
	p = Protect(ProtectOptions{Audience: "aud", Authorize: &AuthorizeOptions{
		Plan:      "my-plan",
		IsRevoked: func(map[string]any, map[string]any) (bool, error) { return false, mine },
		Operation: g14ptOperation,
	}})
	az = p.Options.Authorize
	if az.Plan != "my-plan" || az.Operation == nil {
		t.Fatalf("caller fields: plan %q operation nil %v", az.Plan, az.Operation == nil)
	}
	if revoked, err := az.IsRevoked(nil, map[string]any{"id": "g"}); revoked || !errors.Is(err, mine) {
		t.Errorf("caller revocation: %v %v", revoked, err)
	}
}
