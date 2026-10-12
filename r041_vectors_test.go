package pca

// 0.4.1 vector-level tests that use only the pre-0.4.1 public surface (VerifyPCActnCorePolicy and the
// middleware's header extraction), so they also run against the 0.4.0 sources (failing-first evidence).
//
//   - r041-share-*: threshold share signatures are validated PER SUITE by `wire` (they used to be a fixed 64 bytes).
//   - pca_header through the middleware: a PCA-Action value is strict unpadded base64url of UTF-8 text; anything
//     else takes the 401 "not valid base64url" path.

import (
	"net/http"
	"strings"
	"testing"
)

const headerB64Reason = "PCA-Action header is not valid base64url"

func TestR041ShareVectors(t *testing.T) {
	doc := load(t, "vectors.json")
	ran, skipped := 0, 0
	for _, x := range doc["vectors"].([]any) {
		v := x.(map[string]any)
		name := v["name"].(string)
		if !strings.HasPrefix(name, "r041-share-") {
			continue
		}
		exp := v["expect"].(map[string]any)
		ec := exp["checks"].(map[string]any)
		if suite, bad := unsupportedSuite(v); bad && !terminalWireFalse(ec) {
			skipped++
			t.Logf("skip %s: requires unimplemented suite %q", name, suite)
			continue
		}
		ran++
		t.Run(name, func(t *testing.T) {
			ctx := v["context"].(map[string]any)
			got, err := VerifyPCActnCorePolicy(v["pcactn"].(map[string]any), v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.Allow != exp["allow"].(bool) {
				t.Errorf("allow = %v, want %v (%s)", got.Allow, exp["allow"], got.Reason)
			}
			if w := ec["wire"].(bool); got.Checks["wire"] != w {
				t.Errorf("wire = %v, want %v (%s)", got.Checks["wire"], w, got.Reason)
			}
		})
	}
	if ran+skipped != 20 || skipped != 2 {
		t.Fatalf("expected 20 r041-share vectors (2 skipped for ml-dsa-87 / slh-dsa-sha2-128f), ran %d skipped %d", ran, skipped)
	}
}

// The header's base64url stage as the middleware sees it: valid iff extraction does not fail with the
// base64url reason. (The empty value is not a header at all for net/http's Header.Get, so it is covered by
// the DecodePCAHeader runner, not here.)
func TestR041HeaderThroughMiddleware(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	cases := prim["pca_header"].([]any)
	if len(cases) < 27 {
		t.Fatalf("pca_header: %d cases, want >= 27", len(cases))
	}
	for _, x := range cases {
		c := x.(map[string]any)
		in := c["input"].(string)
		if in == "" {
			continue
		}
		t.Run(c["name"].(string), func(t *testing.T) {
			r := &http.Request{Method: "GET", Header: http.Header{}}
			r.Header[http.CanonicalHeaderKey(PCAHeader)] = []string{in}
			_, reason, _ := extractPCActn(r)
			gotValid := reason != headerB64Reason
			if gotValid != c["valid"].(bool) {
				t.Errorf("input %q: valid = %v, want %v (reason %q)", in, gotValid, c["valid"], reason)
			}
		})
	}
}
