package pca

import "testing"

// Replays packages/pca/conformance/runtime-claim-vectors.json: runtime-class claims (a missing file fails).
func TestRuntimeClaimVectors(t *testing.T) {
	doc := load(t, "runtime-claim-vectors.json")
	tr := doc["trust"].(map[string]any)
	strs := func(k string) []string {
		out := []string{}
		for _, x := range tr[k].([]any) {
			out = append(out, x.(string))
		}
		return out
	}
	cases := doc["cases"].([]any)
	if len(cases) < 8 {
		t.Fatal("too few cases")
	}
	for _, x := range cases {
		c := x.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			got := VerifiedRuntimeClass(c["claim"], strs("pinnedAttestors"), tr["passportDigest"].(string), strs("verifiedEvidenceDigests"), c["now"])
			if got != c["expect"].(string) {
				t.Errorf("got %q, want %q", got, c["expect"])
			}
		})
	}
	first := cases[0].(map[string]any)
	if VerifiedRuntimeClass(first["claim"], nil, tr["passportDigest"].(string), strs("verifiedEvidenceDigests"), first["now"]) != "none" {
		t.Error("an unpinned attestor was accepted")
	}
	if VerifiedRuntimeClass(first["claim"], strs("pinnedAttestors"), tr["passportDigest"].(string), nil, first["now"]) != "none" {
		t.Error("unverified evidence was accepted")
	}
	if VerifiedRuntimeClass(nil, nil, "", nil, nil) != "none" {
		t.Error("nil claim")
	}
}
