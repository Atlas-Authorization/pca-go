package pca

import (
	"strings"
	"testing"
)

// The suite-capability manifest (packages/pca/conformance/SUITES.md): every registered suite is either implemented
// (and verifies for real through the conformance vectors) or refused with the distinct reason unsupported_suite; an
// unregistered alg keeps the plain unknown-alg refusal.
func TestSuiteCapabilityManifest(t *testing.T) {
	want := []string{
		"ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65",
		"slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87",
		"slh-dsa-sha2-256s", "hybrid-ed25519-slh-dsa-sha2-256s",
	}
	refused := []string{"fn-dsa-512", "fn-dsa-1024"}
	if lessCat1Verify != nil { // a `less` (cgo) build
		want = append(want, "less-cat1", "hybrid-ed25519-less-cat1")
	} else {
		refused = append(refused, "less-cat1", "hybrid-ed25519-less-cat1")
	}
	if got := strings.Join(SupportedSuites(), ","); got != strings.Join(want, ",") {
		t.Fatalf("SupportedSuites() = %s", got)
	}
	if len(RegisteredSuites) != 14 {
		t.Fatalf("RegisteredSuites has %d entries", len(RegisteredSuites))
	}
	for _, a := range refused {
		why := validateSignatureWire(map[string]any{"alg": a, "sig": "AA"})
		if why != UnsupportedSuite+": "+a {
			t.Errorf("%s: reason %q", a, why)
		}
		hop := map[string]any{"alg": a}
		if e := checkSig(hop, "", "hop 0", pqVerifyKey{}); e != "hop 0: "+UnsupportedSuite+": "+a {
			t.Errorf("%s: hop reason %q", a, e)
		}
	}
	for _, a := range []any{"ml-dsa-99", "none"} {
		if why := validateSignatureWire(map[string]any{"alg": a, "sig": "AA"}); strings.Contains(why, UnsupportedSuite) {
			t.Errorf("%v: unregistered alg reported as %q", a, why)
		}
	}
}
