package pca

import (
	"encoding/json"
	"testing"
)

// A runtime claim holding the right NUMBER of members but one that is not a claim key is refused with "none" (runtime_claim.go:
// the member loop), not with an empty class.
func TestR7N2_RuntimeClaimUnknownMemberIsNone(t *testing.T) {
	claim := map[string]any{"v": json.Number("1"), "class": "os_confined", "passport_digest": "pd", "evidence_digest": "ed",
		"iat": json.Number("100"), "exp": json.Number("200"), "attestor": "a", "zzz": "x"}
	if len(claim) != len(runtimeClaimKeys) {
		t.Fatalf("fixture has %d members, want %d", len(claim), len(runtimeClaimKeys))
	}
	if got := VerifiedRuntimeClass(claim, []string{"a"}, "pd", []string{"ed"}, json.Number("150")); got != "none" {
		t.Errorf("unknown member: %q, want none", got)
	}
}

// A schema whose signature verifies but whose digest cannot be computed reports sig true and NO digest. The signed body sits
// at the nesting limit (32), so wrapping the whole document one level deeper for the digest exceeds it.
func TestR7N2_SchemaPrimitiveVerifiedButUnhashableHasNoDigest(t *testing.T) {
	site := newKey(t)
	doc := v2Schema()
	var st any = []any{}
	for i := 0; i < 30; i++ {
		st = []any{st}
	}
	doc["state"] = st
	doc["sig"] = map[string]any{"alg": "ed25519", "kid": "k1", "value": signDomain(t, site, actionSchemaDomain, doc)}
	keys := []any{map[string]any{"kid": "k1", "alg": "ed25519", "pk": site.id}}
	if _, ok := actionSchemaDigest(doc); ok {
		t.Fatal("fixture precondition: the digest must not be computable")
	}
	out := IntentSchemaPrimitive(map[string]any{"schema": doc, "keys": keys, "verb": "air.book", "params": map[string]any{}})
	if out["sig"] != true {
		t.Fatalf("fixture precondition: signature must verify: %v", out)
	}
	if d, has := out["digest"]; has {
		t.Errorf("digest %v reported although none can be computed", d)
	}
}
