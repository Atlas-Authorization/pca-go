package pca

import "testing"

// A capability with no `caveats` member is refused. In the chain the well-typed check (the reference's wellTyped) refuses it first
// (`hop 0: malformed capability`); the allocation rule itself refuses a missing or non-array list with `malformed caveats`.
func TestVerifyChainPolicyRefusesALeafWithoutCaveats(t *testing.T) {
	principal, _ := NewKeyPair()
	holder, _ := NewKeyPair()
	// a root signed over `caveats: null` and then carried WITHOUT the member (the body digest and signature stay valid)
	body := map[string]any{"issuer": principal.Public, "holder": holder.Public, "caveats": nil, "parent": nil}
	digest, err := HashCanonical(body)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := DecodeB64uStrict(digest, b32)
	if !ok {
		t.Fatal("digest")
	}
	missing := map[string]any{"id": digest, "issuer": principal.Public, "holder": holder.Public, "body_digest": digest,
		"sig": b64.EncodeToString(principal.Sign(append([]byte(capDomain), raw...)))}
	if why, ok := VerifyChainPolicy([]any{missing}, principal.Public, true, nil, nil, nil); ok || why != "hop 0: malformed capability" {
		t.Fatalf("a leaf without caveats: ok=%v %q", ok, why)
	}
	for _, v := range []any{nil, map[string]any{}, "x"} {
		if why, ok := allocationsMonotone(v); ok || why != "malformed caveats" {
			t.Errorf("allocationsMonotone(%v): ok=%v %q", v, ok, why)
		}
	}
	good, err := MintRoot(principal, holder.Public, []any{}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if why, ok := VerifyChainPolicy([]any{good}, principal.Public, true, nil, nil, nil); !ok {
		t.Fatalf("an empty caveat list is well formed: %q", why)
	}
}
