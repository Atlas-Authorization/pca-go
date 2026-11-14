package pca

import "testing"

const goCLinkDiffers = "grant policy differs from the linked template instantiation"

type goCLinkFx struct {
	reg    map[string]any
	ref    map[string]any
	policy map[string]any
	d      string
	k      *KeyPair
}

func goCLink(t *testing.T, seed byte, caveats []any) goCLinkFx {
	t.Helper()
	k := g05Key(t, seed)
	def := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a"}))
	if caveats != nil {
		def["body"].(map[string]any)["caveats"] = caveats
	}
	d, err := TemplateDigest(def)
	if err != nil {
		t.Fatal(err)
	}
	reg := map[string]any{
		"templates": map[string]any{d: map[string]any{"def": def, "signer": k.Public, "sig": g05LinkSig(t, k, templateSigDomain, def)}},
		"trusted":   []any{k.Public},
	}
	ref := map[string]any{"template_id": "t", "version_digest": d, "slots": map[string]any{"a": "x"}}
	policy, _, why := ResolveLink(ref, reg)
	if why != "" {
		t.Fatalf("resolve: %q", why)
	}
	return goCLinkFx{reg, ref, policy, d, k}
}

func (f goCLinkFx) env() map[string]any {
	return map[string]any{"template_ref": f.ref, "predicates": f.policy["predicates"], "caveats": f.policy["caveats"]}
}

func TestGoCVerifyLinkedPolicy(t *testing.T) {
	f := goCLink(t, 0x91, nil)
	if got := VerifyLinkedPolicy(f.env(), f.reg); got != "" {
		t.Errorf("matching grant: %q", got)
	}
	// no reference: nothing to verify
	if got := VerifyLinkedPolicy(map[string]any{"predicates": []any{}}, f.reg); got != "" {
		t.Errorf("no reference: %q", got)
	}
	// a null reference is a reference, and a malformed one
	if got := VerifyLinkedPolicy(map[string]any{"template_ref": nil}, f.reg); got != "template_ref must be an object" {
		t.Errorf("null reference: %q", got)
	}
	// a reference the registry cannot resolve
	e := f.env()
	e["template_ref"] = map[string]any{"template_id": "t", "version_digest": "nope", "slots": map[string]any{"a": "x"}}
	if got := VerifyLinkedPolicy(e, f.reg); got != "template version is not in the registry" {
		t.Errorf("unresolvable: %q", got)
	}
	// a grant policy that differs
	e = f.env()
	e["predicates"] = []any{}
	if got := VerifyLinkedPolicy(e, f.reg); got != goCLinkDiffers {
		t.Errorf("different predicates: %q", got)
	}
	e = f.env()
	e["caveats"] = []any{map[string]any{"type": "max_blast_radius"}}
	if got := VerifyLinkedPolicy(e, f.reg); got != goCLinkDiffers {
		t.Errorf("extra caveats: %q", got)
	}
	// a grant policy that cannot be canonicalised
	e = f.env()
	e["predicates"] = []any{"\xed\xa0\x80"}
	if got := VerifyLinkedPolicy(e, f.reg); got != goCLinkDiffers {
		t.Errorf("uncanonical predicates: %q", got)
	}
}

func TestGoCVerifyLinkedPolicyCaveats(t *testing.T) {
	cav := []any{map[string]any{"type": "max_blast_radius"}}
	f := goCLink(t, 0x92, cav)
	if got := VerifyLinkedPolicy(f.env(), f.reg); got != "" {
		t.Errorf("grant carrying the template's caveats: %q", got)
	}
	e := f.env()
	e["caveats"] = []any{}
	if got := VerifyLinkedPolicy(e, f.reg); got != goCLinkDiffers {
		t.Errorf("grant dropping the template's caveats: %q", got)
	}
}

func TestGoCVerifyLinkedPolicyPanicIsRefusal(t *testing.T) {
	k := g05Key(t, 0x93)
	def := g05Tpl(map[string]any{}, 1) // a predicate that is not an object: the overlay step cannot copy it
	d, err := TemplateDigest(def)
	if err != nil {
		t.Fatal(err)
	}
	ov := g05Overlay()
	ov["version_digest"] = d
	reg := map[string]any{
		"templates": map[string]any{d: map[string]any{"def": def, "signer": k.Public, "sig": g05LinkSig(t, k, templateSigDomain, def)}},
		"trusted":   []any{k.Public},
		"overlays":  []any{map[string]any{"overlay": ov, "signer": k.Public, "sig": g05LinkSig(t, k, tightenSigDomain, ov)}},
	}
	env := map[string]any{"template_ref": map[string]any{"template_id": "t", "version_digest": d, "slots": map[string]any{}}}
	if got := VerifyLinkedPolicy(env, reg); got != "link verification error (fail closed)" {
		t.Errorf("panic inside resolution: %q", got)
	}
}
