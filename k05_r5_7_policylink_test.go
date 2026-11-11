package pca

import (
	"encoding/json"
	"testing"
)

// r5-7: policy_link.go survivors. Reference: packages/pca/src/policy-link.ts messages.

func TestR5N7_ScanSlotsForbiddenAndPlaceholder(t *testing.T) {
	ok := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a"}))
	g05DefErr(t, "valid", ok, "")
	for _, k := range []string{"__proto__", "constructor", "prototype"} {
		d := g05Tpl(map[string]any{})
		d["body"].(map[string]any)[k] = json.Number("1")
		g05DefErr(t, k, d, "body has the forbidden key '"+k+"'")
		n := g05Tpl(map[string]any{}, map[string]any{"verb": "read", k: json.Number("1")})
		g05DefErr(t, "nested "+k, n, "body has the forbidden key '"+k+"'")
	}
	for _, k := range []string{"pre", "post"} {
		d := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a", k: json.Number("1")}))
		g05DefErr(t, k, d, "placeholder "+k+" must be a string")
		s := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a", k: "x"}))
		g05DefErr(t, k+" string", s, "")
	}
	nilName := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": nil}))
	g05DefErr(t, "nil name", nilName, "placeholder names undeclared slot 'null'")
}

func TestR5N7_LinkJSString(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{{nil, "null"}, {true, "true"}, {false, "false"}, {json.Number("5"), "5"}, {"s", "s"}} {
		if got := linkJSString(c.v); got != c.want {
			t.Fatalf("%v: got %q, want %q", c.v, got, c.want)
		}
	}
}

func TestR5N7_DefSlotAndCaveats(t *testing.T) {
	notObj := g05Tpl(map[string]any{"a": "x"})
	g05DefErr(t, "slot not object", notObj, "slot 'a' must be an object")
	body := func(c any) map[string]any {
		d := g05Tpl(map[string]any{})
		d["body"].(map[string]any)["caveats"] = c
		return d
	}
	g05DefErr(t, "caveats string", body("x"), "body.caveats must be an array")
	g05DefErr(t, "caveats null", body(nil), "body.caveats must be an array")
	g05DefErr(t, "caveats list", body([]any{}), "")
}

func TestR5N7_OverlayErrors(t *testing.T) {
	if e := TightenOverlayError("x"); e != "overlay must be an object" {
		t.Fatalf("non-object: %q", e)
	}
	if e := TightenOverlayError(nil); e != "overlay must be an object" {
		t.Fatalf("nil: %q", e)
	}
	base := func() map[string]any {
		return map[string]any{"v": json.Number("1"), "kind": "pca-template-tighten", "template_id": "t", "version_digest": "D"}
	}
	if e := TightenOverlayError(base()); e != "" {
		t.Fatalf("bare overlay: %q", e)
	}
	unk := base()
	unk["extra"] = json.Number("1")
	if e := TightenOverlayError(unk); e != "overlay has unknown member 'extra' (an overlay can only add where conditions and caveats)" {
		t.Fatalf("unknown: %q", e)
	}
	const werr = "overlay add_where must be a list of conditions"
	const cerr = "overlay add_caveats must be a list of caveats"
	for _, c := range []struct {
		k    string
		v    any
		want string
	}{
		{"add_where", "x", werr}, {"add_where", nil, werr}, {"add_where", []any{json.Number("1")}, werr},
		{"add_where", []any{map[string]any{}}, ""}, {"add_where", []any{}, ""},
		{"add_caveats", "x", cerr}, {"add_caveats", nil, cerr}, {"add_caveats", []any{json.Number("1")}, cerr},
		{"add_caveats", []any{map[string]any{"type": json.Number("1")}}, cerr},
		{"add_caveats", []any{map[string]any{"type": "t"}}, ""}, {"add_caveats", []any{}, ""},
	} {
		o := base()
		o[c.k] = c.v
		if e := TightenOverlayError(o); e != c.want {
			t.Fatalf("%s=%v: got %q, want %q", c.k, c.v, e, c.want)
		}
	}
}

func TestR5N7_SignerNotStringAmongEmptyTrusted(t *testing.T) {
	k := g05Key(t, 0x87)
	def := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a"}))
	sig := g05LinkSig(t, k, templateSigDomain, def)
	if why, ok := VerifyTemplate(map[string]any{"def": def, "signer": json.Number("5"), "sig": sig}, []string{""}); ok || why != "template signer is not trusted" {
		t.Fatalf("template: %v %q", ok, why)
	}
	ov := g05Overlay()
	osig := g05LinkSig(t, k, tightenSigDomain, ov)
	if why, ok := VerifyTighten(map[string]any{"overlay": ov, "signer": nil, "sig": osig}, []string{""}); ok || why != "overlay signer is not trusted" {
		t.Fatalf("overlay: %v %q", ok, why)
	}
}

func TestR5N7_IntegerSlotWithoutBounds(t *testing.T) {
	def := g05Tpl(map[string]any{"n": map[string]any{"type": "integer"}}, g05Where(map[string]any{"$slot": "n"}))
	for _, v := range []string{"-5", "0", "7"} {
		pol, why := InstantiateTemplate(def, map[string]any{"n": json.Number(v)})
		if pol == nil || why != "" {
			t.Fatalf("%s: %v %q", v, pol, why)
		}
	}
}

func TestR5N7_MatcherSafeListInVerb(t *testing.T) {
	def := g05Tpl(map[string]any{"s": map[string]any{"type": "set", "values": []any{"x*", "re:y", "ok"}}},
		map[string]any{"verb": map[string]any{"$slot": "s"}})
	want := "slot 's' would inject a wildcard or regex matcher into a verb or resource"
	for _, v := range []any{[]any{"x*"}, []any{"ok", "re:y"}} {
		pol, why := InstantiateTemplate(def, map[string]any{"s": v})
		if pol != nil || why != want {
			t.Fatalf("%v: %v %q", v, pol, why)
		}
	}
	if pol, why := InstantiateTemplate(def, map[string]any{"s": []any{"ok"}}); pol == nil || why != "" {
		t.Fatalf("clean list: %v %q", pol, why)
	}
}

func TestR5N7_InstantiateFaultSeam(t *testing.T) {
	def := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a"}))
	defer func() { instantiateFault = nil }()
	instantiateFault = func() { panic("boom") }
	if pol, why := InstantiateTemplate(def, map[string]any{"a": "x"}); pol != nil || why != "instantiation error (fail closed)" {
		t.Fatalf("generic panic: %v %q", pol, why)
	}
	instantiateFault = func() { panic(linkRefusal("refused here")) }
	if pol, why := InstantiateTemplate(def, map[string]any{"a": "x"}); pol != nil || why != "refused here" {
		t.Fatalf("link refusal: %v %q", pol, why)
	}
}

func TestR5N7_ResolveSkipsForeignOverlayFirst(t *testing.T) {
	k := g05Key(t, 0x88)
	def := g05Tpl(map[string]any{}, map[string]any{})
	d, err := TemplateDigest(def)
	if err != nil {
		t.Fatal(err)
	}
	ov := g05Overlay()
	ov["version_digest"] = d
	other := g05Overlay()
	other["template_id"] = "other"
	other["version_digest"] = d
	good := map[string]any{"overlay": ov, "signer": k.Public, "sig": g05LinkSig(t, k, tightenSigDomain, ov)}
	for _, first := range []any{map[string]any{}, map[string]any{"overlay": other, "signer": k.Public, "sig": "bad"}} {
		reg := map[string]any{
			"templates": map[string]any{d: map[string]any{"def": def, "signer": k.Public, "sig": g05LinkSig(t, k, templateSigDomain, def)}},
			"trusted":   []any{k.Public},
			"overlays":  []any{first, good},
		}
		pol, n, why := ResolveLink(map[string]any{"template_id": "t", "version_digest": d, "slots": map[string]any{}}, reg)
		if pol == nil || n != 1 || why != "" {
			t.Fatalf("got %v %d %q", pol, n, why)
		}
	}
}
