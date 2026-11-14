package pca

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// g05: policy_link.go. Self-contained templates (no corpus file): every definition, overlay and reference guard with an
// input the later checks would answer differently, the slot-count and closed-set bounds at N and N+1, the splice rules,
// and the overlay count staying 0 on every ResolveLink refusal.

func g05Tpl(slots map[string]any, preds ...any) map[string]any {
	if preds == nil {
		preds = []any{}
	}
	return map[string]any{"v": json.Number("1"), "kind": "pca-policy-template", "id": "t", "version": "1", "slots": slots,
		"body": map[string]any{"predicates": preds}}
}

// g05Where is a predicate whose single where condition has the given value.
func g05Where(value any) map[string]any {
	return map[string]any{"verb": "read", "where": []any{map[string]any{"field": "f", "op": "eq", "value": value}}}
}

func g05Str() map[string]any { return map[string]any{"type": "string"} }

func g05Strs(prefix string, n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%02d", prefix, i)
	}
	return out
}

func g05LinkSig(t *testing.T, k *KeyPair, domain string, v any) string {
	t.Helper()
	d, err := HashCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(k.Sign(linkMessage(domain, d)))
}

func g05DefErr(t *testing.T, label string, def any, want string) {
	t.Helper()
	if got := TemplateDefError(def); got != want {
		t.Fatalf("%s: got %q, want %q", label, got, want)
	}
}

func TestG05PolicyLinkDefErrors(t *testing.T) {
	ok := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a"}))
	g05DefErr(t, "valid", ok, "")
	kind := copyMap(ok)
	kind["kind"] = "pca-other"
	g05DefErr(t, "kind", kind, "template v / kind mismatch")

	const verr = "template version must be a string of 1..64 characters"
	for _, c := range []struct {
		v    any
		want string
	}{{"", verr}, {json.Number("1"), verr}, {strings.Repeat("v", 64), ""}, {strings.Repeat("v", 65), verr}} {
		d := copyMap(ok)
		d["version"] = c.v
		g05DefErr(t, fmt.Sprintf("version %v", c.v), d, c.want)
	}
	noVer := copyMap(ok)
	delete(noVer, "version")
	g05DefErr(t, "no version", noVer, verr)

	noSlots := g05Tpl(nil)
	delete(noSlots, "slots")
	g05DefErr(t, "no slots", noSlots, "slots must be an object")

	// slot count: 32 is the maximum
	many := func(n int) map[string]any {
		slots, where := map[string]any{}, []any{}
		for _, s := range g05Strs("s", n) {
			slots[s.(string)] = g05Str()
			where = append(where, map[string]any{"field": "f", "op": "eq", "value": map[string]any{"$slot": s}})
		}
		return g05Tpl(slots, map[string]any{"verb": "read", "where": where})
	}
	g05DefErr(t, "32 slots", many(32), "")
	g05DefErr(t, "33 slots", many(33), "more than 32 slots")

	one := func(slot map[string]any) map[string]any {
		return g05Tpl(map[string]any{"s": slot}, g05Where(map[string]any{"$slot": "s"}))
	}
	g05DefErr(t, "bogus type", one(map[string]any{"type": "bogus"}), "slot 's'.type must be string, integer or set")
	const vals = "slot 's'.values must be a list of strings"
	g05DefErr(t, "64 values", one(map[string]any{"type": "string", "values": g05Strs("v", 64)}), "")
	g05DefErr(t, "65 values", one(map[string]any{"type": "string", "values": g05Strs("v", 65)}), vals)
	g05DefErr(t, "non-string value", one(map[string]any{"type": "string", "values": []any{json.Number("1")}}), vals)
	g05DefErr(t, "string min ignored", one(map[string]any{"type": "string", "min": "x"}), "")
	g05DefErr(t, "integer min", one(map[string]any{"type": "integer", "min": "x"}), "slot 's'.min must be a safe integer")

	g05DefErr(t, "no predicates", map[string]any{"v": json.Number("1"), "kind": "pca-policy-template", "id": "t", "version": "1",
		"slots": map[string]any{}, "body": map[string]any{}}, "body.predicates must be an array")
	g05DefErr(t, "$slot true", g05Tpl(map[string]any{}, map[string]any{"verb": map[string]any{"$slot": true}}), "placeholder names undeclared slot 'true'")
	g05DefErr(t, "$slot false", g05Tpl(map[string]any{}, map[string]any{"verb": map[string]any{"$slot": false}}), "placeholder names undeclared slot 'false'")
}

func TestG05PolicyLinkVerifyTemplate(t *testing.T) {
	k := g05Key(t, 0x81)
	def := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a"}))
	signed := map[string]any{"def": def, "signer": k.Public, "sig": g05LinkSig(t, k, templateSigDomain, def)}
	if why, ok := VerifyTemplate(signed, []string{k.Public}); !ok || why != "" {
		t.Fatalf("valid: %v %q", ok, why)
	}
	numSigner := copyMap(signed)
	numSigner["signer"] = json.Number("5")
	if why, ok := VerifyTemplate(numSigner, []string{k.Public}); ok || why != "template signer is not trusted" {
		t.Fatalf("non-string signer: %v %q", ok, why)
	}
	badKey := copyMap(signed)
	badKey["signer"] = "bad"
	if why, ok := VerifyTemplate(badKey, []string{"bad"}); ok || why != "bad template signature" {
		t.Fatalf("undecodable signer key: %v %q", ok, why)
	}
	bad := copyMap(def)
	bad["kind"] = "pca-other"
	signedBad := map[string]any{"def": bad, "signer": k.Public, "sig": g05LinkSig(t, k, templateSigDomain, bad)}
	if why, ok := VerifyTemplate(signedBad, []string{k.Public}); ok || why != "template v / kind mismatch" {
		t.Fatalf("signed malformed def: %v %q", ok, why)
	}
}

func g05Overlay() map[string]any {
	return map[string]any{"v": json.Number("1"), "kind": "pca-template-tighten", "template_id": "t", "version_digest": "D",
		"add_where":   []any{map[string]any{"field": "env.tier", "op": "ne", "value": "frozen"}},
		"add_caveats": []any{map[string]any{"type": "max_blast_radius"}}}
}

func TestG05PolicyLinkOverlay(t *testing.T) {
	if e := TightenOverlayError(g05Overlay()); e != "" {
		t.Fatalf("valid overlay: %q", e)
	}
	for _, c := range []struct {
		k    string
		v    any
		want string
	}{
		{"kind", "pca-other", "overlay v / kind mismatch"},
		{"template_id", "BAD", "overlay template_id invalid"},
		{"version_digest", "", "overlay version_digest invalid"},
		{"add_caveats", []any{map[string]any{}}, "overlay add_caveats must be a list of caveats"},
	} {
		o := g05Overlay()
		o[c.k] = c.v
		if e := TightenOverlayError(o); e != c.want {
			t.Fatalf("%s: got %q, want %q", c.k, e, c.want)
		}
	}
	k, other := g05Key(t, 0x82), g05Key(t, 0x83)
	ov := g05Overlay()
	signed := map[string]any{"overlay": ov, "signer": k.Public, "sig": g05LinkSig(t, k, tightenSigDomain, ov)}
	if why, ok := VerifyTighten(signed, []string{k.Public}); !ok || why != "" {
		t.Fatalf("valid: %v %q", ok, why)
	}
	if why, ok := VerifyTighten(signed, []string{other.Public}); ok || why != "overlay signer is not trusted" {
		t.Fatalf("untrusted: %v %q", ok, why)
	}
	bad := g05Overlay()
	bad["kind"] = "pca-other"
	signedBad := map[string]any{"overlay": bad, "signer": k.Public, "sig": g05LinkSig(t, k, tightenSigDomain, bad)}
	if why, ok := VerifyTighten(signedBad, []string{k.Public}); ok || why != "overlay v / kind mismatch" {
		t.Fatalf("signed malformed overlay: %v %q", ok, why)
	}
}

func TestG05PolicyLinkSlotValues(t *testing.T) {
	str := g05Str()
	const serr = "slot 'acct' must be a string of 1..256 characters"
	for _, c := range []struct {
		v    any
		want string
	}{{"", serr}, {json.Number("5"), serr}, {strings.Repeat("a", 256), ""}, {strings.Repeat("a", 257), serr}} {
		if got := slotValueError("acct", str, c.v); got != c.want {
			t.Fatalf("string %v: got %q, want %q", c.v, got, c.want)
		}
	}
	integer := map[string]any{"type": "integer", "min": json.Number("1"), "max": json.Number("1000")}
	for _, c := range []struct {
		v, want string
	}{{"1", ""}, {"1000", ""}, {"0", "slot 'cap' is below its minimum"}, {"1001", "slot 'cap' is above its maximum"}} {
		if got := slotValueError("cap", integer, json.Number(c.v)); got != c.want {
			t.Fatalf("integer %s: got %q, want %q", c.v, got, c.want)
		}
	}
	set := map[string]any{"type": "set", "values": g05Strs("v", 64)}
	if got := slotValueError("v", set, g05Strs("v", 64)); got != "" {
		t.Fatalf("64 members: %q", got)
	}
	if got := slotValueError("v", set, append(g05Strs("v", 64), "v00")); got != "slot 'v' must be a non-empty list of strings" {
		t.Fatalf("65 members: %q", got)
	}
	// without a closed list (never after TemplateDefError, which requires one) any distinct members pass
	if got := slotValueError("v", map[string]any{"type": "set"}, []any{"a"}); got != "" {
		t.Fatalf("open set: %q", got)
	}
}

func g05Inst(t *testing.T, def any, slots any) (any, string) {
	t.Helper()
	pol, why := InstantiateTemplate(def, slots)
	if why != "" {
		if pol != nil {
			t.Fatalf("refusal %q with a policy", why)
		}
		return nil, why
	}
	return pol["predicates"].([]any)[0].(map[string]any)["where"].([]any)[0].(map[string]any)["value"], ""
}

func TestG05PolicyLinkInstantiate(t *testing.T) {
	strSlot := map[string]any{"a": g05Str()}
	splice := func(kv ...string) map[string]any {
		m := map[string]any{"$slot": "a"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return g05Tpl(strSlot, g05Where(m))
	}
	for _, c := range []struct {
		label string
		def   map[string]any
		fill  map[string]any
		val   any
		why   string
	}{
		{"wildcard in a where value", g05Tpl(strSlot, g05Where(map[string]any{"$slot": "a"})), map[string]any{"a": "x*"}, "x*", ""},
		{"pre only", splice("pre", "p-"), map[string]any{"a": "x"}, "p-x", ""},
		{"wildcard spliced", splice("pre", "p-"), map[string]any{"a": "x*"}, nil, "slot 'a' cannot be spliced into a string (wildcard or non-string)"},
		{"integer spliced", g05Tpl(map[string]any{"a": map[string]any{"type": "integer"}}, g05Where(map[string]any{"$slot": "a", "pre": "p-"})),
			map[string]any{"a": json.Number("5")}, nil, "slot 'a' cannot be spliced into a string (wildcard or non-string)"},
		{"regex spliced", splice("post", "/x"), map[string]any{"a": "re:abc"}, nil, "slot 'a' would inject a regex matcher"},
		{"post only", splice("post", "/x"), map[string]any{"a": "abc"}, "abc/x", ""},
		{"regex prefix from pre", splice("pre", "re:"), map[string]any{"a": "x"}, "re:x", ""},
	} {
		val, why := g05Inst(t, c.def, c.fill)
		if why != c.why || !reflect.DeepEqual(val, c.val) {
			t.Fatalf("%s: got %v %q, want %v %q", c.label, val, why, c.val, c.why)
		}
	}
	if pol, why := InstantiateTemplate("x", map[string]any{}); pol != nil || why != "template must be an object" {
		t.Fatalf("non-object def: %v %q", pol, why)
	}
	def := g05Tpl(strSlot, g05Where(map[string]any{"$slot": "a"}))
	if pol, why := InstantiateTemplate(def, "x"); pol != nil || why != "slots must be an object" {
		t.Fatalf("non-object slots: %v %q", pol, why)
	}
	pol, why := InstantiateTemplate(def, map[string]any{"a": "x"})
	if c, ok := pol["caveats"].([]any); why != "" || !ok || c == nil || len(c) != 0 {
		t.Fatalf("absent caveats must instantiate as an empty list: %#v %q", pol["caveats"], why)
	}
}

func TestG05PolicyLinkRefErrors(t *testing.T) {
	ref := func(k string, v any) map[string]any {
		r := map[string]any{"template_id": "t", "version_digest": "D", "slots": map[string]any{}}
		r[k] = v
		return r
	}
	const vd = "template_ref.version_digest invalid"
	for _, c := range []struct {
		r    map[string]any
		want string
	}{
		{ref("template_id", "BAD"), "template_ref.template_id invalid"},
		{ref("version_digest", ""), vd},
		{ref("version_digest", json.Number("1")), vd},
		{ref("version_digest", strings.Repeat("d", 128)), ""},
		{ref("version_digest", strings.Repeat("d", 129)), vd},
	} {
		if got := TemplateRefError(c.r); got != c.want {
			t.Fatalf("%v: got %q, want %q", c.r, got, c.want)
		}
	}
	bound := func(d string) map[string]any {
		return map[string]any{"template_id": "t", "version_digest": "D", "bind_params_digest": d}
	}
	if got := TemplateRefError(bound(strings.Repeat("b", 128))); got != "" {
		t.Fatalf("128-char bound digest: %q", got)
	}
	if got := TemplateRefError(bound(strings.Repeat("b", 129))); got != "template_ref.bind_params_digest invalid" {
		t.Fatalf("129-char bound digest: %q", got)
	}
}

func TestG05PolicyLinkResolve(t *testing.T) {
	k := g05Key(t, 0x84)
	def := g05Tpl(map[string]any{"a": g05Str()}, g05Where(map[string]any{"$slot": "a"}))
	d, err := TemplateDigest(def)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]any{"def": def, "signer": k.Public, "sig": g05LinkSig(t, k, templateSigDomain, def)}
	reg := func(kv ...any) map[string]any {
		r := map[string]any{"templates": map[string]any{d: signed}, "trusted": []any{k.Public}}
		for i := 0; i+1 < len(kv); i += 2 {
			r[kv[i].(string)] = kv[i+1]
		}
		return r
	}
	ref := func(kv ...any) map[string]any {
		r := map[string]any{"template_id": "t", "version_digest": d, "slots": map[string]any{"a": "x"}}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(r, kv[i].(string))
			} else {
				r[kv[i].(string)] = kv[i+1]
			}
		}
		return r
	}
	if pol, n, why := ResolveLink(ref(), reg()); pol == nil || n != 0 || why != "" {
		t.Fatalf("valid: %v %d %q", pol, n, why)
	}
	ov := g05Overlay()
	ov["version_digest"] = d
	badOv := []any{map[string]any{"overlay": ov, "signer": k.Public, "sig": "bad"}}
	for _, c := range []struct {
		label string
		ref   any
		reg   map[string]any
		want  string
	}{
		{"not an object", "x", reg(), "template_ref must be an object"},
		{"unknown version", ref("version_digest", "nope"), reg(), "template version is not in the registry"},
		{"untrusted", ref(), reg("trusted", []any{}), "template signer is not trusted"},
		{"digest mismatch", ref("version_digest", "WRONG"), reg("templates", map[string]any{"WRONG": signed}), "registry entry does not match its digest"},
		{"id mismatch", ref("template_id", "u"), reg(), "template id does not match the reference"},
		{"no params", ref("slots", nil, "bind_params_digest", "pd"), reg(), "parameter object is not available"},
		{"uncanonicalizable params", ref("slots", nil, "bind_params_digest", "pd"),
			reg("params", map[string]any{"pd": map[string]any{"a": "\xed\xa0\x80"}}), "link resolution error (fail closed)"},
		{"params digest", ref("slots", nil, "bind_params_digest", "pd"),
			reg("params", map[string]any{"pd": map[string]any{"a": "x"}}), "parameter object does not match bind_params_digest"},
		{"bad fill", ref("slots", map[string]any{"a": ""}), reg(), "slot 'a' must be a string of 1..256 characters"},
		{"bad overlay", ref(), reg("overlays", badOv), "bad overlay signature"},
	} {
		if pol, n, why := ResolveLink(c.ref, c.reg); pol != nil || n != 0 || why != c.want {
			t.Fatalf("%s: got %v %d %q, want %q", c.label, pol, n, why, c.want)
		}
	}
}

// An overlay over a predicate with no members: each predicate is copied with room for its where.
func TestG05PolicyLinkResolveOverlayEmptyPredicate(t *testing.T) {
	k := g05Key(t, 0x85)
	def := g05Tpl(map[string]any{}, map[string]any{})
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
	pol, n, why := ResolveLink(map[string]any{"template_id": "t", "version_digest": d, "slots": map[string]any{}}, reg)
	want := []any{map[string]any{"where": ov["add_where"]}}
	if why != "" || n != 1 || !reflect.DeepEqual(pol["predicates"], want) {
		t.Fatalf("got %v %d %q", pol, n, why)
	}
}
