package pca

import (
	"sort"
	"strings"
	"testing"
)

// g08: boundary and branch kills for action_schema.go (format checkers, floors, v2 param / verb / document shape,
// confirmation shape, value domains).

const g08B32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // canonical base64url of 32 zero bytes
const g08Sig64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func g08Eq(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", label, got, want)
	}
}

func g08Strs(xs ...string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// g08TwoLetter returns n sorted distinct strings prefix+<two lowercase letters>.
func g08TwoLetter(prefix string, n int) []any {
	out := make([]any, n)
	for i := 0; i < n; i++ {
		out[i] = prefix + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	return out
}

func g08Floors() map[string]any {
	return map[string]any{"risk": 0, "rev": "reversible", "blast_ppm": 0, "esc": 0,
		"caveats": []any{}, "context": []any{}, "prules": []any{}}
}

func g08With(base map[string]any, kv ...any) map[string]any {
	for i := 0; i+1 < len(kv); i += 2 {
		k := kv[i].(string)
		if kv[i+1] == nil {
			delete(base, k)
		} else {
			base[k] = kv[i+1]
		}
	}
	return base
}

func g08Decl(kv ...any) map[string]any {
	return g08With(map[string]any{"type": "string", "semantic": "s", "sensitivity": "free"}, kv...)
}

func g08VerbV2(kv ...any) map[string]any {
	return g08With(map[string]any{"verb": "v", "kind": "read", "params": map[string]any{}, "effects": g08Strs("read"),
		"traits": []any{}, "def": g08B32, "floors": g08Floors()}, kv...)
}

func g08DocV2(kv ...any) map[string]any {
	return g08With(map[string]any{"v": 2, "kind": "pca-action-schema", "site": "s", "aud": "a", "version": "1",
		"verbs": []any{g08VerbV2()}}, kv...)
}

func g08Conf(kv ...any) map[string]any {
	return g08With(map[string]any{"def_digest": g08B32, "traits_digest": g08B32, "facts_digest": g08B32,
		"final_traits": []any{}, "dismissed": []any{}, "reviewer_kid": "k", "ts": 0, "sig": g08Sig64}, kv...)
}

func TestK05KillG08FormatCheckers(t *testing.T) {
	// IBAN: a short string is refused by the regex before slicing; a letter-bearing valid IBAN pins the letter values.
	if ibanOK("ab") || ibanOK("") {
		t.Error("short iban accepted")
	}
	if !ibanOK("AD1200012030200359100100") {
		t.Error("valid AD iban refused")
	}
	if ibanOK("AD1200012030200359100101") {
		t.Error("bad-checksum iban accepted")
	}
	// CIDR v4 bounds.
	for s, want := range map[string]bool{
		"1.2.3.255/8": true, "1.2.3.256/8": false, "1.2.256.4/8": false, "1.2.3.4/32": true, "1.2.3.4/33": false,
		"1.2.3.04/8": false, "255.255.255.255/0": true,
		// CIDR v6: at least two colons, no ":::", prefix <= 128.
		"::/0": true, "::1/128": true, "::1/129": false, "a:/8": false, "a:b/8": false, ":::/8": false, "1::2:3/64": true,
	} {
		if got := cidrOK(s); got != want {
			t.Errorf("cidrOK(%q) = %v, want %v", s, got, want)
		}
	}
	// email: 254 bytes accepted, 255 refused.
	local := strings.Repeat("a", 64)
	l63 := strings.Repeat("b", 63)
	e254 := local + "@" + l63 + "." + l63 + "." + strings.Repeat("c", 61)
	e255 := local + "@" + l63 + "." + l63 + "." + strings.Repeat("c", 62)
	if len(e254) != 254 || len(e255) != 255 {
		t.Fatalf("fixture lengths %d %d", len(e254), len(e255))
	}
	ck := formatCheck("email")
	if !ck(e254) {
		t.Error("254-byte email refused")
	}
	if ck(e255) {
		t.Error("255-byte email accepted")
	}
	if formatCheck("iban") == nil || formatCheck("cidr") == nil || formatCheck("zzz") != nil {
		t.Error("formatCheck table")
	}
}

func TestK05KillG08Floors(t *testing.T) {
	g08Eq(t, "valid", schemaFloorsError(g08Floors()), "")
	g08Eq(t, "unknown", schemaFloorsError(g08With(g08Floors(), "zzz", 1)), "floors: unknown member 'zzz'")
	const re = "floors.risk and floors.esc must be integers in 0..3"
	for _, c := range []struct {
		k    string
		v    any
		want string
	}{
		{"risk", 3, ""}, {"esc", 3, ""}, {"risk", 4, re}, {"esc", 4, re}, {"risk", -1, re}, {"esc", -1, re},
		{"risk", 1.5, re}, {"esc", 1.5, re}, {"risk", "1", re},
		{"rev", "bogus", "floors.rev is not a reversibility class"}, {"rev", "irreversible", ""},
		{"blast_ppm", 1000000, ""}, {"blast_ppm", 1000001, "floors.blast_ppm must be an integer in 0..1000000"},
		{"blast_ppm", -1, "floors.blast_ppm must be an integer in 0..1000000"},
		{"caveats", g08Strs("bogus"), "floors.caveats must be an array of known entries"},
		{"caveats", []any{1}, "floors.caveats must be an array of known entries"},
		{"caveats", g08Strs("window", "amount_cap"), "floors.caveats must be sorted and distinct"},
		{"caveats", g08Strs("window", "window"), "floors.caveats must be sorted and distinct"},
		{"caveats", g08Strs("amount_cap", "window"), ""},
		{"context", g08TwoLetter("session_taint_max:", 64), ""},
		{"context", g08TwoLetter("session_taint_max:", 65), "floors.context must be an array of known entries"},
		{"context", "approval_ref", "floors.context must be an array of known entries"},
	} {
		g08Eq(t, c.k, schemaFloorsError(g08With(g08Floors(), c.k, c.v)), c.want)
	}
	g08Eq(t, "prules missing", schemaFloorsError(g08With(g08Floors(), "prules", nil)), "floors.prules must be an array of known entries")
}

func TestK05KillG08ParamDecl(t *testing.T) {
	const p = "action.params.x"
	pe := func(v2 bool, d map[string]any) string { return paramDeclErrorV(p, d, nil, false, v2) }
	// v1 refuses v2 types and members.
	g08Eq(t, "v1 datetime", pe(false, g08Decl("type", "datetime")), p+": unknown type")
	g08Eq(t, "v1 role", pe(false, g08Decl("role", "r")), p+": unknown member 'role'")
	// min / max applicability.
	const mm = p + ": min must be a safe integer on an integer parameter"
	g08Eq(t, "int min", pe(false, g08Decl("type", "integer", "min", 1)), "")
	g08Eq(t, "int min frac", pe(false, g08Decl("type", "integer", "min", 1.5)), mm)
	g08Eq(t, "array int min", pe(false, g08Decl("type", "array", "items", "integer", "min", 1)), "")
	g08Eq(t, "array str min", pe(false, g08Decl("type", "array", "items", "string", "min", 1)), mm)
	g08Eq(t, "v2 duration min", pe(true, g08Decl("type", "duration", "min", 1)), "")
	g08Eq(t, "v2 string min", pe(true, g08Decl("min", 1)), mm)
	g08Eq(t, "v2 date min", pe(true, g08Decl("type", "date", "min", 1)), mm)
	// role.
	g08Eq(t, "role 128", pe(true, g08Decl("role", strings.Repeat("r", 128))), "")
	g08Eq(t, "role 129", pe(true, g08Decl("role", strings.Repeat("r", 129))), p+": role must be a non-empty string")
	g08Eq(t, "role empty", pe(true, g08Decl("role", "")), p+": role must be a non-empty string")
	// format.
	const fm = p + ": format must be a known format on a string parameter"
	g08Eq(t, "format string", pe(true, g08Decl("format", "email")), "")
	g08Eq(t, "format object_ref", pe(true, g08Decl("type", "object_ref", "format", "uuid")), "")
	g08Eq(t, "format integer", pe(true, g08Decl("type", "integer", "format", "email")), fm)
	g08Eq(t, "format unknown", pe(true, g08Decl("format", "zzz")), fm)
	g08Eq(t, "format non-string", pe(true, g08Decl("format", 1)), fm)
	// tags.
	const tm = p + ": tags must be distinct known tags"
	all := append([]any{}, g08Strs(paramTags...)...)
	g08Eq(t, "tags all", pe(true, g08Decl("tags", all)), "")
	g08Eq(t, "tags one", pe(true, g08Decl("tags", g08Strs("pii"))), "")
	g08Eq(t, "tags empty", pe(true, g08Decl("tags", []any{})), "")
	g08Eq(t, "tags unknown", pe(true, g08Decl("tags", g08Strs("bogus"))), tm)
	g08Eq(t, "tags dup", pe(true, g08Decl("tags", g08Strs("pii", "pii"))), tm)
	g08Eq(t, "tags non-array", pe(true, g08Decl("tags", "pii")), tm)
	g08Eq(t, "tags too many", pe(true, g08Decl("tags", append(all, "pii"))), tm)
	g08Eq(t, "prov", pe(true, g08Decl("provenance_min", "tool")), "")
	g08Eq(t, "prov bad", pe(true, g08Decl("provenance_min", "zzz")), p+": unknown provenance_min")
}

func TestK05KillG08VerbDecl(t *testing.T) {
	ve := func(v2 bool, v any) string { return verbDeclErrorV(v, nil, false, v2) }
	const at = "verb 'v'"
	g08Eq(t, "non-object", ve(false, "x"), "verb entry must be an object")
	g08Eq(t, "nil", ve(true, nil), "verb entry must be an object")
	g08Eq(t, "v1 def", ve(false, map[string]any{"verb": "v", "kind": "read", "params": map[string]any{}, "def": g08B32}),
		"verb entry: unknown member 'def'")
	g08Eq(t, "v2 valid", ve(true, g08VerbV2()), "")
	g08Eq(t, "v2 parent", ve(true, g08VerbV2("params", map[string]any{"action.params.a": g08Decl(), "action.params.a.b": g08Decl()})),
		at+": parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'")
	g08Eq(t, "v2 siblings", ve(true, g08VerbV2("params", map[string]any{"action.params.a": g08Decl(), "action.params.ab": g08Decl()})), "")
	// effects.
	const em = at + ": effects must be 1..12 known effects"
	all := g08Strs(schemaV2Effects...)
	sort.Slice(all, func(i, j int) bool { return all[i].(string) < all[j].(string) })
	g08Eq(t, "effects all", ve(true, g08VerbV2("kind", "write", "effects", all)), "")
	g08Eq(t, "effects empty", ve(true, g08VerbV2("effects", []any{})), em)
	g08Eq(t, "effects missing", ve(true, g08VerbV2("effects", nil)), em)
	g08Eq(t, "effects unknown", ve(true, g08VerbV2("kind", "write", "effects", g08Strs("bogus"))), em)
	g08Eq(t, "effects sorted", ve(true, g08VerbV2("kind", "write", "effects", g08Strs("create", "update"))), "")
	g08Eq(t, "effects unsorted", ve(true, g08VerbV2("kind", "write", "effects", g08Strs("update", "create"))), at+": effects must be sorted and distinct")
	g08Eq(t, "effects dup", ve(true, g08VerbV2("kind", "write", "effects", g08Strs("create", "create"))), at+": effects must be sorted and distinct")
	const km = at + ": kind read must hold exactly when every effect is read"
	g08Eq(t, "write all-read", ve(true, g08VerbV2("kind", "write")), km)
	g08Eq(t, "read with write effect", ve(true, g08VerbV2("effects", g08Strs("create"))), km)
	// traits.
	const trm = at + ": traits must be trait ids"
	g08Eq(t, "traits 64", ve(true, g08VerbV2("traits", g08TwoLetter("t.a", 64))), "")
	g08Eq(t, "traits 65", ve(true, g08VerbV2("traits", g08TwoLetter("t.a", 65))), trm)
	g08Eq(t, "traits missing", ve(true, g08VerbV2("traits", nil)), trm)
	g08Eq(t, "traits bad id", ve(true, g08VerbV2("traits", g08Strs("BAD"))), trm)
	g08Eq(t, "traits unsorted", ve(true, g08VerbV2("traits", g08Strs("t.b", "t.a"))), at+": traits must be sorted and distinct")
	g08Eq(t, "traits dup", ve(true, g08VerbV2("traits", g08Strs("t.a", "t.a"))), at+": traits must be sorted and distinct")
	g08Eq(t, "traits sorted", ve(true, g08VerbV2("traits", g08Strs("t.a", "t.b"))), "")
	g08Eq(t, "def", ve(true, g08VerbV2("def", "x")), at+": def must be a canonical base64url SHA-256 digest")
	g08Eq(t, "floors", ve(true, g08VerbV2("floors", nil)), at+": floors must be an object")
}

func TestK05KillG08Confirmation(t *testing.T) {
	g08Eq(t, "valid", confirmationShapeError(g08Conf()), "")
	g08Eq(t, "non-object", confirmationShapeError("x"), "confirmation must be an object")
	const ftm = "confirmation: final_traits must be trait ids"
	g08Eq(t, "ft 64", confirmationShapeError(g08Conf("final_traits", g08TwoLetter("t.a", 64))), "")
	g08Eq(t, "ft 65", confirmationShapeError(g08Conf("final_traits", g08TwoLetter("t.a", 65))), ftm)
	g08Eq(t, "ft missing", confirmationShapeError(g08Conf("final_traits", nil)), ftm)
	dis := func(n int, reason string) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"trait": "t.a", "reason": reason}
		}
		return out
	}
	const dm = "confirmation: dismissed must be an array"
	g08Eq(t, "dm 64", confirmationShapeError(g08Conf("dismissed", dis(64, "r"))), "")
	g08Eq(t, "dm 65", confirmationShapeError(g08Conf("dismissed", dis(65, "r"))), dm)
	const de = "confirmation: dismissed entries must be {trait, reason}"
	g08Eq(t, "reason 256", confirmationShapeError(g08Conf("dismissed", dis(1, strings.Repeat("r", 256)))), "")
	g08Eq(t, "reason 257", confirmationShapeError(g08Conf("dismissed", dis(1, strings.Repeat("r", 257)))), de)
	const rk = "confirmation: reviewer_kid must be a non-empty string"
	g08Eq(t, "kid 128", confirmationShapeError(g08Conf("reviewer_kid", strings.Repeat("k", 128))), "")
	g08Eq(t, "kid 129", confirmationShapeError(g08Conf("reviewer_kid", strings.Repeat("k", 129))), rk)
}

func TestK05KillG08DocShape(t *testing.T) {
	g08Eq(t, "non-object", actionSchemaShapeError("x", false), "schema is not an object")
	g08Eq(t, "v2 valid", actionSchemaShapeError(g08DocV2(), false), "")
	v1 := map[string]any{"v": 1, "kind": "pca-action-schema", "site": "s", "aud": "a", "version": "1",
		"verbs": []any{map[string]any{"verb": "v", "kind": "read", "params": map[string]any{}}}}
	g08Eq(t, "v1 valid", actionSchemaShapeError(v1, false), "")
	v1["traits_digest"] = g08B32
	g08Eq(t, "v1 traits_digest", actionSchemaShapeError(v1, false), "unknown member 'traits_digest'")
	// trait_defs.
	const tdm = "trait_defs must be an array of up to 64 objects"
	objs := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{}
		}
		return out
	}
	g08Eq(t, "td 1", actionSchemaShapeError(g08DocV2("trait_defs", objs(1)), false), "")
	g08Eq(t, "td 64", actionSchemaShapeError(g08DocV2("trait_defs", objs(64)), false), "")
	g08Eq(t, "td 65", actionSchemaShapeError(g08DocV2("trait_defs", objs(65)), false), tdm)
	g08Eq(t, "td non-array", actionSchemaShapeError(g08DocV2("trait_defs", "x"), false), tdm)
	g08Eq(t, "td non-object", actionSchemaShapeError(g08DocV2("trait_defs", []any{1}), false), tdm)
	// pack.
	const pm = "pack must be {ns, version, root}"
	pack := func(kv ...any) map[string]any {
		return g08With(map[string]any{"ns": "n", "version": "1", "root": g08B32}, kv...)
	}
	g08Eq(t, "pack valid", actionSchemaShapeError(g08DocV2("pack", pack()), false), "")
	g08Eq(t, "pack ns 64 version 128", actionSchemaShapeError(g08DocV2("pack", pack("ns", strings.Repeat("n", 64), "version", strings.Repeat("v", 128))), false), "")
	for name, bad := range map[string]any{
		"non-object": "x", "extra key": pack("zz", "1"), "missing root": pack("root", nil),
		"ns 65": pack("ns", strings.Repeat("n", 65)), "ns empty": pack("ns", ""),
		"version 129": pack("version", strings.Repeat("v", 129)), "version empty": pack("version", ""),
		"root bad": pack("root", "x"),
	} {
		g08Eq(t, "pack "+name, actionSchemaShapeError(g08DocV2("pack", bad), false), pm)
	}
}

func TestK05KillG08ValueDomains(t *testing.T) {
	ref := map[string]any{"type": "object_ref", "max_len": 3}
	pv := func(d map[string]any, x any) string {
		c, r := paramValueViolationReason(d, x)
		return c + "|" + r
	}
	g08Eq(t, "ref at max", pv(ref, "abc"), "|")
	g08Eq(t, "ref over max", pv(ref, "abcd"), "out_of_domain|longer than 3 UTF-8 bytes")
	g08Eq(t, "ref surrogate", pv(ref, "\xed\xa0\x80"), "bad_type|expected a non-empty id string")
	g08Eq(t, "ref empty", pv(ref, ""), "bad_type|expected a non-empty id string")
	g08Eq(t, "ref non-string", pv(ref, 1), "bad_type|expected a non-empty id string")
	dur := map[string]any{"type": "duration"}
	g08Eq(t, "dur 0", pv(dur, 0), "|")
	g08Eq(t, "dur -1", pv(dur, -1), "out_of_domain|a duration is not negative")
	durB := map[string]any{"type": "duration", "min": 5, "max": 9}
	g08Eq(t, "dur min", pv(durB, 5), "|")
	g08Eq(t, "dur max", pv(durB, 9), "|")
	g08Eq(t, "dur below", pv(durB, 4), "out_of_domain|below min 5")
	g08Eq(t, "dur above", pv(durB, 10), "out_of_domain|above max 9")
}
