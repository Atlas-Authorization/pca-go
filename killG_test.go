package pca

// Kill tests for action_schema.go (rule 14: the signed action schema shape, its signature, and the closed-world
// conformance). The oracle is packages/pca/src/action-schema.ts (paramDeclError / verbDeclError /
// actionSchemaShapeError / verifyActionSchema / paramValueViolation / conformAction / accumulationParams): every case
// below is the verdict the reference gives for the same input, at the exact boundary of each rule.

import (
	"fmt"
	"strings"
	"testing"
)

func killGJ(t *testing.T, s string) any {
	t.Helper()
	v, err := ParseJSONLenient([]byte(s))
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return v
}

func killGM(t *testing.T, s string) map[string]any { t.Helper(); return killGJ(t, s).(map[string]any) }

// killGStr is a JSON string literal of n ASCII bytes.
func killGStr(n int) string { return `"` + strings.Repeat("a", n) + `"` }

const killGLone = "\xed\xa0\x80" // a lone surrogate (WTF-8), as the strict parser represents "\ud800"

func TestKillGHelpers(t *testing.T) {
	cases := []struct {
		v    any
		max  int
		want bool
	}{
		{"a", 1, true}, {"ab", 1, false}, {"", 5, false}, {5, 5, false}, {nil, 5, false},
		{"a" + killGLone, 10, false}, {strings.Repeat("a", 128), 128, true}, {strings.Repeat("a", 129), 128, false},
		{"é", 2, true}, {"é", 1, false}, // UTF-8 bytes, not code points
	}
	for i, c := range cases {
		if got := schemaStr(c.v, c.max); got != c.want {
			t.Errorf("schemaStr #%d(%q, %d) = %v, want %v", i, c.v, c.max, got, c.want)
		}
	}
	set := []string{"x", "y"}
	if !strIn("x", set) || strIn("z", set) || strIn(1, set) || strIn(nil, set) {
		t.Error("strIn")
	}
	if !keysWithin(map[string]any{"a": 1}, []string{"a", "b"}) || keysWithin(map[string]any{"a": 1, "c": 1}, []string{"a", "b"}) {
		t.Error("keysWithin")
	}
	if !keysWithin(map[string]any{}, nil) {
		t.Error("keysWithin empty")
	}
}

// ---- paramDeclOK (paramDeclError == null) ----

func TestKillGParamDecl(t *testing.T) {
	units := map[string]any{"usd_cents": map[string]any{"kind": "money"}}
	vals := func(n int, size int) string {
		xs := make([]string, n)
		for i := range xs {
			s := fmt.Sprintf("v%d", i)
			if size > len(s) {
				s += strings.Repeat("z", size-len(s))
			}
			xs[i] = `"` + s + `"`
		}
		return "[" + strings.Join(xs, ",") + "]"
	}
	units8 := func(n int) string {
		xs := make([]string, n)
		for i := range xs {
			xs[i] = fmt.Sprintf(`"u%d"`, i)
		}
		return "[" + strings.Join(xs, ",") + "]"
	}
	const S = `"type":"string","semantic":"s","sensitivity":"free"`
	const I = `"type":"integer","semantic":"s","sensitivity":"free"`
	const A = `"type":"array","semantic":"s","sensitivity":"free"`
	const SET = `"type":"set","semantic":"s","sensitivity":"free"`
	cases := []struct {
		name, path, decl string
		noUnits          bool
		want             bool
	}{
		{"base string", "", `{` + S + `}`, false, true},
		{"bad path", "params.x", `{` + S + `}`, false, false},
		{"path 65", "action.params." + strings.Repeat("a", 65), `{` + S + `}`, false, false},
		{"__proto__", "action.params.__proto__", `{` + S + `}`, false, false},
		{"constructor", "action.params.constructor", `{` + S + `}`, false, false},
		{"prototype", "action.params.prototype", `{` + S + `}`, false, false},
		{"not object", "", `"x"`, false, false},
		{"null decl", "", `null`, false, false},
		{"unknown member", "", `{` + S + `,"zz":1}`, false, false},
		{"bad type", "", `{"type":"number","semantic":"s","sensitivity":"free"}`, false, false},
		{"no type", "", `{"semantic":"s","sensitivity":"free"}`, false, false},
		{"semantic empty", "", `{"type":"string","semantic":"","sensitivity":"free"}`, false, false},
		{"semantic 128", "", `{"type":"string","semantic":` + killGStr(128) + `,"sensitivity":"free"}`, false, true},
		{"semantic 129", "", `{"type":"string","semantic":` + killGStr(129) + `,"sensitivity":"free"}`, false, false},
		{"bad sensitivity", "", `{"type":"string","semantic":"s","sensitivity":"high"}`, false, false},
		{"required true", "", `{` + S + `,"required":true}`, false, true},
		{"required false", "", `{` + S + `,"required":false}`, false, true},
		{"required string", "", `{` + S + `,"required":"no"}`, false, false},
		{"values ok", "", `{` + S + `,"values":["a","b"]}`, false, true},
		{"values not array", "", `{` + S + `,"values":"a"}`, false, false},
		{"values empty", "", `{` + S + `,"values":[]}`, false, false},
		{"values 256", "", `{` + S + `,"values":` + vals(256, 0) + `}`, false, true},
		{"values 257", "", `{` + S + `,"values":` + vals(257, 0) + `}`, false, false},
		{"values entry 256 bytes", "", `{` + S + `,"values":` + vals(1, 256) + `}`, false, true},
		{"values entry 257 bytes", "", `{` + S + `,"values":` + vals(1, 257) + `}`, false, false},
		{"values entry not string", "", `{` + S + `,"values":["a",1]}`, false, false},
		{"values entry empty", "", `{` + S + `,"values":["a",""]}`, false, false},
		{"values dup", "", `{` + S + `,"values":["a","a"]}`, false, false},
		{"values on integer", "", `{` + I + `,"values":["a"]}`, false, false},
		{"values on set", "", `{` + SET + `,"values":["a"]}`, false, true},
		{"set without values", "", `{` + SET + `}`, false, false},
		{"min on integer", "", `{` + I + `,"min":0}`, false, true},
		{"max on integer", "", `{` + I + `,"max":0}`, false, true},
		{"min fraction", "", `{` + I + `,"min":1.5}`, false, false},
		{"max fraction", "", `{` + I + `,"max":1.5}`, false, false},
		{"min on string", "", `{` + S + `,"min":0}`, false, false},
		{"max on string", "", `{` + S + `,"max":0}`, false, false},
		{"min on int array", "", `{` + A + `,"items":"integer","min":0}`, false, true},
		{"max on int array", "", `{` + A + `,"items":"integer","max":0}`, false, true},
		{"min on string array", "", `{` + A + `,"items":"string","min":0}`, false, false},
		{"max on string array", "", `{` + A + `,"items":"string","max":0}`, false, false},
		{"min on set items integer", "", `{` + SET + `,"values":["a"],"min":0}`, false, false},
		{"min == max", "", `{` + I + `,"min":5,"max":5}`, false, true},
		{"min < max", "", `{` + I + `,"min":4,"max":5}`, false, true},
		{"min > max", "", `{` + I + `,"min":6,"max":5}`, false, false},
		{"unit ok", "", `{` + I + `,"unit":"usd_cents"}`, false, true},
		{"unit on string", "", `{` + S + `,"unit":"usd_cents"}`, false, false},
		{"unit not string", "", `{` + I + `,"unit":5}`, false, false},
		{"unit without units", "", `{` + I + `,"unit":"usd_cents"}`, true, false},
		{"unit undeclared", "", `{` + I + `,"unit":"eur_cents"}`, false, false},
		{"max_len 1", "", `{` + S + `,"max_len":1}`, false, true},
		{"max_len 0", "", `{` + S + `,"max_len":0}`, false, false},
		{"max_len fraction", "", `{` + S + `,"max_len":1.5}`, false, false},
		{"max_len string", "", `{` + S + `,"max_len":"1"}`, false, false},
		{"items on array", "", `{` + A + `,"items":"integer"}`, false, true},
		{"items 64", "", `{` + A + `,"items":` + killGStr(64) + `}`, false, true},
		{"items 65", "", `{` + A + `,"items":` + killGStr(65) + `}`, false, false},
		{"items empty", "", `{` + A + `,"items":""}`, false, false},
		{"items on string", "", `{` + S + `,"items":"integer"}`, false, false},
		{"min_items on set", "", `{` + SET + `,"values":["a"],"min_items":0}`, false, true},
		{"max_items on set", "", `{` + SET + `,"values":["a"],"max_items":1}`, false, true},
		{"min_items on array", "", `{` + A + `,"min_items":1}`, false, true},
		{"max_items on array", "", `{` + A + `,"max_items":1}`, false, true},
		{"min_items on string", "", `{` + S + `,"min_items":0}`, false, false},
		{"max_items on string", "", `{` + S + `,"max_items":0}`, false, false},
		{"min_items negative", "", `{` + A + `,"min_items":-1}`, false, false},
		{"max_items negative", "", `{` + A + `,"max_items":-1}`, false, false},
		{"min_items == max_items", "", `{` + A + `,"min_items":2,"max_items":2}`, false, true},
		{"min_items < max_items", "", `{` + A + `,"min_items":1,"max_items":2}`, false, true},
		{"min_items > max_items", "", `{` + A + `,"min_items":3,"max_items":2}`, false, false},
		{"default null", "", `{` + S + `,"default":null}`, false, false},
		{"default", "", `{` + S + `,"default":"x"}`, false, true},
		{"pnd not bool", "", `{` + S + `,"default":"x","principal_neutral_default":1}`, false, false},
		{"pnd true no default", "", `{` + S + `,"principal_neutral_default":true}`, false, false},
		{"pnd true default", "", `{` + S + `,"default":"x","principal_neutral_default":true}`, false, true},
		{"pnd false no default", "", `{` + S + `,"principal_neutral_default":false}`, false, true},
		{"acc ok", "", `{` + I + `,"accumulates_into":["spend.usd"]}`, false, true},
		{"acc on string", "", `{` + S + `,"accumulates_into":["spend"]}`, false, false},
		{"acc not array", "", `{` + I + `,"accumulates_into":"spend"}`, false, false},
		{"acc empty", "", `{` + I + `,"accumulates_into":[]}`, false, false},
		{"acc 8", "", `{` + I + `,"accumulates_into":` + units8(8) + `}`, false, true},
		{"acc 9", "", `{` + I + `,"accumulates_into":` + units8(9) + `}`, false, false},
		{"acc entry not string", "", `{` + I + `,"accumulates_into":[1]}`, false, false},
		{"acc entry 64", "", `{` + I + `,"accumulates_into":[` + killGStr(64) + `]}`, false, true},
		{"acc entry 65", "", `{` + I + `,"accumulates_into":[` + killGStr(65) + `]}`, false, false},
		{"acc entry bad id", "", `{` + I + `,"accumulates_into":["Spend"]}`, false, false},
		{"acc dup", "", `{` + I + `,"accumulates_into":["a","a"]}`, false, false},
		{"issued_by_site", "", `{` + S + `,"issued_by_site":true}`, false, true},
		{"issued_by_site not bool", "", `{` + S + `,"issued_by_site":"yes"}`, false, false},
		{"description 1024", "", `{` + S + `,"description":` + killGStr(1024) + `}`, false, true},
		{"description 1025", "", `{` + S + `,"description":` + killGStr(1025) + `}`, false, false},
		{"description empty", "", `{` + S + `,"description":""}`, false, false},
	}
	for _, c := range cases {
		path := c.path
		if path == "" {
			path = "action.params.x"
		}
		u, hasU := units, true
		if c.noUnits {
			u, hasU = nil, false
		}
		if got := paramDeclOK(path, killGJ(t, c.decl), u, hasU); got != c.want {
			t.Errorf("%s: paramDeclOK = %v, want %v", c.name, got, c.want)
		}
	}
}

// ---- verbDeclOK (verbDeclError == null) ----

func TestKillGVerbDecl(t *testing.T) {
	params := func(n int) string {
		xs := make([]string, n)
		for i := range xs {
			xs[i] = fmt.Sprintf(`"action.params.p%d":{"type":"string","semantic":"s","sensitivity":"free"}`, i)
		}
		return "{" + strings.Join(xs, ",") + "}"
	}
	const P = `"params":{"action.params.cabin":{"type":"string","semantic":"s","sensitivity":"free","values":["eco","biz"]}}`
	const V = `"verb":"a.b","kind":"write",` + P
	cases := []struct {
		name, v string
		want    bool
	}{
		{"base", `{` + V + `}`, true},
		{"read", `{"verb":"a.b","kind":"read",` + P + `}`, true},
		{"not object", `[]`, false},
		{"unknown member", `{` + V + `,"zz":1}`, false},
		{"verb empty", `{"verb":"","kind":"write",` + P + `}`, false},
		{"verb missing", `{"kind":"write",` + P + `}`, false},
		{"verb 128", `{"verb":` + killGStr(128) + `,"kind":"write",` + P + `}`, true},
		{"verb 129", `{"verb":` + killGStr(129) + `,"kind":"write",` + P + `}`, false},
		{"kind bad", `{"verb":"a.b","kind":"delete",` + P + `}`, false},
		{"kind missing", `{"verb":"a.b",` + P + `}`, false},
		{"params missing", `{"verb":"a.b","kind":"write"}`, false},
		{"params array", `{"verb":"a.b","kind":"write","params":[]}`, false},
		{"params empty", `{"verb":"a.b","kind":"write","params":{}}`, true},
		{"params 64", `{"verb":"a.b","kind":"write","params":` + params(64) + `}`, true},
		{"params 65", `{"verb":"a.b","kind":"write","params":` + params(65) + `}`, false},
		{"param bad", `{"verb":"a.b","kind":"write","params":{"action.params.x":{"type":"string"}}}`, false},
		{"reversibility ok", `{` + V + `,"reversibility":"rate_limited"}`, true},
		{"reversibility bad", `{` + V + `,"reversibility":"maybe"}`, false},
		{"rev_by ok", `{` + V + `,"reversibility_by":{"param":"action.params.cabin","map":{"eco":"reversible"},"default":"irreversible"}}`, true},
		{"rev_by no default", `{` + V + `,"reversibility_by":{"param":"action.params.cabin","map":{"eco":"reversible"}}}`, true},
		{"rev_by not object", `{` + V + `,"reversibility_by":"x"}`, false},
		{"rev_by unknown member", `{` + V + `,"reversibility_by":{"param":"action.params.cabin","map":{"eco":"reversible"},"zz":1}}`, false},
		{"rev_by param not string", `{` + V + `,"reversibility_by":{"param":1,"map":{"eco":"reversible"}}}`, false},
		{"rev_by param missing", `{` + V + `,"reversibility_by":{"map":{"eco":"reversible"}}}`, false},
		{"rev_by param undeclared", `{` + V + `,"reversibility_by":{"param":"action.params.other","map":{"eco":"reversible"}}}`, false},
		{"rev_by map not object", `{` + V + `,"reversibility_by":{"param":"action.params.cabin","map":[]}}`, false},
		{"rev_by map missing", `{` + V + `,"reversibility_by":{"param":"action.params.cabin"}}`, false},
		{"rev_by map empty", `{` + V + `,"reversibility_by":{"param":"action.params.cabin","map":{}}}`, false},
		{"rev_by map value bad", `{` + V + `,"reversibility_by":{"param":"action.params.cabin","map":{"eco":"reversible","biz":"nope"}}}`, false},
		{"rev_by default bad", `{` + V + `,"reversibility_by":{"param":"action.params.cabin","map":{"eco":"reversible"},"default":"nope"}}`, false},
		{"mcp ok", `{` + V + `,"mcp":{"tool":"t"}}`, true},
		{"mcp 128", `{` + V + `,"mcp":{"tool":` + killGStr(128) + `}}`, true},
		{"mcp 129", `{` + V + `,"mcp":{"tool":` + killGStr(129) + `}}`, false},
		{"mcp empty tool", `{` + V + `,"mcp":{"tool":""}}`, false},
		{"mcp empty object", `{` + V + `,"mcp":{}}`, false},
		{"mcp extra member", `{` + V + `,"mcp":{"tool":"t","x":"y"}}`, false},
		{"mcp wrong member", `{` + V + `,"mcp":{"name":"t"}}`, false},
		{"mcp not object", `{` + V + `,"mcp":"t"}`, false},
		{"openapi ok", `{` + V + `,"openapi":{"operationId":"op"}}`, true},
		{"openapi 128", `{` + V + `,"openapi":{"operationId":` + killGStr(128) + `}}`, true},
		{"openapi 129", `{` + V + `,"openapi":{"operationId":` + killGStr(129) + `}}`, false},
		{"openapi empty id", `{` + V + `,"openapi":{"operationId":""}}`, false},
		{"openapi extra", `{` + V + `,"openapi":{"operationId":"op","x":"y"}}`, false},
		{"openapi wrong member", `{` + V + `,"openapi":{"tool":"op"}}`, false},
		{"harm ok", `{` + V + `,"harm":{}}`, true},
		{"harm bad", `{` + V + `,"harm":[]}`, false},
		{"effects bad", `{` + V + `,"effects":1}`, false},
		{"returns bad", `{` + V + `,"returns":"x"}`, false},
		{"world ok", `{` + V + `,"world":[]}`, true},
		{"world bad", `{` + V + `,"world":{}}`, false},
		{"description 1024", `{` + V + `,"description":` + killGStr(1024) + `}`, true},
		{"description 1025", `{` + V + `,"description":` + killGStr(1025) + `}`, false},
		{"description empty", `{` + V + `,"description":""}`, false},
	}
	for _, c := range cases {
		if got := verbDeclOK(killGJ(t, c.v), nil, false); got != c.want {
			t.Errorf("%s: verbDeclOK = %v, want %v", c.name, got, c.want)
		}
	}
}

// ---- actionSchemaShapeOK (actionSchemaShapeError == null) ----

func killGDoc(t *testing.T, mod func(d map[string]any)) map[string]any {
	t.Helper()
	d := killGM(t, `{"v":1,"kind":"pca-action-schema","site":"https://s.example","aud":"s.example","version":"1",
		"units":{"usd_cents":{"kind":"money","currency":"USD","exponent":2}},
		"verbs":[{"verb":"a.b","kind":"write","params":{"action.params.total":{"type":"integer","semantic":"money","sensitivity":"critical","unit":"usd_cents"}}}]}`)
	if mod != nil {
		mod(d)
	}
	return d
}

func killGVerbs(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = map[string]any{"verb": fmt.Sprintf("v%d", i), "kind": "read", "params": map[string]any{}}
	}
	return out
}

func TestKillGShape(t *testing.T) {
	str := func(n int) string { return strings.Repeat("a", n) }
	unit := func(t *testing.T, u string) func(d map[string]any) {
		return func(d map[string]any) { d["units"].(map[string]any)["usd_cents"] = killGJ(t, u) }
	}
	sig := func(s string) func(d map[string]any) {
		return func(d map[string]any) { d["sig"] = killGJ(t, s) }
	}
	cases := []struct {
		name   string
		mod    func(d map[string]any)
		signed bool
		want   bool
	}{
		{"base", nil, false, true},
		{"no units, no unit refs", func(d map[string]any) { delete(d, "units"); d["verbs"] = killGVerbs(1) }, false, true},
		{"units not object", func(d map[string]any) { d["units"] = []any{} }, false, false},
		{"units null", func(d map[string]any) { d["units"] = nil; d["verbs"] = killGVerbs(1) }, false, false},
		{"unknown member", func(d map[string]any) { d["zz"] = "x" }, false, false},
		{"v 2", func(d map[string]any) { d["v"] = jnum(2) }, false, false},
		{"v string", func(d map[string]any) { d["v"] = "1" }, false, false},
		{"v missing", func(d map[string]any) { delete(d, "v") }, false, false},
		{"kind wrong", func(d map[string]any) { d["kind"] = "pca-schema" }, false, false},
		{"site 2048", func(d map[string]any) { d["site"] = str(2048) }, false, true},
		{"site 2049", func(d map[string]any) { d["site"] = str(2049) }, false, false},
		{"site empty", func(d map[string]any) { d["site"] = "" }, false, false},
		{"aud 256", func(d map[string]any) { d["aud"] = str(256) }, false, true},
		{"aud 257", func(d map[string]any) { d["aud"] = str(257) }, false, false},
		{"aud missing", func(d map[string]any) { delete(d, "aud") }, false, false},
		{"version 128", func(d map[string]any) { d["version"] = str(128) }, false, true},
		{"version 129", func(d map[string]any) { d["version"] = str(129) }, false, false},
		{"version missing", func(d map[string]any) { delete(d, "version") }, false, false},
		{"unit id bad", func(d map[string]any) { d["units"].(map[string]any)["USD"] = map[string]any{"kind": "money"} }, false, false},
		{"unit id 64", func(d map[string]any) { d["units"].(map[string]any)[str(64)] = map[string]any{"kind": "money"} }, false, true},
		{"unit id 65", func(d map[string]any) { d["units"].(map[string]any)[str(65)] = map[string]any{"kind": "money"} }, false, false},
		{"unit not object", unit(t, `"money"`), false, false},
		{"unit kind missing", unit(t, `{"currency":"USD"}`), false, false},
		{"unit kind 64", unit(t, `{"kind":`+killGStr(64)+`}`), false, true},
		{"unit kind 65", unit(t, `{"kind":`+killGStr(65)+`}`), false, false},
		{"unit unknown member", unit(t, `{"kind":"money","zz":1}`), false, false},
		{"currency 16", unit(t, `{"kind":"money","currency":`+killGStr(16)+`}`), false, true},
		{"currency 17", unit(t, `{"kind":"money","currency":`+killGStr(17)+`}`), false, false},
		{"currency empty", unit(t, `{"kind":"money","currency":""}`), false, false},
		{"exponent 0", unit(t, `{"kind":"money","exponent":0}`), false, true},
		{"exponent 18", unit(t, `{"kind":"money","exponent":18}`), false, true},
		{"exponent 19", unit(t, `{"kind":"money","exponent":19}`), false, false},
		{"exponent -1", unit(t, `{"kind":"money","exponent":-1}`), false, false},
		{"exponent fraction", unit(t, `{"kind":"money","exponent":1.5}`), false, false},
		{"state ok", func(d map[string]any) { d["state"] = []any{} }, false, true},
		{"state not array", func(d map[string]any) { d["state"] = map[string]any{} }, false, false},
		{"verbs missing", func(d map[string]any) { delete(d, "verbs") }, false, false},
		{"verbs not array", func(d map[string]any) { d["verbs"] = map[string]any{} }, false, false},
		{"verbs empty", func(d map[string]any) { d["verbs"] = []any{} }, false, false},
		{"verbs 1", func(d map[string]any) { d["verbs"] = killGVerbs(1) }, false, true},
		{"verbs 256", func(d map[string]any) { d["verbs"] = killGVerbs(256) }, false, true},
		{"verbs 257", func(d map[string]any) { d["verbs"] = killGVerbs(257) }, false, false},
		{"verb twice", func(d map[string]any) { d["verbs"] = append(killGVerbs(2), killGVerbs(1)...) }, false, false},
		{"verb bad", func(d map[string]any) { d["verbs"] = []any{map[string]any{"verb": "x"}} }, false, false},
		{"verb unit undeclared", func(d map[string]any) { delete(d, "units") }, false, false},
		{"unsigned with sig", sig(`{"alg":"ed25519","kid":"k","value":"AA"}`), false, false},
		{"non-strict number", func(d map[string]any) {
			d["state"] = []any{jsNumber(0.5), killGJ(t, "-0")}
		}, false, false},
		{"signed ok", sig(`{"alg":"ed25519","kid":"k","value":"AA"}`), true, true},
		{"signed pq_value ok", sig(`{"alg":"ed25519","kid":"k","value":"AA","pq_value":"AAAA"}`), true, true},
		{"signed no alg", sig(`{"kid":"k","value":"AA"}`), true, true},
		{"signed missing", nil, true, false},
		{"signed not object", sig(`"x"`), true, false},
		{"signed unknown member", sig(`{"alg":"ed25519","kid":"k","value":"AA","zz":1}`), true, false},
		{"signed alg unknown", sig(`{"alg":"rsa","kid":"k","value":"AA"}`), true, false},
		{"signed alg null", sig(`{"alg":null,"kid":"k","value":"AA"}`), true, false},
		{"signed kid missing", sig(`{"alg":"ed25519","value":"AA"}`), true, false},
		{"signed kid 128", sig(`{"alg":"ed25519","kid":` + killGStr(128) + `,"value":"AA"}`), true, true},
		{"signed kid 129", sig(`{"alg":"ed25519","kid":` + killGStr(129) + `,"value":"AA"}`), true, false},
		{"signed value bad", sig(`{"alg":"ed25519","kid":"k","value":"A+"}`), true, false},
		{"signed value missing", sig(`{"alg":"ed25519","kid":"k"}`), true, false},
		{"signed pq_value bad", sig(`{"alg":"ed25519","kid":"k","value":"AA","pq_value":"A="}`), true, false},
		{"signed pq_value null", sig(`{"alg":"ed25519","kid":"k","value":"AA","pq_value":null}`), true, false},
	}
	for _, c := range cases {
		d := killGDoc(t, c.mod)
		if got := actionSchemaShapeOK(d, c.signed); got != c.want {
			t.Errorf("%s: actionSchemaShapeOK(signed=%v) = %v, want %v", c.name, c.signed, got, c.want)
		}
	}
	if actionSchemaShapeOK("x", false) || actionSchemaShapeOK(nil, true) {
		t.Error("non-object schema accepted")
	}
}

// ---- verifyActionSchema ----

func TestKillGVerify(t *testing.T) {
	f := newV2Fx(t)
	site := f.site
	doc := func() map[string]any { return deepM(t, f.schema) }
	key := func(m map[string]any) []any {
		k := map[string]any{"kid": "k1", "alg": "ed25519", "pk": site.id}
		for a, b := range m {
			if b == nil {
				k[a] = nil
			} else if b == "DELETE" {
				delete(k, a)
			} else {
				k[a] = b
			}
		}
		return []any{k}
	}
	if !verifyActionSchema(doc(), key(nil)) {
		t.Fatal("valid schema refused")
	}
	// the key list: non-array, kid lookup (non-object entries skipped, first match wins)
	if verifyActionSchema(doc(), map[string]any{"kid": "k1", "pk": site.id}) || verifyActionSchema(doc(), nil) {
		t.Error("keys not an array accepted")
	}
	if verifyActionSchema(doc(), []any{}) || verifyActionSchema(doc(), []any{map[string]any{"kid": "k2", "pk": site.id}}) {
		t.Error("no key with the kid accepted")
	}
	if !verifyActionSchema(doc(), append([]any{"junk", nil, map[string]any{"kid": "k2", "pk": newKey(t).id}}, key(nil)...)) {
		t.Error("non-object / other-kid entries must be skipped")
	}
	// pk
	if verifyActionSchema(doc(), key(map[string]any{"pk": "DELETE"})) || verifyActionSchema(doc(), key(map[string]any{"pk": 5})) {
		t.Error("missing / non-string pk accepted")
	}
	if verifyActionSchema(doc(), key(map[string]any{"pk": site.id[:20]})) {
		t.Error("short pk accepted")
	}
	// pq_pk present must be a string
	if verifyActionSchema(doc(), key(map[string]any{"pq_pk": nil})) || verifyActionSchema(doc(), key(map[string]any{"pq_pk": jnum(1)})) {
		t.Error("non-string pq_pk accepted")
	}
	// key alg: absent = ed25519; unknown or another suite refuses
	if !verifyActionSchema(doc(), key(map[string]any{"alg": "DELETE"})) {
		t.Error("absent key alg (ed25519) refused")
	}
	if verifyActionSchema(doc(), key(map[string]any{"alg": "rsa"})) || verifyActionSchema(doc(), key(map[string]any{"alg": "ml-dsa-65"})) {
		t.Error("key alg mismatch accepted")
	}
	// shape is checked before anything else: a signature-valid document with an unknown member is refused
	d := doc()
	delete(d, "sig")
	d["zz"] = "x"
	d["sig"] = map[string]any{"alg": "ed25519", "kid": "k1", "value": signDomain(t, site, actionSchemaDomain, withoutKeys(d, "sig"))}
	if verifyActionSchema(deep(t, d), key(nil)) {
		t.Error("ill-shaped signed schema accepted")
	}
	// tampered body / foreign signer
	d = doc()
	d["version"] = "other"
	if verifyActionSchema(d, key(nil)) {
		t.Error("tampered schema accepted")
	}
	if verifyActionSchema(doc(), key(map[string]any{"pk": newKey(t).id})) {
		t.Error("foreign key accepted")
	}
}

// ---- schemaVerbOf ----

func TestKillGSchemaVerbOf(t *testing.T) {
	type r struct {
		found  bool
		throws bool
	}
	cases := []struct {
		doc  string
		verb string
		want r
	}{
		{`{"verbs":[{"verb":"a"},{"verb":"b"}]}`, "b", r{true, false}},
		{`{"verbs":[{"verb":"a"}]}`, "z", r{false, false}},
		{`{"verbs":[{"verb":"a"},null,{"verb":"b"}]}`, "b", r{false, true}},
		{`{"verbs":[{"verb":"b"},null]}`, "b", r{true, false}},
		{`{"verbs":{"verb":"b"}}`, "b", r{false, false}},
		{`{}`, "b", r{false, false}},
		{`"x"`, "b", r{false, false}},
		{`{"verbs":["b",{"verb":"b"}]}`, "b", r{true, false}},
	}
	for i, c := range cases {
		v, th := schemaVerbOf(killGJ(t, c.doc), c.verb)
		if (v != nil) != c.want.found || th != c.want.throws {
			t.Errorf("#%d schemaVerbOf = (%v, %v), want %+v", i, v, th, c.want)
		}
		if v != nil && v["verb"] != c.verb {
			t.Errorf("#%d wrong verb %v", i, v["verb"])
		}
	}
	if v, th := schemaVerbOf(nil, "b"); v != nil || th {
		t.Error("nil doc")
	}
}

// ---- isCalendarDate ----

func TestKillGCalendarDate(t *testing.T) {
	dim := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	for m := 1; m <= 12; m++ {
		for _, y := range []int{2023, 2024, 1900, 2000} {
			last := dim[m-1]
			if m == 2 && (y%4 == 0 && y%100 != 0 || y%400 == 0) {
				last = 29
			}
			if !isCalendarDate(fmt.Sprintf("%04d-%02d-%02d", y, m, last)) {
				t.Errorf("%04d-%02d-%02d refused", y, m, last)
			}
			if isCalendarDate(fmt.Sprintf("%04d-%02d-%02d", y, m, last+1)) {
				t.Errorf("%04d-%02d-%02d accepted", y, m, last+1)
			}
			if !isCalendarDate(fmt.Sprintf("%04d-%02d-01", y, m)) {
				t.Errorf("%04d-%02d-01 refused", y, m)
			}
		}
	}
	for s, want := range map[string]bool{
		"2024-02-29": true, "2023-02-29": false, "1900-02-29": false, "2000-02-29": true, "2024-02-30": false, "2021-02-29": false,
		"2022-02-29": false, "2025-02-29": false, "2028-02-29": true,
		"0001-01-01": true, "0000-01-01": false, "2024-00-01": false, "2024-13-01": false, "2024-01-00": false, "2024-12-31": true,
		"2024-1-01": false, "2024-01-1": false, "20240-1-01": false, "2024/01/01": false, "2024-01/01": false, "2024/01-01": false,
		"202a-01-01": false, "2024-0a-01": false, "2024-01-0a": false, "202/-01-01": false, "2024-0/-01": false, "2024-01-0/": false,
		"2024-01-01 ": false, "": false, "2024-01-:1": false, "2024-:1-01": false, "2:24-01-01": false,
	} {
		if got := isCalendarDate(s); got != want {
			t.Errorf("isCalendarDate(%q) = %v, want %v", s, got, want)
		}
	}
}

// ---- paramValueViolation ----

func TestKillGValueViolation(t *testing.T) {
	strs := func(n, size int) string {
		xs := make([]string, n)
		for i := range xs {
			s := fmt.Sprintf("s%d", i)
			if size > len(s) {
				s += strings.Repeat("z", size-len(s))
			}
			xs[i] = `"` + s + `"`
		}
		return "[" + strings.Join(xs, ",") + "]"
	}
	ints := func(n int) string {
		xs := make([]string, n)
		for i := range xs {
			xs[i] = fmt.Sprint(i)
		}
		return "[" + strings.Join(xs, ",") + "]"
	}
	cases := []struct {
		name, d, x string
		want       string
	}{
		{"string ok", `{"type":"string"}`, `"x"`, ""},
		{"string not string", `{"type":"string"}`, `1`, "bad_type"},
		{"string lone surrogate", `{"type":"string"}`, `"a\ud800"`, "bad_type"},
		{"string default max 1024", `{"type":"string"}`, killGStr(1024), ""},
		{"string default max 1025", `{"type":"string"}`, killGStr(1025), "out_of_domain"},
		{"string max_len 3", `{"type":"string","max_len":3}`, `"abc"`, ""},
		{"string max_len 3 over", `{"type":"string","max_len":3}`, `"abcd"`, "out_of_domain"},
		{"string max_len bytes", `{"type":"string","max_len":3}`, `"aé"`, ""},
		{"string max_len bytes over", `{"type":"string","max_len":3}`, `"aéé"`, "out_of_domain"},
		{"string values in", `{"type":"string","values":["a","b"]}`, `"b"`, ""},
		{"string values out", `{"type":"string","values":["a","b"]}`, `"c"`, "out_of_domain"},
		{"integer ok", `{"type":"integer"}`, `7`, ""},
		{"integer fraction", `{"type":"integer"}`, `7.5`, "bad_type"},
		{"integer -0", `{"type":"integer"}`, `-0`, "bad_type"},
		{"integer string", `{"type":"integer"}`, `"7"`, "bad_type"},
		{"integer at min", `{"type":"integer","min":5,"max":9}`, `5`, ""},
		{"integer at max", `{"type":"integer","min":5,"max":9}`, `9`, ""},
		{"integer below min", `{"type":"integer","min":5,"max":9}`, `4`, "out_of_domain"},
		{"integer above max", `{"type":"integer","min":5,"max":9}`, `10`, "out_of_domain"},
		{"boolean", `{"type":"boolean"}`, `false`, ""},
		{"boolean string", `{"type":"boolean"}`, `"true"`, "bad_type"},
		{"date ok", `{"type":"date"}`, `"2024-02-29"`, ""},
		{"date bad", `{"type":"date"}`, `"2023-02-29"`, "out_of_domain"},
		{"date not string", `{"type":"date"}`, `20240229`, "bad_type"},
		{"set ok", `{"type":"set","values":["a","b","c"]}`, `["c","a"]`, ""},
		{"set empty ok", `{"type":"set","values":["a","b","c"]}`, `[]`, ""},
		{"set all (default max = len(values))", `{"type":"set","values":["a","b","c"]}`, `["a","b","c"]`, ""},
		{"set not array", `{"type":"set","values":["a"]}`, `"a"`, "bad_type"},
		{"set member not string", `{"type":"set","values":["a"]}`, `["a",1]`, "bad_type"},
		{"set member not string first", `{"type":"set","values":["a"]}`, `[1,"z","z"]`, "bad_type"},
		{"set dup", `{"type":"set","values":["a","b"]}`, `["a","a"]`, "out_of_domain"},
		{"set unknown member", `{"type":"set","values":["a","b"]}`, `["a","z"]`, "out_of_domain"},
		{"set at min_items", `{"type":"set","values":["a","b","c"],"min_items":2}`, `["a","b"]`, ""},
		{"set below min_items", `{"type":"set","values":["a","b","c"],"min_items":2}`, `["a"]`, "out_of_domain"},
		{"set at max_items", `{"type":"set","values":["a","b","c"],"max_items":2}`, `["a","b"]`, ""},
		{"set above max_items", `{"type":"set","values":["a","b","c"],"max_items":2}`, `["a","b","c"]`, "out_of_domain"},
		{"array strings ok", `{"type":"array"}`, `["x","y"]`, ""},
		{"array not array", `{"type":"array"}`, `"x"`, "bad_type"},
		{"array string item not string", `{"type":"array"}`, `["x",1]`, "bad_type"},
		{"array string item at max_len", `{"type":"array","max_len":2}`, `["ab"]`, ""},
		{"array string item over max_len", `{"type":"array","max_len":2}`, `["abc"]`, "bad_type"},
		{"array string item lone surrogate", `{"type":"array"}`, `["\ud800"]`, "bad_type"},
		{"array ints ok", `{"type":"array","items":"integer"}`, `[1,2]`, ""},
		{"array ints string item", `{"type":"array","items":"integer"}`, `[1,"2"]`, "bad_type"},
		{"array ints fraction", `{"type":"array","items":"integer"}`, `[1.5]`, "bad_type"},
		{"array ints at min", `{"type":"array","items":"integer","min":2,"max":5}`, `[2,5]`, ""},
		{"array ints below min", `{"type":"array","items":"integer","min":2,"max":5}`, `[1]`, "out_of_domain"},
		{"array ints above max", `{"type":"array","items":"integer","min":2,"max":5}`, `[6]`, "out_of_domain"},
		{"array ints below min later", `{"type":"array","items":"integer","min":2}`, `[3,1]`, "out_of_domain"},
		{"array strings with min (ignored)", `{"type":"array","min":2,"max":5}`, `["a"]`, ""},
		{"array empty default min_items", `{"type":"array"}`, `[]`, ""},
		{"array at min_items", `{"type":"array","min_items":2}`, `["a","b"]`, ""},
		{"array below min_items", `{"type":"array","min_items":2}`, `["a"]`, "out_of_domain"},
		{"array at max_items", `{"type":"array","max_items":2}`, `["a","b"]`, ""},
		{"array above max_items", `{"type":"array","max_items":2}`, `["a","b","c"]`, "out_of_domain"},
		{"array default max_items 64", `{"type":"array","items":"integer"}`, ints(64), ""},
		{"array default max_items 65", `{"type":"array","items":"integer"}`, ints(65), "out_of_domain"},
		{"array default max_len 1024 item", `{"type":"array"}`, strs(1, 1024), ""},
		{"array default max_len 1025 item", `{"type":"array"}`, strs(1, 1025), "bad_type"},
		{"unknown type", `{"type":"number"}`, `1`, "bad_type"},
		{"no type", `{}`, `1`, "bad_type"},
	}
	for _, c := range cases {
		if got := paramValueViolation(killGM(t, c.d), killGJ(t, c.x)); got != c.want {
			t.Errorf("%s: paramValueViolation = %q, want %q", c.name, got, c.want)
		}
	}
	if !strOK("ab", 2) || strOK("abc", 2) || strOK(1, 5) || strOK("a"+killGLone, 9) || !strOK("", 0) {
		t.Error("strOK")
	}
}

// ---- conformAction ----

func TestKillGConform(t *testing.T) {
	doc := killGJ(t, `{"verbs":[{"verb":"a.b","kind":"write","params":{
		"action.params.n":{"type":"integer","min":1,"max":9},
		"action.params.a":{"type":"string","values":["x","y"]},
		"action.params.opt":{"type":"boolean","required":false},
		"action.params.req":{"type":"boolean","required":true}}}]}`)
	cases := []struct {
		name, verb, params string
		want               SchemaConform
	}{
		{"ok", "a.b", `{"n":5,"a":"x","req":true}`, SchemaConform{OK: true}},
		{"ok with optional", "a.b", `{"n":5,"a":"x","req":true,"opt":false}`, SchemaConform{OK: true}},
		{"params array", "a.b", `[]`, SchemaConform{Code: "params_not_object"}},
		{"params null", "a.b", `null`, SchemaConform{Code: "params_not_object"}},
		{"unknown verb", "a.c", `{}`, SchemaConform{Code: "unknown_verb"}},
		{"undeclared first in utf8 order", "a.b", `{"zz":1,"b0":1,"n":5}`, SchemaConform{Code: "undeclared_param", Path: "action.params.b0"}},
		{"missing (first declared in order)", "a.b", `{"n":5,"req":true}`, SchemaConform{Code: "missing_param", Path: "action.params.a"}},
		{"missing required true", "a.b", `{"n":5,"a":"x"}`, SchemaConform{Code: "missing_param", Path: "action.params.req"}},
		{"bad_type", "a.b", `{"n":"5","a":"x","req":true}`, SchemaConform{Code: "bad_type", Path: "action.params.n"}},
		{"out_of_domain", "a.b", `{"n":10,"a":"x","req":true}`, SchemaConform{Code: "out_of_domain", Path: "action.params.n"}},
		{"first failure wins (a before n)", "a.b", `{"n":10,"a":"z","req":true}`, SchemaConform{Code: "out_of_domain", Path: "action.params.a"}},
	}
	for _, c := range cases {
		if got := conformAction(doc, c.verb, killGJ(t, c.params)); got != c.want {
			t.Errorf("%s: conformAction = %+v, want %+v", c.name, got, c.want)
		}
	}
	// a null declaration (only on an unverified document) is the reference's TypeError: bad_type, no path, whether
	// or not the parameter is present
	nd := killGJ(t, `{"verbs":[{"verb":"v","kind":"read","params":{"action.params.p":null}}]}`)
	for _, p := range []string{`{}`, `{"p":1}`} {
		if got := conformAction(nd, "v", killGJ(t, p)); got != (SchemaConform{Code: "bad_type"}) {
			t.Errorf("null declaration, params %s: %+v, want {bad_type}", p, got)
		}
	}
}

// ---- canonProjection ----

func TestKillGCanonProjection(t *testing.T) {
	doc := killGJ(t, `{"verbs":[{"verb":"v","kind":"write","params":{
		"action.params.b":{"type":"boolean"},"action.params.f":{"type":"boolean"},"action.params.s":{"type":"set","values":["x","y","z"]},
		"action.params.arr":{"type":"array"},"action.params.n":{"type":"integer"},"action.params.absent":{"type":"boolean"}}}]}`)
	out, ok := canonProjection(doc, "v", killGM(t, `{"b":true,"f":false,"s":["z","x"],"arr":["q","p"],"n":3}`))
	if !ok {
		t.Fatal("projection refused")
	}
	want := map[string]any{"b": "true", "f": "false", "s": `["x","z"]`, "arr": `["q","p"]`}
	if len(out) != len(want) {
		t.Errorf("projection %v, want %v", out, want)
	}
	for k, w := range want {
		if out[k] != w {
			t.Errorf("projection[%s] = %v, want %v", k, out[k], w)
		}
	}
	if _, has := out["absent"]; has {
		t.Error("absent parameter projected")
	}
	// unknown verb: empty projection, ok
	if out, ok := canonProjection(doc, "nope", map[string]any{"b": true}); !ok || len(out) != 0 {
		t.Errorf("unknown verb: %v %v", out, ok)
	}
	// a member the strict canonical form refuses fails the projection
	if _, ok := canonProjection(doc, "v", killGM(t, `{"s":["\ud800"]}`)); ok {
		t.Error("set with a lone surrogate projected")
	}
	if _, ok := canonProjection(doc, "v", killGM(t, `{"arr":[-0]}`)); ok {
		t.Error("array with -0 projected")
	}
}

// ---- accumulationParams ----

func TestKillGAccumulationParams(t *testing.T) {
	type r struct {
		out    string
		throws bool
	}
	cases := []struct {
		name, v string
		want    r
	}{
		{"array", `{"params":{"action.params.b":{"type":"integer","accumulates_into":["u","w"]},"action.params.a":{"type":"integer","accumulates_into":["u"]}}}`, r{"action.params.a,action.params.b", false}},
		{"array without unit", `{"params":{"action.params.a":{"type":"integer","accumulates_into":["w"]}}}`, r{"", false}},
		{"non-integer skipped", `{"params":{"action.params.a":{"type":"string","accumulates_into":["u"]}}}`, r{"", false}},
		{"non-object entry skipped", `{"params":{"action.params.a":"x","action.params.b":{"type":"integer","accumulates_into":["u"]}}}`, r{"action.params.b", false}},
		{"absent accumulates_into", `{"params":{"action.params.a":{"type":"integer"}}}`, r{"", false}},
		{"null accumulates_into", `{"params":{"action.params.a":{"type":"integer","accumulates_into":null}}}`, r{"", false}},
		{"string accumulates_into (substring)", `{"params":{"action.params.a":{"type":"integer","accumulates_into":"xux"}}}`, r{"action.params.a", false}},
		{"string accumulates_into without", `{"params":{"action.params.a":{"type":"integer","accumulates_into":"w"}}}`, r{"", false}},
		{"number accumulates_into throws", `{"params":{"action.params.a":{"type":"integer","accumulates_into":5}}}`, r{"", true}},
		{"null entry throws", `{"params":{"action.params.a":null}}`, r{"", true}},
		{"params absent throws", `{}`, r{"", true}},
		{"params null throws", `{"params":null}`, r{"", true}},
		{"params not object", `{"params":"x"}`, r{"", false}},
	}
	for _, c := range cases {
		out, th := accumulationParams(killGM(t, c.v), "u")
		if strings.Join(out, ",") != c.want.out || th != c.want.throws {
			t.Errorf("%s: accumulationParams = (%v, %v), want %+v", c.name, out, th, c.want)
		}
	}
}
