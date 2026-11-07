package pca

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// g14: tool_schema internals (UTF-16 re-encoding, name charset, depth / node bounds of schemas and values), the
// fail-closed digest paths of EvaluateToolSchema, the value-node budget of a whole call, and the agent-native evaluator's
// catches and malformed inputs.

func TestK05KillG14UnitsString(t *testing.T) {
	cases := []struct {
		u    []uint16
		want string
	}{
		{[]uint16{0xD800}, "\xed\xa0\x80"},
		{[]uint16{0xDFFF}, "\xed\xbf\xbf"},
		{[]uint16{0xD800, 0xDC00}, "\U00010000"},
		{[]uint16{0xDBFF, 0xDFFF}, "\U0010ffff"},
		{[]uint16{0xDC00, 0xDC00}, "\xed\xb0\x80\xed\xb0\x80"},
		{[]uint16{0xD800, 0xE000}, "\xed\xa0\x80"},
		{[]uint16{0xD800, 'a'}, "\xed\xa0\x80a"},
		{[]uint16{0xE000}, ""},
		{[]uint16{0xD7FF}, "퟿"},
		{[]uint16{'a', 0xD800}, "a\xed\xa0\x80"},
	}
	for _, c := range cases {
		if got := unitsString(c.u); got != c.want {
			t.Errorf("unitsString(%04x) = %q, want %q", c.u, got, c.want)
		}
	}
}

func TestK05KillG14TruncUnits(t *testing.T) {
	// an invalid UTF-8 byte reads as one unit (U+FFFD): a string of exactly n units comes back unchanged, not re-encoded
	if got := truncUnits("\xff", 1); got != "\xff" {
		t.Errorf("truncUnits(\\xff, 1) = %q", got)
	}
	if got := truncUnits("\xffb", 1); got != "�" {
		t.Errorf("truncUnits(\\xffb, 1) = %q", got)
	}
	if got := truncUnits("ab", 2); got != "ab" {
		t.Errorf("truncUnits(ab, 2) = %q", got)
	}
}

func TestK05KillG14SafeSchemaName(t *testing.T) {
	alnum := func(c byte) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
	}
	for c := 0; c < 256; c++ {
		b := byte(c)
		if got := safeSchemaName(string([]byte{'x', b})); got != alnum(b) {
			t.Errorf("safeSchemaName(x%q) = %v", b, got)
		}
		if got := safeSchemaName(string([]byte{b, 'x'})); got != alnum(b) {
			t.Errorf("safeSchemaName(%qx) = %v", b, got)
		}
	}
	for n, want := range map[string]bool{"": false, "-a": false, "a": true, "9": true, strings.Repeat("a", 64): true, strings.Repeat("a", 65): false} {
		if got := safeSchemaName(n); got != want {
			t.Errorf("safeSchemaName(%q) = %v, want %v", n, got, want)
		}
	}
}

func TestK05KillG14SchemaBounds(t *testing.T) {
	n := 0
	if e := objectSchemaError(map[string]any{}, nil, false, 9, &n); e != "schema too deep" {
		t.Errorf("object at depth 9: %q", e)
	}
	n = 0
	if e := objectSchemaError(map[string]any{}, nil, false, 8, &n); e != "" || n != 1 {
		t.Errorf("object at depth 8: %q n=%d", e, n)
	}
	n = 255
	if e := objectSchemaError(map[string]any{}, nil, false, 1, &n); e != "" || n != 256 {
		t.Errorf("node 256: %q n=%d", e, n)
	}
	n = 256
	if e := objectSchemaError(map[string]any{}, nil, false, 1, &n); e != "schema too large" {
		t.Errorf("node 257: %q", e)
	}
	if e := ValidateArgSchema(map[string]any{"props": map[string]any{"x": map[string]any{"type": "foo"}}}); e != "x: unknown type" {
		t.Errorf("unknown type name: %q", e)
	}
	if schemaEq(nil, nil) || schemaEq([]any{}, []any{}) {
		t.Error("schemaEq holds for non-scalars")
	}
}

func TestK05KillG14ValueBounds(t *testing.T) {
	boolean := map[string]any{"type": "boolean"}
	n := 0
	if e := checkSchemaValue(boolean, true, "p", 9, &n); e != "" {
		t.Errorf("value at depth 9: %q", e)
	}
	n = 0
	if e := checkSchemaValue(boolean, true, "p", 10, &n); e != "p: too deep" {
		t.Errorf("value at depth 10: %q", e)
	}
	n = MaxSchemaValueNodes - 1
	if e := checkSchemaValue(boolean, true, "p", 1, &n); e != "" || n != MaxSchemaValueNodes {
		t.Errorf("value node 10000: %q n=%d", e, n)
	}
	n = MaxSchemaValueNodes
	if e := checkSchemaValue(boolean, true, "p", 1, &n); e != "p: too many values" {
		t.Errorf("value node 10001: %q", e)
	}
	if MaxSchemaValueNodes != 10_000 {
		t.Errorf("MaxSchemaValueNodes = %d", MaxSchemaValueNodes)
	}
	arr := map[string]any{"type": "array", "items": boolean}
	n = 0
	if e := checkSchemaValue(arr, []any{true}, "p", 9, &n); e != "p[0]: too deep" {
		t.Errorf("array at depth 9: %q", e)
	}
	n = 0
	if e := checkSchemaValue(arr, []any{true}, "p", 8, &n); e != "" || n != 2 {
		t.Errorf("array at depth 8: %q n=%d", e, n)
	}
	props := map[string]any{"a": boolean}
	n = 0
	if e := checkSchemaObject(props, nil, map[string]any{"a": true}, "p", 9, &n); e != "p.a: too deep" {
		t.Errorf("object at depth 9: %q", e)
	}
	n = 0
	if e := checkSchemaObject(props, nil, map[string]any{"a": true}, "p", 8, &n); e != "" || n != 1 {
		t.Errorf("object at depth 8: %q n=%d", e, n)
	}
}

// g14tsCaveat is a well-formed tool_schema caveat for tool over schema (both digests recomputed, no signature_digest).
func g14tsCaveat(t *testing.T, tool string, schema map[string]any) map[string]any {
	t.Helper()
	sd, err := HashCanonical(schema)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := HashCanonical(map[string]any{"tool": tool, "signature_digest": "undefined", "schema": schema})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"type": "tool_schema", "tool": tool, "schema": schema, "schema_digest": sd, "binding_digest": bd}
}

func TestK05KillG14ToolSchemaDigestErrors(t *testing.T) {
	call := &ToolCall{Tool: "t", Args: map[string]any{}}
	// a lone surrogate in a const: the schema validates, but it has no canonical form, so the schema digest fails closed
	bad := map[string]any{"props": map[string]any{"x": map[string]any{"type": "string", "const": "\xed\xa0\x80"}}}
	if e := ValidateArgSchema(bad); e != "" {
		t.Fatalf("schema refused: %q", e)
	}
	c := map[string]any{"type": "tool_schema", "tool": "t", "schema": bad, "schema_digest": "zzz", "binding_digest": "zzz"}
	if ok, reason := EvaluateToolSchema(c, call); ok || reason != "evaluation error (fail closed)" {
		t.Errorf("schema digest error: %v %q", ok, reason)
	}
	// a lone surrogate in the tool name: the schema digest is fine, the binding digest fails closed
	schema := map[string]any{"props": map[string]any{}}
	sd, err := HashCanonical(schema)
	if err != nil {
		t.Fatal(err)
	}
	c = map[string]any{"type": "tool_schema", "tool": "t\xed\xa0\x80", "schema": schema, "schema_digest": sd, "binding_digest": "zzz"}
	if ok, reason := EvaluateToolSchema(c, call); ok || reason != "evaluation error (fail closed)" {
		t.Errorf("binding digest error: %v %q", ok, reason)
	}
	// sanity: the well-formed caveat admits the empty call
	if ok, reason := EvaluateToolSchema(g14tsCaveat(t, "t", schema), call); !ok || reason != "" {
		t.Errorf("well-formed: %v %q", ok, reason)
	}
}

func TestK05KillG14ToolSchemaValueBudget(t *testing.T) {
	arr := func() map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "boolean"}, "maxItems": json.Number("4096")}
	}
	schema := map[string]any{"props": map[string]any{"a": arr(), "b": arr(), "c": arr()}}
	c := g14tsCaveat(t, "t", schema)
	trues := func(k int) []any {
		out := make([]any, k)
		for i := range out {
			out[i] = true
		}
		return out
	}
	// 3 arrays + 4096 + 4096 + 1805 items = exactly MaxSchemaValueNodes values
	args := map[string]any{"a": trues(4096), "b": trues(4096), "c": trues(1805)}
	if ok, reason := EvaluateToolSchema(c, &ToolCall{Tool: "t", Args: args}); !ok || reason != "" {
		t.Errorf("10000 values: %v %q", ok, reason)
	}
	args["c"] = trues(1806)
	if ok, reason := EvaluateToolSchema(c, &ToolCall{Tool: "t", Args: args}); ok || reason != "args.c[1805]: too many values" {
		t.Errorf("10001 values: %v %q", ok, reason)
	}
}

func TestK05KillG14AgentCatches(t *testing.T) {
	ok, reason := func() (ok bool, reason string) {
		defer toolSchemaFailClosed(&ok, &reason)
		ok, reason = true, ""
		panic("boom")
	}()
	if ok || reason != "evaluation error (fail closed)" {
		t.Errorf("tool_schema catch: %v %q", ok, reason)
	}
	sat := func() (sat bool) {
		defer agentCaveatFailClosed(&sat)
		sat = true
		panic("boom")
	}()
	if sat {
		t.Error("caveat catch left sat true")
	}
	ok, failed := func() (ok bool, failed []string) {
		defer agentCaveatsFailClosed(&ok, &failed)
		ok, failed = true, []string{}
		panic("boom")
	}()
	if ok || !reflect.DeepEqual(failed, []string{"<evaluation error>"}) {
		t.Errorf("caveats catch: %v %v", ok, failed)
	}
	// no panic: the catches change nothing
	ok, reason = func() (ok bool, reason string) {
		defer toolSchemaFailClosed(&ok, &reason)
		return true, "x"
	}()
	if !ok || reason != "x" {
		t.Errorf("tool_schema catch without a panic: %v %q", ok, reason)
	}
}

func TestK05KillG14AgentMalformed(t *testing.T) {
	if ok, failed := EvaluateAgentCaveats("x", nil, nil, nil); ok || !reflect.DeepEqual(failed, []string{"<malformed caveats>"}) {
		t.Errorf("not an array: %v %v", ok, failed)
	}
	cvs := []any{"x", map[string]any{"type": "predicates", "allow": "x"}, map[string]any{"type": "budget_alloc", "limit": json.Number("1")}}
	if ok, failed := EvaluateAgentCaveats(cvs, nil, nil, nil); ok || !reflect.DeepEqual(failed, []string{"<malformed>", "predicates", "budget_alloc"}) {
		t.Errorf("nil ctx: %v %v", ok, failed)
	}
	ctx := map[string]any{"now": json.Number("1")}
	if ok, failed := EvaluateAgentCaveats(cvs[2:], ctx, nil, nil); !ok || len(failed) != 0 {
		t.Errorf("budget_alloc with a clock: %v %v", ok, failed)
	}
	if agentCaveatSatisfied("x", ctx, nil, nil, &regexBudget{}) {
		t.Error("a non-object caveat is satisfied")
	}
	if agentCaveatSatisfied(map[string]any{"type": "predicates", "allow": "x"}, ctx, nil, nil, &regexBudget{}) {
		t.Error("predicates without an allow array is satisfied")
	}
}
