package pca

import (
	"strings"
	"testing"
)

// JSON null vs absent obligations. The reference refuses null (obligations.ts obligationsError allows only undefined). Go's nil is
// both, by the gate API, so the check is on the token path: no read site takes obligations from JSON, the wire's closed key set
// refuses the member (wire.ts validateWireV2), and the parser keeps a present null so that it can.
func TestK05NullObligationsWire(t *testing.T) {
	for name, v := range map[string]any{"null": nil, "empty": []any{}, "string": "x"} {
		p := newFx(t).norm()
		if r := ValidateWireV2(p); r != "" {
			t.Fatalf("base wire: %q", r)
		}
		p["obligations"] = v
		if r := ValidateWireV2(p); r != "unknown field 'obligations'" {
			t.Errorf("%s: %q", name, r)
		}
	}
}

// The signed bytes as they arrive: the text form through ParsePCActn and through Authorize, against a fixture that allows without the member.
func TestK05NullObligationsToken(t *testing.T) {
	d := authorizeFixtures(t)
	for _, cv := range d["cases"].([]any) {
		c := cv.(map[string]any)
		step := c["steps"].([]any)[0].(map[string]any)
		if step["expect"].(map[string]any)["allow"] != true {
			continue
		}
		grant := c["grant"].(map[string]any)
		run := func(pcactn any) AuthorizeResult {
			revoked := false
			in := fixInput(d, grant, NewMemoryStateStore(), &revoked)
			in.Operation = fixOp(step["operation"].(map[string]any))
			return Authorize(pcactn, in)
		}
		text, err := Canonicalize(step["pcactn"])
		if err != nil {
			t.Fatal(err)
		}
		if res := run(text); !res.Allow {
			t.Fatalf("%v without the member: %s", c["name"], res.Reason)
		}
		nulled := `{"obligations":null,` + strings.TrimPrefix(text, "{")
		m, err := ParsePCActn(nulled)
		if err != nil {
			t.Fatal(err)
		}
		if v, has := m["obligations"]; !has || v != nil {
			t.Fatalf("the parser dropped a present null: %v %v", v, has)
		}
		for name, form := range map[string]any{"text": nulled, "parsed": m} {
			res := run(form)
			if res.Allow || res.Status != 401 || res.Reason != "wire: unknown field 'obligations'" {
				t.Errorf("%v %s: allow=%v status=%d reason=%q", c["name"], name, res.Allow, res.Status, res.Reason)
			}
		}
		return
	}
	t.Fatal("no fixture allows on its first step")
}

// Inside an obligation Go does tell null from absent: every member below is refused, as obligations.ts refuses it. The messages
// that are the reference's are pinned; the rest differ in wording only.
func TestK05NullInsideAnObligation(t *testing.T) {
	for _, c := range []struct {
		o    any
		want string
	}{
		{nil, "an obligation must be an object"},
		{map[string]any{"kind": "log", "params": nil}, "params must be an object"},
		{map[string]any{"kind": "log", "due": nil}, "due must be a non-negative safe integer"},
		{map[string]any{"kind": "log", "params": map[string]any{"sink": nil}}, "log.sink must be a non-empty string of at most 128 characters"},
		{map[string]any{"kind": "undo_window", "params": map[string]any{"id": "x", "window_end": nil}}, "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)"},
		{map[string]any{"kind": "redact", "params": map[string]any{"fields": nil}}, "redact.fields must be 1..32 dotted field paths"},
		{map[string]any{"kind": "redact", "params": map[string]any{"fields": []any{nil}}}, "redact.fields must be 1..32 dotted field paths"},
		{map[string]any{"kind": nil}, ""},
		{map[string]any{"kind": "notify", "params": map[string]any{"to": nil}}, ""},
		{map[string]any{"kind": "watermark", "params": map[string]any{"id": nil}}, ""},
	} {
		got := ObligationError(c.o)
		if got == "" || (c.want != "" && got != c.want) {
			t.Errorf("ObligationError(%v) = %q, want %q", c.o, got, c.want)
		}
		if ObligationsError([]any{c.o}) == "" {
			t.Errorf("ObligationsError([%v]) accepted", c.o)
		}
		if g := PepObligationGate("allow", false, []any{c.o}, []any{"log", "notify", "redact", "watermark", "undo_window"}); g.Decision != "deny" {
			t.Errorf("gate over [%v]: %+v", c.o, g)
		}
	}
}
