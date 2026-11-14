package pca

import (
	"errors"
	"testing"
)

// intent-v2.ts: `ctx.actions?.records ?? []`, so an absent list is an empty array, never null.
func TestK05Kill3X4ListOrEmpty(t *testing.T) {
	if got := listOrEmpty(nil); got == nil || len(got) != 0 {
		t.Errorf("listOrEmpty(nil) = %#v, want an empty non-nil list", got)
	}
	in := []any{"a"}
	if got := listOrEmpty(in); len(got) != 1 || got[0] != "a" {
		t.Errorf("listOrEmpty(list) = %#v", got)
	}
}

// core-traits.ts: ['impersonation', ['external_communication'], { risk: 2, esc: CONFIRM }, 'acts as a person'].
func TestK05Kill3X4CoreImpersonationOwnRisk(t *testing.T) {
	for _, row := range coreTable {
		if row.name == "impersonation" {
			if row.own.Risk != 2 {
				t.Errorf("own risk = %d, want 2", row.own.Risk)
			}
			return
		}
	}
	t.Fatal("no impersonation row")
}

func TestK05Kill3X4ReserveMaxUsesNoStore(t *testing.T) {
	bound := []BoundCaveat{{Caveat: map[string]any{"type": "max_uses", "id": "u", "n": jsNumber(1), "until": jsNumber(100)}, CapHash: "h"}}
	r := ReserveMaxUses(nil, bound, 1)
	if want := "max_uses error (fail closed): no replay store"; r.OK || r.Spent != 0 || r.Reason != want {
		t.Fatalf("got %+v, want reason %q", r, want)
	}
}

// pack.ts verifyPack: a throwing defDigest reaches the outer catch, `pack verification error: <message>`, with no digest and no count.
func TestK05Kill3X4VerifyPackDefDigestFailure(t *testing.T) {
	k := newKey(t)
	pack := g04RegSign(t, k, packSigDomain, g04PackBody(t, g04HonestDefs(t)))
	old := packDefDigest
	defer func() { packDefDigest = old }()
	packDefDigest = func(map[string]any) (string, error) { return "", errors.New("x4") }
	d, n, r := verifyPack(pack, g04RegKeys(k), nil)
	if want := "pack verification error: x4"; d != "" || n != 0 || r != want {
		t.Fatalf("got %q %d %q, want reason %q", d, n, r, want)
	}
}

// forbid-certificate.ts certificateConsistent: a certificate with no shadowed list is never consistent (cert.shadowed.length
// throws on the malformed path, JSON.stringify(undefined) differs from "[]" on the table path).
func TestK05Kill3X4ForbidCertificateNoShadowed(t *testing.T) {
	for _, kind := range []string{"malformed", "none"} {
		cert := map[string]any{"v": jsonOne(), "kind": "forbid-wins", "clauses": []any{}, "decision": "deny",
			"winner": map[string]any{"kind": kind, "id": nil}}
		if ForbidCertificateConsistent(cert, nil) {
			t.Errorf("winner kind %s without shadowed: consistent", kind)
		}
		cert["shadowed"] = []any{}
		if !ForbidCertificateConsistent(cert, nil) {
			t.Errorf("winner kind %s with an empty shadowed: not consistent", kind)
		}
	}
}

func x4Check(t *testing.T, d v2Decision, name string) v2Check {
	t.Helper()
	for _, c := range d.checks {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no %s check in %+v", name, d.checks)
	return v2Check{}
}

// intent-v2.ts modelRules: `schemaMemo ??= ... schemaStep(p, ctx)` runs once and a failed step is the traits verdict (`if (!s.ok) return s`).
func TestK05Kill3X4TraitsReturnsSchemaWhyOnce(t *testing.T) {
	calls := 0
	old := v2SchemaStep
	defer func() { v2SchemaStep = old }()
	v2SchemaStep = func(map[string]any, *IntentV2Context) (any, string) {
		calls++
		return map[string]any{"v": jsNumber(2)}, "x4 why"
	}
	c := r22Vec(t, "rule22-allow")
	c.noClose = true
	c.pin = r22Pin(c)
	d := r22Run(t, c)
	for _, name := range []string{"pin", "traits"} {
		if got := x4Check(t, d, name); got.ok || got.why != "x4 why" {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if calls != 1 {
		t.Errorf("schemaStep ran %d times, want 1", calls)
	}
}

// intent-v2.ts modelRules: `out.schema !== undefined ? { ok: true, doc: out.schema } : schemaStep(p, ctx)`, so a schema the closed-world step already decided is not decided again.
func TestK05Kill3X4SchemaForReusesClosedWorldSchema(t *testing.T) {
	calls := 0
	old := v2SchemaStep
	defer func() { v2SchemaStep = old }()
	v2SchemaStep = func(map[string]any, *IntentV2Context) (any, string) {
		calls++
		return nil, "x4 why"
	}
	c := r22Vec(t, "rule22-allow")
	c.pin = r22Pin(c)
	d := r22Run(t, c)
	if got := x4Check(t, d, "schema"); !got.ok {
		t.Fatalf("schema: %+v", got)
	}
	if calls != 0 {
		t.Errorf("schemaStep ran %d times, want 0", calls)
	}
}

// intent-v2.ts run(): a throw in the units step is `units error (fail closed): <message>`, the V8 text of dereferencing a null verb entry.
func TestK05Kill3X4UnitsNullVerbThrow(t *testing.T) {
	old := v2SchemaVerbOf
	defer func() { v2SchemaVerbOf = old }()
	v2SchemaVerbOf = func(any, string) (map[string]any, bool) { return nil, true }
	f := newV2Fx(t)
	p := f.p2()
	delete(p, "intent_session")
	env := map[string]any{"type": envelopeCaveat, "goal_commit": "g", "predicates": []any{}, "caveats": []any{}, "agent_binding": map[string]any{}, "risk_policy": DefaultRiskPolicy(), "units": map[string]any{}}
	grant := deepM(t, map[string]any{"id": "G", "issuer": "I", "caveats": []any{env}})
	d := decideIntentV2(p, grant, IntentV2ContextFromJSON(f.ctx), float64(f.now))
	want := "units error (fail closed): Cannot read properties of null (reading 'verb')"
	if got := x4Check(t, d, "units"); got.ok || got.why != want {
		t.Fatalf("units: %+v, want %q", got, want)
	}
}
