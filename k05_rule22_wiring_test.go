package pca

import (
	"strings"
	"testing"
)

// Rule 22 and the grant pin inside decideIntentV2. Reference: packages/pca-actions/test/verifier.test.ts and
// packages/pca/src/intent-v2.ts:83-87, 321-325, 614-634; documents from the shared rule22 vectors.

const (
	r22Root     = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRQ"
	r22Other    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	r22Refund   = "stripe.refund"
	r22Gmail    = "gmail.send"
	r22Escalate = "escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)"
	r22Deny     = "the action floors exceed what the grant authorizes (rule 22)"
)

type r22Case struct {
	doc     map[string]any
	verb    string
	params  map[string]any
	envCav  []any
	pin     any // nil: no pin
	mutCtx  func(ctx map[string]any)
	aud     any
	noClose bool
}

func r22Vec(t *testing.T, id string) r22Case {
	t.Helper()
	in := actionVectorByID(t, id)
	doc := deep(t, in["doc"]).(map[string]any)
	doc["pack"] = map[string]any{"ns": "stripe", "version": "1.0.0", "root": r22Root}
	return r22Case{doc: doc, verb: r22Refund, params: map[string]any{"amount": jnum(1000), "charge": "ch_abcdefgh", "idempotency_key": "k1"}, envCav: []any{},
		mutCtx: func(ctx map[string]any) {
			ctx["reviewers"] = actionVectorByID(t, "rule22-allow")["pins"]
			ctx["call_context"] = []any{"fresh_revocation", "idempotency"}
		}}
}

func r22Def(doc map[string]any, verb string) string {
	for _, e := range doc["verbs"].([]any) {
		if m := e.(map[string]any); m["verb"] == verb {
			return m["def"].(string)
		}
	}
	return ""
}

func r22Pin(c r22Case, tiers ...int64) map[string]any {
	p := map[string]any{"pack": map[string]any{"ns": "stripe", "root": r22Root}, "defs": map[string]any{c.verb: r22Def(c.doc, c.verb)}, "on_new_action": "deny",
		"caveats": []any{"amount_cap", "count_cap", "window"}}
	if len(tiers) == 2 {
		p["max_esc"], p["preauth_esc"] = jnum(tiers[0]), jnum(tiers[1])
	}
	return p
}

// r22Run signs the document with a fresh site key and decides a closed-world action (no session) against it.
func r22Run(t *testing.T, c r22Case) v2Decision {
	t.Helper()
	site := newKey(t)
	doc := deepM(t, c.doc)
	delete(doc, "sig")
	doc["sig"] = map[string]any{"alg": "ed25519", "kid": "k1", "value": signDomain(t, site, actionSchemaDomain, doc)}
	pd, ok := hashCanonicalV(deepM(t, c.params))
	if !ok {
		t.Fatal("params digest")
	}
	aud := c.aud
	if aud == nil {
		aud = doc["aud"]
	}
	p := map[string]any{"aud": aud, "action": map[string]any{"verb": c.verb, "resource": "x", "params_digest": pd}}
	env := map[string]any{"type": envelopeCaveat, "goal_commit": "g", "predicates": []any{}, "caveats": c.envCav, "agent_binding": map[string]any{}, "risk_policy": DefaultRiskPolicy()}
	if c.pin != nil {
		env["actions"] = c.pin
	}
	grant := deepM(t, map[string]any{"id": "G", "issuer": "I", "caveats": []any{env}})
	if ReadEnvelope(grant) == nil {
		t.Fatal("fixture envelope refused")
	}
	ctx := map[string]any{"schema": map[string]any{"docs": []any{doc}, "keys": []any{map[string]any{"kid": "k1", "alg": "ed25519", "pk": site.id}}}, "params": c.params}
	if !c.noClose {
		ctx["policy"] = map[string]any{"schema": map[string]any{"closed_world": true}}
	}
	if c.mutCtx != nil {
		c.mutCtx(ctx)
	}
	return decideIntentV2(p, grant, IntentV2ContextFromJSON(deep(t, ctx)), float64(v2Now))
}

// r22Want: exactly these rule 14 / 22 / pin checks in this order; a "" reason passes, others must equal it exactly.
func r22Want(t *testing.T, name string, d v2Decision, want ...[2]string) {
	t.Helper()
	var got [][2]string
	for _, c := range d.checks {
		got = append(got, [2]string{c.name, c.why})
	}
	if len(got) != len(want) {
		t.Fatalf("%s: checks %q, want %q", name, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: check %d = %q, want %q", name, i, got[i], want[i])
		}
	}
}

func TestRule22ControlAndTierDecisions(t *testing.T) {
	base := r22Vec(t, "rule22-allow")
	c := base
	c.pin = r22Pin(c, 3, 2)
	r22Want(t, "control", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", ""})

	c.pin = r22Pin(c, 1, 0)
	r22Want(t, "above max_esc", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", r22Deny})
	c.pin = r22Pin(c, 3, 1)
	r22Want(t, "above preauth_esc", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", r22Escalate})

	// no tiers on the pin: max_esc defaults to 3 (esc 2 is not denied), preauth_esc to 0 (esc 1 escalates)
	c.pin = r22Pin(c)
	r22Want(t, "default tiers", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", r22Escalate})
	g := base
	g.verb = r22Gmail
	g.params = map[string]any{"to": "a@b.co", "subject": "s", "body": "b", "idempotency_key": "k"}
	pin := r22Pin(g)
	pin["caveats"] = []any{"rate_cap", "recipient_scope", "resource_scope"}
	g.pin = pin
	r22Want(t, "default preauth_esc 0", r22Run(t, g), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", r22Escalate})
	pin2 := deepM(t, pin)
	pin2["max_esc"], pin2["preauth_esc"] = jnum(3), jnum(1)
	g.pin = pin2
	r22Want(t, "gmail control", r22Run(t, g), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", ""})

	// a v2 schema with no pin at all still meets the floors, with the same defaults
	n := base
	r22Want(t, "no pin", r22Run(t, n), [2]string{"schema", ""}, [2]string{"traits", r22Escalate})

	// the call context comes from the verifier context; absent is empty
	c = base
	c.pin = r22Pin(c, 3, 2)
	c.mutCtx = func(ctx map[string]any) { ctx["reviewers"] = actionVectorByID(t, "rule22-allow")["pins"] }
	r22Want(t, "no call_context", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", r22Escalate})
}

func TestRule22CaveatsCountFromEnvelopeAndValidPin(t *testing.T) {
	c := r22Vec(t, "rule22-allow")
	pin := r22Pin(c, 3, 2)
	pin["caveats"] = []any{"window"}
	c.pin = pin
	c.envCav = []any{map[string]any{"type": "amount_cap"}, map[string]any{"type": "count_cap"}, map[string]any{"type": jnum(1)}, "not-an-object", nil}
	r22Want(t, "split", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", ""})
	c.envCav = []any{map[string]any{"type": "amount_cap"}}
	r22Want(t, "one short", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", r22Escalate})
	pin3 := deepM(t, pin)
	delete(pin3, "caveats")
	c.pin = pin3
	c.envCav = []any{map[string]any{"type": "amount_cap"}, map[string]any{"type": "count_cap"}, map[string]any{"type": "window"}}
	r22Want(t, "envelope only", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", ""}, [2]string{"traits", ""})

	// an invalid pin provides nothing: its caveats and tiers are not read
	bad := deepM(t, r22Pin(c, 3, 2))
	bad["extra"] = jnum(1)
	c.pin = bad
	c.envCav = []any{}
	d := r22Run(t, c)
	if len(d.checks) != 3 || !strings.HasPrefix(d.checks[1].why, "bad_pin: ") || d.checks[2].why != r22Escalate {
		t.Errorf("malformed pin: %+v", d.checks)
	}
}

func TestRule22ForgedSchemasRefused(t *testing.T) {
	for id, code := range map[string]string{
		"rule22-forged-floors-denied":       "schema_floor_forged: floors are below",
		"rule22-dropped-traits-denied":      "schema_traits_forged",
		"rule22-schema-trait-unknown":       "unknown_trait",
		"rule22-schema-traits-digest-wrong": "traits_digest_mismatch",
	} {
		c := r22Vec(t, id)
		c.pin = r22Pin(c, 3, 2)
		d := r22Run(t, c)
		// the pin reads the same failing schema step; no schema, so traits is not reported (intent-v2.ts:623)
		if len(d.checks) != 2 || d.checks[0].name != "schema" || d.checks[1].name != "pin" || d.checks[0].why != d.checks[1].why {
			t.Fatalf("%s: %+v", id, d.checks)
		}
		if w := d.checks[0].why; !strings.HasPrefix(w, "schema_floor_forged: ") || !strings.Contains(w, code) {
			t.Errorf("%s: %q, want schema_floor_forged: ...%s", id, w, code)
		}
	}
	// position: after the aud check, before the params
	c := r22Vec(t, "rule22-forged-floors-denied")
	c.aud = "other-aud"
	r22Want(t, "aud first", r22Run(t, c), [2]string{"schema", "schema aud does not match the PCActn aud"})
	c = r22Vec(t, "rule22-forged-floors-denied")
	mut := c.mutCtx
	c.mutCtx = func(ctx map[string]any) { mut(ctx); delete(ctx, "params") }
	if d := r22Run(t, c); !strings.HasPrefix(d.checks[0].why, "schema_floor_forged: ") {
		t.Errorf("floors before params: %+v", d.checks)
	}
	// the reviewers come from the verifier context: a confirmed verb without them must carry every trait
	c = r22Vec(t, "rule22-conf-allow")
	c.mutCtx = func(ctx map[string]any) { ctx["call_context"] = []any{"fresh_revocation", "idempotency"} }
	if d := r22Run(t, c); !strings.Contains(d.checks[0].why, "schema_traits_forged") {
		t.Errorf("no reviewers: %+v", d.checks)
	}
}

func TestPinCheckReasons(t *testing.T) {
	base := r22Vec(t, "rule22-allow")
	c := base
	pin := r22Pin(c, 3, 2)
	pin["defs"] = map[string]any{r22Refund: r22Other}
	c.pin = pin
	const noChain = "def_changed: the definition differs from the pinned digest and no signed evolution record chains to it"
	r22Want(t, "pin mismatch", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", noChain}, [2]string{"traits", ""})

	// a signed widening names the diff to re-approve; another key's record is ignored; an approved one is not reached here
	k := newKey(t)
	rec := g04Evo(t, k, "stripe", r22Refund, r22Other, r22Def(c.doc, r22Refund), "widen")
	diff, ok := evolutionDiffDigest(rec)
	if !ok {
		t.Fatal("diff")
	}
	mut := base.mutCtx
	c.mutCtx = func(ctx map[string]any) {
		mut(ctx)
		ctx["actions"] = map[string]any{"records": []any{rec}, "keys": g04RegKeys(k), "reapprovals": []any{}}
	}
	d := r22Run(t, c)
	want := "def_changed: the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve (re-approve diff " + diff + ")"
	r22Want(t, "needs re-approval", d, [2]string{"schema", ""}, [2]string{"pin", want}, [2]string{"traits", ""})
	c.mutCtx = func(ctx map[string]any) {
		mut(ctx)
		ctx["actions"] = map[string]any{"records": []any{rec}}
	}
	r22Want(t, "keys read from context", r22Run(t, c), [2]string{"schema", ""}, [2]string{"pin", noChain}, [2]string{"traits", ""})

	// on_new_action: escalate names the prefix
	e := base
	pe := r22Pin(e, 3, 2)
	pe["defs"] = map[string]any{r22Gmail: r22Def(e.doc, r22Gmail)}
	pe["on_new_action"] = "escalate"
	e.pin = pe
	r22Want(t, "escalate", r22Run(t, e), [2]string{"schema", ""},
		[2]string{"pin", "escalate: new_action: the grant does not name 'stripe.refund' (on_new_action: escalate)"}, [2]string{"traits", ""})
	pe2 := deepM(t, pe)
	pe2["on_new_action"] = "deny"
	e.pin = pe2
	r22Want(t, "deny", r22Run(t, e), [2]string{"schema", ""},
		[2]string{"pin", "new_action: the grant does not name 'stripe.refund' (on_new_action: deny)"}, [2]string{"traits", ""})

	// a pin with no closed world still reaches the schema step and the floors
	o := base
	o.pin = r22Pin(o, 3, 2)
	o.noClose = true
	r22Want(t, "pin without schema check", r22Run(t, o), [2]string{"pin", ""}, [2]string{"traits", ""})
}

func TestRule22V1SchemaUnchanged(t *testing.T) {
	c := r22Case{doc: v2Schema(), verb: "air.book", aud: v2Aud, envCav: []any{},
		params: map[string]any{"offer_id": "OF-1", "total": jnum(38_900), "add_ons": []any{"none"}, "refundable": false}}
	r22Want(t, "v1", r22Run(t, c), [2]string{"schema", ""})
	c.pin = map[string]any{"pack": map[string]any{"ns": "stripe", "root": r22Root}, "defs": map[string]any{"air.book": r22Other}, "on_new_action": "deny"}
	d := r22Run(t, c)
	if len(d.checks) != 2 || d.checks[1].name != "pin" || d.checks[1].ok {
		t.Errorf("v1 with a pin: no traits check, the pin refuses: %+v", d.checks)
	}
}

func TestIntentV2ContextRule22Members(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"reviewers", nil, "reviewers must be {keys: [...]}"},
		{"reviewers", []any{}, "reviewers must be {keys: [...]}"},
		{"reviewers", map[string]any{}, "reviewers must be {keys: [...]}"},
		{"reviewers", map[string]any{"keys": "x"}, "reviewers must be {keys: [...]}"},
		{"reviewers", map[string]any{"keys": []any{}}, ""},
		{"call_context", nil, "call_context must be an array of strings"},
		{"call_context", "x", "call_context must be an array of strings"},
		{"call_context", []any{jnum(1)}, "call_context must be an array of strings"},
		{"call_context", []any{"idempotency"}, ""},
		{"call_context", []any{}, ""},
		{"actions", nil, "actions must be an object"},
		{"actions", []any{}, "actions must be an object"},
		{"actions", map[string]any{"records": "x"}, "actions.records must be an array"},
		{"actions", map[string]any{"keys": nil}, "actions.keys must be an array"},
		{"actions", map[string]any{"reapprovals": map[string]any{}}, "actions.reapprovals must be an array"},
		{"actions", map[string]any{"records": []any{}, "keys": []any{}, "reapprovals": []any{}}, ""},
		{"actions", map[string]any{}, ""},
	} {
		ctx := &IntentV2Context{raw: map[string]any{c.name: c.v}}
		if got := intentV2ContextError(ctx); got != c.want {
			t.Errorf("%s = %#v: %q, want %q", c.name, c.v, got, c.want)
		}
	}
	// ordering: reviewers, call_context, actions, then params
	ctx := &IntentV2Context{raw: map[string]any{"reviewers": nil, "call_context": nil, "actions": nil, "params": nil}}
	if got := intentV2ContextError(ctx); got != "reviewers must be {keys: [...]}" {
		t.Errorf("order: %q", got)
	}
	delete(ctx.raw, "reviewers")
	if got := intentV2ContextError(ctx); got != "call_context must be an array of strings" {
		t.Errorf("order: %q", got)
	}
	delete(ctx.raw, "call_context")
	if got := intentV2ContextError(ctx); got != "actions must be an object" {
		t.Errorf("order: %q", got)
	}
}

// A pin alone makes Authorize build the v2 context (server/verify.ts:299 needsModelRules).
func TestNeedsModelRulesOnPin(t *testing.T) {
	env := map[string]any{"type": envelopeCaveat, "goal_commit": "g", "predicates": []any{}, "caveats": []any{}, "agent_binding": map[string]any{}, "risk_policy": DefaultRiskPolicy()}
	grant := func() map[string]any { return deepM(t, map[string]any{"caveats": []any{env}}) }
	if needsModelRules(grant()) {
		t.Fatal("no pin: no model rules")
	}
	env["actions"] = map[string]any{}
	if !needsModelRules(grant()) {
		t.Fatal("a pin needs the v2 pipeline")
	}
}

// V8 refuses a zone offset past 23:59 (attest-intel-collateral.ts:260).
func TestJsDateParseZoneOffset(t *testing.T) {
	const base = "2025-01-01T00:00:00"
	for _, z := range []string{"+24:00", "-24:00", "+00:60", "-00:60", "+99:99"} {
		if ms, ok := jsDateParse(base + z); ok || ms != 0 {
			t.Errorf("%s: %d %v, want a refusal", z, ms, ok)
		}
	}
	z0, _ := jsDateParse(base + "Z")
	for z, off := range map[string]int64{"+23:59": -(23*60 + 59), "-23:59": 23*60 + 59, "+00:00": 0, "+01:30": -90} {
		if ms, ok := jsDateParse(base + z); !ok || ms != z0+off*60_000 {
			t.Errorf("%s: %d %v, want %d", z, ms, ok, z0+off*60_000)
		}
	}
}
