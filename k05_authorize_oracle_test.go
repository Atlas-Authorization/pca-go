package pca

// k05 differential oracle: the authorize pipeline's 0.5 additions (provenance by default, fresh_at escalation, escalation
// answers, undo admission) and its pure pieces (tool_schema, risk policy, envelope) against the TypeScript reference
// (testdata/k05-authorize.json.gz, tools/pca-audit/k05-oracles/authorize-oracle.mts). An `authorize` case is a scenario
// {grant, config, steps}: the createAuthorizer options map onto AuthorizeInput (fresh memory store per scenario, revocation
// hook, single-step plan, provenance pins / action facts / observations, fresh_at policy, undo admission hook, escalation
// principals / render) and each step's result is compared on the reference projection (allow, decision, status, the named
// checks, the failed ones, the gate-owned reasons, the escalation and the undo admission).

import (
	"strings"
	"testing"
)

var k05AzKeys = []string{"wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "plan_root_authorized", "leaf_signature",
	"counter_format", "fresh_at", "attestation", "revocation", "grant_ref", "operation", "params_digest", "delegated_caveats", "policy", "replay",
	"provenance_flow", "undo_window", "escalation"}
var k05AzOwn = []string{"provenance_flow: ", "undo_window: ", "escalation: ", "fresh_at: "}

func k05AzPins(v any) []ProvMediatorPin {
	var out []ProvMediatorPin
	list, _ := v.([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		p := ProvMediatorPin{}
		p.Mediator, _ = m["mediator"].(string)
		p.Kid, _ = m["kid"].(string)
		p.PK, _ = m["pk"].(string)
		p.PQPK, _ = m["pq_pk"].(string)
		out = append(out, p)
	}
	return out
}

func k05AzOp(v any) *Operation {
	m, _ := v.(map[string]any)
	op := &Operation{}
	op.Verb, _ = m["verb"].(string)
	op.Resource, _ = m["resource"].(string)
	op.Params, _ = m["params"].(map[string]any)
	return op
}

// k05AzScenario replays one scenario; ok false when the scenario uses an option Go cannot express.
func k05AzScenario(sc map[string]any) []any {
	grant := sc["grant"].(map[string]any)
	cfg := sc["config"].(map[string]any)
	now, _ := k05UndoInt(cfg["now"])
	revoked := false
	in := AuthorizeInput{Risk: InsecureCalmRisk,
		Audience: cfg["audience"].(string),
		ResolveGrant: func(ref string) (map[string]any, error) {
			if ref == grant["id"] {
				return grant, nil
			}
			return nil, nil
		},
		StateStore: NewMemoryStateStore(),
		IsRevoked:  func(_, _ map[string]any) (bool, error) { return revoked, nil },
		Now:        now,
		Plan:       PlanSingleStep,
	}
	prov := &ArgProvenanceOptions{Mediators: k05AzPins(cfg["mediators"])}
	if acts, ok := cfg["actions"].(map[string]any); ok {
		prov.Actions = func(op Operation) map[string]any { m, _ := acts[op.Verb].(map[string]any); return m }
	}
	if obs, ok := cfg["observed"].([]any); ok {
		var list []ProvObservation
		for _, x := range obs {
			m := x.(map[string]any)
			list = append(list, ProvObservation{Origin: m["origin"].(string), Source: m["source"].(string)})
		}
		prov.Observed = func(map[string]any, Operation, string) []ProvObservation { return list }
	}
	in.ArgProvenance = prov
	if fa, ok := cfg["freshAt"]; ok {
		in.FreshAt = FreshAtPolicyFromJSON(fa)
	}
	if u, ok := cfg["undo"].(map[string]any); ok {
		in.Undo = func(a UndoAdmitInput) (*UndoAdmission, error) {
			m, ok := u[a.Operation.Verb].(map[string]any)
			if !ok {
				return nil, nil // the reference hook refuses: not eligible
			}
			adm := &UndoAdmission{}
			adm.ID, _ = m["id"].(string)
			adm.WindowEnd, _ = k05I64(m["window_end"]) // 2^53 passes through: Authorize must refuse it
			cm, _ := m["compensation"].(map[string]any)
			adm.Compensation.Verb, _ = cm["verb"].(string)
			adm.Compensation.Resource, _ = cm["resource"].(string)
			return adm, nil
		}
	}
	if e, ok := cfg["escalation"].(map[string]any); ok {
		for _, p := range e["principals"].([]any) {
			in.EscalationPrincipals = append(in.EscalationPrincipals, p.(string))
		}
		if rd, ok := e["render_digest"].(string); ok {
			in.EscalationRender = func(map[string]any) string { return rd }
		}
		in.InsecureUnboundApproval = e["insecureUnboundApproval"] == true
	}
	out := []any{}
	for _, sv := range sc["steps"].([]any) {
		s := sv.(map[string]any)
		revoked = s["revoked"] == true
		step := in
		step.Operation = k05AzOp(s["operation"])
		step.ProvenanceBundle = s["provenance"]
		step.EscalationAnswer = s["escalationAnswer"]
		r := Authorize(s["pcactn"], step)
		checks := map[string]any{}
		failed := []any{}
		for _, k := range k05AzKeys {
			gk := k
			if k == "cap_chain" {
				gk = "chain" // Go's name for the capability chain check
			}
			if v, has := r.Checks[gk]; has {
				checks[k] = v
				if v == "fail" {
					failed = append(failed, k)
				}
			}
		}
		reasons := []any{}
		for _, x := range r.Reasons {
			for _, o := range k05AzOwn {
				if strings.HasPrefix(x, o) {
					reasons = append(reasons, x)
					break
				}
			}
		}
		var esc any
		if r.Escalation != nil {
			if r.Allow {
				esc = r.Escalation
			} else {
				esc = map[string]any{"request": true}
			}
		}
		var undo any
		if r.Undo != nil {
			undo = map[string]any{"id": r.Undo.ID, "window_end": r.Undo.WindowEnd,
				"compensation": map[string]any{"verb": r.Undo.Compensation.Verb, "resource": r.Undo.Compensation.Resource}}
		}
		out = append(out, map[string]any{"allow": r.Allow, "decision": r.Decision, "status": int64(r.Status), "checks": checks,
			"failed": failed, "reasons": reasons, "escalation": esc, "undo": undo})
	}
	return out
}

func TestK05Authorize(t *testing.T) {
	var k k05Tally
	k05Each(t, "k05-authorize.json.gz", func(c *k05Case) {
		a := c.Args
		switch c.Fn {
		case "validateArgSchema", "validateRiskPolicy":
			k.run(c.Fn)
			got := ValidateArgSchema(a[0])
			if c.Fn == "validateRiskPolicy" {
				got = validateRiskPolicy(a[0])
			}
			want, _ := c.Out.(string)
			// the node budget is order independent but WHICH property crosses it follows member order (insertion order in
			// the reference, sorted in a Go map): the refusal is compared, not the property it names
			const tooLarge = ": schema too large"
			if strings.HasSuffix(want, tooLarge) && strings.HasSuffix(got, tooLarge) {
				want, got = tooLarge, tooLarge
			}
			if got != want {
				k.fail(c, "want %v, got %q", c.Out, got)
			}
		case "evaluateToolSchema":
			var call *ToolCall
			if m, ok := a[1].(map[string]any); ok {
				if _, has := m["toolSignature"]; has {
					k.skip(c.Fn, "Go ToolCall has no toolSignature member (only the digest)")
					return
				}
				tool, isStr := m["tool"].(string)
				if _, has := m["tool"]; has && !isStr {
					k.skip(c.Fn, "typed port: the call's tool is not a string")
					return
				}
				call = &ToolCall{Tool: tool}
				call.Args, _ = m["args"].(map[string]any) // not an object = no args (malformed call)
				if dv, has := m["toolSignatureDigest"]; has {
					d, ok := dv.(string)
					if !ok {
						k.skip(c.Fn, "typed port: toolSignatureDigest present but not a string (Go's *string has only absent)")
						return
					}
					call.ToolSignatureDigest = &d
				}
			}
			k.run(c.Fn)
			ok, reason := EvaluateToolSchema(a[0], call)
			got := map[string]any{"ok": ok}
			if !ok {
				got["reason"] = reason
			}
			if k05Canon(got) != k05Canon(c.Out) {
				k.fail(c, "want %s, got %s", k05Canon(c.Out), k05Canon(got))
			}
		case "readEnvelope":
			k.run(c.Fn)
			var got any
			if e := ReadEnvelope(a[0]); e != nil {
				got = e
			}
			if k05Canon(got) != k05Canon(c.Out) {
				k.fail(c, "want %s, got %s", k05Canon(c.Out), k05Canon(got))
			}
		case "requiresAttestation":
			k.run(c.Fn)
			if got := requiresAttestation(a[0]); got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		case "authorize":
			cfg, _ := a[0].(map[string]any)["config"].(map[string]any)
			if u, ok := cfg["undo"].(map[string]any); ok {
				for _, x := range u {
					m, _ := x.(map[string]any)
					_, idOK := m["id"].(string)
					if _, weOK := k05I64(m["window_end"]); !weOK || !idOK {
						k.skip(c.Fn, "typed port: the undo admission's id / window_end has no UndoAdmission form (string, int64)")
						return
					}
				}
			}
			k.run(c.Fn)
			var got []any
			if p := k05Call(func() { got = k05AzScenario(a[0].(map[string]any)) }); p != "" {
				k.fail(c, "panicked: %s", p)
				return
			}
			// attestation 'not-enforced' is the reference's report of a check Go does not run (no attestation verifier): an
			// unreported attestation is that; a 'fail' still has to match
			if steps, ok := c.Out.([]any); ok {
				for _, st := range steps {
					if sm, ok := st.(map[string]any); ok {
						if ch, ok := sm["checks"].(map[string]any); ok && ch["attestation"] == "not-enforced" {
							delete(ch, "attestation")
						}
					}
				}
			}
			if g := k05Canon(normalizeJSON(got)); g != k05Canon(c.Out) {
				k.fail(c, "want %s\n     got  %s", k05Canon(c.Out), g)
			}
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}
