package pca

// Replays the reference corpus for the hosted action registry: the publish gate, the version digest, rules documents, trait
// registries, the verifier's view (lookup / provenance / floors / undo plans), grant facts, call context and rate keys. The
// corpus holds public keys and signatures only; no key material is derived here.

import (
	"errors"
	"strings"
	"testing"
)

func hostedSampleParams(d map[string]any) map[string]any {
	out := map[string]any{}
	params, _ := d["params"].(map[string]any)
	for k, pv := range params {
		p, _ := pv.(map[string]any)
		if p["required"] == false {
			continue
		}
		role, _ := p["role"].(string)
		switch vals, hasVals := p["values"].([]any); {
		case strings.HasPrefix(role, "id."):
			out[k] = "abc12345"
		case p["type"] == "integer":
			out[k] = jsNumber(7)
		case p["type"] == "boolean":
			out[k] = true
		case hasVals:
			if len(vals) > 0 {
				out[k] = vals[0]
			}
		case p["type"] == "array":
			out[k] = []any{"x"}
		case p["type"] == "set":
			out[k] = []any{}
		case p["type"] == "datetime":
			out[k] = "2030-01-01T00:00:00Z"
		default:
			out[k] = "val"
		}
	}
	return out
}

func TestActionHostedVectors(t *testing.T) {
	// the defs of the view probe's undo plans: the first definition seen per verb, in corpus order (the gate cases come first)
	defs := map[string]map[string]any{}
	note := func(pack any) {
		p, _ := pack.(map[string]any)
		for _, dv := range hostedList(p["defs"]) {
			if d, _ := dv.(map[string]any); d != nil {
				if v, ok := d["verb"].(string); ok && defs[v] == nil {
					defs[v] = d
				}
			}
		}
	}
	grants := []GrantFacts{
		{Caveats: []string{}, MaxEsc: 3, PreauthEsc: 0},
		{Caveats: []string{"amount_cap", "window", "bogus"}, MaxEsc: 3, PreauthEsc: 3},
		{Caveats: []string{"amount_cap", "count_cap", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"}, MaxEsc: 1, PreauthEsc: 1},
		{Caveats: []string{}, MaxEsc: 0, PreauthEsc: 0},
	}
	ctxs := [][]string{{}, {"fresh_revocation"}, {"fresh_revocation", "idempotency", "approval_ref", "revocable", "dry_run_first"}}
	replayVectors(t, "ref-actions-hosted-py.json.gz", map[string]vecFn{
		"publishGate": func(a []any) (any, error) {
			in := vecObj(vecArg(a, 0))
			note(in["pack"])
			return ActionPublishGate(in)
		},
		"hostedVersionDigest": func(a []any) (any, error) { return ActionHostedVersionDigest(vecObj(vecArg(a, 0))) },
		"rulesDocError": func(a []any) (any, error) {
			if e := ActionRulesDocError(vecArg(a, 0), jsAnyString(vecArg(a, 1)), hostedList(vecArg(a, 2))); e != "" {
				return e, nil
			}
			return nil, nil
		},
		"registryOfTraits": func(a []any) (any, error) {
			reg, err := ActionRegistryOfTraits(hostedList(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			d, err := traitsDigest(reg)
			return map[string]any{"digest": d}, err
		},
		"hostedView": func(a []any) (any, error) {
			// the probe's verb order is the oracle's: the first six builtin definitions, then the seventh (gmail.delete)
			order := []string{"stripe.charge", "stripe.refund", "stripe.payout", "stripe.create_customer", "gmail.send", "gmail.draft", "gmail.delete"}
			for _, v := range order {
				if defs[v] == nil {
					return nil, errors.New("the definition table of the probe is incomplete")
				}
			}
			view := NewActionHostedView(hostedList(vecArg(a, 0)), vecArg(a, 1))
			verbs := append(append([]string{}, order...), "unknown.verb")
			var lookups, prov, floors, undo []any
			for _, v := range verbs {
				lookups = append(lookups, view.Lookup(v))
				prov = append(prov, view.Provenance(map[string]any{"verb": v}))
			}
			for _, v := range verbs {
				for _, g := range grants {
					for _, c := range ctxs {
						floors = append(floors, view.Floor(v, g, c))
					}
				}
			}
			for _, v := range order {
				undo = append(undo, view.UndoPlan(map[string]any{"verb": v, "params": hostedSampleParams(defs[v])}))
			}
			vs := make([]any, 0, len(view.Versions))
			for _, s := range view.Versions {
				vs = append(vs, s)
			}
			return map[string]any{"versions": vs, "lookups": lookups, "prov": prov, "floors": floors, "undo": undo}, nil
		},
		"grantFactsOf": func(a []any) (any, error) {
			g := ActionGrantFactsOf(vecArg(a, 0))
			return map[string]any{"caveats": g.Caveats, "max_esc": g.MaxEsc, "preauth_esc": g.PreauthEsc}, nil
		},
		"hostedCallContext": func(a []any) (any, error) {
			l := vecObj(vecArg(a, 0))
			if _, isStr := l["idempotency_param"].(string); isStr && vecArg(a, 1) == nil {
				return nil, vecSkip("the reference throws reading a member of an absent params object; Go reads it as empty and establishes no idempotency (stricter than nothing, same context)")
			}
			return ActionHostedCallContext(l, vecObj(vecArg(a, 1))), nil
		},
		"rateKeysOf": func(a []any) (any, error) { return ActionRateKeysOf(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil },
	})
}
