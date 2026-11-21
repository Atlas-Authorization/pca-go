package pca

import (
	"errors"
	"math"
	"testing"
)

// Replays of the connector catalog (ref-catalog), reputation (ref-reputation) and the budget forecaster (ref-budget-forecast)
// against the reference, every case; the catalog is driven through one scenario function (an op script, a refusal is {"$err": true}).

// catScenarioActions reads action specs as given (not validated): the members the catalog uses, absent ones left empty.
func catScenarioActions(v any) []CatalogAction {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]CatalogAction, 0, len(l))
	for _, x := range l {
		m := vecObj(x)
		a := CatalogAction{Connector: rsStr(m["connector"]), Action: rsStr(m["action"]), Verb: rsStr(m["verb"]), Reversibility: rsStr(m["reversibility"]),
			BlastRadius: jsF(scDecode(m["blastRadius"])), AmountField: rsStr(m["amountField"]), Resource: rsStr(m["resource"]), Description: rsStr(m["description"])}
		if l, ok := m["aliases"].([]any); ok {
			a.Aliases = []string{}
			for _, s := range l {
				a.Aliases = append(a.Aliases, rsStr(s))
			}
		}
		if l, ok := m["traits"].([]any); ok {
			a.Traits = []string{}
			for _, s := range l {
				a.Traits = append(a.Traits, rsStr(s))
			}
		}
		out = append(out, a)
	}
	return out
}

func catSpecs(l []CatalogAction) []any {
	out := make([]any, len(l))
	for i, a := range l {
		out[i] = catalogSpecMap(a)
	}
	return out
}

func catSpecOrNull(a CatalogAction, ok bool) any {
	if !ok {
		return nil
	}
	return catalogSpecMap(a)
}

func catOp(c *Catalog, op []any) (res any, err error) {
	name, _ := vecArg(op, 0).(string)
	arg := func(i int) string { s, _ := vecArg(op, i).(string); return s }
	switch name {
	case "get":
		a, ok := c.Get(arg(1))
		return catSpecOrNull(a, ok), nil
	case "forConnector":
		return catSpecs(c.ForConnector(arg(1))), nil
	case "all":
		return catSpecs(c.All()), nil
	case "resolve":
		a, ok := c.Resolve(arg(1), arg(2))
		return catSpecOrNull(a, ok), nil
	case "resolveAction":
		a, cat := ResolveAction(c, arg(1))
		return map[string]any{"spec": catalogSpecMap(a), "catalogued": cat}, nil
	case "digest":
		return ActionCatalogDigest(c)
	case "assertPinned":
		expected := arg(1)
		if expected == "$self" {
			if expected, err = ActionCatalogDigest(c); err != nil {
				return nil, err
			}
		}
		if err := AssertCatalogPinned(c, expected); err != nil {
			return nil, err
		}
		return true, nil
	case "extend":
		n, err := ExtendCatalog(c, catScenarioActions(vecArg(op, 1)))
		if err != nil {
			return nil, err
		}
		d, err := ActionCatalogDigest(n)
		if err != nil {
			return nil, err
		}
		return map[string]any{"all": catSpecs(n.All()), "digest": d}, nil
	}
	return nil, errors.New("unknown op " + name)
}

func TestCatalogMatchesTheReference(t *testing.T) {
	fns := map[string]vecFn{
		"defineAction": func(a []any) (any, error) { return DefineActionValue(scDecode(vecArg(a, 0))) },
		"uncataloguedSpec": func(a []any) (any, error) {
			v, _ := vecArg(a, 0).(string)
			return catalogSpecMap(UncataloguedSpec(v)), nil
		},
		"builtin": func([]any) (any, error) {
			d, err := ActionCatalogDigest(DefaultCatalog())
			if err != nil {
				return nil, err
			}
			return map[string]any{"actions": catSpecs(BuiltinActions), "digest": d, "blast": CatalogBlast()}, nil
		},
		"catalog": func(a []any) (any, error) {
			c := BuildCatalog(catScenarioActions(vecArg(a, 0)))
			ops, _ := vecArg(a, 1).([]any)
			out := make([]any, len(ops))
			for i, o := range ops {
				op, _ := o.([]any)
				r, err := catOp(c, op)
				if err != nil {
					r = map[string]any{"$err": true}
				}
				out[i] = r
			}
			return out, nil
		},
	}
	replayAll(t, "ref-catalog.json.gz", 75, fns, nil, map[string]bool{"defineAction": true})
}

func TestReputationMatchesTheReference(t *testing.T) {
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"MAX_REPUTATION_RECORDS": jsNumber(MaxReputationRecords), "COVERAGE_QUOTE_DOMAIN": CoverageQuoteDomain}, nil
		},
		"validateReputationInput": func(a []any) (any, error) {
			if r := ValidateReputationInput(vecObj(scDecode(vecArg(a, 0)))); r != "" {
				return r, nil
			}
			return nil, nil
		},
		"reputation": func(a []any) (any, error) { return Reputation(vecObj(scDecode(vecArg(a, 0)))), nil },
	}
	replayAll(t, "ref-reputation.json.gz", 85, fns, nil, nil)
}

func TestBudgetForecastMatchesTheReference(t *testing.T) {
	fns := map[string]vecFn{
		"forecast": func(a []any) (any, error) {
			policy, err := rsCompileErr(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			var plan []map[string]any
			for _, p := range rsList(vecArg(a, 1)) {
				plan = append(plan, vecObj(p))
			}
			start := 0.0
			if f := rsOptNum(vecArg(a, 2)); f != nil {
				start = *f
			}
			var catalog *Catalog
			if l, ok := vecArg(a, 3).([]any); ok {
				defined := make([]any, len(l))
				for i, x := range l {
					d, err := DefineActionValue(x)
					if err != nil {
						return nil, err
					}
					defined[i] = d
				}
				catalog = BuildCatalog(catScenarioActions(defined))
			}
			return ForecastBudget(policy, plan, catalog, start), nil
		},
		"recommendPolicy": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			// a kappa that is present but not a number (a string) is `?? 1`-kept by the reference and then refused as not finite
			kappa := rsOptNum(vecArg(a, 2))
			if k := vecArg(a, 2); kappa == nil && k != nil {
				nan := math.NaN()
				kappa = &nan
			}
			return RecommendPolicy(jsF(vecArg(a, 0)), jsF(vecArg(a, 1)), kappa)
		},
		"autonomyBoundOf": func(a []any) (any, error) {
			return scNumOut(AutonomyBoundOf(vecObj(scDecode(vecArg(a, 0))))), nil
		},
	}
	replayAll(t, "ref-budget-forecast.json.gz", 326, fns, nil, nil)
}
