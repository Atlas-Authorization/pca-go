package pca

// The Goal IR domain vocabularies (payments, email, code, data, travel) as action defs: the defs, the bindings of NL short ids
// to defs, and the ontology and role maps derived from them. The effect class of each verb is derived, never assigned.

import (
	_ "embed"
	"fmt"
)

//go:embed actions_domain_data.json
var actionDomainDataJSON []byte

var actionDomainData = func() map[string]any {
	v, err := ParseJSONLenient(actionDomainDataJSON)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		panic("actions_domain_data.json is unreadable")
	}
	return m
}()

// ActionDomainDefs returns a fresh copy of the defs the domain vocabularies add to the built-in pack.
func ActionDomainDefs() []map[string]any {
	v, _ := ParseJSONLenient(actionDomainDataJSON)
	list, _ := v.(map[string]any)["domain"].([]any)
	out := make([]map[string]any, len(list))
	for i, x := range list {
		out[i] = aisMap(x)
	}
	return out
}

// ActionCorePackDefs is every def the domain vocabularies and the connector catalog are built from: one pack, one alias namespace.
func ActionCorePackDefs() []map[string]any { return append(ActionBuiltinDefs(), ActionDomainDefs()...) }

// ActionDomainVerb binds an NL short id to a def: the NL resource type, the def parameters the NL layer surfaces (NL name to def
// name) and, for money, the currencies it accepts.
type ActionDomainVerb struct {
	ID           string
	Verb         string
	ResourceType string
	Params       map[string]string
	Ccys         []string
}

// ActionDomainNames lists the domain names in vocabulary order.
var ActionDomainNames = []string{"payments", "email", "code_repos", "data_access", "calendar_travel"}

// ActionDomainVerbs maps each domain name to its bindings.
var ActionDomainVerbs = func() map[string][]ActionDomainVerb {
	dv, _ := actionDomainData["domainVerbs"].(map[string]any)
	out := map[string][]ActionDomainVerb{}
	for name, lv := range dv {
		list, _ := lv.([]any)
		for _, x := range list {
			m, _ := x.(map[string]any)
			b := ActionDomainVerb{ID: jsAnyString(m["id"]), Verb: jsAnyString(m["verb"]), ResourceType: jsAnyString(m["resourceType"]), Params: map[string]string{}}
			if pm, ok := m["params"].(map[string]any); ok {
				for k, v := range pm {
					b.Params[k] = jsAnyString(v)
				}
			}
			if cs, ok := strsOf(m["ccys"]); ok {
				b.Ccys = cs
			}
			out[name] = append(out[name], b)
		}
	}
	return out
}()

func actionDomainDefOf(defs []map[string]any, verb string) (map[string]any, error) {
	for _, d := range defs {
		if d["verb"] == verb {
			return d, nil
		}
	}
	return nil, fmt.Errorf("domain binding names unknown def '%s'", verb)
}

// ActionDomainVerbsOf is the verbs and aliases of a domain ontology, derived from the defs: the effect class is the derived
// one, a surfaced money parameter lists the currencies of its binding, and the aliases are the defs' aliases other than the
// short id. The result has "verbs" ([]any of {id, effect, resource_type, params}) and "aliases" (alias to short id).
func ActionDomainVerbsOf(domain string, reg Registry) (map[string]any, error) {
	if reg == nil {
		reg = coreRegistry
	}
	bindings, ok := ActionDomainVerbs[domain]
	if !ok {
		return nil, fmt.Errorf("unknown domain '%s'", domain)
	}
	pack := ActionCorePackDefs()
	defs := make([]any, len(bindings))
	for i, b := range bindings {
		d, err := actionDomainDefOf(pack, b.Verb)
		if err != nil {
			return nil, err
		}
		defs[i] = d
	}
	onto, err := ActionToOntology(defs, reg, func(map[string]any) bool { return false })
	if err != nil {
		return nil, err
	}
	ovs, _ := onto["verbs"].([]any)
	verbs := []any{}
	aliases := map[string]any{}
	for i, b := range bindings {
		d := defs[i].(map[string]any)
		al, _ := strsOf(d["aliases"])
		if !contains(al, b.ID) {
			return nil, fmt.Errorf("domain binding '%s' is not an alias of '%s'", b.ID, b.Verb)
		}
		var ov map[string]any
		for _, x := range ovs {
			if m := x.(map[string]any); m["id"] == b.Verb {
				ov = m
			}
		}
		oparams, _ := ov["params"].(map[string]any)
		params := map[string]any{}
		for nl, dp := range b.Params {
			p, ok := oparams[dp].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("domain binding '%s' surfaces unknown parameter '%s'", b.ID, dp)
			}
			if p["kind"] == "money" && b.Ccys != nil {
				params[nl] = map[string]any{"kind": "money", "ccys": anyStrs(b.Ccys)}
			} else {
				params[nl] = p
			}
		}
		verbs = append(verbs, map[string]any{"id": b.ID, "effect": ActionEffectClass(d), "resource_type": b.ResourceType, "params": params})
		for _, a := range al {
			if a != b.ID {
				aliases[a] = b.ID
			}
		}
	}
	return map[string]any{"verbs": verbs, "aliases": aliases}, nil
}

// ActionDomainRoles is the role map of a domain's verbs for the selector layer: short id, then role, then the NL parameter names
// carrying it (sorted).
func ActionDomainRoles(domain string) (map[string]map[string][]string, error) {
	pack := ActionCorePackDefs()
	out := map[string]map[string][]string{}
	for _, b := range ActionDomainVerbs[domain] {
		d, err := actionDomainDefOf(pack, b.Verb)
		if err != nil {
			return nil, err
		}
		pm, _ := d["params"].(map[string]any)
		roles := map[string][]string{}
		for _, nl := range sortedKeysStd(anyMapOfStrings(b.Params)) {
			if pd, ok := pm[b.Params[nl]].(map[string]any); ok {
				if r, ok := pd["role"].(string); ok {
					roles[r] = append(roles[r], nl)
				}
			}
		}
		out[b.ID] = roles
	}
	return out, nil
}

func anyMapOfStrings(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
