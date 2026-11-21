package pca

// The natural-language facade as a compiler: a grounding prompt over the catalog, a strict parse of the model's JSON policy
// (never fails on model garbage) and the compilation of what it grants into a risk policy.

import (
	"fmt"
	"strings"
)

// IntentNLCatalog is a catalog that remembers the order its actions were defined in (the grounding prompt lists them in that order).
type IntentNLCatalog struct {
	specs []CatalogAction
	cat   *Catalog
}

// NewIntentNLCatalog is the built-in catalog followed by extra actions; a later definition of a verb replaces the earlier one in place.
func NewIntentNLCatalog(extra []CatalogAction) *IntentNLCatalog {
	c := &IntentNLCatalog{}
	idx := map[string]int{}
	for _, a := range append(append([]CatalogAction{}, BuiltinActions...), extra...) {
		if i, ok := idx[a.Verb]; ok {
			c.specs[i] = a
			continue
		}
		idx[a.Verb] = len(c.specs)
		c.specs = append(c.specs, a)
	}
	c.cat = NewCatalog(c.specs)
	return c
}

// IntentNLPrompt is the grounding prompt: the model may only use verbs the catalog defines.
func IntentNLPrompt(instruction string, c *IntentNLCatalog) string {
	if c == nil {
		c = NewIntentNLCatalog(nil)
	}
	lines := make([]string, len(c.specs))
	for i, s := range c.specs {
		af, al := "", ""
		if s.AmountField != "" {
			af = ", amount field \"" + s.AmountField + "\""
		}
		if len(s.Aliases) > 0 {
			al = ", also called: " + strings.Join(s.Aliases, ", ")
		}
		lines[i] = fmt.Sprintf("  - %s (%s%s%s): %s", s.Verb, s.Reversibility, af, al, s.Description)
	}
	return strings.Join([]string{
		"You translate an instruction into a strict JSON agent policy. Output ONLY JSON, no prose, no code fence.",
		`Shape: {"permissions":{"<connector>":["<action>",...]},"limits":{"<action-or-verb>":"$<amount>/<period>"|"<count>/<period>"}}`,
		`Rules: use ONLY the verbs below (connector.action). A limit key is a bare action (e.g. "refund") or a full verb (e.g. "stripe.refund").`,
		`Monetary limits start with "$"; plain numbers are counts. Periods: hour, day, week, month. Omit limits you are unsure about.`,
		"",
		"Available verbs:",
		strings.Join(lines, "\n"),
		"",
		"Instruction: " + instruction,
		"JSON:",
	}, "\n")
}

type ixNlEntry struct {
	key string
	val any
}

// ixNlEntries is Object.entries of a parsed JSON object or array.
func ixNlEntries(o any) []ixNlEntry {
	switch t := o.(type) {
	case []any:
		out := make([]ixNlEntry, len(t))
		for i, v := range t {
			out[i] = ixNlEntry{fmt.Sprint(i), v}
		}
		return out
	case map[string]any:
		var out []ixNlEntry
		for _, k := range jsKeys(t) {
			out = append(out, ixNlEntry{k, t[k]})
		}
		return out
	}
	return nil
}

func ixNlUniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// IntentParseNLPolicy strictly parses and grounds the model's JSON against the catalog; it never fails on model garbage:
// {permissions, limits, unknownVerbs, droppedLimits}. permConnectors is the order the connectors were first granted in.
func IntentParseNLPolicy(raw string, c *IntentNLCatalog) map[string]any {
	out, _ := ixNlParse(raw, c)
	return out
}

func ixNlParse(raw string, c *IntentNLCatalog) (map[string]any, []string) {
	if c == nil {
		c = NewIntentNLCatalog(nil)
	}
	permissions := map[string][]string{}
	var connOrder []string
	limits := map[string]any{}
	unknown, dropped := []any{}, []any{}
	result := func() map[string]any {
		perms := map[string]any{}
		for k, v := range permissions {
			perms[k] = ixToAny(v)
		}
		return map[string]any{"permissions": perms, "limits": limits, "unknownVerbs": unknown, "droppedLimits": dropped}
	}
	t := jsTrim(raw)
	if i, j := strings.Index(t, "{"), strings.LastIndex(t, "}"); i >= 0 && j >= i {
		t = t[i : j+1]
	}
	obj, err := ParseJSONLenient([]byte(t))
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		obj, err = parseJSONLastWins(t) // JSON.parse keeps the last of a repeated member
	}
	if err != nil {
		return result(), nil
	}
	var members func(key string) any
	switch o := obj.(type) {
	case map[string]any:
		members = func(key string) any { return o[key] }
	case []any:
		members = func(string) any { return nil }
	default:
		return result(), nil
	}
	if perms := members("permissions"); ixIsObj(perms) || ixIsList(perms) {
		for _, e := range ixNlEntries(perms) {
			actions, ok := e.val.([]any)
			if !ok {
				continue
			}
			for _, av := range actions {
				action, ok := av.(string)
				if !ok {
					continue
				}
				verb := e.key + "." + action
				spec, found := c.cat.Get(verb)
				if !found {
					spec, found = c.cat.Resolve(e.key, action)
				}
				if !found {
					unknown = append(unknown, verb)
					continue
				}
				if _, seen := permissions[e.key]; !seen {
					connOrder = append(connOrder, e.key)
				}
				name := action
				if spec.Connector == e.key {
					name = spec.Action
				}
				permissions[e.key] = append(permissions[e.key], name)
			}
		}
	}
	for k, v := range permissions {
		permissions[k] = ixNlUniq(v)
	}
	granted := map[string]bool{}
	for _, cn := range connOrder {
		for _, a := range permissions[cn] {
			granted[cn+"."+a], granted[a] = true, true
			if s, ok := c.cat.Get(cn + "." + a); ok {
				for _, al := range s.Aliases {
					granted[al] = true
				}
			}
		}
	}
	if lims := members("limits"); ixIsObj(lims) || ixIsList(lims) {
		for _, e := range ixNlEntries(lims) {
			spec, ok := e.val.(string)
			if !ok {
				dropped = append(dropped, e.key)
				continue
			}
			if _, err := ParseLimit(spec); err != nil || !granted[e.key] {
				dropped = append(dropped, e.key)
				continue
			}
			limits[e.key] = spec
		}
	}
	return result(), connOrder
}

// IntentNLFacadeCompiler is the nl.ts path as a compiler: grounding prompt -> strict parse -> compile policy. complete is the
// model call (a failure makes the compiler fail, which RunCompilers turns into an empty grant and a note).
func IntentNLFacadeCompiler(id, family string, c *IntentNLCatalog, complete func(prompt string) (string, error)) IntentCompiler {
	if c == nil {
		c = NewIntentNLCatalog(nil)
	}
	return IntentCompiler{ID: id, Family: family, Compile: func(in map[string]any) (map[string]any, error) {
		return ixTryMap(func() map[string]any {
			raw, err := complete(IntentNLPrompt(ixS(in["text"]), c))
			if err != nil {
				panic(err)
			}
			parsed, connOrder := ixNlParse(raw, c)
			notes := []any{}
			for _, v := range ixL(parsed["unknownVerbs"]) {
				notes = append(notes, "unknown verb dropped: "+ixS(v))
			}
			for _, k := range ixL(parsed["droppedLimits"]) {
				notes = append(notes, "limit dropped: "+ixS(k))
			}
			perms := ixM(parsed["permissions"])
			if len(perms) == 0 {
				return map[string]any{"compiler": id, "family": family, "policy": map[string]any{"predicates": []any{}, "caveats": []any{}},
					"notes": append(notes, "no grantable permission"), "raw": raw}
			}
			ordered := map[string]any{}
			for _, cn := range connOrder {
				ordered[cn] = perms[cn]
			}
			recordKeyOrder(ordered, connOrder)
			limits := map[string]string{}
			for k, v := range ixM(parsed["limits"]) {
				limits[k] = ixS(v)
			}
			cp, err := CompilePolicy(PolicyOptions{Permissions: ordered, Limits: limits, Catalog: c.cat})
			if err != nil {
				panic(err)
			}
			for _, cv := range cp.Caveats {
				if m := ixM(cv); m["type"] != "reversibility_max" {
					notes = append(notes, "caveat outside Ω not measured: "+ixS(m["type"]))
				}
			}
			return map[string]any{"compiler": id, "family": family,
				"policy": map[string]any{"predicates": cp.Predicates, "caveats": ixMeasurableCaveats(cp.Caveats)}, "notes": notes, "raw": raw}
		})
	}}
}
