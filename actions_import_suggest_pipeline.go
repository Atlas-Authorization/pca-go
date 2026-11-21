package pca

// `import -> suggest` as one call: the suggestion step over already imported defs (rules, optionally pinned models), and the importer
// run followed by it. Pure: no file system, no network (model adapters are injected).

// ActionSuggestOptions steers the suggestion step: Mode ("rules" default, "model", "none"), Rules (nil = the shipped rules),
// Registry (nil = the core registry) and Models (the adapters of mode "model").
type ActionSuggestOptions struct {
	Mode     string
	Rules    any
	Registry Registry
	Models   []ActionModelAdapter
}

// ActionSuggestDefs suggests for already imported defs: new defs (review state `suggested`) and the model errors, if any.
func ActionSuggestDefs(defs []map[string]any, o ActionSuggestOptions) ([]map[string]any, []any, error) {
	mode := o.Mode
	if mode == "" {
		mode = "rules"
	}
	if mode == "none" {
		return append([]map[string]any{}, defs...), []any{}, nil
	}
	reg := o.Registry
	if reg == nil {
		reg = coreRegistry
	}
	rules := o.Rules
	if rules == nil {
		rules = ActionDefaultRules()
	}
	digest, err := ActionRulesDigest(rules)
	if err != nil {
		return nil, nil, err
	}
	out := make([]map[string]any, 0, len(defs))
	errs := []any{}
	for _, d := range defs {
		s, err := ActionSuggestWithRules(d, rules, reg)
		if err != nil {
			return nil, nil, err
		}
		by := map[string]any{"rules": map[string]any{"version": aisMap(rules)["version"], "digest": digest, "fired": s["fired"]}}
		if mode == "model" {
			run, err := ActionSuggestWithModels(d, o.Models, reg)
			if err != nil {
				return nil, nil, err
			}
			for _, e := range aisList(run["errors"]) {
				m := aisShallow(aisMap(e))
				m["verb"] = d["verb"]
				errs = append(errs, m)
			}
			traits := aisSortUniq(append(aisStrList(s["traits"]), aisStrList(aisMap(run["suggestion"])["traits"])...))
			s = map[string]any{"traits": anyStrs(traits), "roles": s["roles"], "tags": s["tags"], "fired": s["fired"]}
			if ms := aisList(run["models"]); len(ms) > 0 {
				by["models"] = ms
			}
		}
		nd, err := ActionApplySuggestion(d, s, by)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, nd)
	}
	return out, errs, nil
}

// ActionImportAndSuggest imports one source and suggests for its defs: {defs, todo, source, suggestErrors}.
func ActionImportAndSuggest(kind string, source any, opts map[string]any, o ActionSuggestOptions) (map[string]any, error) {
	r, err := ActionImport(kind, source, opts)
	if err != nil {
		return nil, err
	}
	defs, errs, err := ActionSuggestDefs(r.Defs, o)
	if err != nil {
		return nil, err
	}
	ds := make([]any, len(defs))
	for i, d := range defs {
		ds[i] = d
	}
	todo := make([]any, len(r.Todo))
	for i, t := range r.Todo {
		todo[i] = map[string]any{"where": t.Where, "code": t.Code, "message": t.Message}
	}
	return map[string]any{"defs": ds, "todo": todo, "source": r.Source.asMap(), "suggestErrors": errs}, nil
}
