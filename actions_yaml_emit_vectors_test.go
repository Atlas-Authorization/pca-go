package pca

// Replays the reference corpora for the YAML text of an action pack (defsToYaml): byte-identical output, including the
// anchors and aliases written for containers that appear more than once.

import "testing"

func yamlDefsArgs(a []any) (string, []any, map[string]any) {
	ns, _ := vecArg(a, 0).(string)
	defs, _ := vecArg(a, 1).([]any)
	rules, _ := vecArg(a, 2).(map[string]any)
	return ns, defs, rules
}

func TestActionsYamlEmitVectors(t *testing.T) {
	replayOrdered(t, "ref-core-yaml-java.json.gz", map[string]vecFn{
		"defsToYaml": func(a []any) (any, error) {
			ns, defs, rules := yamlDefsArgs(a)
			return ActionsDefsToYaml(ns, defs, rules)
		},
	})
}

// yamlMaterialize builds ONE container per id of `shared`, fills them (cycles allowed) and substitutes every {"$ref": id}
// node of the roots by that container; everything else is copied with its member order.
func yamlMaterialize(shared map[string]any, roots ...any) []any {
	box := map[string]any{}
	for id, v := range shared {
		if _, isList := v.([]any); isList {
			box[id] = &[]any{}
		} else {
			box[id] = map[string]any{}
		}
	}
	var sub func(x any) any
	sub = func(x any) any {
		switch t := x.(type) {
		case []any:
			out := make([]any, len(t))
			for i, e := range t {
				out[i] = sub(e)
			}
			return out
		case map[string]any:
			keys := jsKeys(t)
			if len(keys) == 1 && keys[0] == "$ref" {
				id, _ := t["$ref"].(string)
				return box[id]
			}
			m := make(map[string]any, len(t))
			for _, k := range keys {
				m[k] = sub(t[k])
			}
			recordKeyOrder(m, keys)
			return m
		}
		return x
	}
	for id, v := range shared {
		filled := sub(v)
		switch c := box[id].(type) {
		case *[]any:
			*c, _ = filled.([]any)
		case map[string]any:
			fm, _ := filled.(map[string]any)
			for k, e := range fm {
				c[k] = e
			}
			recordKeyOrder(c, jsKeys(fm))
		}
	}
	out := make([]any, len(roots))
	for i, r := range roots {
		out[i] = sub(r)
	}
	return out
}

func TestActionsYamlEmitAnchorVectors(t *testing.T) {
	replayOrdered(t, "ref-core-yaml-anchors-java.json.gz", map[string]vecFn{
		"defsToYaml": func(a []any) (any, error) {
			ns, _ := vecArg(a, 0).(string)
			shared, _ := vecArg(a, 3).(map[string]any)
			m := yamlMaterialize(shared, vecArg(a, 1), vecArg(a, 2))
			defs, _ := m[0].([]any)
			rules, _ := m[1].(map[string]any)
			return ActionsDefsToYaml(ns, defs, rules)
		},
	})
}
