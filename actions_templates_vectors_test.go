package pca

// Replays the reference corpus for the starter templates (metadata, custom traits and authoring YAML under several namespaces).

import (
	"errors"
	"testing"
)

func TestActionTemplatesVectors(t *testing.T) {
	meta := func(x *ActionStarterTemplate) map[string]any {
		return map[string]any{"id": x.ID, "title": x.Title, "description": x.Description, "ns": x.NS}
	}
	tmpl := func(a []any) (*ActionStarterTemplate, error) {
		id, _ := vecArg(a, 0).(string)
		x := ActionStarterTemplateByID(id)
		if x == nil {
			return nil, errors.New("no such template")
		}
		return x, nil
	}
	replayVectors(t, "ref-actions-templates-py.json.gz", map[string]vecFn{
		"templateList": func([]any) (any, error) {
			out := []any{}
			for _, x := range ActionStarterTemplates() {
				out = append(out, meta(x))
			}
			return out, nil
		},
		"starterTemplate": func(a []any) (any, error) {
			id, _ := vecArg(a, 0).(string)
			if x := ActionStarterTemplateByID(id); x != nil {
				return meta(x), nil
			}
			return nil, nil
		},
		"templateTraits": func(a []any) (any, error) {
			x, err := tmpl(a)
			if err != nil {
				return nil, err
			}
			ns, err := ActionCheckNs(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return x.Traits(ns)
		},
		"templateYaml": func(a []any) (any, error) {
			x, err := tmpl(a)
			if err != nil {
				return nil, err
			}
			ns, err := ActionCheckNs(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return x.YAML(ns)
		},
	})
}
