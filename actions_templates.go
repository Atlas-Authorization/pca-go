package pca

// Starter packs a platform can begin from: typical actions of five business types in the authoring YAML form, with custom
// traits and business rules (and their examples). Every action is an authored draft: a template never confirms anything, so
// until a reviewer of the platform signs each action it is treated as the most dangerous case. The data is the reference output
// rendered under a marker namespace (actions_templates_data.json, embedded); the namespace is substituted into it. The YAML is
// returned as text: parse it with a YAML reader of your choice and hand the value to the action authoring entry points.

import (
	_ "embed"
	"regexp"
	"strings"
)

//go:embed actions_templates_data.json
var actionTemplatesJSON []byte

var actionNsRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// ActionStarterTemplate is one starter pack: id (ecommerce, fintech, healthcare, saas_admin, devtools), a short picker title, a
// description and the default namespace (the first segment of every verb).
type ActionStarterTemplate struct {
	ID, Title, Description, NS string
	traits                     any
	yaml                       string
	marker                     string
}

// ActionCheckNs: the namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`.
func ActionCheckNs(ns any) (string, error) {
	s, ok := ns.(string)
	if !ok || !actionNsRe.MatchString(s) {
		return "", &CodedError{Code: "bad_ns", Msg: "ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)"}
	}
	if s == "pca" {
		return "", &CodedError{Code: "bad_ns", Msg: "the namespace 'pca' is reserved for core traits"}
	}
	return s, nil
}

func actionTemplateSub(v any, marker, ns string) any {
	switch t := v.(type) {
	case string:
		return strings.ReplaceAll(t, marker, ns)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = actionTemplateSub(x, marker, ns)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = actionTemplateSub(x, marker, ns)
		}
		return out
	}
	return v
}

// Traits is the pack's custom trait definitions under namespace ns (ids `<ns>.<name>`).
func (t *ActionStarterTemplate) Traits(ns string) ([]any, error) {
	s, err := ActionCheckNs(ns)
	if err != nil {
		return nil, err
	}
	out, _ := actionTemplateSub(t.traits, t.marker, s).([]any)
	return out, nil
}

// YAML is the authoring YAML under namespace ns, with `rules:` blocks and their examples.
func (t *ActionStarterTemplate) YAML(ns string) (string, error) {
	s, err := ActionCheckNs(ns)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(t.yaml, t.marker, s), nil
}

// ActionStarterTemplates lists the starter packs.
func ActionStarterTemplates() []*ActionStarterTemplate {
	v, err := ParseJSONLenient(actionTemplatesJSON)
	root, ok := v.(map[string]any)
	if err != nil || !ok {
		anlFail("actions_templates_data.json is unreadable")
	}
	marker, _ := root["marker"].(string)
	list, _ := root["templates"].([]any)
	out := make([]*ActionStarterTemplate, 0, len(list))
	for _, x := range list {
		m, _ := x.(map[string]any)
		str := func(k string) string { s, _ := m[k].(string); return s }
		out = append(out, &ActionStarterTemplate{ID: str("id"), Title: str("title"), Description: str("description"), NS: str("ns"), traits: m["traits"], yaml: str("yaml"), marker: marker})
	}
	return out
}

// ActionStarterTemplateByID is the starter pack with this id, or nil.
func ActionStarterTemplateByID(id string) *ActionStarterTemplate {
	for _, t := range ActionStarterTemplates() {
		if t.ID == id {
			return t
		}
	}
	return nil
}
