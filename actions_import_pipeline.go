package pca

// The importer registry the CLI reads (every source kind reachable by name, every def `unreviewed`), the `import` dispatch, the JSON
// Lines text form of defs, and the shipped suggestion rules as data. Pure: no file system, no network (the caller fetches and writes).

import (
	_ "embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed testdata/suggest-rules.json
var aimDefaultRulesJSON []byte

// ActionImportDefaultRules is the shipped suggestion rules document (parsed JSON: v, kind, version, rules), as the importers' suggest
// step reads it.
func ActionImportDefaultRules() (any, error) { return ParseJSONLenient(aimDefaultRulesJSON) }

// ActionImport imports one source of the given kind (one of ActionImportKinds); every def is `unreviewed`. A JSON Schema import needs
// opts["verb"].
func ActionImport(kind string, source any, opts map[string]any) (*ActionImportReport, error) {
	switch kind {
	case "openapi":
		return ActionImportOpenAPI(source, opts)
	case "mcp":
		return ActionImportMCP(source, opts)
	case "graphql":
		return ActionImportGraphQL(source, opts)
	case "grpc":
		return ActionImportGRPC(source, opts)
	case "asyncapi":
		return ActionImportAsyncAPI(source, opts)
	case "jsonschema":
		return ActionImportJSONSchema(source, opts)
	}
	return nil, &CodedError{Code: "bad_kind", Msg: fmt.Sprintf("unknown import kind '%s' (one of %s)", kind, strings.Join(ActionImportKinds, ", "))}
}

// ActionImporter is the CLI shape of an importer: the defs and the notes as `<where>: <message>` lines.
type ActionImporter func(doc any, opts map[string]any) (defs []map[string]any, todo []string, err error)

// ActionImporters maps each import kind to its CLI importer.
var ActionImporters = func() map[string]ActionImporter {
	out := map[string]ActionImporter{}
	for _, k := range ActionImportKinds {
		kind := k
		out[kind] = func(doc any, opts map[string]any) ([]map[string]any, []string, error) {
			if kind == "jsonschema" && !aimTruthy(opts["verb"]) {
				return nil, nil, errors.New("a JSON Schema import needs --verb <ns.noun.action>")
			}
			r, err := ActionImport(kind, doc, opts)
			if err != nil {
				return nil, nil, err
			}
			todo := make([]string, len(r.Todo))
			for i, t := range r.Todo {
				todo[i] = t.Where + ": " + t.Message
			}
			return r.Defs, todo, nil
		}
	}
	return out
}()

// ActionDefsToJSONL is one def per line, strict canonical JSON, sorted by verb: byte-reproducible.
func ActionDefsToJSONL(defs []map[string]any) (string, error) {
	sorted := append([]map[string]any{}, defs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, _ := sorted[i]["verb"].(string)
		b, _ := sorted[j]["verb"].(string)
		return a < b
	})
	lines := make([]string, len(sorted))
	for i, d := range sorted {
		s, err := Canonicalize(d)
		if err != nil {
			return "", err
		}
		lines[i] = s
	}
	out := strings.Join(lines, "\n")
	if len(defs) > 0 {
		out += "\n"
	}
	return out, nil
}

// ActionJSONLToDefs parses and validates a JSON Lines file of defs; the error ("bad_defs") names the first bad line.
func ActionJSONLToDefs(text string) ([]map[string]any, error) {
	out := []map[string]any{}
	for i, raw := range strings.Split(text, "\n") {
		l := jsTrim(raw)
		if l == "" {
			continue
		}
		v, err := ParseJSONLenient([]byte(l))
		if err != nil {
			return nil, &CodedError{Code: "bad_defs", Msg: "line " + strconv.Itoa(i+1) + ": not JSON"}
		}
		if bad := validateDef(v); bad != "" {
			return nil, &CodedError{Code: "bad_defs", Msg: "line " + strconv.Itoa(i+1) + ": " + bad}
		}
		out = append(out, v.(map[string]any))
	}
	return out, nil
}
