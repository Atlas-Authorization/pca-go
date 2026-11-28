package pca

import (
	"errors"
	"strings"
	"testing"
)

func TestActionImportPipeline(t *testing.T) {
	src := map[string]any{"tools": []any{map[string]any{"name": "search_docs", "description": "Search."}}}
	r, err := ActionImport("mcp", src, map[string]any{"ns": "api"})
	if err != nil || len(r.Defs) != 1 || r.Defs[0]["verb"] != "api.docs.search" {
		t.Fatalf("import: %v %+v", err, r)
	}
	text, err := ActionDefsToJSONL(r.Defs)
	if err != nil || !strings.HasSuffix(text, "\n") {
		t.Fatalf("jsonl: %v %q", err, text)
	}
	back, err := ActionJSONLToDefs(text)
	if err != nil || len(back) != 1 || back[0]["verb"] != "api.docs.search" {
		t.Fatalf("jsonl round trip: %v %+v", err, back)
	}
	var ce *CodedError
	if _, err := ActionImport("nope", src, nil); !errors.As(err, &ce) || ce.Code != "bad_kind" {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := ActionJSONLToDefs("{}\n"); !errors.As(err, &ce) || ce.Code != "bad_defs" {
		t.Fatalf("bad def line: %v", err)
	}
	if _, _, err := ActionImporters["jsonschema"](map[string]any{"type": "object"}, map[string]any{"ns": "api"}); err == nil {
		t.Fatal("jsonschema import without a verb must refuse")
	}
	if _, err := ActionImportDefaultRules(); err != nil {
		t.Fatalf("rules: %v", err)
	}
}
