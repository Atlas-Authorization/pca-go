package pca

// Differential kill test for action_schema.go (rule 14, signed action schemas) against the TypeScript reference:
// testdata/k042-actionschema.json is written by tools/pca-audit/java-mutate/k042-actionschema-oracle.mts (shared with the
// Java suite): actionSchemaShapeError / verifyActionSchema / paramValueViolation / conformAction / accumulationParams /
// canonProjection on targeted inputs at the exact boundary of every rule. Every input is raw JSON text. Go reports verdicts
// and codes, not reason texts, so the verdict (and code / path / output) is compared exactly.

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func k042ASLoad(t *testing.T) map[string][]map[string]any {
	b, err := os.ReadFile("testdata/k042-actionschema.json")
	if err != nil {
		t.Fatal(err)
	}
	var g map[string][]map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&g); err != nil {
		t.Fatal(err)
	}
	return g
}

func k042J(t *testing.T, raw any) any {
	v, err := ParseJSONLenient([]byte(raw.(string)))
	if err != nil {
		t.Fatal(err)
	}
	return normalizeJSON(v)
}

func k042Report(t *testing.T, bad []string, n int) {
	t.Helper()
	if len(bad) > 0 {
		if len(bad) > 40 {
			bad = bad[:40]
		}
		t.Fatalf("mismatches (of %d cases):\n%s", n, strings.Join(bad, "\n"))
	}
}

func TestK042ActionSchemaShape(t *testing.T) {
	cs := k042ASLoad(t)["shape"]
	var bad []string
	for _, c := range cs {
		want := c["expect"] == nil
		if got := actionSchemaShapeOK(k042J(t, c["doc"]), true); got != want {
			bad = append(bad, fmt.Sprintf("%v: want ok=%v got %v (%v)", c["name"], want, got, c["expect"]))
		}
	}
	k042Report(t, bad, len(cs))
}

func TestK042ActionSchemaParamValueViolation(t *testing.T) {
	cs := k042ASLoad(t)["pvv"]
	var bad []string
	for _, c := range cs {
		want := ""
		if e, ok := c["expect"].(map[string]any); ok {
			want = e["code"].(string)
		}
		d, _ := k042J(t, c["d"]).(map[string]any)
		if got := paramValueViolation(d, k042J(t, c["x"])); got != want {
			bad = append(bad, fmt.Sprintf("%v: want <%s> got <%s>", c["name"], want, got))
		}
	}
	k042Report(t, bad, len(cs))
}

func TestK042ActionSchemaConform(t *testing.T) {
	cs := k042ASLoad(t)["conform"]
	var bad []string
	for _, c := range cs {
		e := c["expect"].(map[string]any)
		want := SchemaConform{OK: e["ok"] == true}
		if !want.OK {
			want.Code = e["code"].(string)
			if p, ok := e["path"].(string); ok {
				want.Path = p
			}
		}
		got := conformAction(k042J(t, c["doc"]), c["verb"].(string), k042J(t, c["params"]))
		if got != want {
			bad = append(bad, fmt.Sprintf("%v: want %+v got %+v", c["name"], want, got))
		}
	}
	k042Report(t, bad, len(cs))
}

func TestK042ActionSchemaVerify(t *testing.T) {
	cs := k042ASLoad(t)["verify"]
	var bad []string
	for _, c := range cs {
		want := c["expect"] == nil
		if got := verifyActionSchema(k042J(t, c["doc"]), k042J(t, c["keys"])); got != want {
			bad = append(bad, fmt.Sprintf("%v: want ok=%v got %v (%v)", c["name"], want, got, c["expect"]))
		}
	}
	k042Report(t, bad, len(cs))
}

func TestK042ActionSchemaAccumulationParams(t *testing.T) {
	cs := k042ASLoad(t)["acc"]
	var bad []string
	for _, c := range cs {
		v, _ := k042J(t, c["v"]).(map[string]any)
		got, throws := accumulationParams(v, c["unit"].(string))
		want := []string{}
		for _, x := range c["expect"].([]any) {
			want = append(want, x.(string))
		}
		if len(got) == 0 {
			got = []string{}
		}
		if throws || !reflect.DeepEqual(got, want) {
			bad = append(bad, fmt.Sprintf("%v: want %v got %v (throws %v)", c["name"], want, got, throws))
		}
	}
	k042Report(t, bad, len(cs))
}

func TestK042ActionSchemaCanonProjection(t *testing.T) {
	cs := k042ASLoad(t)["canon"]
	var bad []string
	for _, c := range cs {
		e := c["expect"].(map[string]any)
		params, _ := k042J(t, c["params"]).(map[string]any)
		got, ok := canonProjection(k042J(t, c["doc"]), c["verb"].(string), params)
		if e["ok"] != true {
			if ok {
				bad = append(bad, fmt.Sprintf("%v: want a throw, got %v", c["name"], got))
			}
			continue
		}
		want := map[string]any{}
		for k, v := range e["out"].(map[string]any) {
			want[k] = v
		}
		if !ok || !reflect.DeepEqual(got, want) {
			bad = append(bad, fmt.Sprintf("%v: want %v got %v (%v)", c["name"], want, got, ok))
		}
	}
	k042Report(t, bad, len(cs))
}
