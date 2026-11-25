package pca

// Replays the reference corpus of the action schema drafting helpers: the OpenAPI draft, the MCP annotation hints, the
// value-dependent reversibility and the verb lookup.

import "testing"

func TestActionSchemaDraftVectors(t *testing.T) {
	replayVectors(t, "ref-action-schema-draft.json.gz", map[string]vecFn{
		"draftSchemaFromOpenApi": func(a []any) (any, error) { return DraftSchemaFromOpenApi(vecArg(a, 0), vecArg(a, 1)) },
		"reversibilityFromMcpHints": func(a []any) (any, error) {
			return ReversibilityFromMcpHints(vecArg(a, 0)), nil
		},
		"reversibilityOf": func(a []any) (any, error) {
			return ReversibilityOf(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
		"schemaVerb": func(a []any) (any, error) {
			verb, _ := vecArg(a, 1).(string)
			v, _ := SchemaVerb(vecArg(a, 0), verb)
			if v == nil {
				return nil, nil
			}
			return v, nil
		},
	})
}

func TestActionSchemaKeyOf(t *testing.T) {
	kp, err := KeyPairFromSeed(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	e, err := ActionSchemaKeyOf("k1", kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e["kid"] != "k1" || e["alg"] != "ed25519" || e["pk"] != kp.Public || len(e) != 3 {
		t.Fatalf("ed25519 key entry: %v", e)
	}
	pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	e, err = ActionSchemaKeyOf("k2", kp, &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq})
	if err != nil {
		t.Fatal(err)
	}
	if e["alg"] != "hybrid-ed25519-ml-dsa-65" || e["pq_pk"] != pq.Public {
		t.Fatalf("hybrid key entry: %v", e)
	}
	if _, err := ActionSchemaKeyOf("k3", kp, &SuiteOpts{Alg: "ml-dsa-65"}); err == nil {
		t.Fatal("a PQ suite without its key pair must be refused")
	}
}
