package pca

import "testing"

// r6-2: IsAuthorizedFor is fail-closed. A panic after the params copy succeeded (ok is already true) must still be a refusal.
func TestR6N2_IsAuthorizedForPanicRefuses(t *testing.T) {
	params := map[string]any{"a": jnum(1)}
	d, err := ParamsDigest(params)
	if err != nil {
		t.Fatal(err)
	}
	op := &Operation{Verb: "v", Resource: "r", Params: params}
	res := AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Verb: "v", Resource: "r", ParamsDigest: d}}
	if !IsAuthorizedFor(res, op) {
		t.Fatal("the exact allowed operation must be authorized")
	}
	old := isAuthorizedFault
	isAuthorizedFault = func() { panic("late") }
	got := IsAuthorizedFor(res, op)
	isAuthorizedFault = old
	if got {
		t.Error("a panic inside IsAuthorizedFor authorized the operation")
	}
}

// r6-2: a schema whose sig.alg names a suite with no usable name is refused with the reference's unsupported_suite text, even
// though the suite capability check let the alg through (the suite table entry is injected with an empty alg name).
func TestR6N2_SchemaSigAlgWithoutSuiteName(t *testing.T) {
	const alg = "zz-r6n2-nameless"
	sigSuites[alg] = sigSuite{}
	defer delete(sigSuites, alg)
	d := survivorSchemaDoc(map[string]any{"type": "string", "semantic": "s", "sensitivity": "free"}, nil)
	d["sig"] = map[string]any{"kid": "k", "value": "AAAA", "alg": alg}
	if got := actionSchemaShapeError(normalizeJSON(d), true); got != "sig.alg: unsupported_suite" {
		t.Errorf("got %q", got)
	}
}
