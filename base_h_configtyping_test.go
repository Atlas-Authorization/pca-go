package pca

import (
	"strings"
	"testing"
)

// H9 / H11 / H12: wrong-typed collateral and policy members are refused, never read as "absent".

func h9Cfg(mut func(cfg map[string]any)) map[string]any {
	cfg := map[string]any{"rootSpkiSha256": []any{strings.Repeat("a", 64)}, "policy": map[string]any{"measurements": map[string]any{"1": "aa"}}}
	if mut != nil {
		mut(cfg)
	}
	return cfg
}

func TestH9_NvidiaConfigTyping(t *testing.T) {
	pins := []any{strings.Repeat("b", 64)}
	col := func(m map[string]any) func(cfg map[string]any) {
		return func(cfg map[string]any) {
			c := map[string]any{"rimRootSpkiSha256": pins}
			for k, v := range m {
				c[k] = v
			}
			cfg["collateral"] = c
		}
	}
	for name, c := range map[string]struct {
		mut  func(cfg map[string]any)
		want string // "" = builds
	}{
		"collateral string":            {func(cfg map[string]any) { cfg["collateral"] = "required" }, "createNvidiaSpdmVerifier: collateral must be an object"},
		"collateral number":            {func(cfg map[string]any) { cfg["collateral"] = jnum(1) }, "createNvidiaSpdmVerifier: collateral must be an object"},
		"collateral array":             {func(cfg map[string]any) { cfg["collateral"] = []any{} }, "createNvidiaSpdmVerifier: collateral must be an object"},
		"collateral false":             {func(cfg map[string]any) { cfg["collateral"] = false }, "createNvidiaSpdmVerifier: collateral must be an object"},
		"collateral null":              {func(cfg map[string]any) { cfg["collateral"] = nil }, ""},
		"collateral absent":            {nil, ""},
		"leafSubjectIncludes number":   {func(cfg map[string]any) { cfg["policy"].(map[string]any)["leafSubjectIncludes"] = jnum(5) }, "createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string"},
		"leafSubjectIncludes array":    {func(cfg map[string]any) { cfg["policy"].(map[string]any)["leafSubjectIncludes"] = []any{"x"} }, "createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string"},
		"leafSubjectIncludes null":     {func(cfg map[string]any) { cfg["policy"].(map[string]any)["leafSubjectIncludes"] = nil }, ""},
		"leafSubjectIncludes string":   {func(cfg map[string]any) { cfg["policy"].(map[string]any)["leafSubjectIncludes"] = "GH100" }, ""},
		"firmware string":              {col(map[string]any{"firmware": "x"}), "nvidiaCollateralHook: firmware must be an object"},
		"firmware number":              {col(map[string]any{"firmware": jnum(1)}), "nvidiaCollateralHook: firmware must be an object"},
		"firmware array":               {col(map[string]any{"firmware": []any{}}), "nvidiaCollateralHook: firmware must be an object"},
		"firmware empty string":        {col(map[string]any{"firmware": ""}), "nvidiaCollateralHook: firmware must be an object"},
		"firmware false":               {col(map[string]any{"firmware": false}), "nvidiaCollateralHook: firmware must be an object"},
		"firmware null":                {col(map[string]any{"firmware": nil}), ""},
		"min driver number":            {col(map[string]any{"firmware": map[string]any{"minDriverVersion": jnum(535)}}), "nvidiaCollateralHook: malformed minDriverVersion '535'"},
		"min driver unparseable":       {col(map[string]any{"firmware": map[string]any{"minDriverVersion": "x"}}), "nvidiaCollateralHook: malformed minDriverVersion 'x'"},
		"min driver true":              {col(map[string]any{"firmware": map[string]any{"minDriverVersion": true}}), "nvidiaCollateralHook: malformed minDriverVersion 'true'"},
		"min driver empty is no floor": {col(map[string]any{"firmware": map[string]any{"minDriverVersion": ""}}), ""},
		"min driver zero is no floor":  {col(map[string]any{"firmware": map[string]any{"minDriverVersion": jnum(0)}}), ""},
		"min driver ok":                {col(map[string]any{"firmware": map[string]any{"minDriverVersion": "535.54"}}), ""},
		"min vbios object":             {col(map[string]any{"firmware": map[string]any{"minVbiosVersion": map[string]any{}}}), "nvidiaCollateralHook: malformed minVbiosVersion '[object Object]'"},
		"min vbios ok":                 {col(map[string]any{"firmware": map[string]any{"minVbiosVersion": "96.00.5C.00.01"}}), ""},
		"deny driver entry number":     {col(map[string]any{"firmware": map[string]any{"denyDriverVersions": []any{"535.1", jnum(5)}}}), "nvidiaCollateralHook: malformed denyDriverVersions entry '5'"},
		"deny driver entry bad":        {col(map[string]any{"firmware": map[string]any{"denyDriverVersions": []any{"x"}}}), "nvidiaCollateralHook: malformed denyDriverVersions entry 'x'"},
		"deny driver not a list":       {col(map[string]any{"firmware": map[string]any{"denyDriverVersions": "535.1"}}), "nvidiaCollateralHook: malformed denyDriverVersions entry '535.1'"},
		"deny vbios entry number":      {col(map[string]any{"firmware": map[string]any{"denyVbiosVersions": []any{jnum(1)}}}), "nvidiaCollateralHook: malformed denyVbiosVersions entry '1'"},
		"deny lists ok":                {col(map[string]any{"firmware": map[string]any{"denyDriverVersions": []any{"535.1"}, "denyVbiosVersions": []any{"96.00"}}}), ""},
		"deny null":                    {col(map[string]any{"firmware": map[string]any{"denyDriverVersions": nil}}), ""},
		"issuers string":               {col(map[string]any{"requireCrlIssuers": "NVIDIA GH100"}), "nvidiaCollateralHook: requireCrlIssuers must list only strings"},
		"issuers mixed":                {col(map[string]any{"requireCrlIssuers": []any{"NVIDIA", jnum(1)}}), "nvidiaCollateralHook: requireCrlIssuers must list only strings"},
		"issuers ok":                   {col(map[string]any{"requireCrlIssuers": []any{"NVIDIA"}}), ""},
		"issuers null":                 {col(map[string]any{"requireCrlIssuers": nil}), ""},
	} {
		v, err := newNvidiaVerifier(h9Cfg(c.mut))
		switch {
		case c.want == "" && (err != nil || v == nil):
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (err == nil || err.Error() != c.want):
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// collateral null still builds when no measurements are pinned only if a hook exists: with null and no measurements it is refused
	cfg := h9Cfg(func(cfg map[string]any) { cfg["policy"] = map[string]any{}; cfg["collateral"] = nil })
	if _, err := newNvidiaVerifier(cfg); err == nil {
		t.Error("no measurements and no hook must be refused")
	}
}

func TestH11_IntelPolicyCollateralMustBeAnObject(t *testing.T) {
	m96 := strings.Repeat("a", 96)
	mk := func(c any, has bool) (*dcapVerifier, error) {
		pol := map[string]any{"mrtds": []any{m96}}
		if has {
			pol["collateral"] = c
		}
		return newDcapVerifier(map[string]any{"binding": "report-data", "policy": pol})
	}
	for name, c := range map[string]any{"string": "x", "number": jnum(1), "array": []any{}, "true": true, "false": false, "empty string": ""} {
		if _, err := mk(c, true); err == nil || err.Error() != "createIntelDcapVerifier: policy.collateral must be an object" {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		v   any
		has bool
	}{"absent": {nil, false}, "null": {nil, true}, "empty object": {map[string]any{}, true}, "floor": {map[string]any{"minTcbEvaluationDataNumber": jnum(7)}, true}} {
		if v, err := mk(c.v, c.has); err != nil || v == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the floor given under policy.collateral is still read
	v, _ := mk(map[string]any{"minTcbEvaluationDataNumber": jnum(7)}, true)
	if v == nil || !v.collateralPol.hasMinEval || v.collateralPol.minEval != 7 {
		t.Errorf("floor dropped: %+v", v)
	}
}

func TestH12_GarbageEvidenceCollateral(t *testing.T) {
	for name, c := range map[string]struct {
		ev   map[string]any
		want bool
	}{
		"string":       {map[string]any{"collateral": "x"}, true},
		"number":       {map[string]any{"collateral": jnum(5)}, true},
		"empty array":  {map[string]any{"collateral": []any{}}, true},
		"true":         {map[string]any{"collateral": true}, true},
		"object":       {map[string]any{"collateral": map[string]any{}}, false},
		"absent":       {map[string]any{}, false},
		"null":         {map[string]any{"collateral": nil}, false},
		"zero":         {map[string]any{"collateral": jnum(0)}, false},
		"empty string": {map[string]any{"collateral": ""}, false},
		"false":        {map[string]any{"collateral": false}, false},
		"nil evidence": {nil, false},
	} {
		if got := intelCollateralIsGarbage(c.ev); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
