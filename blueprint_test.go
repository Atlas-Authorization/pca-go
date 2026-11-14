package pca

import "testing"

// Replays packages/pca/conformance/blueprint-vectors.json: agent blueprints (ceiling and group kill, verification side).
func TestBlueprintVectors(t *testing.T) {
	doc := load(t, "blueprint-vectors.json")
	recs := doc["records"].([]any)
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	if VerifyBlueprint(recs[8]) {
		t.Error("the tampered record verified")
	}
	for i := 0; i < 8; i++ {
		if !VerifyBlueprint(recs[i]) {
			t.Errorf("record %d did not verify", i)
		}
	}
	for _, x := range doc["scenarios"].([]any) {
		s := x.(map[string]any)
		t.Run(s["name"].(string), func(t *testing.T) {
			reg := NewBlueprintRegistry([]string{doc["operator"].(string)}, MemoryBlueprintKv())
			for _, y := range s["steps"].([]any) {
				st := y.(map[string]any)
				exp := st["expect"].(map[string]any)
				if st["op"] == "accept" {
					code, replaced := reg.Accept(recs[num(st["record"])])
					if exp["ok"].(bool) != (code == "") || (code != "" && code != exp["code"]) || (code == "" && replaced != exp["replaced"].(bool)) {
						t.Errorf("accept: code=%q replaced=%v, want %v", code, replaced, exp)
					}
					continue
				}
				o := st["opts"].(map[string]any)
				var min *int64
				if m, has := o["minEpoch"]; has {
					v := num(m)
					min = &v
				}
				var admit BlueprintAdmitted // opts.admitted: 'all' | 'none' | [instance keys] (absent: no hook)
				switch a := o["admitted"].(type) {
				case string:
					admit = func(string, map[string]any) bool { return a == "all" }
				case []any:
					admit = func(k string, _ map[string]any) bool {
						for _, x := range a {
							if x == k {
								return true
							}
						}
						return false
					}
				}
				var got BlueprintDecision
				if admit != nil {
					got = CheckBlueprints(st["chain"], reg, o["now"], o["mode"].(string), min, admit)
				} else {
					got = CheckBlueprints(st["chain"], reg, o["now"], o["mode"].(string), min)
				}
				if got.Decision != exp["decision"] {
					t.Errorf("decision %q, want %v (%v)", got.Decision, exp["decision"], exp)
				}
				if c, has := exp["code"]; has && got.Code != c {
					t.Errorf("code %q, want %v", got.Code, c)
				}
				if b, has := exp["blueprint"]; has && got.Blueprint != b {
					t.Errorf("blueprint %q, want %v", got.Blueprint, b)
				}
				if g, has := exp["governed"]; has {
					want := g.([]any)
					if len(got.Governed) != len(want) {
						t.Errorf("governed %v, want %v", got.Governed, want)
					}
				}
				if exp["decision"] == "escalate" && (got.Have != num(exp["have"]) || got.Need != num(exp["need"])) {
					t.Errorf("have/need %d/%d, want %v", got.Have, got.Need, exp)
				}
			}
		})
	}
}
