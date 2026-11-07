package pca

import "testing"

// Replays packages/pca/conformance/break-glass-vectors.json (a missing file fails: load calls t.Fatal).
func TestBreakGlassVectors(t *testing.T) {
	doc := load(t, "break-glass-vectors.json")
	grants, reviews := doc["grants"].([]any), doc["reviews"].([]any)
	scenarios := doc["scenarios"].([]any)
	if len(grants) == 0 || len(reviews) == 0 || len(scenarios) < 15 {
		t.Fatal("too few vectors")
	}
	for _, x := range scenarios {
		s := x.(map[string]any)
		t.Run(s["name"].(string), func(t *testing.T) {
			pol := BreakGlassPolicy{Authorities: []string{doc["authority"].(string)}, Reviewers: []string{doc["reviewer"].(string)}}
			if e, has := s["extra_reviewers"]; has {
				pol.Reviewers = append(pol.Reviewers, strs(e)...)
			}
			reg := NewBreakGlassRegistry(pol)
			for _, y := range s["steps"].([]any) {
				st := y.(map[string]any)
				exp := st["expect"]
				switch st["op"] {
				case "accept", "review":
					var got BgResult
					if st["op"] == "accept" {
						got = reg.Accept(grants[num(st["grant"])], st["now"])
					} else {
						got = reg.Review(reviews[num(st["review"])], st["holder"].(string), st["now"])
					}
					e := exp.(map[string]any)
					if got.Ok != e["ok"].(bool) || (!got.Ok && got.Code != e["code"]) || (got.Ok && got.Replaced != e["replaced"].(bool)) {
						t.Errorf("%v: %+v, want %v", st["op"], got, e)
					}
				case "use":
					got := reg.Use(st["id"].(string), st["holder"].(string), st["action_digest"].(string), st["now"], st["notified"])
					e := exp.(map[string]any)
					id, _ := e["id"].(string)
					code, _ := e["code"].(string)
					if got.Decision != e["decision"] || got.ID != id || got.Code != code {
						t.Errorf("use: %+v, want %v", got, e)
					}
					if got.Decision == "allow" && (got.Use != num(e["use"]) || got.Remaining != num(e["remaining"]) || got.ReviewDue != num(e["review_due"])) {
						t.Errorf("use numbers: %+v, want %v", got, e)
					}
				default:
					if got := reg.Frozen(st["holder"].(string), st["now"]); got != exp.(bool) {
						t.Errorf("frozen: %v, want %v", got, exp)
					}
				}
			}
		})
	}
}
