package pca

import "testing"

// Replays packages/pca/conformance/lease-vectors.json: leases (issue, renew, SoD, revoke, check).
func TestLeaseVectors(t *testing.T) {
	doc := load(t, "lease-vectors.json")
	recs, revs := doc["records"].([]any), doc["revocations"].([]any)
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	for _, x := range doc["scenarios"].([]any) {
		s := x.(map[string]any)
		t.Run(s["name"].(string), func(t *testing.T) {
			pol := LeasePolicy{Authorities: []string{doc["authority"].(string)}}
			if p, has := s["policy"].(map[string]any); has {
				if m, ok := p["minApprovals"]; ok {
					n := num(m)
					pol.MinApprovals = &n
				}
				if e, ok := p["eligibleApprovers"]; ok {
					pol.Eligible = append([]string{}, strs(e)...)
				}
				if f, ok := p["freshJustification"].(bool); ok {
					pol.FreshJustification = &f
				}
			}
			reg := NewLeaseRegistry(pol)
			for _, y := range s["steps"].([]any) {
				st := y.(map[string]any)
				exp := st["expect"].(map[string]any)
				switch st["op"] {
				case "accept":
					var chain []string
					if c, has := st["chain"]; has {
						chain = strs(c)
					}
					got := reg.Accept(recs[num(st["record"])], chain)
					if got.Ok != exp["ok"].(bool) || (!got.Ok && got.Code != exp["code"]) || (got.Ok && (got.Replaced != exp["replaced"].(bool) || got.Seq != num(exp["seq"]))) {
						t.Errorf("accept: %+v, want %v", got, exp)
					}
				case "revoke":
					code, n := reg.Revoke(revs[num(st["revocation"])])
					if (code == "") != exp["ok"].(bool) || (code != "" && code != exp["code"]) || (code == "" && int64(n) != num(exp["revoked"])) {
						t.Errorf("revoke: %q %d, want %v", code, n, exp)
					}
				default:
					got := CheckLease(recs[num(st["record"])], reg, st["now"])
					id, _ := exp["lease_id"].(string)
					if got.Decision != exp["decision"] || got.LeaseID != id {
						t.Errorf("check: %+v, want %v", got, exp)
					}
					if c, has := exp["code"]; has && got.Code != c {
						t.Errorf("check code %q, want %v", got.Code, c)
					}
					if got.Decision == "allow" && got.ExpiresAt != num(exp["expires_at"]) {
						t.Errorf("expires_at %d, want %v", got.ExpiresAt, exp["expires_at"])
					}
				}
			}
		})
	}
}
