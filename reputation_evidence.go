package pca

// DisputesFromSettlements derives reputation evidence from guardian-signed settlement records: every verified release or slash
// becomes a dispute record {id, subject, slashed, at, amount} (id is the record digest, so one settlement counts once); an open
// record is not an outcome and is skipped. A record that does not verify under guardianPublic (with the PQ pin, for a
// post-quantum suite), or whose claim has no subject, is counted in rejected and never scores. subjectOf maps a claim id to the
// agent it is about. The result is {disputes, rejected}.
func DisputesFromSettlements(records []any, guardianPublic string, subjectOf func(claimID string) (subject string, ok bool), pins ...map[string]string) (map[string]any, error) {
	disputes := []any{}
	rejected := 0
	for _, rec := range records {
		r, _ := rec.(map[string]any)
		subject, has := "", false
		if id, isStr := r["claimId"].(string); isStr {
			subject, has = subjectOf(id)
		}
		if !has || !VerifySettlement(r, guardianPublic, pins...) {
			rejected++
			continue
		}
		action, _ := r["action"].(string)
		if action == "open" {
			continue
		}
		id, err := SettlementRecordDigest(r)
		if err != nil {
			return nil, err
		}
		d := map[string]any{"id": id, "subject": subject, "slashed": action == "slash"}
		bsPut(d, "at", r, "at")
		bsPut(d, "amount", r, "amount")
		disputes = append(disputes, d)
	}
	return map[string]any{"disputes": disputes, "rejected": jsNumber(float64(rejected))}, nil
}
