package pca

import (
	"encoding/json"
	"math"
	"testing"
)

// The extension layer of the conformance corpus (optimistic-vectors.json, ledger-vectors.json): every vector must
// reproduce the reference verdict exactly. Nothing is skipped; each table's size must equal the file's `counts`.

func rows(t *testing.T, doc map[string]any, table string) []map[string]any {
	t.Helper()
	arr, ok := doc[table].([]any)
	if !ok {
		t.Fatalf("%s: missing table", table)
	}
	if want := num(doc["counts"].(map[string]any)[table]); int64(len(arr)) != want {
		t.Fatalf("%s: %d vectors, counts says %d", table, len(arr), want)
	}
	out := make([]map[string]any, len(arr))
	for i, v := range arr {
		out[i] = v.(map[string]any)
	}
	return out
}

func f64(v any) float64 { f, _ := jsNum(v); return f }

func policyOf(v any) map[string]any { m, _ := v.(map[string]any); return m }

func TestExtOptimisticVectors(t *testing.T) {
	doc := load(t, "optimistic-vectors.json")
	wp := doc["window_policy"].(map[string]any)
	pol := ChallengeWindowPolicy{MinWindowMs: f64(wp["minWindowMs"]), MaxWindowMs: f64(wp["maxWindowMs"]), MaxSkewMs: f64(wp["maxSkewMs"])}
	for _, v := range rows(t, doc, "optimistic_claim") {
		got := ClaimCheck(v["claim"], v["pcactn_digest"].(string), v["signer_public"].(string), f64(v["server_now"]), pol)
		exp := v["expect"].(map[string]any)
		if got != exp["check"] || (got == "ok") != exp["ok"].(bool) {
			t.Errorf("claim/%s: got %s want %v", v["name"], got, exp["check"])
		}
	}
	for _, v := range rows(t, doc, "optimistic_window") {
		i, w, now := f64(v["issued_at"]), f64(v["challenge_window_ms"]), f64(v["now"])
		exp := v["expect"].(map[string]any)
		if ChallengeWindowEnd(i, w) != f64(exp["end"]) || WithinChallengeWindow(i, w, now) != exp["within"].(bool) || ClaimStatus(i, w, now) != exp["phase"] {
			t.Errorf("window/%s", v["name"])
		}
	}
	for _, v := range rows(t, doc, "optimistic_fraud_proof") {
		got := FraudProofWireCheck(v["claim"], v["proof"])
		if exp := v["expect"].(map[string]any); got != exp["check"] {
			t.Errorf("fraud/%s: got %s want %v", v["name"], got, exp["check"])
		}
	}
	for _, v := range rows(t, doc, "optimistic_settlement") {
		got := SettlementWireCheck(v["record"], v["guardian_public"].(string))
		if exp := v["expect"].(map[string]any); got != exp["check"] {
			t.Errorf("settlement/%s: got %s want %v", v["name"], got, exp["check"])
		}
	}
}

func TestExtLedgerVectors(t *testing.T) {
	doc := load(t, "ledger-vectors.json")
	if doc["empty_tree_root"] != EmptyTreeRoot {
		t.Fatal("empty tree root")
	}
	doms := doc["domains"].(map[string]any)
	if doms["sth"] != sthDomain || doms["sth_witness"] != sthWitnessDomain || doms["ledger_head"] != ledgerHeadDomain ||
		doms["optimistic_claim"] != claimDomain || doms["settlement"] != settlementDomain {
		t.Fatal("domain separators differ from the corpus")
	}
	okOf := func(v map[string]any) bool { return v["expect"].(map[string]any)["ok"].(bool) }
	chk := func(table, name string, got, want bool) {
		if got != want {
			t.Errorf("%s/%s: got %v want %v", table, name, got, want)
		}
	}
	for _, v := range rows(t, doc, "ledger_inclusion") {
		chk("inclusion", v["name"].(string), VerifyLedgerInclusion(v["root"].(string), v["proof"], v["leaf"]), okOf(v))
	}
	for _, v := range rows(t, doc, "ledger_consistency") {
		chk("consistency", v["name"].(string), VerifyLedgerConsistency(v["old_root"], v["new_root"], v["proof"]), okOf(v))
	}
	for _, v := range rows(t, doc, "ledger_tree_head") {
		chk("tree_head", v["name"].(string), VerifyTreeHead(v["sth"], v["guardian_public"].(string), nil), okOf(v))
	}
	for _, v := range rows(t, doc, "ledger_cosign") {
		chk("cosign", v["name"].(string), VerifyTreeHead(v["sth"], v["guardian_public"].(string), policyOf(v["policy"])), okOf(v))
	}
	for _, v := range rows(t, doc, "ledger_head_consistency") {
		chk("head_consistency", v["name"].(string), VerifyHeadConsistency(v["older"], v["newer"], v["proof"], v["guardian_public"].(string), nil), okOf(v))
	}
	for _, v := range rows(t, doc, "ledger_checkpoint_chain") {
		got := VerifyCheckpointChain(v["chain"], v["guardian_public"].(string), policyOf(v["policy"]))
		exp := v["expect"].(map[string]any)
		if got.OK != exp["ok"].(bool) || (!got.OK && int64(got.At) != num(exp["at"])) {
			t.Errorf("chain/%s: got %+v want %v", v["name"], got, exp)
		}
	}
	for _, v := range rows(t, doc, "ledger_witnessed_head") {
		chk("witnessed_head", v["name"].(string), VerifyWitnessedHead(v["head"], v["witness_public"].(string)), okOf(v))
	}
	for _, v := range rows(t, doc, "ledger_equivocation") {
		chk("equivocation", v["name"].(string), DetectEquivocation(v["a"], v["b"], v["witness_public"].(string)), v["expect"].(map[string]any)["equivocation"].(bool))
	}
}

// Units beyond the corpus: hostile shapes never panic, and the 32-bit-wrap and unsafe-size guards hold.
func TestExtHostileInputsNeverPanic(t *testing.T) {
	var bad []any
	for _, s := range []string{`null`, `1`, `"x"`, `[]`, `{}`, `{"size":1e999}`, `[null]`, `{"sth":null,"proof":null}`} {
		v, err := ParseJSONLenient([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		bad = append(bad, v)
	}
	for _, v := range bad {
		if VerifyLedgerConsistency(v, v, v) || VerifyTreeHead(v, "k", nil) || VerifyTreeHead(v, "k", map[string]any{"threshold": json.Number("0")}) ||
			VerifyWitnessedHead(v, "k") || VerifyWitnessCosignature(v, v, "k") || VerifyHeadConsistency(v, v, v, "k", nil) ||
			DetectEquivocation(v, v, "k") || VerifyCheckpointChain(v, "k", nil).OK || VerifyLedgerInclusion("r", v, v) {
			t.Errorf("accepted %v", v)
		}
		for _, f := range []func(any, any) string{FraudProofWireCheck} {
			if f(v, v) == "ok" {
				t.Errorf("fraud ok %v", v)
			}
		}
		if SettlementWireCheck(v, "k") == "ok" || ClaimCheck(v, "d", "k", 0, DefaultChallengeWindowPolicy) == "ok" {
			t.Errorf("accepted %v", v)
		}
	}
}

func TestExtWindowBoundaryAndNonFinite(t *testing.T) {
	if !WithinChallengeWindow(100, 50, 150) || WithinChallengeWindow(100, 50, 151) {
		t.Fatal("window end is inclusive")
	}
	if ClaimStatus(100, 50, 151) != "finalized" || ClaimStatus(100, 50, 150) != "open" {
		t.Fatal("phase")
	}
	if WithinChallengeWindow(100, 50, math.Inf(1)) || WithinChallengeWindow(100, 50, math.NaN()) {
		t.Fatal("non-finite now must not be within the window")
	}
}
