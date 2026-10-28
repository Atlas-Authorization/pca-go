package pca

import "testing"

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// Replays packages/pca/conformance/a2a-vectors.json: the A2A binding (typed needs, chain extension, resume gate, push tokens, receipts).
func TestA2AVectors(t *testing.T) {
	doc := load(t, "a2a-vectors.json")
	for _, x := range doc["need"].([]any) {
		c := x.(map[string]any)
		t.Run("need/"+c["name"].(string), func(t *testing.T) {
			need, code := DecodeA2ANeed(c["input"])
			exp := c["expect"].(map[string]any)
			if (code == "") != exp["ok"].(bool) {
				t.Fatalf("code %q, want %v", code, exp)
			}
			if code != "" {
				if code != exp["code"] {
					t.Errorf("code %q, want %v", code, exp["code"])
				}
				return
			}
			if d, _ := A2ANeedDigest(need); d != exp["digest"] {
				t.Errorf("digest %q, want %v", d, exp["digest"])
			}
		})
	}
	push := doc["push"].(map[string]any)
	for _, x := range push["tokens"].([]any) {
		c := x.(map[string]any)
		if tok, ok := A2APushToken(c["task_id"].(string), strs(c["chain_ids"]), c["salt"].(string)); !ok || tok != c["token"] {
			t.Errorf("token %q, want %v", tok, c["token"])
		}
	}
	for _, s := range strs(push["weak_salts"]) {
		if _, ok := A2APushToken("t", []string{"a"}, s); ok {
			t.Errorf("weak salt %q accepted", s)
		}
	}
	for _, x := range push["checks"].([]any) {
		c := x.(map[string]any)
		t.Run("push/"+c["name"].(string), func(t *testing.T) {
			e := c["expected"].(map[string]any)
			d := c["delivered"].(map[string]any)
			got := CheckA2APush(e["task_id"].(string), strs(e["chain_ids"]), e["salt"].(string), d["token"], d["payload"])
			exp := c["expect"].(map[string]any)
			if (got == "") != exp["ok"].(bool) || (got != "" && got != exp["reason"]) {
				t.Errorf("got %q, want %v", got, exp)
			}
		})
	}
	for _, x := range doc["chains"].([]any) {
		c := x.(map[string]any)
		t.Run("chains/"+c["name"].(string), func(t *testing.T) {
			var chains [][]string
			for _, l := range c["chains"].([]any) {
				chains = append(chains, strs(l))
			}
			hop, reason := CheckA2AChainExtension(chains)
			exp := c["expect"].(map[string]any)
			if (reason == "") != exp["ok"].(bool) || (reason != "" && (reason != exp["reason"] || int64(hop) != num(exp["failedHop"]))) {
				t.Errorf("got hop=%d %q, want %v", hop, reason, exp)
			}
		})
	}
	for _, x := range doc["resume"].([]any) {
		c := x.(map[string]any)
		t.Run("resume/"+c["name"].(string), func(t *testing.T) {
			var verb, res *string
			if pa, ok := c["proof_action"].(map[string]any); ok {
				v, r := pa["verb"].(string), pa["resource"].(string)
				verb, res = &v, &r
			}
			got := A2AResumeGate(c["state"].(string), c["need_encoded"], c["answer_need_digest"], verb, res)
			want, _ := c["expect"].(string)
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
	R := doc["receipts"].(map[string]any)
	signer := R["signer"].(string)
	recs := R["records"].([]any)
	for _, v := range R["verify"].([]any) {
		m := v.(map[string]any)
		if VerifyA2AReceipt(recs[num(m["record"])], signer) != m["ok"].(bool) {
			t.Errorf("verify record %v", m["record"])
		}
	}
	for _, d := range R["digests"].([]any) {
		m := d.(map[string]any)
		if got, _ := A2AReceiptDigest(recs[num(m["record"])]); got != m["digest"] {
			t.Errorf("digest of record %v = %q", m["record"], got)
		}
	}
	for _, x := range R["scenarios"].([]any) {
		s := x.(map[string]any)
		t.Run("receipts/"+s["name"].(string), func(t *testing.T) {
			var list []any
			for _, i := range s["indices"].([]any) {
				list = append(list, recs[num(i)])
			}
			got := CheckA2AReceiptChain(list, signer, s["task_id"].(string), strs(s["chain_ids"]))
			exp := s["expect"].(map[string]any)
			if got.OK != exp["ok"].(bool) {
				t.Fatalf("got %+v, want %v", got, exp)
			}
			if got.OK && (got.Terminal != exp["terminal"].(bool) || got.LastState != exp["last_state"]) {
				t.Errorf("got %+v, want %v", got, exp)
			}
			if !got.OK && (got.Code != exp["code"] || (exp["at"] != nil && int64(got.At) != num(exp["at"]))) {
				t.Errorf("got %+v, want %v", got, exp)
			}
			if A2AMayTriggerNext(list, signer, s["task_id"].(string), strs(s["chain_ids"])) != s["may_trigger_next"].(bool) {
				t.Errorf("may_trigger_next")
			}
		})
	}
}
