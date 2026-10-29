package pca

import (
	"encoding/json"
	"testing"
)

func k5Int(v any) int64 { i, _ := safeInt(v); return i }

// Replays packages/pca/conformance/vault-aggregate-vectors.json (a missing file fails: load calls t.Fatal).
func TestK5VaultAggregateVectors(t *testing.T) {
	V := load(t, "vault-aggregate-vectors.json")
	keys := V["keys"].(map[string]any)
	grants := V["grants"].(map[string]any)
	samp := V["sampler"].(map[string]any)
	for _, x := range samp["uniform"].([]any) {
		u := x.(map[string]any)
		d := k5SeededDraws(u["seed"].(string))
		for i, b := range u["bounds"].([]any) {
			if got, want := d.uniform(k5Int(b)), k5Int(u["draws"].([]any)[i]); got != want {
				t.Errorf("uniform(%v) = %d, want %d", b, got, want)
			}
		}
	}
	for _, x := range samp["laplace"].([]any) {
		l := x.(map[string]any)
		d := k5SeededDraws(l["seed"].(string))
		for i, w := range l["values"].([]any) {
			if got := k5DiscreteLaplace(d, k5Int(l["s"]), k5Int(l["t"])); got != k5Int(w) {
				t.Errorf("laplace[%d] = %d, want %v", i, got, w)
			}
		}
	}
	for _, x := range V["vault"].([]any) {
		c := x.(map[string]any)
		t.Run("vault/"+c["name"].(string), func(t *testing.T) {
			store := NewMemoryVault()
			r := c["redact"].(map[string]any)
			red := RedactReadWithVault(ReadInput{Grant: grants["vault"].(map[string]any)[c["redact_grant"].(string)], Principal: r["principal"].(string), Now: r["now"], Verb: r["verb"].(string),
				Resource: r["resource"].(string), Purpose: r["purpose"].(string), Schema: r["schema"], Record: r["record"], Tighten: r["tighten"], Salt: r["salt"].(string), Counts: r["counts"]}, store)
			token, _ := c["token"].(string)
			if token == "" {
				token, _ = red.View[c["field"].(string)].(string)
			}
			d := c["detok"].(map[string]any)
			got := Detokenize(DetokenizeInput{Grant: grants["vault"].(map[string]any)[c["detok_grant"].(string)], Principal: d["principal"].(string), Now: d["now"], Sink: d["sink"].(string), Token: token, Store: store})
			k5Equal(t, map[string]any{"decision": got.Decision, "code": k5Null(got.Code), "value": got.Value}, c["expect"])
		})
	}
	for _, x := range V["aggregate"].([]any) {
		c := x.(map[string]any)
		t.Run("aggregate/"+c["name"].(string), func(t *testing.T) {
			is := c["initial_state"].(map[string]any)
			st := AggregateState{SpentMicro: k5Int(is["spent_micro"]), Queries: k5Int(is["queries"]), Answered: map[string]int64{}}
			for k, v := range is["answered"].(map[string]any) {
				st.Answered[k] = k5Int(v)
			}
			for i, y := range c["steps"].([]any) {
				s := y.(map[string]any)
				in := map[string]any{"principal": keys["principal"], "now": json.Number("1800000000000"), "verb": "orders.stats", "resource": "orders/eu", "purpose": "analytics", "fn": "sum",
					"values": []any{json.Number("10"), json.Number("20"), json.Number("500"), json.Number("-900")}, "salt": "a-per-read-secret-salt", "noise": "seeded"}
				for k, v := range s["input"].(map[string]any) {
					in[k] = v
				}
				g, _ := in["grant"].(string)
				if g == "" {
					g = "main"
				}
				r := AggregateRead(AggregateInput{Grant: grants["aggregate"].(map[string]any)[g], Principal: in["principal"].(string), Now: in["now"], Verb: in["verb"].(string), Resource: in["resource"].(string),
					Purpose: in["purpose"].(string), Fn: in["fn"].(string), Values: in["values"], Salt: in["salt"].(string), Noise: in["noise"].(string), State: st})
				ans := map[string]any{}
				for k, v := range r.State.Answered {
					ans[k] = json.Number(itoa64(v))
				}
				var val any
				if r.Decision == "allow" {
					val = json.Number(itoa64(r.Value))
				}
				k5Equal(t, map[string]any{"decision": r.Decision, "code": k5Null(r.Code), "value": val,
					"state": map[string]any{"spent_micro": json.Number(itoa64(r.State.SpentMicro)), "queries": json.Number(itoa64(r.State.Queries)), "answered": ans}, "charged_micro": json.Number(itoa64(r.ChargedMicro))}, s["expect"])
				if t.Failed() {
					t.Fatalf("step %d", i)
				}
				st = r.State
			}
		})
	}
}

func itoa64(i int64) string { b, _ := json.Marshal(i); return string(b) }

// The secure mode draws a fresh CSPRNG seed per call; only that two calls differ is checked (never values).
func TestK5SecureNoiseDiffers(t *testing.T) {
	V := load(t, "vault-aggregate-vectors.json")
	g := V["grants"].(map[string]any)["aggregate"].(map[string]any)["main"]
	vals := make([]any, 40)
	for i := range vals {
		vals[i] = json.Number("1")
	}
	seen := map[int64]bool{}
	for i := 0; i < 12; i++ {
		r := AggregateRead(AggregateInput{Grant: g, Principal: V["keys"].(map[string]any)["principal"].(string), Now: json.Number("1800000000000"), Verb: "orders.stats", Resource: "orders/eu",
			Purpose: "analytics", Fn: "count", Values: vals, Salt: "a-per-read-secret-salt", Noise: "secure"})
		if r.Decision != "allow" {
			t.Fatalf("%+v", r)
		}
		seen[r.Value] = true
	}
	if len(seen) < 2 {
		t.Errorf("secure noise gave one value 12 times: %v", seen)
	}
}

// The sampler panics on a bad bound (the reference RangeError); AggregateRead recovers it into deny bad_request with an empty state.
func TestK5SamplerBadBoundPanics(t *testing.T) {
	d := k5SeededDraws("x")
	func() {
		defer func() {
			if recover() == nil {
				t.Error("uniform(0) must panic")
			}
		}()
		d.uniform(0)
	}()
}
