package pca

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func g07xNeed(mut func(m map[string]any)) map[string]any {
	m := map[string]any{"v": json.Number("1"), "kind": "scope", "verb": "read", "resource": "r"}
	if mut != nil {
		mut(m)
	}
	return m
}

func g07xList(n int, f func(i int) any) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

func g07xLimits(n int) map[string]any {
	out := map[string]any{}
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("k%d", i)] = json.Number("0")
	}
	return out
}

func TestG07A2ANeedBounds(t *testing.T) {
	rep := strings.Repeat
	disch := func(i int) any { return map[string]any{"issuer": "i", "claim": "c"} }
	cases := []struct {
		name string
		mut  func(m map[string]any)
		want string
	}{
		{"baseline", nil, ""},
		{"verb 128", func(m map[string]any) { m["verb"] = rep("v", 128) }, ""},
		{"verb 129", func(m map[string]any) { m["verb"] = rep("v", 129) }, "bad_field"},
		{"resource 512", func(m map[string]any) { m["resource"] = rep("r", 512) }, ""},
		{"resource 513", func(m map[string]any) { m["resource"] = rep("r", 513) }, "bad_field"},
		{"16 scopes", func(m map[string]any) { m["scopes"] = g07xList(16, func(int) any { return "s" }) }, ""},
		{"17 scopes", func(m map[string]any) { m["scopes"] = g07xList(17, func(int) any { return "s" }) }, "bad_field"},
		{"scope 128", func(m map[string]any) { m["scopes"] = []any{rep("s", 128)} }, ""},
		{"scope 129", func(m map[string]any) { m["scopes"] = []any{rep("s", 129)} }, "bad_field"},
		{"scope leading space", func(m map[string]any) { m["scopes"] = []any{" a"} }, "bad_field"},
		{"grant_ref", func(m map[string]any) { m["grant_ref"] = "g" }, ""},
		{"grant_ref 128", func(m map[string]any) { m["grant_ref"] = rep("g", 128) }, ""},
		{"grant_ref 129", func(m map[string]any) { m["grant_ref"] = rep("g", 129) }, "bad_field"},
		{"policy_digest 128", func(m map[string]any) { m["policy_digest"] = rep("p", 128) }, ""},
		{"policy_digest 129", func(m map[string]any) { m["policy_digest"] = rep("p", 129) }, "bad_field"},
		{"tier 2", func(m map[string]any) { m["kind"] = "escalate"; m["tier"] = json.Number("2") }, ""},
		{"tier 3", func(m map[string]any) { m["kind"] = "escalate"; m["tier"] = json.Number("3") }, ""},
		{"tier 1", func(m map[string]any) { m["kind"] = "escalate"; m["tier"] = json.Number("1") }, "bad_field"},
		{"limits not object", func(m map[string]any) { m["limits"] = []any{} }, "bad_field"},
		{"16 limits", func(m map[string]any) { m["limits"] = g07xLimits(16) }, ""},
		{"17 limits", func(m map[string]any) { m["limits"] = g07xLimits(17) }, "bad_field"},
		{"limit key 64", func(m map[string]any) { m["limits"] = map[string]any{rep("k", 64): json.Number("1")} }, ""},
		{"limit key 65", func(m map[string]any) { m["limits"] = map[string]any{rep("k", 65): json.Number("1")} }, "bad_field"},
		{"limit zero", func(m map[string]any) { m["limits"] = map[string]any{"k": json.Number("0")} }, ""},
		{"discharges not array", func(m map[string]any) { m["discharges"] = "x" }, "bad_field"},
		{"16 discharges", func(m map[string]any) { m["discharges"] = g07xList(16, disch) }, ""},
		{"17 discharges", func(m map[string]any) { m["discharges"] = g07xList(17, disch) }, "bad_field"},
		{"discharge no issuer", func(m map[string]any) { m["discharges"] = []any{map[string]any{"claim": "c"}} }, "bad_field"},
		{"discharge no claim", func(m map[string]any) { m["discharges"] = []any{map[string]any{"issuer": "i"}} }, "bad_field"},
		{"discharge extra member", func(m map[string]any) {
			m["discharges"] = []any{map[string]any{"issuer": "i", "claim": "c", "x": "y"}}
		}, "bad_field"},
		{"issuer 512", func(m map[string]any) { m["discharges"] = []any{map[string]any{"issuer": rep("i", 512), "claim": "c"}} }, ""},
		{"issuer 513", func(m map[string]any) { m["discharges"] = []any{map[string]any{"issuer": rep("i", 513), "claim": "c"}} }, "bad_field"},
		{"claim 256", func(m map[string]any) { m["discharges"] = []any{map[string]any{"issuer": "i", "claim": rep("c", 256)}} }, ""},
		{"claim 257", func(m map[string]any) { m["discharges"] = []any{map[string]any{"issuer": "i", "claim": rep("c", 257)}} }, "bad_field"},
	}
	for _, c := range cases {
		if got := ValidateA2ANeed(g07xNeed(c.mut)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestG07A2ANeedDecodeAndGate(t *testing.T) {
	if _, code := DecodeA2ANeed(strings.Repeat("A", 2048)); code != "bad_json" {
		t.Errorf("2048 chars: %q", code)
	}
	if _, code := DecodeA2ANeed(strings.Repeat("A", 2052)); code != "too_long" {
		t.Errorf("2052 chars: %q", code)
	}
	if hop, why := CheckA2AChainExtension([][]string{{"a"}, {"a", "b"}}); hop != -1 || why != "" {
		t.Errorf("extension: %d %q", hop, why)
	}
	raw, err := canonBytes(g07xNeed(nil))
	if err != nil {
		t.Fatal(err)
	}
	enc := b64.EncodeToString(raw)
	need, code := DecodeA2ANeed(enc)
	if code != "" {
		t.Fatalf("decode: %q", code)
	}
	d, err := A2ANeedDigest(need)
	if err != nil {
		t.Fatal(err)
	}
	verb, res := "read", "r"
	if got := A2AResumeGate("TASK_STATE_AUTH_REQUIRED", enc, d, nil, &res); got != "no_proof" {
		t.Errorf("no verb: %q", got)
	}
	if got := A2AResumeGate("TASK_STATE_AUTH_REQUIRED", enc, d, &verb, nil); got != "no_proof" {
		t.Errorf("no resource: %q", got)
	}
	if got := A2AResumeGate("TASK_STATE_AUTH_REQUIRED", enc, d, &verb, &res); got != "" {
		t.Errorf("full: %q", got)
	}
	if got := A2AResumeGate("TASK_STATE_AUTH_REQUIRED", nil, d, &verb, &res); got != "no_valid_need" {
		t.Errorf("nil need: %q", got)
	}
}

func TestG07A2APush(t *testing.T) {
	salt := "0123456789abcdef"
	tok, ok := A2APushToken("t", []string{"c"}, salt)
	if !ok || tok == "" {
		t.Fatal("16-character salt refused")
	}
	if tok2, ok := A2APushToken("t", []string{"\xed\xa0\x80"}, salt); ok || tok2 != "" {
		t.Errorf("uncanonicalizable chain: %q %v", tok2, ok)
	}
	payload := map[string]any{"task": map[string]any{}, "statusUpdate": map[string]any{"taskId": "t"}}
	if got := CheckA2APush("t", []string{"c"}, salt, tok, payload); got != "" {
		t.Errorf("push: %q", got)
	}
}

func g07xRec(t *testing.T, k fxKey, seq int64, prev any, state string, mut func(m map[string]any)) map[string]any {
	t.Helper()
	cd, err := PcaGrantChainDigest([]string{"c1"})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{"v": json.Number("1"), "task_id": "task", "state": state, "seq": json.Number(strconv.FormatInt(seq, 10)),
		"prev": prev, "chain": cd, "issued_at": json.Number("10"), "signer": k.id}
	if mut != nil {
		mut(m)
	}
	return signArt(t, k, a2aReceiptDomain, m)
}

func TestG07A2AReceiptVerify(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	d32 := b64.EncodeToString(make([]byte, 32))
	w := "TASK_STATE_WORKING"
	rep := strings.Repeat
	cases := []struct {
		name string
		rec  any
		want bool
	}{
		{"baseline", g07xRec(t, k, 0, nil, w, nil), true},
		{"seq 1 with prev", g07xRec(t, k, 1, d32, w, nil), true},
		{"not an object", "x", false},
		{"v 2", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["v"] = json.Number("2") }), false},
		{"signer member differs", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["signer"] = other.id }), false},
		{"task_id 4096", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["task_id"] = rep("t", 4096) }), true},
		{"task_id 4097", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["task_id"] = rep("t", 4097) }), false},
		{"bad state", g07xRec(t, k, 0, nil, "BOGUS", nil), false},
		{"seq a string", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["seq"] = "0" }), false},
		{"issued_at a string", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["issued_at"] = "x" }), false},
		{"empty chain", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["chain"] = "" }), false},
		{"31-byte chain", g07xRec(t, k, 0, nil, w, func(m map[string]any) { m["chain"] = b64.EncodeToString(make([]byte, 31)) }), false},
		{"prev a number", g07xRec(t, k, 1, json.Number("5"), w, nil), false},
		{"prev not 32 bytes", g07xRec(t, k, 1, "abc", w, nil), false},
		{"seq 0 with prev", g07xRec(t, k, 0, d32, w, nil), false},
	}
	for _, c := range cases {
		if got := VerifyA2AReceipt(c.rec, k.id); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestG07A2AReceiptChain(t *testing.T) {
	k := newKey(t)
	if r := CheckA2AReceiptChain(nil, k.id, "task", []string{"c1"}); r.Code != "empty" || r.At != -1 || r.OK {
		t.Errorf("empty: %+v", r)
	}
	r0 := g07xRec(t, k, 0, nil, "TASK_STATE_WORKING", nil)
	if r := CheckA2AReceiptChain([]any{r0}, k.id, "task", []string{"\xed\xa0\x80"}); r.Code != "bad_receipt" || r.At != 0 {
		t.Errorf("bad chain ids: %+v", r)
	}
	d0, ok := A2AReceiptDigest(r0)
	if !ok {
		t.Fatal("digest")
	}
	r1 := g07xRec(t, k, 1, d0, "TASK_STATE_COMPLETED", nil)
	got := CheckA2AReceiptChain([]any{r0, r1}, k.id, "task", []string{"c1"})
	if !got.OK || got.At != -1 || !got.Terminal || got.LastState != "TASK_STATE_COMPLETED" || got.Code != "" {
		t.Errorf("good chain: %+v", got)
	}
	bad := g07xRec(t, k, 1, b64.EncodeToString(make([]byte, 32)), "TASK_STATE_COMPLETED", nil)
	if r := CheckA2AReceiptChain([]any{r0, bad}, k.id, "task", []string{"c1"}); r.Code != "broken_link" || r.At != 1 {
		t.Errorf("wrong prev: %+v", r)
	}
}
