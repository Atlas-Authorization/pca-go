package pca

import (
	"strings"
	"testing"
)

// The producer dispatcher on malformed vector entries: each argument reader's refusal (the first one wins), a refusal from
// the producer it calls passed through unchanged, a runtime fault refused as a malformed vector, and the ops' exact outputs
// where an argument shape could change them.

const pvkSurrogate = "\xed\xa0\x80" // a lone surrogate, as WTF-8

func pvkRefusal(t *testing.T, name string, op string, args, pq map[string]any, want string) {
	t.Helper()
	_, err := ProduceVector(op, args, sreDoc(t)["keys"].(map[string]any), pq)
	sreErr(t, name, err, want)
}

func TestProduceArgumentReadersRefuseTheWrongType(t *testing.T) {
	doc := sreDoc(t)
	act := func(edit func(a map[string]any)) map[string]any {
		a := sreCaseArgs(t, doc, "act-root-refund")
		edit(a)
		return a
	}
	for _, c := range []struct {
		name string
		edit func(a map[string]any)
		want string
	}{
		{"counter", func(a map[string]any) { a["counter"] = "x" }, "produce: counter must be an integer"},
		{"grant", func(a map[string]any) { a["grant"] = 5 }, "produce: grant must be an object"},
		{"plan", func(a map[string]any) { a["plan"] = 5 }, "produce: plan must be an array"},
		{"plan nodes", func(a map[string]any) { a["plan"] = []any{5} }, "produce: plan must be an array of objects"},
		{"signer", func(a map[string]any) { a["signer"] = "nope" }, `produce: no Ed25519 key "nope"`},
		// the first refusal wins
		{"plan then counter", func(a map[string]any) { a["plan"], a["counter"] = 5, "x" }, "produce: plan must be an array"},
	} {
		pvkRefusal(t, c.name, "act", act(c.edit), nil, c.want)
	}
	// a producer that signs anyway does not hide the argument refusal
	a := sreCaseArgs(t, doc, "read-receipt-first")
	a["labels"] = []any{5}
	pvkRefusal(t, "labels", "sign_read_receipt", a, nil, "produce: labels must be an array of strings")
	e := sreCaseArgs(t, doc, "escalation-digests")
	e["last_counter"] = "x"
	pvkRefusal(t, "last_counter", "escalation_digests", e, nil, "produce: last_counter must be an integer")
}

func TestProduceSuiteArgs(t *testing.T) {
	keys := sreDoc(t)["keys"].(map[string]any)
	// a pq key without an alg is no suite: it is never read
	out, err := ProduceVector("goal_commit", map[string]any{"goal": "g", "salt": "s", "pq": "nope"}, keys, nil)
	want, _ := GoalCommitOf("g", "s")
	if err != nil || sreCanon(t, out) != sreCanon(t, map[string]any{"commit": want}) {
		t.Errorf("goal_commit: %v %v", out, err)
	}
	// a bad holder_pq is refused before the op is looked at
	pvkRefusal(t, "holder_pq", "nope", map[string]any{"holder_pq": "x"}, nil, "produce: unsupported_suite: ")
	pvkRefusal(t, "unknown op", "nope", map[string]any{}, nil, "unsupported_op: nope")
	pq := map[string]any{"fn": map[string]any{"family": "fn-dsa-512", "seed": "AA"}, "short": map[string]any{"family": "ml-dsa-65", "seed": "AA"}}
	pvkRefusal(t, "pq family", "nope", map[string]any{"holder_pq": "fn"}, pq, "produce: unsupported_suite: fn-dsa-512")
	_, gerr := GeneratePqKeyPairFromSeed("ML-DSA-65", []byte{0})
	if gerr == nil {
		t.Fatal("a 1-byte ML-DSA seed was accepted")
	}
	pvkRefusal(t, "pq seed", "nope", map[string]any{"holder_pq": "short"}, pq, "produce: "+gerr.Error())
}

func TestProduceRuntimeFaultIsAMalformedVector(t *testing.T) {
	// no such signer: refused up front, never a crash
	out, err := ProduceVector("sign_contract", map[string]any{"signer": "nope", "contract": map[string]any{}}, sreDoc(t)["keys"].(map[string]any), nil)
	const prefix = "produce: no Ed25519 key \"nope\""
	if out != nil || err == nil || !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("got %v %v", out, err)
	}
}

func TestProduceProducerRefusalsPassThrough(t *testing.T) {
	doc := sreDoc(t)
	args := func(name string, edit func(a map[string]any)) map[string]any {
		a := sreCaseArgs(t, doc, name)
		edit(a)
		return a
	}
	_, seedErr := KeyPairFromSeedB64u("x")
	_, pqSeedErr := GeneratePqKeyPairFromSeed("ML-DSA-65", []byte{0})
	if seedErr == nil || pqSeedErr == nil {
		t.Fatal("a bad seed was accepted")
	}
	const surrogate = "canonicalize: lone surrogate in string"
	head := map[string]any{"mediator": "agent-harness", "kid": "k1", "key": "mediator", "session": "mmTWpUWNQx1UhvNzV3FyhtPdAzuxvKk1DgD1tT1g-DA"}
	rec := func(more map[string]any) map[string]any {
		a := map[string]any{}
		for k, v := range head {
			a[k] = v
		}
		for k, v := range more {
			a[k] = v
		}
		return a
	}
	for _, c := range []struct {
		name, op string
		args     map[string]any
		want     string
	}{
		{"seed", "ed25519_sign", map[string]any{"seed": "x", "message_utf8": "m"}, seedErr.Error()},
		{"empty plan", "plan_commit", map[string]any{"nodes": []any{}}, "CommitPlan: empty plan"},
		{"no goal", "mint_grant", args("mint-grant-basic", func(a map[string]any) { a["goal"] = "" }), "MintGrant: goal required"},
		{"unknown node", "act", args("act-root-refund", func(a map[string]any) { a["node_id"] = "nope" }), "BuildPCActn: unknown plan node nope"},
		{"escalation grant", "escalation_digests", args("escalation-digests", func(a map[string]any) { a["grant"].(map[string]any)["x"] = pvkSurrogate }), surrogate},
		{"escalation pcactn", "escalation_digests", args("escalation-digests", func(a map[string]any) { a["pcactn"].(map[string]any)["x"] = pvkSurrogate }), surrogate},
		{"passport identity", "sign_passport", args("passport-sign", func(a map[string]any) { a["identity"].(map[string]any)["x"] = pvkSurrogate }), surrogate},
		{"hardware-rooted passport", "sign_passport", args("passport-sign", func(a map[string]any) { a["identity"].(map[string]any)["hardware_rooted"] = true }),
			"SignPassport: hardware_rooted requires attestation evidence (fail closed)"},
		{"pq family", "pq_keygen", map[string]any{"family": "x", "seed": "AA"}, "unsupported_suite: x"},
		{"pq seed", "pq_keygen", map[string]any{"family": "ml-dsa-65", "seed": "AA"}, pqSeedErr.Error()},
		{"mesh chain", "sign_mesh_action", map[string]any{"signer": "agent", "chain": []any{}, "action": map[string]any{}}, "SignMeshAction: empty chain"},
		{"no clock", "prov_recorder", rec(map[string]any{"steps": []any{}}), "produce: clock must be an array"},
		{"empty clock", "prov_recorder", rec(map[string]any{"clock": []any{}, "steps": []any{}}), "produce: clock must not be empty"},
		{"no steps", "prov_recorder", rec(map[string]any{"clock": []any{jsonNumberOf(5)}, "steps": []any{}}), "produce: no recorder steps"},
		{"no mediator", "prov_recorder", rec(map[string]any{"mediator": "", "clock": []any{jsonNumberOf(5)}, "steps": []any{}}),
			"NewProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required"},
		{"step", "prov_recorder", rec(map[string]any{"clock": []any{jsonNumberOf(5)}, "steps": []any{map[string]any{"kind": "tool", "name": "t", "output": pvkSurrogate}}}), surrogate},
		{"permissions", "facade_act", args("facade-act-refund", func(a map[string]any) { a["permissions"] = map[string]any{"stripe": 5} }),
			"compilePolicy: permissions.stripe must be an array"},
		{"principal message", "facade_act", args("facade-act-refund", func(a map[string]any) { a["principal_messages"] = []any{pvkSurrogate} }), surrogate},
		{"sub-agent caveats", "facade_act", args("facade-sub-agent-act", func(a map[string]any) {
			a["sub_agent"].(map[string]any)["added_caveats"] = []any{"\xff"}
		}), "canonicalize: invalid UTF-8"},
		{"no aud", "facade_act", args("facade-act-no-params-nonce", func(a map[string]any) { delete(a, "aud") }),
			"Act: aud (resource-server / instance id) is required (pass ActOptions.Aud or AgentOptions.Aud)"},
	} {
		pvkRefusal(t, c.name, c.op, c.args, nil, c.want)
	}
}

// delegate_suite without an alg is the ed25519 delegate: it reproduces the delegate vectors, with and without to_holder
func TestProduceSuiteDelegateReproducesTheDelegateVectors(t *testing.T) {
	doc := sreDoc(t)
	keys := doc["keys"].(map[string]any)
	with, without := 0, 0
	for _, c := range doc["cases"].([]any) {
		cm := c.(map[string]any)
		if cm["op"] != "delegate" {
			continue
		}
		a := sreClone(t, cm["args"]).(map[string]any)
		if a["to_holder"] == nil {
			without++
		} else {
			with++
		}
		out, err := ProduceVector("delegate_suite", a, keys, nil)
		if err != nil || sreCanon(t, out) != sreCanon(t, cm["expect"]) {
			t.Errorf("%s: %v", cm["name"], err)
		}
	}
	if with == 0 || without == 0 {
		t.Fatalf("with %d, without %d", with, without)
	}
}

func TestProduceRecorderClockRepeatsItsLastTick(t *testing.T) {
	keys := sreDoc(t)["keys"].(map[string]any)
	run := func(clock ...int64) any {
		cl := []any{}
		for _, n := range clock {
			cl = append(cl, jsonNumberOf(n))
		}
		out, err := ProduceVector("prov_recorder", map[string]any{"mediator": "agent-harness", "kid": "k1", "key": "mediator",
			"session": "mmTWpUWNQx1UhvNzV3FyhtPdAzuxvKk1DgD1tT1g-DA", "clock": cl,
			"steps": []any{map[string]any{"kind": "principal", "text": "a"}, map[string]any{"kind": "principal", "text": "b"}}}, keys, nil)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if g, w := sreCanon(t, run(7)), sreCanon(t, run(7, 7, 7, 7, 7, 7)); g != w {
		t.Errorf("a one-tick clock\n got  %s\n want %s", g, w)
	}
	// one step: no receipts before the bundle
	out, err := ProduceVector("prov_recorder", map[string]any{"mediator": "agent-harness", "kid": "k1", "key": "mediator",
		"session": "mmTWpUWNQx1UhvNzV3FyhtPdAzuxvKk1DgD1tT1g-DA", "clock": []any{jsonNumberOf(7)},
		"steps": []any{map[string]any{"kind": "principal", "text": "a"}}}, keys, nil)
	if err != nil || len(out.(map[string]any)["receipts"].([]any)) != 0 || out.(map[string]any)["bundle"] == nil {
		t.Errorf("one step: %v %v", out, err)
	}
}
