package pca

// Round 5, list 3: agent.go. Named a0_ so it runs before the other callers of Agent.Act (a mutant that panics there ends the
// whole test binary; here the panic is recovered and reported as an ordinary failure).

import (
	"errors"
	"testing"
	"time"
)

func r5n3Deep(levels int) map[string]any {
	m := map[string]any{}
	cur := m
	for i := 1; i < levels; i++ {
		n := map[string]any{}
		cur["a"] = n
		cur = n
	}
	return m
}

func r5n3Recover(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panicked: %v", name, r)
		}
	}()
	f()
}

func TestR5N3ActCounterHookLockAndFirstNode(t *testing.T) {
	p, _ := NewKeyPair()
	k, _ := NewKeyPair()
	r, err := MintGrant(p, k.Public, prodEnv(), "g", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// no hook: nothing is called (a nil hook must not be dereferenced)
	r5n3Recover(t, "Act without OnCounter", func() {
		if _, err := NewAgent(k, r.Grant, "rs", 0).Act("v", "r", nil, nil); err != nil {
			t.Errorf("Act: %v", err)
		}
	})
	// the hook is called once per action with the new counter
	var seen []int64
	a := NewAgent(k, r.Grant, "rs", 5)
	a.OnCounter = func(n int64) { seen = append(seen, n) }
	// three actions in a row: a lock that is never released blocks the second one forever
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			_, _ = a.Act("v", "r", nil, nil)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Act did not release the agent lock")
	}
	if len(seen) != 3 || seen[0] != 6 || seen[1] != 7 || seen[2] != 8 {
		t.Fatalf("OnCounter calls: %v", seen)
	}
	// the first plan node that matches the verb and resource is the one signed
	d, _ := ParamsDigest(nil)
	pa := NewAgent(k, r.Grant, "rs", 0)
	pa.UsePlan([]map[string]any{
		{"id": "a", "verb": "v", "resource": "r", "params_digest": d},
		{"id": "b", "verb": "v", "resource": "r", "params_digest": d},
	})
	act, err := pa.Act("v", "r", nil, nil)
	if err != nil || act.NodeID != "a" {
		t.Fatalf("plan node: %v %v", act, err)
	}
}

func TestR5N3SignWithSuiteErrorsReturnNoSignature(t *testing.T) {
	k := g10agKey(t, 3)
	boom := errors.New("pq down")
	for name, c := range map[string]struct {
		s  *SuiteOpts
		ed *KeyPair
	}{
		"registered verify-only": {&SuiteOpts{Alg: "fn-dsa-512"}, k},
		"unknown":                {&SuiteOpts{Alg: "rot13"}, k},
		"less is verify-only":    {&SuiteOpts{Alg: "less-cat1"}, k},
		"ed25519 key missing":    {nil, nil},
		"pq pair missing":        {&SuiteOpts{Alg: "ml-dsa-65"}, k},
		"pure pq sign error":     {&SuiteOpts{Alg: "ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "P", boom)}, k},
		"hybrid ed key missing":  {&SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "P", nil)}, nil},
		"hybrid pq sign error":   {&SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "P", boom)}, k},
	} {
		sig, pq, err := signWithSuite(c.s, c.ed, []byte("m"))
		if err == nil || sig != "" || pq != "" {
			t.Errorf("%s: sig %q pq %q err %v", name, sig, pq, err)
		}
	}
	if sig, err := signBody(k, "d", map[string]any{"x": g10agLone}); err == nil || sig != "" {
		t.Errorf("signBody: %q %v", sig, err)
	}
}

func TestR5N3NormObjAndListRefuseWrongShape(t *testing.T) {
	for _, v := range []any{[]any{}, "s", 5, true} {
		if m, err := normObj(v); err == nil || m != nil || err.Error() != "expected a JSON object" {
			t.Errorf("normObj(%v): %v %v", v, m, err)
		}
	}
	for _, v := range []any{map[string]any{}, "s", 5, true} {
		if l, err := normList(v); err == nil || l != nil || err.Error() != "expected a JSON array" {
			t.Errorf("normList(%v): %v %v", v, l, err)
		}
	}
}

func TestR5N3SealRefusesAnUndecodableDigest(t *testing.T) {
	k := g10agKey(t, 4)
	old := sealDigest
	sealDigest = func(any) (string, error) { return "!!", nil }
	c, err := seal("i", "h", []any{}, "", "", k, nil)
	sealDigest = old
	if err == nil || c != nil || err.Error() != "internal: digest" {
		t.Fatalf("seal: %v %v", c, err)
	}
}

func TestR5N3CommitPlanProofForUnknownNode(t *testing.T) {
	pc, err := CommitPlan([]map[string]any{{"id": "a", "verb": "v", "resource": "r"}})
	if err != nil {
		t.Fatal(err)
	}
	pr, err := pc.proofFor("zz")
	if err == nil || pr != nil || err.Error() != "CommitPlan: unknown node zz" {
		t.Fatalf("proofFor: %v %v", pr, err)
	}
	if pr, err := pc.proofFor("a"); err != nil || pr == nil {
		t.Fatalf("proofFor a: %v %v", pr, err)
	}
}

func TestR5N3SignPassportNeedsASafeIssuedAt(t *testing.T) {
	issuer := g10agKey(t, 5)
	for name, id := range map[string]map[string]any{
		"missing": {"model_id": "m", "operator": "o", "hardware_rooted": false},
		"string":  {"model_id": "m", "operator": "o", "hardware_rooted": false, "issued_at": "x"},
	} {
		pp, err := IssuePassport(id)
		if err != nil {
			t.Fatal(err)
		}
		out, err := SignPassport(pp, issuer, "sub", 0, 0, 100, nil, nil)
		if err == nil || out != nil || err.Error() != "SignPassport: passport.issued_at must be a safe integer" {
			t.Errorf("%s: %v %v", name, out, err)
		}
	}
}

func TestR5N3SignStepReceiptRefusesWhatCannotBeReferenced(t *testing.T) {
	k := g10agKey(t, 6)
	// a workflow at the depth limit normalizes but cannot be wrapped for its reference digest
	out, err := SignStepReceipt(k, r5n3Deep(MaxJSONDepth), "s", "ok", "pd", map[string]any{}, 1, nil)
	if err == nil || out != nil || err.Error() != "SignStepReceipt: malformed workflow" {
		t.Errorf("workflow: %v %v", out, err)
	}
	out, err = SignStepReceipt(k, map[string]any{"a": 1}, "s", "ok", "pd", map[string]any{}, 1, r5n3Deep(MaxJSONDepth))
	if err == nil || out != nil || err.Error() != "SignStepReceipt: malformed previous receipt" {
		t.Errorf("prev: %v %v", out, err)
	}
}

// bytes marshal as base64: their content is never checked as UTF-8
func TestR5N3NormalizeJSONAcceptsRawBytes(t *testing.T) {
	for _, v := range []any{[]byte{0xff, 0xfe}, map[string]any{"b": []byte{0xff}}, [2]byte{0xff, 0xfe}} {
		if _, err := NormalizeJSON(v); err != nil {
			t.Errorf("NormalizeJSON(%v): %v", v, err)
		}
	}
}
