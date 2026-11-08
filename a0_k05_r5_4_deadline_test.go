package pca

import (
	"testing"
	"time"
)

// r5n4: deadline kills. A mutant that stops a loop from advancing (or leaves a mutex held) makes these calls spin or block
// forever. They run before every other caller of the same code (the a0_ prefix sorts first under -failfast), so the mutant is
// decided by a short deadline failure instead of a go-test timeout.

func r5n4Within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish within 5s", what)
	}
}

func TestR5N4StrictJSONTerminates(t *testing.T) {
	for _, in := range []string{" 1", "\t[1]", "1", `"a"`, "\"\x01\"", `"\n"`, `{"a":"b"}`, `["a", 2]`} {
		in := in
		r5n4Within(t, "StrictParse("+in+")", func() { _, _ = StrictParse(in) })
	}
}

func TestR5N4CompareVersionTerminates(t *testing.T) {
	var a, b, c int
	r5n4Within(t, "compareVersion", func() {
		a = compareVersion("1.2", "1.2")
		b = compareVersion("1", "1.0")
		c = compareVersion("1.2", "1.10")
	})
	if a != 0 || b != 0 || c != -1 {
		t.Fatalf("compareVersion: %d %d %d", a, b, c)
	}
}

func TestR5N4PackProofTerminates(t *testing.T) {
	digests := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	var proof map[string]any
	var err error
	r5n4Within(t, "packProof", func() { proof, err = packProof(digests, "a") })
	if err != nil {
		t.Fatal(err)
	}
	if path, _ := proof["path"].([]any); len(path) != 3 {
		t.Fatalf("path %v", proof["path"])
	}
}

func TestR5N4NvidiaOpaqueTLVAdvances(t *testing.T) {
	var rep *spdmReport
	var err error
	r5n4Within(t, "parseNvidiaSpdmEvidence", func() { rep, err = parseNvidiaSpdmEvidence(g10nvRaw(nil, 0, nil, []byte{3, 0, 0, 0})) })
	if err != nil || len(rep.opaque) != 1 {
		t.Fatalf("empty TLV: %v %v", rep, err)
	}
}

func TestR5N4BlueprintRegistryReleasesItsLock(t *testing.T) {
	op := newKey(t)
	reg := NewBlueprintRegistry([]string{op.id})
	b := parityBlueprint(t, op, "K", "active", func(b map[string]any) { delete(b, "runtime_pins") })
	var c1, c2 string
	r5n4Within(t, "Accept twice", func() {
		c1, _ = reg.Accept(b)
		c2, _ = reg.Accept(b)
	})
	if c1 != "" || c2 != "" {
		t.Fatalf("accept: %q %q", c1, c2)
	}
	chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
	var d1, d2 BlueprintDecision
	r5n4Within(t, "CheckBlueprints twice", func() {
		d1 = CheckBlueprints(chain, reg, jnum(2), "any", nil)
		d2 = CheckBlueprints(chain, reg, jnum(2), "any", nil)
	})
	if d1.Decision != "allow" || d2.Decision != "allow" {
		t.Fatalf("check: %+v %+v", d1, d2)
	}
	var e1, e2 int64
	r5n4Within(t, "Epoch twice", func() {
		e1 = reg.Epoch()
		e2 = reg.Epoch()
	})
	if e1 != 1 || e2 != 1 {
		t.Fatalf("epoch %d %d", e1, e2)
	}
}
