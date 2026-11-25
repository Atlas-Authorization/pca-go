package pca

import (
	"bytes"
	"errors"
	"testing"
)

func TestAdapterGuardFailsFastOnDryRunDenial(t *testing.T) {
	agent, err := ControlBuildExampleAgent(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	run := func(p map[string]any, c *PcaCall) (string, error) { ran++; return "ok", nil }
	spec := AdapterGuardSpec{Verb: "github.push", Resource: func(map[string]any) string { return "repo:x" }} // github is granted read only
	_, err = AdapterGuard(agent, spec, run)(map[string]any{}, nil)
	var d *PcaDenied
	if !errors.As(err, &d) || d.Verb != "github.push" || ran != 0 {
		t.Fatalf("not denied before dispatch: %v ran=%d", err, ran)
	}
	spec.NoFailFast = true
	if out, err := AdapterGuard(agent, spec, run)(map[string]any{}, nil); err != nil || out != "ok" || ran != 1 {
		t.Fatalf("NoFailFast must dispatch: %v %d", err, ran)
	}
}

func TestRevokeMessageIsDomainSeparated(t *testing.T) {
	m, err := RevokeMessage("g1", "c1")
	if err != nil || !bytes.HasPrefix(m, []byte("atlas-pca/revoke/v1\x00")) || !bytes.Contains(m, []byte(`"grant_ref":"g1"`)) {
		t.Fatalf("bad message %q %v", m, err)
	}
	if AdapterProvenanceFrom(nil) != nil || AdapterProvenanceFrom(42) != nil {
		t.Fatal("non-bundle must be nil")
	}
}
