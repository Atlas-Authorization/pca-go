package pca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// An inactive VBIOS measurement is skipped, and the active ones after it are still merged.
func TestR7N5_NvidiaInactiveVbiosMeasurementDoesNotStopTheMerge(t *testing.T) {
	rep := &spdmReport{measurements: []spdmMeasurement{{index: 4, digest: []byte{0xaa}}}}
	vbios := g12Rims(g12Golden(2, false, 1, "aa"), g12Golden(3, true, 1, "aa"))
	if got := compareReportToRims(rep, g12Rims(), vbios); got != "" {
		t.Fatalf("an active measurement after an inactive one: %q", got)
	}
}

// A detail whose digest does not match the chain is skipped, and the next detail still decides.
func TestR7N5_PcaGrantLaterDetailAfterADigestMismatch(t *testing.T) {
	d, err := PcaGrantChainDigest([]string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{"type": "pca_grant", "chain_len": json.Number("2"), "chain_digest": "not-the-digest"}
	good := map[string]any{"type": "pca_grant", "chain_len": json.Number("2"), "chain_digest": d}
	if i, code := CheckPcaGrantPresentation([]map[string]any{bad, good}, "https://rs", []string{"a", "b"}, true); i != 1 || code != "" {
		t.Errorf("second detail: %d %q", i, code)
	}
	if i, code := CheckPcaGrantPresentation([]map[string]any{bad}, "https://rs", []string{"a", "b"}, true); i != -1 || code != "chain_mismatch" {
		t.Errorf("only the mismatching detail: %d %q", i, code)
	}
}

// A signer set that cannot be hashed is refused even when the rest of the share would verify: the hash here is the real one,
// reported as failed.
func TestR7N5_ThresholdRefusesWhenHashingFailsEvenWithAUsableHash(t *testing.T) {
	e, _ := signedShare(t, "agent", []byte("m"))
	old := signerSetHash
	defer func() { signerSetHash = old }()
	signerSetHash = func(s []any) ([]byte, bool) {
		h, _ := SignerSetHash(s)
		return h, false
	}
	if VerifyThresholdShare(e) {
		t.Error("a share was accepted although its signer set did not hash")
	}
	signerSetHash = old
	if !VerifyThresholdShare(e) {
		t.Error("control: the share must verify")
	}
}

// A fault while reading the confirmation means no confirmation, even for a verb that is validly confirmed: the verb is then
// judged as unconfirmed and must carry every trait of the registry.
func TestR7N5_TraitsConfirmFaultMeansUnconfirmed(t *testing.T) {
	reg := Registry{
		"t.one": {ID: "t.one", Floor: mkProfile(Profile{})},
		"t.two": {ID: "t.two", Floor: mkProfile(Profile{})},
	}
	fl, err := reg.floorOf([]string{"t.one"})
	if err != nil {
		t.Fatal(err)
	}
	v := map[string]any{"verb": "a.b", "kind": "write", "params": map[string]any{}, "effects": []any{}, "traits": []any{"t.one"},
		"floors": fl.raw(), "reversibility": "reversible", "def": "w"}
	fd, err := factsDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	td, err := traitsDigest(reg)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]any{"keys": []any{map[string]any{"kid": "rev-1", "pk": b64.EncodeToString(pub), "roles": []any{"reviewer"}}}}
	msg, ok := domainMessage(reviewDomain, map[string]any{"def_digest": "w", "traits_digest": td, "facts_digest": fd,
		"final_traits": []any{"t.one"}, "dismissed": []any{}, "reviewer_kid": "rev-1", "ts": json.Number("100")})
	if !ok {
		t.Fatal("review message")
	}
	v["confirmation"] = map[string]any{"def_digest": "w", "traits_digest": td, "facts_digest": fd, "final_traits": []any{"t.one"},
		"dismissed": []any{}, "reviewer_kid": "rev-1", "ts": json.Number("100"), "sig": b64.EncodeToString(ed25519.Sign(priv, msg))}
	if got := verbConfirmationError(v, reg, pins); got != "" {
		t.Fatalf("premise: the confirmation must be valid: %q", got)
	}
	if got := schemaVerbFloorError(v, reg, pins); got != "" {
		t.Fatalf("control: a confirmed verb may carry fewer traits: %q", got)
	}
	defer func() { traitsFault = nil }()
	traitsFault = func(scope string) {
		if scope == "confirm" {
			panic("boom")
		}
	}
	want := "schema_traits_forged: unconfirmed action must carry every trait (missing t.two)"
	if got := schemaVerbFloorError(v, reg, pins); got != want {
		t.Errorf("a fault in the confirmation check: %q, want %q", got, want)
	}
}
