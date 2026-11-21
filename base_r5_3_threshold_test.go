package pca

import "testing"

func TestR5N3ThresholdMessageThatDoesNotDecodeIsRefused(t *testing.T) {
	// signed over the empty message: an undecodable threshold_message must not read as empty
	e, _ := signedShare(t, "agent", []byte{})
	e["threshold_message"] = "!!"
	if VerifyThresholdShare(e) {
		t.Fatal("an undecodable threshold_message was read as the empty message")
	}
}

func TestR5N3ThresholdFaultIsARefusal(t *testing.T) {
	e, _ := signedShare(t, "agent", []byte("m"))
	old := thresholdFaultHook
	thresholdFaultHook = func() { panic("fault") }
	defer func() { thresholdFaultHook = old }()
	r5n3Recover(t, "VerifyThresholdShare", func() {
		if VerifyThresholdShare(e) {
			t.Error("a faulting verification accepted the share")
		}
	})
	thresholdFaultHook = old
	if !VerifyThresholdShare(e) {
		t.Error("control: the share must verify")
	}
}

func TestR5N3ThresholdT(t *testing.T) {
	for _, v := range []any{"1", nil, true, []any{}} {
		if _, ok := thresholdT(v); ok {
			t.Errorf("thresholdT(%v) accepted", v)
		}
	}
}

func TestR5N3ThresholdRefusesWhenTheSignerSetCannotBeHashed(t *testing.T) {
	e, _ := signedShare(t, "agent", []byte("m"))
	old := signerSetHash
	signerSetHash = func([]any) ([]byte, bool) { return nil, false }
	got := VerifyThresholdShare(e)
	signerSetHash = old
	if got {
		t.Error("a share was accepted without a signer-set hash")
	}
	if !VerifyThresholdShare(e) {
		t.Error("control: the share must verify")
	}
}
