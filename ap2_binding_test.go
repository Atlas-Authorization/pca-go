package pca

import (
	"errors"
	"testing"
)

func TestAp2VerifyPcaBindingRefusals(t *testing.T) {
	decide := func(map[string]any) (map[string]any, error) { return nil, errors.New("unused") }
	var be *Ap2PcaBindingError
	if _, err := Ap2VerifyPcaBinding(Ap2VerifyPcaBindingInput{Decide: decide}); !errors.As(err, &be) || be.Code != "mandate_required" {
		t.Fatalf("missing mandate must be refused, got %v", err)
	}
	limited := map[string]any{"terms": map[string]any{"maxTransactionsPerPeriod": jsNumber(3)}}
	if _, err := Ap2VerifyPcaBinding(Ap2VerifyPcaBindingInput{Decide: decide, Mandate: limited}); !errors.As(err, &be) || be.Code != "charge_history_required" {
		t.Fatalf("missing history must be refused, got %v", err)
	}
	r, err := Ap2VerifyPcaBinding(Ap2VerifyPcaBindingInput{Decide: decide, Mandate: map[string]any{}, Open: map[string]any{}, Closed: map[string]any{}})
	if err != nil || r.OK || r.Reason != "open mandate carries no x_pca grant" {
		t.Fatalf("got %+v %v", r, err)
	}
}
