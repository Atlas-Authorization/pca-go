package pca

import "testing"

func TestOAGrantVerifierWithoutGrantRefuses(t *testing.T) {
	v, err := OAGrantVerifier(OAGrantVerify{}, nil)(map[string]any{})
	if err != nil || v.Allow || v.Reason == nil {
		t.Fatalf("no grant must refuse: %+v %v", v, err)
	}
}
