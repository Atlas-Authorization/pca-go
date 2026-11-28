//go:build !(less && cgo)

package pca

import (
	"errors"
	"testing"
)

// The no-LESS build (what a consumer gets without -tags less): both entry points refuse with ErrLessUnavailable and return no key material.
// The oracle of the lessstub mutation run (less_sign_stub.go is only compiled without the less tag).
func TestLessSignStubRefuses(t *testing.T) {
	pk, sk, err := LessCat1Keygen([]byte("seed"))
	if !errors.Is(err, ErrLessUnavailable) || pk != nil || sk != nil {
		t.Fatalf("keygen: %v %v %v", pk, sk, err)
	}
	sig, err := LessCat1Sign([]byte("sk"), []byte("msg"), []byte("seed"))
	if !errors.Is(err, ErrLessUnavailable) || sig != nil {
		t.Fatalf("sign: %v %v", sig, err)
	}
}
