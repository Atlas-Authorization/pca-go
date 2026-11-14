package pcasigstore

import (
	"errors"
	"testing"
)

// b64's decode-error check, restored after the k05 kill program deleted it: the pattern and length checks leave no real input
// to trip it, so the decoder seam is swapped. The refusal is the reference's text (sigstore.ts: `throw new Error('not base64')`).
func TestGr2B64DecodeGuard(t *testing.T) {
	defer func(old func(string) ([]byte, error)) { b64Decode = old }(b64Decode)
	if err := catch(func() { b64("AAAA") }); err != nil {
		t.Fatalf("genuine base64: %v", err)
	}
	b64Decode = func(string) ([]byte, error) { return nil, errors.New("gr2") }
	if err := catch(func() { b64("AAAA") }); err == nil || err.Error() != "not base64" {
		t.Fatalf("undecodable: %v", err)
	}
}
