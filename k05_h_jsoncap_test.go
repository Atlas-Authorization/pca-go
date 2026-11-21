package pca

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// H7: a lenient / attestation JSON segment larger than 16 MiB is refused before any parsing.
func TestH7_LenientJSONSizeCap(t *testing.T) {
	pad := func(n int) []byte { // a JSON string value of n bytes in all
		return append(append([]byte(`"`), bytes.Repeat([]byte("a"), n-2)...), '"')
	}
	if _, err := jsonLenient(pad(maxLenientJSONBytes)); err != nil {
		t.Errorf("exactly 16 MiB is parsed: %v", err)
	}
	over := pad(maxLenientJSONBytes + 1) // built before the clock starts: only the refusal is timed, not the 16 MiB allocation
	start := time.Now()
	if _, err := jsonLenient(over); !errors.Is(err, errJSONTooLarge) {
		t.Errorf("16 MiB + 1: %v", err)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("the refusal took %v: it must come before any parsing", d)
	}
	// reported through a compact JWS as the reference words it
	enc := base64.RawURLEncoding.EncodeToString
	token := enc([]byte(`{"alg":"RS256"}`)) + "." + enc(pad(maxLenientJSONBytes+1)) + "." + enc([]byte("sig"))
	_, err := parseJWT(token, "h7")
	if err == nil || err.Error() != "h7: malformed JSON segment: input too large" {
		t.Errorf("jwt: %v", err)
	}
	if !strings.Contains(jsonSegmentError("x", "y", errJSONTooLarge), "input too large") {
		t.Error("jsonSegmentError")
	}
}
