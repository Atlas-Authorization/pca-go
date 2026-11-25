package pca

import (
	"strings"
	"testing"
)

// parseEvent reads the text under the strict canonical JSON profile: each of these is refused before any member is looked at.
func TestParseEventRefusesWhatTheStrictProfileRefuses(t *testing.T) {
	for name, text := range map[string]string{
		"duplicate member":        `{"id":"a","id":"b"}`,
		"duplicate nested member": `{"action":{"verb":"v","verb":"w"}}`,
		"exponent":                `{"at":1e3}`,
		"trailing-zero fraction":  `{"at":1.0}`,
		"lone surrogate":          `{"id":"\ud800"}`,
		"leading BOM":             "\ufeff{}",
		"negative zero":           `{"at":-0}`,
	} {
		_, err := ParseEvent(text)
		if err == nil || !strings.HasPrefix(err.Error(), "strict JSON:") {
			t.Errorf("%s: ParseEvent(%q) = %v, want a strict JSON refusal", name, text, err)
		}
	}
	// a text the profile accepts goes on to the member checks
	if _, err := ParseEvent(`{"id":"a"}`); err == nil || strings.HasPrefix(err.Error(), "strict JSON:") {
		t.Errorf("a valid JSON object must reach the member checks, got %v", err)
	}
}
