package pca

import (
	"strings"
	"testing"
)

// O5: SafeRegex literals the reference classifies (nested quantified alternation, adjacent quantified atoms, bit budget).
func TestO5_SafeRegexLiterals(t *testing.T) {
	for src, want := range map[string]bool{
		`(a|(b))*`:                   false,
		`((a|b))*`:                   false,
		`a*b*a{0,64}`:                false,
		strings.Repeat(`a{0,1}`, 23): false,
		strings.Repeat(`a{0,1}`, 22): true,
		`a*`:                         true,
		`(a|b)`:                      true,
	} {
		if got := isSafeRegexSource(utf16Units(src)); got != want {
			t.Errorf("isSafeRegexSource(%q) = %v, want %v", src, got, want)
		}
	}
}
