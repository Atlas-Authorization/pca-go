package pca

import (
	"fmt"
	"testing"
)

// r7-4: attest_nvidia_ocsp.go. An element is walked as a container (its children parsed, a bad child fails the parse) or read as a
// leaf; these separate the two for the tag classes and numbers the container rule and the constructed-universal refusal list name.

func TestR7N4_BERWalkedVersusLeaf(t *testing.T) {
	fail := r5n0Want{}
	// walked: a child 0xff is not an element, so the parse fails
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"primitive SET", []byte{0x11, 0x01, 0xff}},
		{"context-specific constructed, number 10", []byte{0xaa, 0x01, 0xff}},
		{"context-specific constructed, number 12", []byte{0xac, 0x01, 0xff}},
		{"context-specific constructed, number 18", []byte{0xb2, 0x01, 0xff}},
		{"constructed universal 7", []byte{0x27, 0x01, 0xff}},
		{"constructed universal 8", []byte{0x28, 0x01, 0xff}},
		{"constructed universal 11", []byte{0x2b, 0x01, 0xff}},
	} {
		r5n0Check(t, c.name, c.b, fail)
	}
	// read as a leaf: constructed ENUMERATED, UTF8String and character strings are never walked
	for _, c := range []struct {
		num  int
		tag  byte
		name string
	}{{10, 0x2a, "ENUMERATED"}, {12, 0x2c, "UTF8String"}, {18, 0x32, "NumericString"}, {22, 0x36, "IA5String"}} {
		r5n0Check(t, "constructed "+c.name+" is a leaf", []byte{c.tag, 0x01, 0xff}, r5n0OK(3, c.num))
	}
}

// A constructed universal element whose number is on the refusal list fails; its neighbours do not.
func TestR7N4_BERConstructedUniversalRefusalList(t *testing.T) {
	for _, n := range []int{1, 2, 5, 6, 9, 13, 14, 23, 24} {
		r5n0Check(t, fmt.Sprintf("constructed universal %d", n), []byte{0x20 | byte(n), 0x00}, r5n0Want{})
	}
	for _, n := range []int{31, 32, 33, 34} {
		r5n0Check(t, fmt.Sprintf("constructed universal %d (high tag)", n), []byte{0x3f, byte(n), 0x00}, r5n0Want{})
	}
	for _, n := range []int{7, 8, 10, 11, 12, 18, 19, 22} {
		r5n0Check(t, fmt.Sprintf("constructed universal %d", n), []byte{0x20 | byte(n), 0x00}, r5n0OK(2, n))
	}
	for _, n := range []int{35, 36} {
		r5n0Check(t, fmt.Sprintf("constructed universal %d (high tag)", n), []byte{0x3f, byte(n), 0x00}, r5n0OK(3, n))
	}
}

// parseInt skips leading white space and a sign before the first digit, so a sign or a space in the first offset position is fine
// when a digit follows it.
func TestR7N4_GenTimeOffsetSignThenDigit(t *testing.T) {
	for s, want := range map[string]bool{
		"20260531000000+ 5": false, "20260531000000+-5": false, "20260531000000+x5": true, "20260531000000+ x": true,
	} {
		if got := ocspGenTimeThrows(s); got != want {
			t.Errorf("ocspGenTimeThrows(%q) = %v, want %v", s, got, want)
		}
	}
}
