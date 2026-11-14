package pca

import (
	"strings"
	"testing"
)

// r5-7: attest_xml.go survivors.

// The open-element bound is exactly maxXMLDepth: 256 nested elements read, a 257th is refused.
func TestR5N7_XMLDepthBound(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("<a>", n) + strings.Repeat("</a>", n) }
	if _, err := parseXML(deep(256)); err != nil {
		t.Fatalf("256 deep: %v", err)
	}
	if _, err := parseXML(deep(257)); err == nil || err.Error() != "XML nesting too deep" {
		t.Fatalf("257 deep: %v", err)
	}
}

// Text that runs to the end of an unclosed element is an error, never a read past the input.
func TestR5N7_XMLTextToTheEndOfAnUnclosedElement(t *testing.T) {
	for _, in := range []string{"<a>text", "<a><b/>tail"} {
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%q panicked: %v", in, r)
				}
			}()
			_, err = parseXML(in)
		}()
		if err == nil || err.Error() != "element <a> is not closed" {
			t.Errorf("%q: %v", in, err)
		}
	}
}
