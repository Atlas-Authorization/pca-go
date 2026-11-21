package pca

import (
	"errors"
	"strings"
	"testing"
)

// An installed domain-to-ASCII replaces the built-in mapping for domain hosts only, refuses structural characters before it runs,
// and its failure fails the URL.
func TestWhatwgDomainHook(t *testing.T) {
	defer SetWhatwgDomainToASCII(nil)
	calls := 0
	SetWhatwgDomainToASCII(func(d string) (string, error) {
		calls++
		if d == "bad.example" {
			return "", errors.New("no")
		}
		return strings.ToUpper(d), nil // visibly not the built-in
	})
	if h, err := whatwgHost("https://Host.Example/x"); err != nil || h != "HOST.EXAMPLE" {
		t.Fatalf("hook not used: %q %v", h, err)
	}
	if _, err := whatwgHost("https://bad.example/"); err == nil {
		t.Fatal("a failing hook produced a host")
	}
	if _, err := whatwgHost("https://a%2Fb.example/"); err == nil {
		t.Fatal("a decoded structural character reached the hook")
	}
	before := calls
	if h, err := whatwgHost("https://[::1]:8443/"); err != nil || h != "[::1]:8443" || calls != before {
		t.Fatalf("an IP literal went through the hook: %q %v", h, err)
	}
	SetWhatwgDomainToASCII(nil)
	if h, _ := whatwgHost("https://Host.Example/"); h != "host.example" {
		t.Fatalf("the built-in was not restored: %q", h)
	}
}
