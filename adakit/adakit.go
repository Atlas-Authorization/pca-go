// Package adakit is the OPT-IN full WHATWG domain-to-ASCII for the pca-go core: UTS #46 mapping, validation, punycode and the IPv4
// number forms, by the Ada URL parser (the parser Node.js uses). The core's built-in IDNA is lower-case + NFC + punycode; install
// this package when a host that UTS #46 maps or forbids differently must serialise exactly as a browser or Node would.
//
// It needs cgo and a C++20 compiler (goada compiles the amalgamated Ada sources), which is why it is its own module: the core builds
// without cgo and without goada. Use:
//
//	import _ "github.com/Atlas-Authorization/pca-go/adakit/install"
//
// or call adakit.Install() once at start-up, before any URL is parsed.
package adakit

import (
	"errors"

	"github.com/ada-url/goada"

	pca "github.com/Atlas-Authorization/pca-go"
)

// DomainToASCII returns the ASCII host of domain as the WHATWG URL parser serialises it. The text must carry no URL-structural
// character (the core refuses those before calling). An unparseable host is an error.
func DomainToASCII(domain string) (string, error) {
	u, err := goada.New("https://" + domain + "/")
	if err != nil {
		return "", err
	}
	if !u.Valid() || !u.HasHostname() {
		return "", errors.New("adakit: invalid host")
	}
	return u.Hostname(), nil
}

// Install routes the core's host parsing through Ada.
func Install() { pca.SetWhatwgDomainToASCII(DomainToASCII) }
