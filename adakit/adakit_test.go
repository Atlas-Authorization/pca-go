package adakit

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/ada-url/goada"

	pca "github.com/Atlas-Authorization/pca-go"
)

type idnaCase struct {
	Fn   string
	Name string
	Args []any
	Out  any
}

// The reference corpus is Node's domainToASCII / new URL(...).host, which Node computes with Ada: this checks the binding agrees.
func TestIdnaCorpus(t *testing.T) {
	f, err := os.Open("testdata/ref-idna-kotlin.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	var doc struct{ Cases []idnaCase }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("empty corpus")
	}
	for _, c := range doc.Cases {
		word, _ := c.Args[0].(string)
		switch c.Fn {
		case "domainToAscii": // '' when the domain cannot be encoded
			got := ""
			if u, err := goada.New("ws://x"); err == nil && u.Valid() && u.SetHostname(word) { // Node's domainToASCII is the hostname setter
				got = u.Hostname()
			}
			if want, _ := c.Out.(string); got != want {
				t.Errorf("domainToAscii(%q) = %q want %q", word, got, want)
			}
		case "urlHost": // null when the URL does not parse
			var got any
			if u, err := goada.New("https://" + word); err == nil && u.Valid() {
				got = u.Host()
			}
			if got != c.Out {
				t.Errorf("urlHost(%q) = %v want %v", word, got, c.Out)
			}
		}
	}
}

func TestDomainToASCII(t *testing.T) {
	for in, want := range map[string]string{"EXAMPLE.com": "example.com", "münchen.de": "xn--mnchen-3ya.de", "0x7f.1": "127.0.0.1"} {
		if got, err := DomainToASCII(in); err != nil || got != want {
			t.Errorf("DomainToASCII(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := DomainToASCII("a\u05d0.com"); err == nil {
		t.Error("a label that breaks the bidi rule was accepted")
	}
	for _, bad := range []string{"", "a b.com", "a\u05d0.com", "exa%mple.com", "[::1"} {
		if got, err := DomainToASCII(bad); err == nil || got != "" {
			t.Errorf("DomainToASCII(%q) = %q, %v; want an error and no host", bad, got, err)
		}
	}
}

// Install routes the core through DomainToASCII.
func TestInstallRoutesTheCore(t *testing.T) {
	Install()
	t.Cleanup(func() { pca.SetWhatwgDomainToASCII(nil) })
	const in = "\uff25\uff38\uff21\uff2d\uff30\uff2c\uff25.com"
	if got := pca.CibaASCIIForm(in); got != "example.com" {
		t.Fatalf("Install did not route the core through Ada: %q", got)
	}
}
