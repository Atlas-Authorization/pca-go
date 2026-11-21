package wasmhostbin

import (
	"errors"
	"os"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

func TestResolveOrder(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LocalAppData", t.TempDir())
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	found := func(string) (string, error) { return "/usr/bin/pca-wasmtime-host", nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }
	packaged := []byte("packaged host")

	// an explicit option wins over the packaged host and PATH
	o, err := resolve(pca.ComponentOptions{Host: "/x/host"}, env(nil), found, packaged)
	if err != nil || o.Host != "/x/host" {
		t.Fatalf("option: %v %+v", err, o)
	}
	// the environment wins too
	o, err = resolve(pca.ComponentOptions{}, env(map[string]string{"PCA_WASMTIME_HOST": "/e/host"}), found, packaged)
	if err != nil || o.Host != "" {
		t.Fatalf("env: %v %+v", err, o)
	}
	// then the packaged host, pinned by its digest
	o, err = resolve(pca.ComponentOptions{}, env(nil), found, packaged)
	if err != nil || o.Host == "" || len(o.ExpectedSHA256) != 64 {
		t.Fatalf("packaged: %v %+v", err, o)
	}
	if _, serr := os.Stat(o.Host); serr != nil {
		t.Fatal(serr)
	}
	// then PATH, only with a pin
	if _, err = resolve(pca.ComponentOptions{}, env(nil), found, nil); !errors.Is(err, ErrNoHost) {
		t.Fatalf("PATH without pin: %v", err)
	}
	o, err = resolve(pca.ComponentOptions{ExpectedSHA256: "ab"}, env(nil), found, nil)
	if err != nil || o.Host != "/usr/bin/pca-wasmtime-host" {
		t.Fatalf("PATH with pin: %v %+v", err, o)
	}
	if _, err = resolve(pca.ComponentOptions{}, env(nil), missing, nil); !errors.Is(err, ErrNoHost) {
		t.Fatalf("nothing: %v", err)
	}
}
