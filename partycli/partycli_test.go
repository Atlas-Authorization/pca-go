package partycli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

func TestBehaviorAcceptsStringAndObject(t *testing.T) {
	var s, o behavior
	if err := json.Unmarshal([]byte(`"lie"`), &s); err != nil || s.Kind != "lie" || s.Round != "" {
		t.Fatalf("bare string: %+v %v", s, err)
	}
	if err := json.Unmarshal([]byte(`{"kind":"lie","round":"open"}`), &o); err != nil || o.Kind != "lie" || o.Round != "open" {
		t.Fatalf("object: %+v %v", o, err)
	}
	if err := json.Unmarshal([]byte(`7`), &o); err == nil {
		t.Fatal("a number is neither a kind nor an object")
	}
}

func TestKeygenWritesTheIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	if rc := Main([]string{"p", "keygen", dir, "n1"}); rc != 0 {
		t.Fatalf("status %d", rc)
	}
	if err := pca.OwnerOnly(filepath.Join(dir, "key.pem")); err != nil { // mode 0600 on POSIX, an owner-only protected access list on Windows
		t.Fatalf("key.pem is not private to its owner: %v", err)
	}
	crt, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil || !strings.Contains(string(crt), "BEGIN CERTIFICATE") {
		t.Fatalf("cert.pem: %v", err)
	}
	if rc := Main([]string{"p", "keygen", dir}); rc != 0 { // the common name defaults
		t.Fatalf("default cn: status %d", rc)
	}
}

func TestKeygenFailsWhenTheDirectoryCannotBeMade(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := Main([]string{"p", "keygen", filepath.Join(blocker, "sub")}); rc != 1 {
		t.Fatalf("status %d, want 1", rc)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, a := range [][]string{{"p"}, {"p", "keygen"}, {"p", "a", "b"}} {
		if rc := Main(a); rc != 2 {
			t.Fatalf("%v: status %d, want 2", a, rc)
		}
	}
}

func TestUnreadableOrMalformedConfigIsALocalAbort(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bad, filepath.Join(t.TempDir(), "missing.json")} {
		if rc := Main([]string{"p", p}); rc != 3 {
			t.Fatalf("%s: status %d, want 3", p, rc)
		}
	}
}

// Test hooks are refused unless both the config flag and the environment variable allow them.
func TestTestHooksAreRefusedByDefault(t *testing.T) {
	t.Setenv("PCA_MPC_UNSAFE_TEST_HOOKS", "")
	cfg := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(cfg, []byte(`{"role":"party","behavior":"lie","unsafeTestHooks":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := Main([]string{"p", cfg}); rc != 3 {
		t.Fatalf("status %d, want 3", rc)
	}
}
