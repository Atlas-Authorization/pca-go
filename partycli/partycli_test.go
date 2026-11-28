package partycli

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// bind first: the reported port is the held port, the peer map is applied, and nothing probes and releases.
func TestBindFirstHoldsTheReportedPort(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	if _, err := w.WriteString(`{"ports":{"0":4321,"1":1}}` + "\n"); err != nil {
		t.Fatal(err)
	}
	cfg := nodeConfig{ID: 1, ListenHost: "127.0.0.1"}
	cfg.Nodes = append(cfg.Nodes, struct {
		ID       int    `json:"id"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		CertPath string `json:"certPath"`
	}{ID: 0}, struct {
		ID       int    `json:"id"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		CertPath string `json:"certPath"`
	}{ID: 1})
	ln, err := bindFirst(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if port == 0 || cfg.Nodes[1].Port != port || cfg.Nodes[0].Port != 4321 {
		t.Fatalf("ports not applied: own %d (bound %d), peer %d", cfg.Nodes[1].Port, port, cfg.Nodes[0].Port)
	}
	if again, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		again.Close()
		t.Fatal("the node does not hold its port")
	}
}

func TestBindFirstFailsClosedOnAClosedStdin(t *testing.T) {
	r, w, _ := os.Pipe()
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	cfg := nodeConfig{ID: 0, ListenHost: "127.0.0.1"}
	cfg.Nodes = append(cfg.Nodes, struct {
		ID       int    `json:"id"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		CertPath string `json:"certPath"`
	}{ID: 0})
	if _, err := bindFirst(&cfg); err == nil {
		t.Fatal("expected an error")
	}
}
