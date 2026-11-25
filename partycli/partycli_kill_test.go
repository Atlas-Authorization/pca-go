package partycli

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Tests that drive run() end to end (the OT roles, a party, the silent-party idle) and pin its observable effects: exit status, the
// JSON line it prints, which peer it talks to, and that it lingers after printing so abort/result frames flush.

type capLine struct {
	at time.Time
	m  map[string]any
}

// capture redirects os.Stdout into a pipe while fn runs and returns every JSON line printed, each stamped with its arrival time.
func capture(fn func()) []capLine {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	old := os.Stdout
	os.Stdout = w
	var mu sync.Mutex
	var lines []capLine
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				mu.Lock()
				lines = append(lines, capLine{time.Now(), m})
				mu.Unlock()
			}
		}
	}()
	fn()
	os.Stdout = old
	w.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return lines
}

type nodeFiles struct{ key, cert string }

func makeIdentity(t *testing.T, dir, cn string) nodeFiles {
	t.Helper()
	k, c, err := pca.MpcGenerateIdentity(cn, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := nodeFiles{filepath.Join(dir, cn+".key"), filepath.Join(dir, cn+".crt")}
	if err := os.WriteFile(f.key, []byte(k), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cert, []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeCfg(t *testing.T, dir string, name string, cfg map[string]any) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name+".json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// twoNodeCfgs builds the configs of node 0 (role r0) and node 1 (role r1) on loopback, with extra merged into both.
func twoNodeCfgs(t *testing.T, r0, r1 string, extra map[string]any) []string {
	t.Helper()
	dir := t.TempDir()
	ids := []nodeFiles{makeIdentity(t, dir, "n0"), makeIdentity(t, dir, "n1")}
	ports := []int{freePort(t), freePort(t)}
	nodes := []map[string]any{}
	for i := 0; i < 2; i++ {
		nodes = append(nodes, map[string]any{"id": i, "host": "127.0.0.1", "port": ports[i], "certPath": ids[i].cert})
	}
	var paths []string
	for i, role := range []string{r0, r1} {
		cfg := map[string]any{"role": role, "id": i, "n": 2, "sessionId": "kill-sess", "listenHost": "127.0.0.1", "nodes": nodes,
			"keyPath": ids[i].key, "certPath": ids[i].cert, "recvTimeoutMs": 10000, "connectTimeoutMs": 10000}
		for k, v := range extra {
			cfg[k] = v
		}
		paths = append(paths, writeCfg(t, dir, "cfg"+string(rune('0'+i)), cfg))
	}
	return paths
}

type nodeRun struct {
	rc    int
	retAt time.Time
}

// runAll runs Main on every config concurrently, in-process, and returns the exit statuses and every line printed.
func runAll(paths []string) ([]nodeRun, []capLine) {
	res := make([]nodeRun, len(paths))
	lines := capture(func() {
		var wg sync.WaitGroup
		for i, p := range paths {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rc := Main([]string{"pca-mpc-party", p})
				res[i] = nodeRun{rc, time.Now()}
			}()
		}
		wg.Wait()
	})
	return res, lines
}

func lineFor(t *testing.T, lines []capLine, role string) capLine {
	t.Helper()
	for _, l := range lines {
		if l.m["role"] == role {
			return l
		}
	}
	t.Fatalf("no line for role %q in %v", role, lines)
	return capLine{}
}

// lingers asserts the process kept running at least ~the 300ms flush window after printing its line (lower bound only).
func lingers(t *testing.T, what string, l capLine, r nodeRun) {
	t.Helper()
	if d := r.retAt.Sub(l.at); d < 250*time.Millisecond {
		t.Fatalf("%s returned %v after printing; it must linger ~300ms", what, d)
	}
}

func otResult(t *testing.T, l capLine) map[string]any {
	t.Helper()
	if l.m["ok"] != true {
		t.Fatalf("not ok: %v", l.m)
	}
	r, ok := l.m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", l.m)
	}
	return r
}

// Default OT (cfg.OT nil: ec, 128 transfers): sender (node 0) talks to node 1 and the receiver (node 1) to node 0, so both complete.
func TestOtRolesDefaultToEc128AndPairWithTheOtherNode(t *testing.T) {
	res, lines := runAll(twoNodeCfgs(t, "ot-sender", "ot-receiver", nil))
	s, r := lineFor(t, lines, "ot-sender"), lineFor(t, lines, "ot-receiver")
	for i, l := range []capLine{s, r} {
		if res[i].rc != 0 {
			t.Fatalf("node %d status %d, want 0", i, res[i].rc)
		}
		x := otResult(t, l)
		if x["kind"] != "ec" || x["count"] != float64(128) || x["matched"] != true || x["padDigest"] == "" {
			t.Fatalf("node %d result %v", i, x)
		}
		if _, ok := l.m["links"]; !ok {
			t.Fatalf("node %d: no links", i)
		}
		if _, ok := l.m["connectMs"]; !ok {
			t.Fatalf("node %d: no connectMs", i)
		}
		lingers(t, l.m["role"].(string), l, res[i])
	}
	if otResult(t, s)["role"] != "sender" || otResult(t, r)["role"] != "receiver" {
		t.Fatalf("roles: %v / %v", s.m, r.m)
	}
}

// An explicit ot object overrides the defaults.
func TestOtConfigOverridesKindAndCount(t *testing.T) {
	res, lines := runAll(twoNodeCfgs(t, "ot-sender", "ot-receiver", map[string]any{"ot": map[string]any{"kind": "ec", "count": 8}}))
	for i, role := range []string{"ot-sender", "ot-receiver"} {
		if res[i].rc != 0 {
			t.Fatalf("%s status %d", role, res[i].rc)
		}
		if x := otResult(t, lineFor(t, lines, role)); x["count"] != float64(8) || x["kind"] != "ec" {
			t.Fatalf("%s result %v", role, x)
		}
	}
}

// A failing OT (unknown kind) prints the attributable abort, exits 3 and also lingers before exiting.
func TestOtFailureIsAnAbortWithStatusThreeAfterLingering(t *testing.T) {
	res, lines := runAll(twoNodeCfgs(t, "ot-sender", "ot-receiver", map[string]any{"ot": map[string]any{"kind": "bogus", "count": 4}}))
	for i, role := range []string{"ot-sender", "ot-receiver"} {
		if res[i].rc != 3 {
			t.Fatalf("%s status %d, want 3", role, res[i].rc)
		}
		l := lineFor(t, lines, role)
		e, _ := l.m["error"].(map[string]any)
		if l.m["ok"] != false || e == nil || !strings.Contains(e["message"].(string), "unknown ot kind") {
			t.Fatalf("%s: %v", role, l.m)
		}
		if _, hasResult := l.m["result"]; hasResult {
			t.Fatalf("%s printed a result on failure", role)
		}
		lingers(t, role, l, res[i])
	}
}

func singleNodeCfg(t *testing.T, extra map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	id := makeIdentity(t, dir, "solo")
	cfg := map[string]any{"role": "party", "id": 0, "n": 1, "sessionId": "solo-sess", "listenHost": "127.0.0.1",
		"nodes":   []map[string]any{{"id": 0, "host": "127.0.0.1", "port": 0, "certPath": id.cert}},
		"keyPath": id.key, "certPath": id.cert, "recvTimeoutMs": 5000, "connectTimeoutMs": 5000,
		"input": map[string]any{"allow": 1, "t": 2, "rQuant": 3}}
	for k, v := range extra {
		if v == nil {
			delete(cfg, k)
		} else {
			cfg[k] = v
		}
	}
	return writeCfg(t, dir, "solo", cfg)
}

// A party without an input aborts locally (status 3) after connecting, before running anything.
func TestPartyWithoutInputAborts(t *testing.T) {
	res, lines := runAll([]string{singleNodeCfg(t, map[string]any{"input": nil})})
	if res[0].rc != 3 || len(lines) != 1 {
		t.Fatalf("status %d, lines %v", res[0].rc, lines)
	}
	e, _ := lines[0].m["error"].(map[string]any)
	if lines[0].m["ok"] != false || e == nil || !strings.Contains(e["message"].(string), "a party needs an input") {
		t.Fatalf("%v", lines[0].m)
	}
}

// A lone honest party completes: status 0, one ok line with its result, then lingers.
func TestPartyPrintsItsResultAndLingers(t *testing.T) {
	res, lines := runAll([]string{singleNodeCfg(t, nil)})
	if res[0].rc != 0 || len(lines) != 1 {
		t.Fatalf("status %d, lines %v", res[0].rc, lines)
	}
	l := lines[0]
	x, _ := l.m["result"].(map[string]any)
	if l.m["ok"] != true || l.m["role"] != "party" || x == nil || x["n"] != float64(1) || x["id"] != float64(0) {
		t.Fatalf("%v", l.m)
	}
	lingers(t, "party", l, res[0])
}

// A malformed input vector makes MpcRunParty fail: the party aborts (status 3), prints the abort, and lingers.
func TestPartyRunFailureIsAnAbortAfterLingering(t *testing.T) {
	res, lines := runAll([]string{singleNodeCfg(t, map[string]any{"input": map[string]any{"allow": 5, "t": 2, "rQuant": 3}})})
	if res[0].rc != 3 || len(lines) != 1 || lines[0].m["ok"] != false {
		t.Fatalf("status %d, lines %v", res[0].rc, lines)
	}
}

// The "silent" behaviour (round prep) reaches the party through cfg.Behavior and must make the process idle with its sockets open:
// it neither prints nor returns (the real sleep is an hour, so the goroutine is simply left asleep when the test ends).
func TestSilentPartyIdlesAndSaysNothing(t *testing.T) {
	t.Setenv("PCA_MPC_UNSAFE_TEST_HOOKS", "1")
	p := singleNodeCfg(t, map[string]any{"unsafeTestHooks": true, "behavior": map[string]any{"kind": "silent", "round": "prep"}})
	returned := make(chan int, 1)
	lines := capture(func() {
		go func() { returned <- Main([]string{"pca-mpc-party", p}) }()
		select {
		case rc := <-returned:
			t.Errorf("a silent party returned with status %d; it must idle", rc)
		case <-time.After(2 * time.Second):
		}
	})
	if len(lines) != 0 {
		t.Fatalf("a silent party printed %v", lines)
	}
}
