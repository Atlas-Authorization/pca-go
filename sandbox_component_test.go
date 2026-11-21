package pca

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the fake reference host: RunComponent execs a copy of the pinned file with `<dir>/tool.component <fuel>`
// and an empty environment; the component file's text is the mode.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && filepath.Base(os.Args[1]) == "tool.component" {
		fakeHost(os.Args[1], os.Args[2])
		return
	}
	os.Exit(m.Run())
}

func fakeHost(path, fuel string) {
	modeB, _ := os.ReadFile(path)
	in := bufio.NewReader(os.Stdin)
	say := func(v any) { b, _ := json.Marshal(v); fmt.Println(string(b)) }
	ask := func(v any) map[string]any {
		say(v)
		line, _ := in.ReadString('\n')
		var m map[string]any
		_ = json.Unmarshal([]byte(line), &m)
		return m
	}
	switch strings.TrimSpace(string(modeB)) {
	case "ok":
		n := ask(map[string]any{"op": "count"})["n"].(float64)
		v := ask(map[string]any{"op": "verb", "h": 1})["ok"].(string)
		bad := ask(map[string]any{"op": "verb", "h": 99})
		r := ask(map[string]any{"op": "invoke", "h": 1})["ok"].([]any)
		e := ask(map[string]any{"op": "invoke", "h": 2})
		total := n*1000 + float64(len(v))*100
		for _, x := range r {
			total += x.(float64)
		}
		if e["err"] != float64(-3) {
			total += 7
		}
		if bad["err"] != float64(-1) {
			total += 9
		}
		var f int
		fmt.Sscan(fuel, &f)
		say(map[string]any{"done": total, "fuel_used": f / 2})
	case "fail":
		say(map[string]any{"fail": "fuel_exhausted"})
	case "garbage":
		fmt.Println("not json")
	case "hang":
		time.Sleep(time.Minute)
	case "env":
		n := 0
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(kv), "SYSTEMROOT=") { // Windows adds this one variable to an empty environment itself
				n++
			}
		}
		say(map[string]any{"done": n})
	}
}

func shaHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func fakeHostFile(t *testing.T) (path, pin string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	return self, shaHex(b)
}

func compTable(t *testing.T, ex map[string]HandleExecutor, verbs ...string) (*HandleTable, *SandboxReceiptLog) {
	t.Helper()
	log := NewSandboxReceiptLog(func() float64 { return 0 }, nil)
	table := NewHandleTable("wasi_no_ambient", log, ex, func() float64 { return 0 })
	for _, v := range verbs {
		params := map[string]any{"url": "https://example.com/a"}
		d, _ := HashCanonical(params)
		op := map[string]any{"verb": v, "resource": "r", "params": params}
		res := map[string]any{"allow": true, "operation": map[string]any{"verb": v, "resource": "r", "params_digest": d, "id": "op1"}}
		if _, err := table.Mint(res, op, map[string]any{"uses": 5}); err != nil {
			t.Fatal(err)
		}
	}
	return table, log
}

func TestComponentBadFuel(t *testing.T) {
	table, _ := compTable(t, nil)
	for _, f := range []int64{0, -1, 1 << 53} {
		if r := RunComponent(table, []byte("x"), ComponentOptions{Fuel: f, Host: "/nope"}); r.Reason != "bad_fuel" {
			t.Fatalf("fuel %d: %+v", f, r)
		}
	}
}

func TestComponentPinLogic(t *testing.T) {
	table, _ := compTable(t, nil)
	t.Setenv("PCA_WASMTIME_HOST", "")
	t.Setenv("PCA_WASMTIME_HOST_SHA256", "")
	dir := t.TempDir()
	exe := filepath.Join(dir, "host")
	body := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(exe, body, 0o700); err != nil {
		t.Fatal(err)
	}
	spawned := "host_exit" // a shell script is no executable on Windows: the spawn itself fails there
	if runtime.GOOS == "windows" {
		spawned = "host_unavailable"
	}
	reason := func(o ComponentOptions) string {
		o.Fuel = 10
		return RunComponent(table, []byte("(component)"), o).Reason
	}
	for _, c := range []struct {
		o    ComponentOptions
		want string
	}{
		{ComponentOptions{}, "host_missing"},
		{ComponentOptions{Host: filepath.Join(dir, "absent"), ExpectedSHA256: shaHex([]byte("x"))}, "host_missing"},
		{ComponentOptions{Host: exe}, "host_unpinned"},
		{ComponentOptions{Host: exe, ExpectedSHA256: "abc"}, "host_unpinned"},
		{ComponentOptions{Host: exe, ExpectedSHA256: strings.Repeat("0", 64)}, "host_hash_mismatch"},
		{ComponentOptions{Host: exe, ExpectedSHA256: shaHex(body)}, spawned}, // matches: proceeds to spawn, and the no-op host exits
	} {
		if got := reason(c.o); got != c.want {
			t.Fatalf("%+v: got %q, want %q", c.o, got, c.want)
		}
	}
	t.Setenv("PCA_WASMTIME_HOST", exe)
	t.Setenv("PCA_WASMTIME_HOST_SHA256", shaHex(body))
	if got := reason(ComponentOptions{}); got != spawned {
		t.Fatalf("env config: %q", got)
	}
}

func TestComponentProtocolAgainstAFakeHost(t *testing.T) {
	host, pin := fakeHostFile(t)
	table, log := compTable(t, map[string]HandleExecutor{
		"fetch": func(map[string]any) ([]byte, error) { return []byte{3, 4}, nil },
		"send":  func(map[string]any) ([]byte, error) { return make([]byte, 9), nil },
	}, "fetch", "send")
	run := func(mode string, o ComponentOptions) SandboxRunResult {
		o.Fuel, o.Host, o.ExpectedSHA256 = 100, host, pin
		return RunComponent(table, []byte(mode), o)
	}
	if r := run("ok", ComponentOptions{MaxResultBytes: 8}); r != (SandboxRunResult{OK: true, Value: 2000 + 500 + 7, FuelUsed: 50}) {
		t.Fatalf("ok: %+v", r)
	}
	if len(log.Entries) != 2 || log.Entries[0]["outcome"] != "ok" || log.Entries[1]["outcome"] != "ok" { // the oversized result is refused to the guest, not the table
		t.Fatalf("receipts: %v", log.Entries)
	}
	for mode, want := range map[string]string{"fail": "fuel_exhausted", "garbage": "host_protocol", "exit": "host_exit"} {
		if r := run(mode, ComponentOptions{}); r.OK || r.Reason != want {
			t.Fatalf("%s: %+v", mode, r)
		}
	}
	t0 := time.Now()
	if r := run("hang", ComponentOptions{TimeoutMs: 300}); r.OK || r.Reason != "timeout" || time.Since(t0) > 10*time.Second {
		t.Fatalf("hang: %+v after %v", r, time.Since(t0))
	}
	if r := run("env", ComponentOptions{}); !r.OK || r.Value != 0 { // an empty environment: no inherited secrets
		t.Fatalf("env: %+v", r)
	}
}

func TestComponentTempDirIsRemoved(t *testing.T) {
	host, pin := fakeHostFile(t)
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	table, _ := compTable(t, nil)
	RunComponent(table, []byte("fail"), ComponentOptions{Fuel: 5, Host: host, ExpectedSHA256: pin})
	if left, _ := os.ReadDir(root); len(left) != 0 {
		t.Fatalf("temp dir left behind: %v", left)
	}
}

func TestSandboxMemoryLimits(t *testing.T) {
	if in, ok := SandboxMemoryLimits(BuildTool(map[string]any{"memory": map[string]any{"min": 1, "max": 2}})); !ok || in == nil || *in != (SandboxMemoryInfo{Count: 1, Min: 1, Max: 2, HasMax: true}) {
		t.Fatalf("%+v %v", in, ok)
	}
	if in, ok := SandboxMemoryLimits([]byte("\x00asm\x01\x00\x00\x00")); in != nil || !ok {
		t.Fatalf("no memory section: %+v %v", in, ok)
	}
	if _, ok := SandboxMemoryLimits([]byte("junk")); ok {
		t.Fatal("junk must be unparseable")
	}
}

// The real run needs the reference host binary: set PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256.
func TestRealHostReferenceComponent(t *testing.T) {
	host, pin := os.Getenv("PCA_WASMTIME_HOST_BIN"), os.Getenv("PCA_WASMTIME_HOST_SHA256")
	if (host == "" || pin == "") && os.Getenv("CI") != "" {
		t.Fatal("CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256") // a green CI run never skips the real host
	}
	if host == "" || pin == "" {
		t.Skip("set PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256 to run the real wasmtime host")
	}
	run := func(table *HandleTable, wat string, fuel int64) SandboxRunResult {
		return RunComponent(table, []byte(wat), ComponentOptions{Fuel: fuel, Host: host, ExpectedSHA256: pin})
	}
	table, log := compTable(t, map[string]HandleExecutor{"fetch": func(map[string]any) ([]byte, error) { return []byte{42}, nil }}, "fetch")
	if r := run(table, ReferenceComponentWat(nil), 10_000_000); !r.OK || r.Value != 42 || len(log.Entries) != 1 || log.Entries[0]["outcome"] != "ok" {
		t.Fatalf("reference: %+v %v", r, log.Entries)
	}
	if r := run(table, ReferenceComponentWat(map[string]any{"spin": true}), 100_000); r.OK || r.Reason != "fuel_exhausted" {
		t.Fatalf("spin: %+v", r)
	}
	if r := run(table, ReferenceComponentWat(map[string]any{"extraImport": "wasi:cli/environment@0.2.0"}), 10_000_000); r.OK || !strings.HasPrefix(r.Reason, "ambient_import:") {
		t.Fatalf("extra import: %+v", r)
	}
	deny := map[string]HandleExecutor{"fetch": func(map[string]any) ([]byte, error) { return nil, os.ErrPermission }}
	table, log = compTable(t, deny, "fetch")
	if r := run(table, ReferenceComponentWat(nil), 10_000_000); !r.OK || r.Value != int64(SandboxUseErr["executor_error"]) || len(log.Entries) != 1 || log.Entries[0]["outcome"] != "error" {
		t.Fatalf("egress refusal: %+v %v", r, log.Entries)
	}
}
