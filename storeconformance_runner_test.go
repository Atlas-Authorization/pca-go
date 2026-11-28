package pca

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func storeRun(t *testing.T, a StoreAdapter, tests []string, o StoreWorkloadOptions) StoreSuiteReport {
	t.Helper()
	r, err := RunStoreConformance(a, StoreConformanceOptions{StoreWorkloadOptions: o, Tests: tests})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestStoreConformanceGoodAdaptersPass(t *testing.T) {
	small := StoreWorkloadOptions{Clients: 8, Rounds: 8, RevisitKeys: 40, DurationMs: 300, Seed: 7}
	if r := storeRun(t, StoreInMemoryAdapter(), []string{"burst", "concurrent", "retention", "durability"}, small); r.Status != "pass" {
		t.Fatal(StoreFormatReport(r, 3))
	}
	d, err := StoreDurableFileAdapter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r := storeRun(t, d, []string{"burst", "retention", "durability"}, small); r.Status != "pass" {
		t.Fatal(StoreFormatReport(r, 3))
	}
}

func TestStoreConformanceBadAdaptersAreFlagged(t *testing.T) {
	small := StoreWorkloadOptions{Clients: 8, Rounds: 12, RevisitKeys: 60, Seed: 11}
	cases := []struct {
		a    StoreAdapter
		test string
	}{
		{StoreReadThenWriteAdapter(), "burst"},
		{StoreVolatileAdapter(), "durability"},
		{StoreEvictingAdapter(8), "retention"},
		{StoreNonStrictCounterAdapter(), "burst"},
	}
	for _, c := range cases {
		if r := storeRun(t, c.a, []string{c.test}, small); r.Status != "fail" {
			t.Fatalf("%s must be flagged by %s: %s", c.a.Name(), c.test, StoreFormatReport(r, 3))
		}
	}
}

func TestStoreDurabilitySkippedWhenNotDurable(t *testing.T) {
	r := storeRun(t, StoreInMemoryAdapter(), []string{"durability", "crash"}, StoreWorkloadOptions{Clients: 2})
	for _, tr := range r.Tests {
		if tr.Status != "skip" {
			t.Fatalf("%s/%s not skipped", tr.Test, tr.Kind)
		}
	}
}

func TestStoreLoadAdapter(t *testing.T) {
	if _, err := StoreLoadAdapter("builtin:nope", nil); err == nil {
		t.Fatal("unknown built-in accepted")
	}
	if _, err := StoreLoadAdapter("builtin:bad-evicting", map[string]string{"capacity": "x"}); err == nil {
		t.Fatal("bad capacity accepted")
	}
	if a, err := StoreLoadAdapter("builtin:in-memory", nil); err != nil || a.Name() == "" {
		t.Fatal("in-memory")
	}
}

func TestStoreSettle(t *testing.T) {
	if StoreSettle(func() (bool, error) { return true, nil }, 100) != "true" || StoreSettle(func() (bool, error) { return false, nil }, 100) != "false" {
		t.Fatal("definite answers")
	}
	if StoreSettle(func() (bool, error) { panic("x") }, 100) != "unknown" || StoreSettle(func() (bool, error) { return true, os.ErrClosed }, 100) != "unknown" {
		t.Fatal("failures must be unknown")
	}
	if StoreSettle(func() (bool, error) { select {} }, 20) != "unknown" {
		t.Fatal("timeout must be unknown")
	}
}

// The crash test re-runs this binary as the client process.
func TestStoreWorkerEntry(t *testing.T) {
	if os.Getenv("PCASC_TEST_WORKER") == "" {
		t.Skip("only as a crash-harness child")
	}
	var cfg StoreWorkerConfig
	if err := json.Unmarshal([]byte(os.Args[len(os.Args)-1]), &cfg); err != nil {
		t.Fatal(err)
	}
	// the child is a fresh process: the adapter the parent registered exists only there, so register it here too
	if dir := os.Getenv("PCASC_TEST_DIR"); dir != "" {
		StoreRegisterAdapter("test-durable", func(map[string]string) (StoreAdapter, error) { return StoreDurableFileAdapter(dir) })
	}
	if err := StoreWorkerMain(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCrashHarnessOnDurableFileStore(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-process run")
	}
	dir := t.TempDir()
	StoreRegisterAdapter("test-durable", func(map[string]string) (StoreAdapter, error) { return StoreDurableFileAdapter(dir) })
	t.Setenv("PCASC_TEST_WORKER", "1")
	t.Setenv("PCASC_TEST_DIR", dir)
	for _, kind := range []string{"consume", "advance"} {
		res, err := RunStoreCrash(kind, StoreCrashOptions{
			StoreWorkloadOptions: StoreWorkloadOptions{DurationMs: 1500, Seed: 5}, Worker: []string{os.Args[0], "-test.run=^TestStoreWorkerEntry$", "--"},
			Adapter: "test-durable", Processes: 2, KillEvery: 500,
		})
		if err != nil {
			t.Fatal(err)
		}
		h := StoreCheckHistory(res.Ops, StoreCheckOptions{})
		if len(h.Violations) > 0 || res.Kills == 0 {
			t.Fatalf("%s: %d violations, %d kills", kind, len(h.Violations), res.Kills)
		}
	}
}

func TestStoreParseCli(t *testing.T) {
	a, err := StoreParseCli([]string{"--adapter", "builtin:in-memory", "--option", "k=v=w", "--tests", "burst,retention", "--clients", "4", "--seed", "9", "--json"})
	if err != nil || a.Adapter != "builtin:in-memory" || a.Options["k"] != "v=w" || len(a.Conf.Tests) != 2 || a.Conf.Clients != 4 || a.Conf.Seed != 9 || !a.JSON {
		t.Fatalf("parse: %+v %v", a, err)
	}
	for _, bad := range [][]string{{"--option", "kv"}, {"--tests", "nope"}, {"--tests", ""}, {"--clients", "-1"}, {"--values", "0"}, {"--seed", "1.5"}, {"--wat"}, {"--profile", "nope"}, {"--profile", "pca-state", "--tests", "burst"}, {"--rounds"}} {
		if _, err := StoreParseCli(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	var out, errOut strings.Builder
	if code := StoreCliMain([]string{"--adapter", "builtin:in-memory", "--tests", "burst", "--clients", "4", "--rounds", "4", "--seed", "3"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	if code := StoreCliMain([]string{"--adapter", "builtin:bad-non-strict-counter", "--tests", "burst", "--clients", "8", "--rounds", "12", "--seed", "3"}, &out, &errOut); code != 1 {
		t.Fatalf("a bad store must exit 1, got %d", code)
	}
	p, err := StoreParseCli([]string{"--profile", "pca-state", "--adapter", "builtin:in-memory", "--tests", "one-instance,retry-after-timeout", "--rounds", "3", "--clients", "8"})
	if err != nil || p.Profile != "pca-state" || len(p.PcaStateTests) != 2 || p.Conf.Rounds != 3 || p.Conf.Clients != 8 {
		t.Fatalf("pca-state parse: %+v %v", p, err)
	}
	out.Reset()
	if code := StoreCliMain([]string{"--profile", "pca-state", "--adapter", "builtin:in-memory", "--tests", "one-instance,retry-after-timeout", "--rounds", "3", "--clients", "8"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "one-instance") {
		t.Fatalf("pca-state in-memory: exit %d: %s %s", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := StoreCliMain([]string{"--profile", "pca-state", "--adapter", "builtin:durable-file", "--tests", "claim-burst,one-instance,instances,retry-after-timeout", "--rounds", "3", "--clients", "8", "--json"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), `"instances"`) {
		t.Fatalf("pca-state durable-file: exit %d: %s %s", code, out.String(), errOut.String())
	}
	if code := StoreCliMain([]string{"--profile", "pca-state", "--adapter", "builtin:bad-read-then-write-claim", "--tests", "one-instance", "--rounds", "3", "--clients", "8"}, &out, &errOut); code != 1 {
		t.Fatalf("a racy claim must exit 1, got %d", code)
	}
	if code := StoreCliMain([]string{"--profile", "pca-state", "--adapter", "builtin:nope"}, &out, &errOut); code != 2 {
		t.Fatalf("an unknown adapter must exit 2, got %d", code)
	}
	if StoreCliMain([]string{}, &out, &errOut) != 2 || StoreCliMain([]string{"-h"}, &out, &errOut) != 0 {
		t.Fatal("usage exits")
	}
}
