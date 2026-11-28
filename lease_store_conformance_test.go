package pca

import (
	"strings"
	"testing"
)

func TestLeaseStoreConformanceMemoryKv(t *testing.T) {
	passed, err := RunLeaseStoreConformance(LeaseStoreKit{
		Open:   func() (AtomicKV, error) { return MemoryLeaseKv(), nil },
		Reopen: func(kv AtomicKV) (AtomicKV, error) { return kv, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "spread,atomic update,independent leases,revocation placement,shard count is pinned,state survives a restart,pruning bounds revocations"
	if strings.Join(passed, ",") != want {
		t.Fatalf("passed %v", passed)
	}
}

// a store that forgets on reopen is caught by the restart check
func TestLeaseStoreConformanceCatchesAStoreThatForgetsOnReopen(t *testing.T) {
	_, err := RunLeaseStoreConformance(LeaseStoreKit{
		Open:   func() (AtomicKV, error) { return MemoryLeaseKv(), nil },
		Reopen: func(AtomicKV) (AtomicKV, error) { return MemoryLeaseKv(), nil },
	})
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("a store that forgets on reopen passed: %v", err)
	}
}
