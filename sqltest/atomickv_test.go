package sqltest

// The operation-record store and the plan registry over SQLAtomicKV: exactly-once execution and exactly-one-winner plan
// transitions hold across connections of a real database.

import (
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
	_ "modernc.org/sqlite"
)

func openKV(t *testing.T) *pca.SQLAtomicKV {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kv.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	kv, err := pca.NewSQLAtomicKV(db, pca.SQLAtomicKVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return kv
}

func TestSQLAtomicKVUpdateIsAtomic(t *testing.T) {
	kv := openKV(t)
	if _, ok, _ := kv.Get("k"); ok {
		t.Fatal("empty store")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// create-if-absent: exactly one writer may insert
			if err := kv.Update("only", func(prev []byte) []byte {
				if prev != nil {
					return nil
				}
				return []byte(`{"v":1}`)
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if v, ok, _ := kv.Get("only"); !ok || string(v) != `{"v":1}` {
		t.Fatalf("stored %q", v)
	}
	// read-modify-write never loses an update
	var wg2 sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			_ = kv.Update("n", func(prev []byte) []byte { return append(prev, 'x') })
		}()
	}
	wg2.Wait()
	if v, _, _ := kv.Get("n"); len(v) != 16 {
		t.Fatalf("lost updates: %d of 16 survived", len(v))
	}
	if _, err := pca.NewSQLAtomicKV(nil, pca.SQLAtomicKVOptions{}); err == nil {
		t.Fatal("nil db must be refused")
	}
}

func TestSQLOperationStoreRunsExactlyOnce(t *testing.T) {
	store := pca.NewKVOperationStore(openKV(t), "")
	digest, _ := pca.ParamsDigest(nil)
	az := pca.AuthorizeResult{Allow: true, PCActn: map[string]any{"action": map[string]any{"reversibility_class": "reversible"}},
		Operation: &pca.AuthorizedOperation{ID: "op-sql", Verb: "v", Resource: "/r", ParamsDigest: digest}}
	var calls int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := pca.ExecuteAuthorized(az, func(pca.ExecutionHandle) (any, error) {
				atomic.AddInt32(&calls, 1)
				return "done", nil
			}, pca.ExecuteOptions{Store: store})
			if o.Status == "refused" {
				t.Errorf("refused: %s", o.Reason)
			}
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("fn ran %d times", calls)
	}
	if r, _ := store.Get("op-sql"); r == nil || r.State != pca.OpCommitted || r.Result != "done" {
		t.Fatalf("%+v", r)
	}
}

func TestSQLPlanRegistryOneWinner(t *testing.T) {
	reg := pca.NewPlanRegistry(pca.PlanRegistryOptions{KV: openKV(t), Now: func() int64 { return 1 }})
	d := reg.Draft("g", []map[string]any{{"id": "n1", "verb": "v", "resource": "/r"}})
	if !d.OK {
		t.Fatal(d.Reason)
	}
	root := d.Record.Root
	if !reg.Validate("g", root).OK || !reg.Commit("g", root).OK {
		t.Fatal("setup")
	}
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if reg.Authorize("g", root, &pca.PlanApproval{By: "p"}).OK {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || !reg.Status("g", root, 0).Executable {
		t.Fatalf("%d winners", wins)
	}
}
