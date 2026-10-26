package sqltest

// Separate module so the pca-go library itself stays free of any SQL driver dependency.

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
	_ "modernc.org/sqlite"
)

func TestSQLStateStoreMonotoneAndConcurrent(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := pca.NewSQLStateStore(db, pca.SQLStateStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		n  int64
		ok bool
	}{{5, true}, {5, false}, {4, false}, {6, true}} {
		if r, err := st.Claim("k", s.n); err != nil || r.OK != s.ok {
			t.Fatalf("claim %d: %+v %v", s.n, r, err)
		}
	}
	if r, _ := st.Claim("k", 1); r.LastCounter == nil || *r.LastCounter != 6 {
		t.Fatalf("refused claim must report the stored counter: %+v", r)
	}
	var mu sync.Mutex
	wins := 0
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := st.Claim("c", 1); err == nil && r.OK {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one concurrent claim must win, got %d", wins)
	}
	if _, err := pca.NewSQLStateStore(db, pca.SQLStateStoreOptions{Table: "bad name;"}); err == nil {
		t.Fatal("invalid table name must be refused")
	}
}
