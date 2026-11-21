package sqltest

// Separate module so the pca-go library itself stays free of any SQL driver dependency.

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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

func TestSQLStateStoreConsumeOnceTTL(t *testing.T) {
	var _ pca.OnceStore = (*pca.SQLStateStore)(nil)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "o.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := pca.NewSQLStateStore(db, pca.SQLStateStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// the shared consume_once_ttl vectors, replayed against the SQL store (a fresh store per vector)
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "pca", "conformance", "caveat-lang-vectors.json"))
	if err != nil {
		raw, err = os.ReadFile(filepath.Join("..", "conformance", "caveat-lang-vectors.json"))
	}
	if err != nil {
		t.Fatalf("caveat-lang-vectors.json is required: %v", err)
	}
	var doc struct {
		Primitives struct {
			Once []struct {
				Name  string `json:"name"`
				Input struct {
					Steps []struct {
						Key         string `json:"key"`
						RetainUntil int64  `json:"retain_until"`
						Now         int64  `json:"now"`
					} `json:"steps"`
				} `json:"input"`
				Expect struct {
					Results []string `json:"results"`
				} `json:"expect"`
			} `json:"consume_once_ttl"`
		} `json:"primitives"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Primitives.Once) < 9 {
		t.Fatalf("only %d consume_once_ttl vectors", len(doc.Primitives.Once))
	}
	for i, v := range doc.Primitives.Once {
		tbl := "once_" + strconv.Itoa(i)
		vs, err := pca.NewSQLStateStore(db, pca.SQLStateStoreOptions{Table: tbl})
		if err != nil {
			t.Fatal(err)
		}
		for j, s := range v.Input.Steps {
			got, err := vs.ConsumeOnce(s.Key, s.RetainUntil, s.Now)
			res := "false"
			if err != nil {
				res = "error"
			} else if got {
				res = "true"
			}
			if res != v.Expect.Results[j] {
				t.Fatalf("%s step %d: %s, want %s", v.Name, j, res, v.Expect.Results[j])
			}
		}
	}
	// expired rows are pruned by a later successful take
	if ok, _ := st.ConsumeOnce("old", 10, 1); !ok {
		t.Fatal("first take")
	}
	if ok, _ := st.ConsumeOnce("other", 100, 50); !ok {
		t.Fatal("take")
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + pca.DefaultReplayTable + "_once WHERE key = 'old'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("expired row pruned: n=%d err=%v", n, err)
	}
}
