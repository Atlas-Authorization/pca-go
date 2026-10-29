package sqltest

// The SQL-backed stores through the store conformance helper: several database handles onto one file, closing every
// handle between steps.

import (
	"database/sql"
	"path/filepath"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
	_ "modernc.org/sqlite"
)

type sqlState struct {
	*pca.SQLStateStore
	db *sql.DB
}

func (s sqlState) Close() error { return s.db.Close() }

type sqlOps struct {
	*pca.KVOperationStore
	db *sql.DB
}

func (s sqlOps) Close() error { return s.db.Close() }

func dsn(t *testing.T) string {
	return filepath.Join(t.TempDir(), "conf.db") + "?_pragma=busy_timeout(5000)"
}

func TestSQLStateStoreConforms(t *testing.T) {
	d := dsn(t)
	r := pca.RunStateStoreConformance(pca.StateStoreConformance{Name: "SQLStateStore (sqlite file)", Shared: true, Durable: true,
		Open: func() (pca.StateStore, error) {
			db, err := sql.Open("sqlite", d)
			if err != nil {
				return nil, err
			}
			st, err := pca.NewSQLStateStore(db, pca.SQLStateStoreOptions{})
			if err != nil {
				db.Close()
				return nil, err
			}
			return sqlState{st, db}, nil
		}})
	if !r.OK() {
		t.Fatal(r)
	}
}

func TestSQLOperationStoreConforms(t *testing.T) {
	d := dsn(t)
	r := pca.RunOperationStoreConformance(pca.OperationStoreConformance{Name: "KVOperationStore over SQLAtomicKV (sqlite file)", Shared: true, Durable: true,
		Open: func() (pca.OperationStore, error) {
			db, err := sql.Open("sqlite", d)
			if err != nil {
				return nil, err
			}
			kv, err := pca.NewSQLAtomicKV(db, pca.SQLAtomicKVOptions{})
			if err != nil {
				db.Close()
				return nil, err
			}
			return sqlOps{pca.NewKVOperationStore(kv, ""), db}, nil
		}})
	if !r.OK() {
		t.Fatal(r)
	}
}
