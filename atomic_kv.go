package pca

// AtomicKV: the small durable key/value contract the operation records and the plan registry are built on. A value is the
// JSON of one record. Update is the only mutation: it MUST be atomic across every goroutine, process and node that shares
// the store (a conditional UPDATE, a unique-key insert, a Redis script), and a call that cannot decide MUST return an
// error (the callers then fail closed).

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
)

// AtomicKV is an atomic key/value store of byte values.
type AtomicKV interface {
	// Get returns the value under key; ok is false when there is none.
	Get(key string) (value []byte, ok bool, err error)
	// Update atomically replaces the value under key with fn(prev) (prev is nil when there is none). fn returning nil leaves
	// the key unchanged. fn may be called more than once (an optimistic store retries) and must not call the store.
	Update(key string, fn func(prev []byte) []byte) error
}

// MemoryAtomicKV is the in-process AtomicKV (tests and single-process tools). Its values die with the process.
type MemoryAtomicKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemoryAtomicKV returns an empty in-memory AtomicKV.
func NewMemoryAtomicKV() *MemoryAtomicKV { return &MemoryAtomicKV{m: map[string][]byte{}} }

// Get implements AtomicKV.
func (s *MemoryAtomicKV) Get(key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	return append([]byte(nil), v...), ok, nil
}

// Update implements AtomicKV under one lock.
func (s *MemoryAtomicKV) Update(key string, fn func(prev []byte) []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var prev []byte
	if v, ok := s.m[key]; ok {
		prev = append([]byte(nil), v...)
	}
	if next := fn(prev); next != nil {
		s.m[key] = append([]byte(nil), next...)
	}
	return nil
}

// DefaultKVTable is the table SQLAtomicKV uses when SQLAtomicKVOptions.Table is empty.
const DefaultKVTable = "pca_kv"

// SQLAtomicKVOptions configures NewSQLAtomicKV (same conventions as SQLStateStoreOptions).
type SQLAtomicKVOptions struct {
	Table              string
	DollarPlaceholders bool
}

// sqlKVMaxAttempts bounds the optimistic retry loop of SQLAtomicKV.Update.
const sqlKVMaxAttempts = 1000

// SQLAtomicKV is an AtomicKV over database/sql (SQLite 3.24+ or PostgreSQL 9.5+; the package imports no driver). Every
// write is one conditional statement under the row's version (compare-and-set), retried when another writer won, so
// concurrent goroutines, connections and processes sharing the database never lose an update. Safe for concurrent use.
type SQLAtomicKV struct {
	db                           *sql.DB
	selectSQL, insertSQL, updSQL string
}

// NewSQLAtomicKV creates the table if it does not exist and returns the store.
func NewSQLAtomicKV(db *sql.DB, opts SQLAtomicKVOptions) (*SQLAtomicKV, error) {
	if db == nil {
		return nil, errors.New("pca: NewSQLAtomicKV needs a *sql.DB")
	}
	t := opts.Table
	if t == "" {
		t = DefaultKVTable
	}
	if !validTableName(t) {
		return nil, fmt.Errorf("pca: invalid kv table name %q", t)
	}
	ph := func(i int) string {
		if opts.DollarPlaceholders {
			return fmt.Sprintf("$%d", i)
		}
		return "?"
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS " + t +
		" (k TEXT NOT NULL PRIMARY KEY, v TEXT NOT NULL, ver BIGINT NOT NULL)"); err != nil {
		return nil, err
	}
	return &SQLAtomicKV{
		db:        db,
		selectSQL: "SELECT v, ver FROM " + t + " WHERE k = " + ph(1),
		insertSQL: "INSERT INTO " + t + " (k, v, ver) VALUES (" + ph(1) + ", " + ph(2) + ", 1) ON CONFLICT(k) DO NOTHING",
		updSQL:    "UPDATE " + t + " SET v = " + ph(1) + ", ver = ver + 1 WHERE k = " + ph(2) + " AND ver = " + ph(3),
	}, nil
}

func (s *SQLAtomicKV) read(key string) (v []byte, ver int64, ok bool, err error) {
	var text string
	switch err := s.db.QueryRow(s.selectSQL, key).Scan(&text, &ver); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, 0, false, nil
	case err != nil:
		return nil, 0, false, err
	}
	return []byte(text), ver, true, nil
}

// Get implements AtomicKV.
func (s *SQLAtomicKV) Get(key string) ([]byte, bool, error) {
	v, _, ok, err := s.read(key)
	return v, ok, err
}

// Update implements AtomicKV: read, compute, then one conditional write; a lost race re-reads and recomputes.
func (s *SQLAtomicKV) Update(key string, fn func(prev []byte) []byte) error {
	for i := 0; i < sqlKVMaxAttempts; i++ {
		prev, ver, ok, err := s.read(key)
		if err != nil {
			return err
		}
		if !ok {
			prev = nil
		}
		next := fn(append([]byte(nil), prev...))
		if next == nil {
			return nil
		}
		var res sql.Result
		if ok {
			res, err = s.db.Exec(s.updSQL, string(next), key, ver)
		} else {
			res, err = s.db.Exec(s.insertSQL, key, string(next))
		}
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 1 {
			return nil
		}
	}
	return fmt.Errorf("pca: SQLAtomicKV: update of %q lost the race %d times (fail closed)", key, sqlKVMaxAttempts)
}
