package pca

// SQLStateStore: a durable replay store over database/sql. The package imports no driver: open the *sql.DB with the
// driver of your database (SQLite 3.24+ or PostgreSQL 9.5+, any driver).

import (
	"database/sql"
	"errors"
	"fmt"
)

// DefaultReplayTable is the table SQLStateStore uses when SQLStateStoreOptions.Table is empty.
const DefaultReplayTable = "pca_replay"

// SQLStateStoreOptions configures NewSQLStateStore.
//
//   - Table: the table name (default DefaultReplayTable); letters, digits and '_', not starting with a digit.
//   - DollarPlaceholders: write $1, $2 (PostgreSQL drivers) instead of ? (SQLite drivers).
type SQLStateStoreOptions struct {
	Table              string
	DollarPlaceholders bool
}

// SQLStateStore is a StateStore on a SQL database: one row per counter stream, `key` is the PRIMARY KEY.
//
// The claim is ONE statement, INSERT ... ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE
// excluded.last_counter > last_counter, which the database runs atomically under the row's unique constraint, so
// concurrent goroutines, connections and processes sharing the database can never both consume the same counter: the
// claim succeeded iff exactly one row was affected. Safe for concurrent use.
type SQLStateStore struct {
	db       *sql.DB
	claimSQL string
	readSQL  string
}

func validTableName(t string) bool {
	if t == "" || len(t) > 63 || (t[0] >= '0' && t[0] <= '9') {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// NewSQLStateStore creates the table if it does not exist and returns the store.
func NewSQLStateStore(db *sql.DB, opts SQLStateStoreOptions) (*SQLStateStore, error) {
	if db == nil {
		return nil, errors.New("pca: NewSQLStateStore needs a *sql.DB")
	}
	t := opts.Table
	if t == "" {
		t = DefaultReplayTable
	}
	if !validTableName(t) {
		return nil, fmt.Errorf("pca: invalid replay table name %q", t)
	}
	p1, p2 := "?", "?"
	if opts.DollarPlaceholders {
		p1, p2 = "$1", "$2"
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS " + t +
		" (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)"); err != nil {
		return nil, err
	}
	return &SQLStateStore{
		db: db,
		claimSQL: "INSERT INTO " + t + " (key, last_counter) VALUES (" + p1 + ", " + p2 + ") ON CONFLICT(key) DO UPDATE " +
			"SET last_counter = excluded.last_counter WHERE excluded.last_counter > " + t + ".last_counter",
		readSQL: "SELECT last_counter FROM " + t + " WHERE key = " + p1,
	}, nil
}

// Claim implements StateStore with one atomic upsert. A database error is returned (Authorize then denies).
func (s *SQLStateStore) Claim(key string, counter int64) (ClaimResult, error) {
	res, err := s.db.Exec(s.claimSQL, key, counter)
	if err != nil {
		return ClaimResult{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ClaimResult{}, err
	}
	if n == 1 {
		return ClaimResult{OK: true}, nil
	}
	// refused: report the stored counter when it can be read (the decision is already made)
	var last int64
	if s.db.QueryRow(s.readSQL, key).Scan(&last) != nil {
		return ClaimResult{}, nil
	}
	return ClaimResult{OK: false, LastCounter: &last}, nil
}

// Last implements LastStore: the stored counter of a stream (nil: no row yet). A database error is returned, and then an
// escalation answer cannot be bound to the history (the decision stays escalate, refused).
func (s *SQLStateStore) Last(key string) (*int64, error) {
	var last int64
	switch err := s.db.QueryRow(s.readSQL, key).Scan(&last); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &last, nil
}
