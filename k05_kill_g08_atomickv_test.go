package pca

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// g08: SQLAtomicKV over an in-memory fake database/sql driver (the package imports no driver). The fake keeps one k/v/ver
// table, logs every statement and can inject errors and lost races.

type g08kvRow struct {
	v   string
	ver int64
}

type g08kvState struct {
	rows                       map[string]g08kvRow
	log                        []string
	createErr, queryErr, exErr error
	raErr                      error
	lose                       int // writes that report 0 rows affected without applying
}

type g08kvConnector struct{ st *g08kvState }
type g08kvDriver struct{ st *g08kvState }
type g08kvConn struct{ st *g08kvState }
type g08kvStmt struct {
	st *g08kvState
	q  string
}
type g08kvResult struct {
	n   int64
	err error
}
type g08kvRows struct {
	vals [][]driver.Value
	i    int
}

func (c g08kvConnector) Connect(context.Context) (driver.Conn, error) { return g08kvConn(c), nil }
func (c g08kvConnector) Driver() driver.Driver                        { return g08kvDriver(c) }
func (d g08kvDriver) Open(string) (driver.Conn, error)                { return g08kvConn(d), nil }
func (c g08kvConn) Prepare(q string) (driver.Stmt, error)             { return &g08kvStmt{st: c.st, q: q}, nil }
func (c g08kvConn) Close() error                                      { return nil }
func (c g08kvConn) Begin() (driver.Tx, error)                         { return nil, errors.New("no tx") }
func (s *g08kvStmt) Close() error                                     { return nil }
func (s *g08kvStmt) NumInput() int                                    { return -1 }
func (r g08kvResult) LastInsertId() (int64, error)                    { return 0, nil }
func (r g08kvResult) RowsAffected() (int64, error)                    { return r.n, r.err }
func (r *g08kvRows) Columns() []string                                { return []string{"v", "ver"} }
func (r *g08kvRows) Close() error                                     { return nil }

func (r *g08kvRows) Next(dest []driver.Value) error {
	if r.i >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.i])
	r.i++
	return nil
}

func (s *g08kvStmt) Exec(args []driver.Value) (driver.Result, error) {
	st := s.st
	st.log = append(st.log, s.q)
	if strings.HasPrefix(s.q, "CREATE") {
		return g08kvResult{}, st.createErr
	}
	if st.exErr != nil {
		return nil, st.exErr
	}
	if st.lose > 0 {
		st.lose--
		return g08kvResult{n: 0, err: st.raErr}, nil
	}
	var n int64
	switch {
	case strings.HasPrefix(s.q, "INSERT"):
		k := args[0].(string)
		if _, has := st.rows[k]; !has {
			st.rows[k] = g08kvRow{v: args[1].(string), ver: 1}
			n = 1
		}
	case strings.HasPrefix(s.q, "UPDATE"):
		k := args[1].(string)
		if r, has := st.rows[k]; has && r.ver == args[2].(int64) {
			st.rows[k] = g08kvRow{v: args[0].(string), ver: r.ver + 1}
			n = 1
		}
	}
	return g08kvResult{n: n, err: st.raErr}, nil
}

func (s *g08kvStmt) Query(args []driver.Value) (driver.Rows, error) {
	st := s.st
	st.log = append(st.log, s.q)
	if st.queryErr != nil {
		return nil, st.queryErr
	}
	rows := &g08kvRows{}
	if r, has := st.rows[args[0].(string)]; has {
		rows.vals = [][]driver.Value{{r.v, r.ver}}
	}
	return rows, nil
}

func g08kvOpen(t *testing.T, opts SQLAtomicKVOptions) (*SQLAtomicKV, *g08kvState) {
	t.Helper()
	st := &g08kvState{rows: map[string]g08kvRow{}}
	kv, err := NewSQLAtomicKV(sql.OpenDB(g08kvConnector{st}), opts)
	if err != nil {
		t.Fatalf("NewSQLAtomicKV: %v", err)
	}
	return kv, st
}

func TestK05KillG08SQLKVConstruct(t *testing.T) {
	if _, err := NewSQLAtomicKV(nil, SQLAtomicKVOptions{}); err == nil || err.Error() != "pca: NewSQLAtomicKV needs a *sql.DB" {
		t.Fatalf("nil db: %v", err)
	}
	kv, st := g08kvOpen(t, SQLAtomicKVOptions{})
	if len(st.log) != 1 || st.log[0] != "CREATE TABLE IF NOT EXISTS pca_kv (k TEXT NOT NULL PRIMARY KEY, v TEXT NOT NULL, ver BIGINT NOT NULL)" {
		t.Fatalf("create log %q", st.log)
	}
	if kv.selectSQL != "SELECT v, ver FROM pca_kv WHERE k = ?" ||
		kv.insertSQL != "INSERT INTO pca_kv (k, v, ver) VALUES (?, ?, 1) ON CONFLICT(k) DO NOTHING" ||
		kv.updSQL != "UPDATE pca_kv SET v = ?, ver = ver + 1 WHERE k = ? AND ver = ?" {
		t.Fatalf("default SQL %q %q %q", kv.selectSQL, kv.insertSQL, kv.updSQL)
	}
	kv, _ = g08kvOpen(t, SQLAtomicKVOptions{Table: "custom_t", DollarPlaceholders: true})
	if kv.selectSQL != "SELECT v, ver FROM custom_t WHERE k = $1" ||
		kv.insertSQL != "INSERT INTO custom_t (k, v, ver) VALUES ($1, $2, 1) ON CONFLICT(k) DO NOTHING" ||
		kv.updSQL != "UPDATE custom_t SET v = $1, ver = ver + 1 WHERE k = $2 AND ver = $3" {
		t.Fatalf("dollar SQL %q %q %q", kv.selectSQL, kv.insertSQL, kv.updSQL)
	}
	st = &g08kvState{rows: map[string]g08kvRow{}}
	if _, err := NewSQLAtomicKV(sql.OpenDB(g08kvConnector{st}), SQLAtomicKVOptions{Table: "bad name"}); err == nil ||
		err.Error() != `pca: invalid kv table name "bad name"` || len(st.log) != 0 {
		t.Fatalf("bad table: %v %q", err, st.log)
	}
	boom := errors.New("create boom")
	st = &g08kvState{rows: map[string]g08kvRow{}, createErr: boom}
	if kv, err := NewSQLAtomicKV(sql.OpenDB(g08kvConnector{st}), SQLAtomicKVOptions{}); !errors.Is(err, boom) || kv != nil {
		t.Fatalf("create error: %v", err)
	}
}

func TestK05KillG08SQLKVReadGet(t *testing.T) {
	kv, st := g08kvOpen(t, SQLAtomicKVOptions{})
	if v, ver, ok, err := kv.read("missing"); v != nil || ver != 0 || ok || err != nil {
		t.Fatalf("missing: %v %d %v %v", v, ver, ok, err)
	}
	st.rows["k"] = g08kvRow{v: "val", ver: 7}
	if v, ver, ok, err := kv.read("k"); string(v) != "val" || ver != 7 || !ok || err != nil {
		t.Fatalf("found: %q %d %v %v", v, ver, ok, err)
	}
	if v, ok, err := kv.Get("k"); string(v) != "val" || !ok || err != nil {
		t.Fatalf("get: %q %v %v", v, ok, err)
	}
	if _, ok, err := kv.Get("missing"); ok || err != nil {
		t.Fatalf("get missing: %v %v", ok, err)
	}
	boom := errors.New("query boom")
	st.queryErr = boom
	if v, ver, ok, err := kv.read("k"); v != nil || ver != 0 || ok || !errors.Is(err, boom) {
		t.Fatalf("query error: %v %d %v %v", v, ver, ok, err)
	}
	if _, ok, err := kv.Get("k"); ok || !errors.Is(err, boom) {
		t.Fatalf("get error: %v %v", ok, err)
	}
	// Update surfaces a read error without calling fn.
	calls := 0
	if err := kv.Update("k", func(p []byte) []byte { calls++; return []byte("x") }); !errors.Is(err, boom) || calls != 0 {
		t.Fatalf("update read error: %v calls=%d", err, calls)
	}
}

func TestK05KillG08SQLKVUpdate(t *testing.T) {
	kv, st := g08kvOpen(t, SQLAtomicKVOptions{})
	// insert path: prev is nil, the row lands with ver 1.
	var seen [][]byte
	if err := kv.Update("a", func(p []byte) []byte { seen = append(seen, p); return []byte("one") }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != nil || st.rows["a"] != (g08kvRow{"one", 1}) {
		t.Fatalf("insert: seen=%q rows=%v", seen, st.rows)
	}
	// update path: prev is the stored value, ver bumps.
	seen = nil
	if err := kv.Update("a", func(p []byte) []byte { seen = append(seen, p); return []byte("two") }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || string(seen[0]) != "one" || st.rows["a"] != (g08kvRow{"two", 2}) {
		t.Fatalf("update: seen=%q rows=%v", seen, st.rows)
	}
	if !strings.HasPrefix(st.log[len(st.log)-1], "UPDATE") {
		t.Fatalf("expected an UPDATE, log %q", st.log)
	}
	// fn returning nil writes nothing.
	n := len(st.log)
	if err := kv.Update("b", func(p []byte) []byte { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, has := st.rows["b"]; has || len(st.log) != n+1 {
		t.Fatalf("nil next wrote: rows=%v log=%q", st.rows, st.log[n:])
	}
	// one lost race: re-read and recompute, then win.
	st.lose = 1
	calls := 0
	if err := kv.Update("a", func(p []byte) []byte { calls++; return []byte("three") }); err != nil || calls != 2 {
		t.Fatalf("lost race once: %v calls=%d", err, calls)
	}
	if st.rows["a"] != (g08kvRow{"three", 3}) {
		t.Fatalf("after race %v", st.rows["a"])
	}
	// exec error.
	boom := errors.New("exec boom")
	st.exErr = boom
	if err := kv.Update("a", func(p []byte) []byte { return []byte("x") }); !errors.Is(err, boom) {
		t.Fatalf("exec error: %v", err)
	}
	st.exErr = nil
	// RowsAffected error.
	ra := errors.New("ra boom")
	st.raErr = ra
	if err := kv.Update("a", func(p []byte) []byte { return []byte("x") }); !errors.Is(err, ra) {
		t.Fatalf("rows affected error: %v", err)
	}
}

func TestK05KillG08SQLKVAttempts(t *testing.T) {
	kv, st := g08kvOpen(t, SQLAtomicKVOptions{})
	st.lose = 1 << 30
	calls := 0
	// fn stops the loop (nil = no write) on call 1001, so a loop that overruns the bound returns nil instead of the error.
	err := kv.Update("k", func(p []byte) []byte {
		calls++
		if calls > 1000 {
			return nil
		}
		return []byte("x")
	})
	if calls != 1000 || err == nil || err.Error() != `pca: SQLAtomicKV: update of "k" lost the race 1000 times (fail closed)` {
		t.Fatalf("attempts: calls=%d err=%v", calls, err)
	}
}
