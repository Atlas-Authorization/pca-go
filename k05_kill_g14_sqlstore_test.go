package pca

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// g14: SQLStateStore over a scripted fake database/sql driver (the package imports no driver). Every statement is logged
// with its arguments; each test scripts the Exec results and the single-row reads.

type g14sqCall struct {
	q    string
	args []driver.Value
}

type g14sqState struct {
	log  []g14sqCall
	exec func(q string, args []driver.Value) (driver.Result, error)  // nil: CREATE ok, anything else 0 rows
	row  func(q string, args []driver.Value) ([]driver.Value, error) // nil row: no rows
}

type g14sqConnector struct{ st *g14sqState }
type g14sqDriver struct{ st *g14sqState }
type g14sqConn struct{ st *g14sqState }
type g14sqStmt struct {
	st *g14sqState
	q  string
}
type g14sqResult struct {
	n   int64
	err error
}
type g14sqRows struct {
	vals [][]driver.Value
	i    int
}

func (c g14sqConnector) Connect(context.Context) (driver.Conn, error) { return g14sqConn(c), nil }
func (c g14sqConnector) Driver() driver.Driver                        { return g14sqDriver(c) }
func (d g14sqDriver) Open(string) (driver.Conn, error)                { return g14sqConn(d), nil }
func (c g14sqConn) Prepare(q string) (driver.Stmt, error)             { return &g14sqStmt{st: c.st, q: q}, nil }
func (c g14sqConn) Close() error                                      { return nil }
func (c g14sqConn) Begin() (driver.Tx, error)                         { return nil, errors.New("no tx") }
func (s *g14sqStmt) Close() error                                     { return nil }
func (s *g14sqStmt) NumInput() int                                    { return -1 }
func (r g14sqResult) LastInsertId() (int64, error)                    { return 0, nil }
func (r g14sqResult) RowsAffected() (int64, error)                    { return r.n, r.err }
func (r *g14sqRows) Columns() []string                                { return []string{"last_counter"} }
func (r *g14sqRows) Close() error                                     { return nil }

func (r *g14sqRows) Next(dest []driver.Value) error {
	if r.i >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.i])
	r.i++
	return nil
}

func (s *g14sqStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.st.log = append(s.st.log, g14sqCall{s.q, append([]driver.Value(nil), args...)})
	if s.st.exec == nil {
		return g14sqResult{}, nil
	}
	return s.st.exec(s.q, args)
}

func (s *g14sqStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.st.log = append(s.st.log, g14sqCall{s.q, append([]driver.Value(nil), args...)})
	rows := &g14sqRows{}
	if s.st.row != nil {
		r, err := s.st.row(s.q, args)
		if err != nil {
			return nil, err
		}
		if r != nil {
			rows.vals = [][]driver.Value{r}
		}
	}
	return rows, nil
}

const (
	g14sqCreate     = "CREATE TABLE IF NOT EXISTS pca_replay (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)"
	g14sqCreateOnce = "CREATE TABLE IF NOT EXISTS pca_replay_once (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)"
	g14sqTake       = "INSERT INTO pca_replay_once (key, retain_until) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET retain_until = excluded.retain_until WHERE pca_replay_once.retain_until < ?"
	g14sqExtend     = "UPDATE pca_replay_once SET retain_until = ? WHERE key = ? AND retain_until < ?"
	g14sqPrune      = "DELETE FROM pca_replay_once WHERE retain_until < ?"
	g14sqClaim      = "INSERT INTO pca_replay (key, last_counter) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE excluded.last_counter > pca_replay.last_counter"
	g14sqRead       = "SELECT last_counter FROM pca_replay WHERE key = ?"
)

// g14sqOpen builds a default store, then clears the log (the two CREATE statements are asserted in the construct test).
func g14sqOpen(t *testing.T, st *g14sqState) *SQLStateStore {
	t.Helper()
	s, err := NewSQLStateStore(sql.OpenDB(g14sqConnector{st}), SQLStateStoreOptions{})
	if err != nil || s == nil {
		t.Fatalf("NewSQLStateStore: %v", err)
	}
	st.log = nil
	return s
}

func g14sqWantLog(t *testing.T, st *g14sqState, want ...g14sqCall) {
	t.Helper()
	if len(st.log) != len(want) {
		t.Fatalf("log %v, want %v", st.log, want)
	}
	for i := range want {
		if st.log[i].q != want[i].q || !reflect.DeepEqual(st.log[i].args, want[i].args) {
			t.Fatalf("log[%d] = %q %v, want %q %v", i, st.log[i].q, st.log[i].args, want[i].q, want[i].args)
		}
	}
}

func g14sqAlnum(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}

func TestK05KillG14SQLValidTableName(t *testing.T) {
	for name, want := range map[string]bool{
		"": false, "a": true, "_": true, "A": true, "z9_": true, "5": false, "0a": false, "9a": false, "-a": false, "a-": false,
		strings.Repeat("a", 62): true, strings.Repeat("a", 63): true, strings.Repeat("a", 64): false,
	} {
		if got := validTableName(name); got != want {
			t.Errorf("validTableName(%q) = %v, want %v", name, got, want)
		}
	}
	for c := 0; c < 256; c++ {
		b := byte(c)
		if got, want := validTableName(string([]byte{'x', b})), g14sqAlnum(b); got != want {
			t.Errorf("validTableName(x%q) = %v, want %v", b, got, want)
		}
		if got, want := validTableName(string([]byte{b, 'x'})), g14sqAlnum(b) && !(b >= '0' && b <= '9'); got != want {
			t.Errorf("validTableName(%qx) = %v, want %v", b, got, want)
		}
	}
}

func TestK05KillG14SQLConstruct(t *testing.T) {
	if s, err := NewSQLStateStore(nil, SQLStateStoreOptions{}); s != nil || err == nil || err.Error() != "pca: NewSQLStateStore needs a *sql.DB" {
		t.Fatalf("nil db: %v %v", s, err)
	}
	st := &g14sqState{}
	s, err := NewSQLStateStore(sql.OpenDB(g14sqConnector{st}), SQLStateStoreOptions{})
	if err != nil || s == nil {
		t.Fatalf("default: %v %v", s, err)
	}
	g14sqWantLog(t, st, g14sqCall{g14sqCreate, nil}, g14sqCall{g14sqCreateOnce, nil})
	if s.claimSQL != g14sqClaim || s.readSQL != g14sqRead || s.onceTakeSQL != g14sqTake || s.onceExtendSQL != g14sqExtend || s.oncePruneSQL != g14sqPrune {
		t.Fatalf("default SQL:\n%q\n%q\n%q\n%q\n%q", s.claimSQL, s.readSQL, s.onceTakeSQL, s.onceExtendSQL, s.oncePruneSQL)
	}

	st = &g14sqState{}
	s, err = NewSQLStateStore(sql.OpenDB(g14sqConnector{st}), SQLStateStoreOptions{Table: "tbl", DollarPlaceholders: true})
	if err != nil || s == nil {
		t.Fatalf("dollar: %v %v", s, err)
	}
	g14sqWantLog(t, st,
		g14sqCall{"CREATE TABLE IF NOT EXISTS tbl (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)", nil},
		g14sqCall{"CREATE TABLE IF NOT EXISTS tbl_once (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)", nil})
	if s.claimSQL != "INSERT INTO tbl (key, last_counter) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE excluded.last_counter > tbl.last_counter" ||
		s.readSQL != "SELECT last_counter FROM tbl WHERE key = $1" ||
		s.onceTakeSQL != "INSERT INTO tbl_once (key, retain_until) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET retain_until = excluded.retain_until WHERE tbl_once.retain_until < $3" ||
		s.onceExtendSQL != "UPDATE tbl_once SET retain_until = $1 WHERE key = $2 AND retain_until < $3" ||
		s.oncePruneSQL != "DELETE FROM tbl_once WHERE retain_until < $1" {
		t.Fatalf("dollar SQL:\n%q\n%q\n%q\n%q\n%q", s.claimSQL, s.readSQL, s.onceTakeSQL, s.onceExtendSQL, s.oncePruneSQL)
	}

	st = &g14sqState{}
	if s, err := NewSQLStateStore(sql.OpenDB(g14sqConnector{st}), SQLStateStoreOptions{Table: "bad name"}); s != nil || err == nil ||
		err.Error() != `pca: invalid replay table name "bad name"` || len(st.log) != 0 {
		t.Fatalf("bad table: %v %v %v", s, err, st.log)
	}

	boom := errors.New("create boom")
	st = &g14sqState{exec: func(q string, _ []driver.Value) (driver.Result, error) { return nil, boom }}
	if s, err := NewSQLStateStore(sql.OpenDB(g14sqConnector{st}), SQLStateStoreOptions{}); s != nil || !errors.Is(err, boom) || len(st.log) != 1 {
		t.Fatalf("first create error: %v %v %v", s, err, st.log)
	}
	st = &g14sqState{exec: func(q string, _ []driver.Value) (driver.Result, error) {
		if strings.Contains(q, "_once") {
			return nil, boom
		}
		return g14sqResult{}, nil
	}}
	if s, err := NewSQLStateStore(sql.OpenDB(g14sqConnector{st}), SQLStateStoreOptions{}); s != nil || !errors.Is(err, boom) || len(st.log) != 2 {
		t.Fatalf("second create error: %v %v %v", s, err, st.log)
	}
}

func TestK05KillG14SQLClaim(t *testing.T) {
	boom, raBoom, qBoom := errors.New("exec boom"), errors.New("rows affected boom"), errors.New("query boom")
	claim := g14sqCall{g14sqClaim, []driver.Value{"k", int64(5)}}
	read := g14sqCall{g14sqRead, []driver.Value{"k"}}
	rowsN := func(n int64, err error) func(string, []driver.Value) (driver.Result, error) {
		return func(string, []driver.Value) (driver.Result, error) { return g14sqResult{n, err}, nil }
	}
	row7 := func(string, []driver.Value) ([]driver.Value, error) { return []driver.Value{int64(7)}, nil }

	st := &g14sqState{}
	s := g14sqOpen(t, st)
	st.exec = func(string, []driver.Value) (driver.Result, error) { return nil, boom }
	if r, err := s.Claim("k", 5); !errors.Is(err, boom) || r.OK || r.LastCounter != nil {
		t.Fatalf("exec error: %+v %v", r, err)
	}
	g14sqWantLog(t, st, claim)

	st.log, st.exec = nil, rowsN(1, raBoom)
	if r, err := s.Claim("k", 5); !errors.Is(err, raBoom) || r.OK || r.LastCounter != nil {
		t.Fatalf("rows affected error: %+v %v", r, err)
	}
	g14sqWantLog(t, st, claim)

	st.log, st.exec, st.row = nil, rowsN(1, nil), row7
	if r, err := s.Claim("k", 5); err != nil || !r.OK || r.LastCounter != nil {
		t.Fatalf("claimed: %+v %v", r, err)
	}
	g14sqWantLog(t, st, claim)

	for _, n := range []int64{0, 2} {
		st.log, st.exec, st.row = nil, rowsN(n, nil), row7
		if r, err := s.Claim("k", 5); err != nil || r.OK || r.LastCounter == nil || *r.LastCounter != 7 {
			t.Fatalf("refused (n=%d): %+v %v", n, r, err)
		}
		g14sqWantLog(t, st, claim, read)
	}

	st.log, st.exec = nil, rowsN(0, nil)
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return nil, qBoom }
	if r, err := s.Claim("k", 5); err != nil || r.OK || r.LastCounter != nil {
		t.Fatalf("refused, unreadable: %+v %v", r, err)
	}
	g14sqWantLog(t, st, claim, read)

	st.log, st.row = nil, nil
	if r, err := s.Claim("k", 5); err != nil || r.OK || r.LastCounter != nil {
		t.Fatalf("refused, no row: %+v %v", r, err)
	}
}

func TestK05KillG14SQLLast(t *testing.T) {
	st := &g14sqState{}
	s := g14sqOpen(t, st)
	if v, err := s.Last("k"); v != nil || err != nil {
		t.Fatalf("no row: %v %v", v, err)
	}
	g14sqWantLog(t, st, g14sqCall{g14sqRead, []driver.Value{"k"}})
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return []driver.Value{int64(9)}, nil }
	if v, err := s.Last("k"); err != nil || v == nil || *v != 9 {
		t.Fatalf("row: %v %v", v, err)
	}
	qBoom := errors.New("query boom")
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return nil, qBoom }
	if v, err := s.Last("k"); v != nil || !errors.Is(err, qBoom) {
		t.Fatalf("query error: %v %v", v, err)
	}
}

func TestK05KillG14SQLConsumeOnce(t *testing.T) {
	boom, raBoom := errors.New("exec boom"), errors.New("rows affected boom")
	take := g14sqCall{g14sqTake, []driver.Value{"k", int64(9), int64(5)}}
	prune := g14sqCall{g14sqPrune, []driver.Value{int64(5)}}
	extend := g14sqCall{g14sqExtend, []driver.Value{int64(9), "k", int64(9)}}
	// script: the take reports takeN rows (or takeErr / raErr); the extend fails with extErr
	script := func(takeN int64, takeErr, raErr, extErr error) func(string, []driver.Value) (driver.Result, error) {
		return func(q string, _ []driver.Value) (driver.Result, error) {
			switch {
			case strings.HasPrefix(q, "INSERT"):
				if takeErr != nil {
					return nil, takeErr
				}
				return g14sqResult{takeN, raErr}, nil
			case strings.HasPrefix(q, "UPDATE"):
				if extErr != nil {
					return nil, extErr
				}
				return g14sqResult{1, nil}, nil
			}
			return g14sqResult{3, nil}, nil
		}
	}

	st := &g14sqState{}
	s := g14sqOpen(t, st)
	st.exec = script(1, nil, nil, nil)
	if ok, err := s.ConsumeOnce("", 9, 5); ok || !errors.Is(err, ErrConsumeOnce) {
		t.Fatalf("empty key: %v %v", ok, err)
	}
	if ok, err := s.ConsumeOnce("k", 4, 5); ok || !errors.Is(err, ErrConsumeOnce) {
		t.Fatalf("retain before now: %v %v", ok, err)
	}
	g14sqWantLog(t, st)

	// retainUntil == now is allowed
	if ok, err := s.ConsumeOnce("k", 5, 5); !ok || err != nil {
		t.Fatalf("retain == now: %v %v", ok, err)
	}
	g14sqWantLog(t, st, g14sqCall{g14sqTake, []driver.Value{"k", int64(5), int64(5)}}, prune)

	st.log = nil
	if ok, err := s.ConsumeOnce("k", 9, 5); !ok || err != nil {
		t.Fatalf("taken: %v %v", ok, err)
	}
	g14sqWantLog(t, st, take, prune)

	st.log, st.exec = nil, script(1, boom, nil, nil)
	if ok, err := s.ConsumeOnce("k", 9, 5); ok || !errors.Is(err, boom) {
		t.Fatalf("take error: %v %v", ok, err)
	}
	g14sqWantLog(t, st, take)

	st.log, st.exec = nil, script(1, nil, raBoom, nil)
	if ok, err := s.ConsumeOnce("k", 9, 5); ok || !errors.Is(err, raBoom) {
		t.Fatalf("rows affected error: %v %v", ok, err)
	}
	g14sqWantLog(t, st, take)

	for _, n := range []int64{0, 2} {
		st.log, st.exec = nil, script(n, nil, nil, nil)
		if ok, err := s.ConsumeOnce("k", 9, 5); ok || err != nil {
			t.Fatalf("live (n=%d): %v %v", n, ok, err)
		}
		g14sqWantLog(t, st, take, extend)
	}

	st.log, st.exec = nil, script(0, nil, nil, boom)
	if ok, err := s.ConsumeOnce("k", 9, 5); ok || !errors.Is(err, boom) {
		t.Fatalf("extend error: %v %v", ok, err)
	}
	g14sqWantLog(t, st, take, extend)
}
