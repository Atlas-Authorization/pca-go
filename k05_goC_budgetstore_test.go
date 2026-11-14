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

// A scripted database/sql driver with transactions: every statement is logged; Exec and single-row reads are scripted per test.

type goCsqCall struct {
	q    string
	args []driver.Value
}

type goCsqState struct {
	log                 []goCsqCall
	exec                func(q string, args []driver.Value) (driver.Result, error)
	row                 func(q string, args []driver.Value) ([]driver.Value, error)
	beginErr, commitErr error
	commits, rollbacks  int
}

type goCsqConnector struct{ st *goCsqState }
type goCsqConn struct{ st *goCsqState }
type goCsqTx struct{ st *goCsqState }
type goCsqStmt struct {
	st *goCsqState
	q  string
}
type goCsqResult struct {
	n   int64
	err error
}
type goCsqRows struct {
	vals [][]driver.Value
	i    int
}

func (c goCsqConnector) Connect(context.Context) (driver.Conn, error) {
	return &goCsqConn{st: c.st}, nil
}
func (c goCsqConnector) Driver() driver.Driver { return goCsqDriver{c.st} }

type goCsqDriver struct{ st *goCsqState }

func (d goCsqDriver) Open(string) (driver.Conn, error)     { return &goCsqConn{st: d.st}, nil }
func (c *goCsqConn) Prepare(q string) (driver.Stmt, error) { return &goCsqStmt{st: c.st, q: q}, nil }
func (c *goCsqConn) Close() error                          { return nil }
func (s *goCsqStmt) Close() error                          { return nil }
func (s *goCsqStmt) NumInput() int                         { return -1 }
func (r goCsqResult) LastInsertId() (int64, error)         { return 0, nil }
func (r goCsqResult) RowsAffected() (int64, error)         { return r.n, r.err }
func (r *goCsqRows) Columns() []string                     { return []string{"c"} }
func (r *goCsqRows) Close() error                          { return nil }
func (t goCsqTx) Commit() error                            { t.st.commits++; return t.st.commitErr }
func (t goCsqTx) Rollback() error                          { t.st.rollbacks++; return nil }
func (c *goCsqConn) Begin() (driver.Tx, error) {
	if c.st.beginErr != nil {
		return nil, c.st.beginErr
	}
	return goCsqTx{c.st}, nil
}

func (r *goCsqRows) Next(dest []driver.Value) error {
	if r.i >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.i])
	r.i++
	return nil
}

func (s *goCsqStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.st.log = append(s.st.log, goCsqCall{s.q, append([]driver.Value(nil), args...)})
	if s.st.exec == nil {
		return goCsqResult{}, nil
	}
	return s.st.exec(s.q, args)
}

func (s *goCsqStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.st.log = append(s.st.log, goCsqCall{s.q, append([]driver.Value(nil), args...)})
	rows := &goCsqRows{}
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

func goCsqOpen(t *testing.T, st *goCsqState, opts SQLStateStoreOptions) *SQLStateStore {
	t.Helper()
	s, err := NewSQLStateStore(sql.OpenDB(goCsqConnector{st}), opts)
	if err != nil || s == nil {
		t.Fatalf("NewSQLStateStore: %v", err)
	}
	st.log = nil
	return s
}

func (st *goCsqState) has(q string) bool {
	for _, c := range st.log {
		if c.q == q {
			return true
		}
	}
	return false
}

func (st *goCsqState) call(q string) *goCsqCall {
	for i := range st.log {
		if st.log[i].q == q {
			return &st.log[i]
		}
	}
	return nil
}

var goCsqBoom = errors.New("boom")

const (
	goCsqBudgetRead   = "SELECT budget FROM pca_replay_budget WHERE key = ?"
	goCsqBudgetInsert = "INSERT INTO pca_replay_budget (key, budget) VALUES (?, ?)"
	goCsqBudgetUpdate = "UPDATE pca_replay_budget SET budget = ? WHERE key = ? AND budget = ?"
	goCsqClaim        = "INSERT INTO pca_replay (key, last_counter) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE excluded.last_counter > pca_replay.last_counter"
	goCsqLastRead     = "SELECT last_counter FROM pca_replay WHERE key = ?"
)

func TestGoCSQLPlaceholders(t *testing.T) {
	s := goCsqOpen(t, &goCsqState{}, SQLStateStoreOptions{DollarPlaceholders: true})
	if s.budgetReadSQL != "SELECT budget FROM pca_replay_budget WHERE key = $1" ||
		s.budgetInsertSQL != "INSERT INTO pca_replay_budget (key, budget) VALUES ($1, $2)" ||
		s.budgetUpdateSQL != "UPDATE pca_replay_budget SET budget = $1 WHERE key = $2 AND budget = $3" {
		t.Errorf("dollar placeholders: %q %q %q", s.budgetReadSQL, s.budgetInsertSQL, s.budgetUpdateSQL)
	}
	q := goCsqOpen(t, &goCsqState{}, SQLStateStoreOptions{})
	if q.budgetReadSQL != goCsqBudgetRead || q.budgetInsertSQL != goCsqBudgetInsert || q.budgetUpdateSQL != goCsqBudgetUpdate {
		t.Errorf("question placeholders: %q %q %q", q.budgetReadSQL, q.budgetInsertSQL, q.budgetUpdateSQL)
	}
}

func TestGoCSQLBudgetTableError(t *testing.T) {
	st := &goCsqState{exec: func(q string, _ []driver.Value) (driver.Result, error) {
		if strings.HasPrefix(q, "CREATE TABLE") && strings.Contains(q, "_budget") {
			return nil, goCsqBoom
		}
		return goCsqResult{}, nil
	}}
	s, err := NewSQLStateStore(sql.OpenDB(goCsqConnector{st}), SQLStateStoreOptions{})
	if s != nil || !errors.Is(err, goCsqBoom) {
		t.Errorf("budget table: %v %v", s, err)
	}
}

func TestGoCSQLPin(t *testing.T) {
	st := &goCsqState{}
	s := goCsqOpen(t, st, SQLStateStoreOptions{})
	if p, err := s.Pin("k"); p != nil || err != nil {
		t.Errorf("no row: %v %v", p, err)
	}
	if c := st.call(goCsqLastRead); c == nil || len(c.args) != 1 || c.args[0] != "pin:k" {
		t.Errorf("pin key: %v", st.log)
	}
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return []driver.Value{int64(7)}, nil }
	if p, err := s.Pin("k"); err != nil || p == nil || *p != 7 {
		t.Errorf("row: %v %v", p, err)
	}
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return nil, goCsqBoom }
	if p, err := s.Pin("k"); p != nil || !errors.Is(err, goCsqBoom) {
		t.Errorf("error: %v %v", p, err)
	}
}

func TestGoCSQLRaisePin(t *testing.T) {
	const msg = "pca: a pin must be a non-negative safe integer"
	st := &goCsqState{exec: func(string, []driver.Value) (driver.Result, error) { return goCsqResult{n: 1}, nil }}
	s := goCsqOpen(t, st, SQLStateStoreOptions{})
	for name, v := range map[string]float64{"fraction": 1.5, "negative": -1, "above safe": 9007199254740992} {
		if err := s.RaisePin("k", v); err == nil || err.Error() != msg {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(st.log) != 0 {
		t.Errorf("a refused pin must not reach the store: %v", st.log)
	}
	for name, v := range map[string]float64{"zero": 0, "one": 1, "max safe": 9007199254740991} {
		if err := s.RaisePin("k", v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c := st.call(goCsqClaim); c == nil || c.args[0] != "pin:k" {
		t.Errorf("claim key: %v", st.log)
	}
}

func TestGoCMemoryBudgetStore(t *testing.T) {
	s := NewMemoryStateStore()
	// a claim without a budget stores no budget
	if c, r, err := s.ClaimBudgeted("a", 5, nil, nil); c != BudgetClaimed || !r.OK || err != nil {
		t.Fatalf("claim a: %v %v %v", c, r, err)
	}
	if b, err := s.Budget("a"); b != nil || err != nil {
		t.Errorf("no budget expected: %v %v", b, err)
	}
	// a second stream does not forget the first one's counter
	if c, _, _ := s.ClaimBudgeted("b", 1, nil, map[string]any{"B": jnum(1)}); c != BudgetClaimed {
		t.Fatal("claim b")
	}
	c, r, _ := s.ClaimBudgeted("a", 5, nil, nil)
	if c != BudgetReplay || r.OK || r.LastCounter == nil || *r.LastCounter != 5 {
		t.Errorf("replay of a: %v %+v", c, r)
	}
	// and a second budget does not forget the first one
	if c, _, _ := s.ClaimBudgeted("c", 1, nil, map[string]any{"B": jnum(2)}); c != BudgetClaimed {
		t.Fatal("claim c")
	}
	if b, _ := s.Budget("b"); b == nil || b["B"] != jnum(1) {
		t.Errorf("budget b: %v", b)
	}
	if b, _ := s.Budget("c"); b == nil || b["B"] != jnum(2) {
		t.Errorf("budget c: %v", b)
	}
	// a changed budget conflicts and writes nothing
	if c, _, _ := s.ClaimBudgeted("b", 2, map[string]any{"B": jnum(9)}, map[string]any{"B": jnum(3)}); c != BudgetConflict {
		t.Errorf("conflict: %v", c)
	}
	if c, _, _ := s.ClaimBudgeted("b", 2, map[string]any{"B": float64(1)}, map[string]any{"B": jnum(3)}); c != BudgetClaimed {
		t.Errorf("numeric forms compare equal: %v", c)
	}
}

func TestGoCBudgetEqual(t *testing.T) {
	one := map[string]any{"B": jnum(1)}
	for _, c := range []struct {
		name   string
		cur    map[string]any
		has    bool
		before map[string]any
		want   bool
	}{
		{"none and none", nil, false, nil, true},
		{"none stored, one read", nil, false, one, false},
		{"stored nil map, none read", nil, true, nil, true},
		{"stored nil map, one read", nil, true, one, false},
		{"stored, none read", one, true, nil, false},
		{"stored empty, none read", map[string]any{}, true, nil, false},
		{"equal numeric forms", one, true, map[string]any{"B": float64(1)}, true},
		{"different", one, true, map[string]any{"B": jnum(2)}, false},
		{"non-numeric members are ignored", map[string]any{"B": jnum(1), "s": "x"}, true, one, true},
	} {
		if got := budgetEqual(c.cur, c.has, c.before); got != c.want {
			t.Errorf("%s: %v want %v", c.name, got, c.want)
		}
	}
	if got := canonBudget(map[string]any{"B": jnum(1), "s": "x"}); len(got) != 1 || got["B"] != 1 {
		t.Errorf("canonBudget: %v", got)
	}
}

func TestGoCDecodeBudget(t *testing.T) {
	for _, raw := range []string{"not json", "null", ""} {
		if m, err := decodeBudget(raw); m != nil || err != errStoreState {
			t.Errorf("%q: %v %v", raw, m, err)
		}
	}
	if m, err := decodeBudget(`{"B":1}`); err != nil || m["B"] != jnum(1) {
		t.Errorf("valid: %v %v", m, err)
	}
}

func TestGoCSQLBudgetRead(t *testing.T) {
	st := &goCsqState{}
	s := goCsqOpen(t, st, SQLStateStoreOptions{})
	if m, err := s.Budget("k"); m != nil || err != nil {
		t.Errorf("no row: %v %v", m, err)
	}
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return nil, goCsqBoom }
	if m, err := s.Budget("k"); m != nil || !errors.Is(err, goCsqBoom) {
		t.Errorf("read error: %v %v", m, err)
	}
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return []driver.Value{`{"B":4}`}, nil }
	if m, err := s.Budget("k"); err != nil || m["B"] != jnum(4) {
		t.Errorf("row: %v %v", m, err)
	}
	st.row = func(string, []driver.Value) ([]driver.Value, error) { return []driver.Value{"garbage"}, nil }
	if m, err := s.Budget("k"); m != nil || err != errStoreState {
		t.Errorf("garbage row: %v %v", m, err)
	}
}

func goCsqClaimStore(t *testing.T, n int64, budgetRow []driver.Value, mut func(st *goCsqState)) (*SQLStateStore, *goCsqState) {
	st := &goCsqState{}
	st.exec = func(q string, _ []driver.Value) (driver.Result, error) {
		if q == goCsqClaim {
			return goCsqResult{n: n}, nil
		}
		return goCsqResult{n: 1}, nil
	}
	st.row = func(q string, _ []driver.Value) ([]driver.Value, error) {
		if q == goCsqBudgetRead {
			return budgetRow, nil
		}
		return nil, nil
	}
	if mut != nil {
		mut(st)
	}
	return goCsqOpen(t, st, SQLStateStoreOptions{}), st
}

func TestGoCSQLClaimBudgetedErrors(t *testing.T) {
	after := map[string]any{"B": jnum(5)}
	// begin
	s, st := goCsqClaimStore(t, 1, nil, func(st *goCsqState) { st.beginErr = goCsqBoom })
	if c, r, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetClaimed || r != (ClaimResult{}) || !errors.Is(err, goCsqBoom) {
		t.Errorf("begin: %v %v %v", c, r, err)
	}
	// counter upsert
	s, st = goCsqClaimStore(t, 1, nil, func(st *goCsqState) {
		inner := st.exec
		st.exec = func(q string, a []driver.Value) (driver.Result, error) {
			if q == goCsqClaim {
				return nil, goCsqBoom
			}
			return inner(q, a)
		}
	})
	if c, r, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetClaimed || r != (ClaimResult{}) || !errors.Is(err, goCsqBoom) || st.rollbacks != 1 || st.commits != 0 {
		t.Errorf("upsert: %v %v %v rb=%d", c, r, err, st.rollbacks)
	}
	// rows affected
	s, st = goCsqClaimStore(t, 1, nil, func(st *goCsqState) {
		st.exec = func(string, []driver.Value) (driver.Result, error) { return goCsqResult{err: goCsqBoom}, nil }
	})
	if c, r, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetClaimed || r != (ClaimResult{}) || !errors.Is(err, goCsqBoom) || st.rollbacks != 1 {
		t.Errorf("rows affected: %v %v %v rb=%d", c, r, err, st.rollbacks)
	}
	// unmarshalable budget
	s, st = goCsqClaimStore(t, 1, nil, nil)
	if c, r, err := s.ClaimBudgeted("k", 3, nil, map[string]any{"x": make(chan int)}); c != BudgetClaimed || r != (ClaimResult{}) || err == nil || st.rollbacks != 1 || st.commits != 0 {
		t.Errorf("marshal: %v %v %v", c, r, err)
	}
	// budget read error
	s, st = goCsqClaimStore(t, 1, nil, func(st *goCsqState) {
		inner := st.row
		st.row = func(q string, a []driver.Value) ([]driver.Value, error) {
			if q == goCsqBudgetRead {
				return nil, goCsqBoom
			}
			return inner(q, a)
		}
	})
	if c, r, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetClaimed || r != (ClaimResult{}) || !errors.Is(err, goCsqBoom) || st.commits != 0 || st.rollbacks != 1 {
		t.Errorf("budget read: %v %v %v", c, r, err)
	}
	// budget update error
	s, st = goCsqClaimStore(t, 1, []driver.Value{`{"B":1}`}, func(st *goCsqState) {
		inner := st.exec
		st.exec = func(q string, a []driver.Value) (driver.Result, error) {
			if q == goCsqBudgetUpdate {
				return nil, goCsqBoom
			}
			return inner(q, a)
		}
	})
	if c, r, err := s.ClaimBudgeted("k", 3, map[string]any{"B": jnum(1)}, after); c != BudgetClaimed || r != (ClaimResult{}) || !errors.Is(err, goCsqBoom) || st.commits != 0 {
		t.Errorf("update: %v %v %v", c, r, err)
	}
	// commit error
	s, st = goCsqClaimStore(t, 1, nil, func(st *goCsqState) { st.commitErr = goCsqBoom })
	if c, r, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetClaimed || r != (ClaimResult{}) || !errors.Is(err, goCsqBoom) {
		t.Errorf("commit: %v %v %v", c, r, err)
	}
}

func TestGoCSQLClaimBudgetedReplay(t *testing.T) {
	// counter not greater: replay with the stored counter when it can be read
	s, st := goCsqClaimStore(t, 0, nil, func(st *goCsqState) {
		st.row = func(q string, _ []driver.Value) ([]driver.Value, error) {
			if q == goCsqLastRead {
				return []driver.Value{int64(9)}, nil
			}
			return nil, nil
		}
	})
	c, r, err := s.ClaimBudgeted("k", 3, nil, map[string]any{"B": jnum(5)})
	if c != BudgetReplay || err != nil || r.OK || r.LastCounter == nil || *r.LastCounter != 9 || st.commits != 0 || st.has(goCsqBudgetInsert) {
		t.Errorf("replay: %v %+v %v", c, r, err)
	}
	// stored counter unreadable: a bare replay
	s, st = goCsqClaimStore(t, 0, nil, nil)
	c, r, err = s.ClaimBudgeted("k", 3, nil, nil)
	if c != BudgetReplay || err != nil || r != (ClaimResult{}) {
		t.Errorf("replay without counter: %v %+v %v", c, r, err)
	}
	// more than one row affected is also not a clean claim
	s, _ = goCsqClaimStore(t, 2, nil, nil)
	if c, _, _ := s.ClaimBudgeted("k", 3, nil, nil); c != BudgetReplay {
		t.Errorf("two rows: %v", c)
	}
}

func TestGoCSQLClaimBudgetedWrites(t *testing.T) {
	after := map[string]any{"B": jnum(5)}
	// no budget in the claim: counter only
	s, st := goCsqClaimStore(t, 1, nil, nil)
	if c, r, err := s.ClaimBudgeted("k", 3, nil, nil); c != BudgetClaimed || !r.OK || err != nil || st.commits != 1 || st.has(goCsqBudgetRead) {
		t.Errorf("counter only: %v %+v %v", c, r, err)
	}
	if c := st.call(goCsqClaim); c == nil || c.args[0] != "k" || c.args[1] != int64(3) {
		t.Errorf("claim args: %v", st.log)
	}
	// first budget: inserted
	s, st = goCsqClaimStore(t, 1, nil, nil)
	if c, r, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetClaimed || !r.OK || err != nil || st.commits != 1 {
		t.Errorf("insert: %v %+v %v", c, r, err)
	}
	if c := st.call(goCsqBudgetInsert); c == nil || c.args[0] != "k" || c.args[1] != `{"B":5}` {
		t.Errorf("insert args: %v", st.log)
	}
	// a budget was read but none is stored: conflict, nothing written
	s, st = goCsqClaimStore(t, 1, nil, nil)
	if c, r, err := s.ClaimBudgeted("k", 3, map[string]any{"B": jnum(1)}, after); c != BudgetConflict || r != (ClaimResult{}) || err != nil || st.has(goCsqBudgetInsert) || st.commits != 0 {
		t.Errorf("read-but-absent: %v %+v %v", c, r, err)
	}
	// a concurrent insert of the same row: conflict
	s, st = goCsqClaimStore(t, 1, nil, func(st *goCsqState) {
		inner := st.exec
		st.exec = func(q string, a []driver.Value) (driver.Result, error) {
			if q == goCsqBudgetInsert {
				return nil, goCsqBoom
			}
			return inner(q, a)
		}
	})
	if c, r, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetConflict || r != (ClaimResult{}) || err != nil || st.commits != 0 {
		t.Errorf("insert race: %v %+v %v", c, r, err)
	}
	// stored budget equals the one read: updated compare-and-set
	s, st = goCsqClaimStore(t, 1, []driver.Value{`{"B":1}`}, nil)
	if c, r, err := s.ClaimBudgeted("k", 3, map[string]any{"B": jnum(1)}, after); c != BudgetClaimed || !r.OK || err != nil || st.commits != 1 {
		t.Errorf("update: %v %+v %v", c, r, err)
	}
	if c := st.call(goCsqBudgetUpdate); c == nil || c.args[0] != `{"B":5}` || c.args[1] != "k" || c.args[2] != `{"B":1}` {
		t.Errorf("update args: %v", st.log)
	}
	// stored budget differs from the one read: conflict
	s, st = goCsqClaimStore(t, 1, []driver.Value{`{"B":1}`}, nil)
	if c, r, err := s.ClaimBudgeted("k", 3, map[string]any{"B": jnum(9)}, after); c != BudgetConflict || r != (ClaimResult{}) || err != nil || st.has(goCsqBudgetUpdate) || st.commits != 0 {
		t.Errorf("differs: %v %+v %v", c, r, err)
	}
	// stored budget is unreadable: conflict even when the read was "none"
	s, st = goCsqClaimStore(t, 1, []driver.Value{"garbage"}, nil)
	if c, _, err := s.ClaimBudgeted("k", 3, nil, after); c != BudgetConflict || err != nil || st.has(goCsqBudgetUpdate) {
		t.Errorf("garbage: %v %v", c, err)
	}
	// a stored budget while none was read: conflict
	s, st = goCsqClaimStore(t, 1, []driver.Value{`{"B":1}`}, nil)
	if c, _, _ := s.ClaimBudgeted("k", 3, nil, after); c != BudgetConflict || st.has(goCsqBudgetUpdate) {
		t.Errorf("stored but not read: %v", c)
	}
}
