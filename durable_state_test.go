//go:build unix

package pca

// The durable state store: the shared scenario corpus (every lane replays the same directory scenarios), plus the parts a corpus
// cannot carry: real concurrent writers and processes, real SIGKILL crash safety, file modes, and the in-memory store.

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const dsTestDead = 999999999

func dsTestSubst(s, host string) string {
	s = strings.ReplaceAll(s, "$HOST", host)
	s = strings.ReplaceAll(s, "$PID", strconv.Itoa(os.Getpid()))
	return strings.ReplaceAll(s, "$DEAD", strconv.Itoa(dsTestDead))
}

func dsTestSO(v any, host string) any {
	switch t := v.(type) {
	case string:
		if t == "$HOST" {
			return host
		}
		if t == "$PID" {
			return float64(os.Getpid())
		}
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = dsTestSO(x, host)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = dsTestSO(x, host)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	}
	return v
}

var (
	dsReFence = regexp.MustCompile(`^(state\.fence\.\d+)-[0-9a-f]+`)
	dsReQuar  = regexp.MustCompile(`\.quarantine-.*$`)
	dsReLegac = regexp.MustCompile(`^state\.lock\.legacy-recovered-.*$`)
)

func dsTestNormName(f string) string {
	f = dsReFence.ReplaceAllString(f, "$1-*")
	f = dsReQuar.ReplaceAllString(f, ".quarantine-*")
	return dsReLegac.ReplaceAllString(f, "state.lock.legacy-recovered-*")
}

func dsTestReadOpt(dir, f string) any {
	b, err := os.ReadFile(filepath.Join(dir, f))
	if err != nil {
		return nil
	}
	return string(b)
}

func dsTestParse(dir, f string) (any, bool) {
	b, err := os.ReadFile(filepath.Join(dir, f))
	if err != nil {
		return nil, false
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	return v, true
}

func dsTestStrip(v any) any {
	if m, ok := v.(map[string]any); ok {
		out := map[string]any{}
		for k, x := range m {
			if k != "t" {
				out[k] = x
			}
		}
		return out
	}
	return v
}

func dsTestSnapshot(dir string) map[string]any {
	es, _ := os.ReadDir(dir)
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	fences := []any{}
	has := func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	if has("state.fence") {
		o, ok := dsTestParse(dir, "state.fence")
		arr, isArr := []any(nil), false
		if m, isMap := o.(map[string]any); ok && isMap {
			arr, isArr = m["fences"].([]any)
		}
		if isArr {
			for _, f := range arr {
				fences = append(fences, dsTestStrip(f))
			}
		} else {
			fences = append(fences, map[string]any{"unreadable": dsTestNormName("state.fence")})
		}
	}
	type ent struct {
		g float64
		n string
	}
	var ents []ent
	for _, n := range names {
		if g, ok := dsFenceEntry(n); ok {
			ents = append(ents, ent{g, n})
		}
	}
	sort.SliceStable(ents, func(i, j int) bool {
		if ents[i].g != ents[j].g {
			return ents[i].g < ents[j].g
		}
		return ents[i].n < ents[j].n
	})
	for _, e := range ents {
		o, ok := dsTestParse(dir, e.n)
		var f any
		if m, isMap := o.(map[string]any); ok && isMap {
			f = m["fence"]
		}
		if _, isMap := f.(map[string]any); isMap {
			fences = append(fences, dsTestStrip(f))
		} else {
			fences = append(fences, map[string]any{"unreadable": dsTestNormName(e.n)})
		}
	}
	var g uint64
	for _, n := range names {
		if x, ok := dsLockNameGen(n); ok && x > g {
			g = x
		}
	}
	var top any
	if g > 0 {
		o, ok := dsTestParse(dir, fmt.Sprintf("state.lock.%d", g))
		if !ok || o == nil {
			top = map[string]any{"g": float64(g), "st": "unreadable"}
		} else {
			m := map[string]any{"g": float64(g)}
			if b, isMap := o.(map[string]any); isMap {
				for _, k := range []string{"st", "recovering", "recoveredFrom"} {
					if v, has := b[k]; has {
						m[k] = v
					}
				}
			}
			top = m
		}
	}
	files := []any{}
	for _, f := range names {
		if strings.HasPrefix(f, "state.lock.tmp-") || strings.HasPrefix(f, "state.probe-") || strings.Contains(f, ".tmp-") {
			continue
		}
		files = append(files, dsTestNormName(f))
	}
	return map[string]any{"t": "dir", "files": files, "journal": dsTestReadOpt(dir, "state.journal"), "head": dsTestReadOpt(dir, "state.head"), "fences": fences, "top": top}
}

type dsTestOp struct {
	Op    string          `json:"op"`
	Key   string          `json:"key"`
	Kind  string          `json:"kind"`
	Name  string          `json:"name"`
	File  string          `json:"file"`
	Text  *string         `json:"text"`
	Value json.RawMessage `json:"value"`
	Arg   json.RawMessage `json:"arg"`
}

type dsTestStep struct {
	T    string         `json:"t"`
	Opts map[string]any `json:"opts"`
	Ops  []dsTestOp     `json:"ops"`
	File string         `json:"file"`
	Text *string        `json:"text"`
}

type dsTestScenario struct {
	Files map[string]string `json:"files"`
	Steps []dsTestStep      `json:"steps"`
}

func dsTestErr(norm func(string) string, err error) map[string]any {
	de, ok := err.(*DurableStateError)
	if !ok {
		panic(err)
	}
	return map[string]any{"err": map[string]any{"code": string(de.Code), "msg": norm(de.Message)}}
}

func dsTestNum(m map[string]any, k string) (float64, bool) {
	f, ok := m[k].(float64)
	return f, ok
}

func dsTestRun(t *testing.T, sc dsTestScenario) any {
	dir := t.TempDir()
	host := dsHostname()
	pid := strconv.Itoa(os.Getpid())
	norm := func(s string) string {
		s = strings.ReplaceAll(s, dir, "$DIR")
		s = strings.ReplaceAll(s, host, "$HOST")
		s = strings.ReplaceAll(s, "pid="+pid, "pid=$PID")
		return strings.ReplaceAll(s, "pid "+pid, "pid $PID")
	}
	for f, txt := range sc.Files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(dsTestSubst(txt, host)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile := func(file string, text *string) {
		if text == nil {
			_ = os.Remove(filepath.Join(dir, file))
			return
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(dsTestSubst(*text, host)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := []any{}
	for _, st := range sc.Steps {
		switch st.T {
		case "write":
			writeFile(st.File, st.Text)
			out = append(out, nil)
		case "dir":
			out = append(out, dsTestSnapshot(dir))
		case "recover":
			opts := map[string]any{"force": true}
			if o, ok := dsTestSO(st.Opts, host).(map[string]any); ok {
				for k, v := range o {
					opts[k] = v
				}
			}
			r, err := RecoverDurableStateValue(dir, opts)
			if err != nil {
				out = append(out, dsTestErr(norm, err))
				continue
			}
			m := map[string]any{"released": r.Released, "reason": r.Reason}
			if r.LockFile != "" {
				m["lockFile"] = norm(r.LockFile)
			}
			out = append(out, map[string]any{"ok": m})
		case "open":
			op := st.Opts
			counter := int64(1000)
			o := DurableStateOptions{Dir: dir, Now: func() int64 { c := counter; counter++; return c }}
			if d, ok := op["dir"].(string); ok && d == "" {
				o.Dir = ""
			}
			if l, ok := op["hmacKey"].(string); ok {
				k := sha256.Sum256([]byte(l))
				o.HmacKey = k[:]
			}
			if n, ok := dsTestNum(op, "hmacKeyBytes"); ok {
				o.HmacKey = make([]byte, int(n))
			}
			o.RecoverFromCorruption = op["recoverFromCorruption"] == true
			if n, ok := dsTestNum(op, "lockTimeoutMs"); ok {
				o.LockTimeoutMs = int64(n)
			}
			if n, ok := dsTestNum(op, "compactEvery"); ok {
				o.CompactEvery = int(n)
				if o.CompactEvery == 0 {
					o.CompactEvery = 2 // the reference: Math.max(2, 0)
				}
			}
			if n, ok := dsTestNum(op, "maxValueBytes"); ok {
				o.MaxValueBytes = int(n)
			}
			h, err := OpenDurableState(o)
			if err != nil {
				out = append(out, dsTestErr(norm, err))
				continue
			}
			res := []any{}
			saved := map[string][2]any{}
			undef := map[string]any{"$undef": true}
			for _, x := range st.Ops {
				var v any
				var err error
				switch x.Op {
				case "set":
					err = h.Set(x.Key, x.Value)
				case "get":
					got, ok, e := h.Get(x.Key)
					err = e
					if ok {
						v = got
					} else {
						v = undef
					}
				case "keys":
					ks, e := h.Keys()
					err = e
					v = ks
				case "verify":
					p, e := h.Verify()
					err = e
					v = map[string]any{"seq": float64(p.Seq), "hash": p.Hash}
				case "position":
					p := h.Position()
					v = map[string]any{"seq": float64(p.Seq), "hash": p.Hash}
				case "update":
					var arg any
					if x.Arg != nil {
						_ = json.Unmarshal(x.Arg, &arg)
					}
					got, ok, e := h.Update(x.Key, func(prev any, has bool) (any, bool) {
						switch x.Kind {
						case "append":
							a, _ := prev.([]any)
							return append(append([]any{}, a...), arg), true
						case "max":
							if !has {
								return x.Arg, true
							}
							af, _ := arg.(float64)
							pf, _ := prev.(float64)
							if af > pf {
								return x.Arg, true
							}
							return nil, false
						case "noop":
							return nil, false
						case "same":
							return prev, has
						case "set":
							return x.Arg, true
						}
						panic("unknown update kind " + x.Kind)
					})
					err = e
					if ok {
						v = got
					} else {
						v = undef
					}
				case "fs":
					writeFile(x.File, x.Text)
				case "save":
					saved[x.Name] = [2]any{dsTestReadOpt(dir, "state.journal"), dsTestReadOpt(dir, "state.head")}
				case "restore":
					s := saved[x.Name]
					for i, f := range []string{"state.journal", "state.head"} {
						if txt, ok := s[i].(string); ok {
							_ = os.WriteFile(filepath.Join(dir, f), []byte(txt), 0o600)
						} else {
							_ = os.Remove(filepath.Join(dir, f))
						}
					}
				default:
					panic("unknown op " + x.Op)
				}
				if err != nil {
					res = append(res, dsTestErr(norm, err))
				} else {
					res = append(res, map[string]any{"ok": v})
				}
			}
			out = append(out, map[string]any{"ok": map[string]any{"recovered": h.Recovered(), "ops": res}})
		default:
			panic("unknown step " + st.T)
		}
	}
	out = append(out, dsTestSnapshot(dir))
	return out
}

func dsTestNormalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

func TestDurableStateCorpusReplaysIdentically(t *testing.T) {
	fh, err := os.Open("testdata/ref-durable-state.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Fn   string            `json:"fn"`
			Name string            `json:"name"`
			Args []json.RawMessage `json:"args"`
			Out  any               `json:"out"`
		} `json:"cases"`
	}
	if err := json.NewDecoder(zr).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 200 {
		t.Fatalf("corpus too small: %d", len(doc.Cases))
	}
	bad := 0
	for _, c := range doc.Cases {
		if c.Fn != "scenario" {
			t.Fatalf("%s: fn %q", c.Name, c.Fn)
		}
		var sc dsTestScenario
		if err := json.Unmarshal(c.Args[0], &sc); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got := dsTestNormalize(dsTestRun(t, sc))
		if !reflect.DeepEqual(got, c.Out) {
			bad++
			if bad <= 3 {
				w, _ := json.Marshal(c.Out)
				g, _ := json.Marshal(got)
				t.Errorf("%s differs\n  want %s\n  got  %s", c.Name, w, g)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d scenarios differ", bad, len(doc.Cases))
	}
}

func dsTestOpen(t *testing.T, d string) *DurableState {
	t.Helper()
	s, err := OpenDurableState(DurableStateOptions{Dir: d})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDurableStateModes(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	s := dsTestOpen(t, d)
	if err := s.Set("a", 1); err != nil {
		t.Fatal(err)
	}
	mode := func(p string) os.FileMode {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	if m := mode(d); m != 0o700 {
		t.Fatalf("dir mode %o", m)
	}
	for _, f := range []string{"state.journal", "state.head"} {
		if m := mode(filepath.Join(d, f)); m != 0o600 {
			t.Fatalf("%s mode %o", f, m)
		}
	}
}

func dsTestIncrement(s *DurableState) error {
	_, _, err := s.Update("n", func(prev any, ok bool) (any, bool) {
		n, _ := prev.(float64)
		return n + 1, true
	})
	return err
}

func TestDurableStateRacingWritersLoseNoUpdate(t *testing.T) {
	d := t.TempDir()
	const writers, each = 4, 12
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := OpenDurableState(DurableStateOptions{Dir: d, LockTimeoutMs: 60_000})
			if err != nil {
				errs <- err
				return
			}
			for j := 0; j < each; j++ {
				if err := dsTestIncrement(s); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	s := dsTestOpen(t, d)
	v, _, err := s.Get("n")
	if err != nil || v != float64(writers*each) {
		t.Fatalf("n = %v, %v", v, err)
	}
	if p, err := s.Verify(); err != nil || p.Seq < writers*each {
		t.Fatalf("verify: %v %v", p, err)
	}
}

func TestDurableStateRacingProcessesLoseNoUpdate(t *testing.T) {
	if os.Getenv("PCA_DS_RACE_DIR") != "" {
		return
	}
	d := t.TempDir()
	const procs, each = 3, 10
	cmds := make([]*exec.Cmd, procs)
	for i := range cmds {
		c := exec.Command(os.Args[0], "-test.run=^TestDurableStateRaceChild$")
		c.Env = append(os.Environ(), "PCA_DS_RACE_DIR="+d, "PCA_DS_RACE_N="+strconv.Itoa(each))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = c
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	s := dsTestOpen(t, d)
	if v, _, err := s.Get("n"); err != nil || v != float64(procs*each) {
		t.Fatalf("n = %v, %v", v, err)
	}
	if _, err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

// TestDurableStateRaceChild is the child body of the racing-processes test (a no-op in a normal run).
func TestDurableStateRaceChild(t *testing.T) {
	d := os.Getenv("PCA_DS_RACE_DIR")
	if d == "" {
		return
	}
	n, _ := strconv.Atoi(os.Getenv("PCA_DS_RACE_N"))
	s, err := OpenDurableState(DurableStateOptions{Dir: d, LockTimeoutMs: 60_000})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := dsTestIncrement(s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDurableStateOneHandleSharedBetweenGoroutines(t *testing.T) {
	s := dsTestOpen(t, t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := dsTestIncrement(s); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if v, _, _ := s.Get("n"); v != float64(40) {
		t.Fatalf("n = %v", v)
	}
}

func TestDurableStateLiveHolderIsNeverRobbed(t *testing.T) {
	d := t.TempDir()
	s := dsTestOpen(t, d)
	if err := s.Set("a", 1); err != nil {
		t.Fatal(err)
	}
	top, _ := dsTopGenIn(d)
	body := fmt.Sprintf(`{"st":"held","pid":%d,"host":%s,"nonce":"n"}`, os.Getpid(), dsJS(dsHostname()))
	if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("state.lock.%d", top+1)), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenDurableState(DurableStateOptions{Dir: d, LockTimeoutMs: 150})
	if de, ok := err.(*DurableStateError); !ok || de.Code != DurableLockTimeout {
		t.Fatalf("want lock-timeout, got %v", err)
	}
}

func TestDurableStateMemoryKvSemantics(t *testing.T) {
	m := CreateMemoryDurableKv()
	setIfAbsent := func(v any) func(any, bool) (any, bool) {
		return func(_ any, has bool) (any, bool) { return v, !has }
	}
	if v, ok, err := m.Update("hw", setIfAbsent(5)); err != nil || !ok || v != float64(5) {
		t.Fatalf("%v %v %v", v, ok, err)
	}
	if v, _, _ := m.Update("hw", setIfAbsent(9)); v != float64(5) {
		t.Fatalf("second update changed the value: %v", v)
	}
	if err := m.Set("b", map[string]any{"x": []any{1, nil}}); err != nil {
		t.Fatal(err)
	}
	if ks, _ := m.Keys(); !reflect.DeepEqual(ks, []string{"b", "hw"}) {
		t.Fatalf("keys %v", ks)
	}
	if _, ok, _ := m.Update("nope", func(any, bool) (any, bool) { return nil, false }); ok {
		t.Fatal("a refused update on an absent key must stay absent")
	}
}

func TestDurableStateOperationStoreOverDurableKv(t *testing.T) {
	store := DurableOperationStore(dsTestOpen(t, t.TempDir()), "")
	rec := OperationRecord{ID: "op1", State: "executing"}
	if created, _, err := store.Create(rec); err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if created, existing, err := store.Create(rec); err != nil || created || existing.ID != "op1" {
		t.Fatalf("second create: %v %v %v", created, existing, err)
	}
	got, err := store.Get("op1")
	if err != nil || got == nil || got.State != "executing" {
		t.Fatalf("get: %v %v", got, err)
	}
}

// ---- real SIGKILL crash safety: the test binary re-runs itself and the child kills itself at the crash point ----

// TestDurableStateCrashChild is the child body of the crash tests (a no-op in a normal run).
func TestDurableStateCrashChild(t *testing.T) {
	d, point := os.Getenv("PCA_DS_CRASH_DIR"), os.Getenv("PCA_DS_CRASH_AT")
	if d == "" || point == "" {
		return
	}
	s, err := OpenDurableState(DurableStateOptions{Dir: d, TestCrashAt: DurableCrashAt(point)})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Set("k", "new")
	t.Fatal("the process must have been killed")
}

func dsTestCrashAt(t *testing.T, point DurableCrashAt) string {
	t.Helper()
	d := t.TempDir()
	if err := dsTestOpen(t, d).Set("k", "old"); err != nil {
		t.Fatal(err)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestDurableStateCrashChild$")
	c.Env = append(os.Environ(), "PCA_DS_CRASH_DIR="+d, "PCA_DS_CRASH_AT="+string(point))
	err := c.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("the child must die by SIGKILL, got %v", err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the child must die by SIGKILL, got %v", err)
	}
	return d
}

func TestDurableStateKilledBetweenTempWriteAndRename(t *testing.T) {
	d := dsTestCrashAt(t, DurableCrashAfterTempWrite)
	s, err := OpenDurableState(DurableStateOptions{Dir: d, LockTimeoutMs: 5_000})
	if err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.Get("k"); v != "old" {
		t.Fatalf("old state not intact: %v", v)
	}
	if err := s.Set("k", "later"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableStateKilledAfterJournalRenameHeadIsRepaired(t *testing.T) {
	d := dsTestCrashAt(t, DurableCrashAfterJournalRename)
	s, err := OpenDurableState(DurableStateOptions{Dir: d, LockTimeoutMs: 5_000})
	if err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.Get("k"); v != "new" {
		t.Fatalf("new value not durable: %v", v)
	}
	b, err := os.ReadFile(filepath.Join(d, "state.head"))
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Verify(); err != nil || p.Seq != head.Seq {
		t.Fatalf("the open must repair the head: %v %v (head seq %d)", p, err, head.Seq)
	}
}
