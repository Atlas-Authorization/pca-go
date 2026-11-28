package pca

// The undo ledger's store contract and its reference stores (port of the pure half of the reference undo module): UndoError,
// UndoStore, KvUndoStore, MemoryUndoStore and WithReceipt. A record is a JSON object (map[string]any, numbers as JS lexemes)
// with id, v, state, ver, window_end, receipts and the optional grant_ref / bond_ref the transitions and queries read.

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

// UndoError is a refusal of the undo ledger. Code is one of not_durable, store_missing, store_corrupt, invalid,
// conflict_exhausted, signer_missing, config. Error() is "<code>: <message>".
type UndoError struct {
	Code    string
	Message string
}

// Error implements error.
func (e *UndoError) Error() string { return e.Code + ": " + e.Message }

func undoErr(code, msg string) *UndoError { return &UndoError{Code: code, Message: msg} }

// UndoQuery selects undo records: the state is required, the rest narrow it.
type UndoQuery struct {
	State string
	// WindowEndedBy keeps only records whose window ended at or before this time (the finalize sweep); nil: any.
	WindowEndedBy *int64
	// GrantRef and BondRef keep only records of that grant / bond ("" = any).
	GrantRef string
	BondRef  string
	// Limit caps the number of records (0 = all).
	Limit int
}

// UndoStore is the persistence contract of the undo ledger. Implement it over a database (a row per record with a unique id and
// a version column: UPDATE ... WHERE id = $1 AND ver = $2) or use KvUndoStore. Every method either answers or fails; a store
// that cannot decide must return an error (the coordinator then reports the outcome as unknown).
type UndoStore interface {
	// Durable is true ONLY when acknowledged writes survive a restart or crash. The coordinator refuses a store that does not say so.
	Durable() bool
	// Get returns a copy of the record, nil when there is none.
	Get(id string) (map[string]any, error)
	// Create atomically inserts the record if none with this id exists; otherwise the stored one comes back unchanged.
	Create(rec map[string]any) (created bool, existing map[string]any, err error)
	// Replace atomically replaces the record iff its stored ver is expectedVer.
	Replace(id string, expectedVer int64, next map[string]any) (bool, error)
	// List returns the records matching the query, in id order.
	List(q UndoQuery) ([]map[string]any, error)
}

func undoMatches(r map[string]any, q UndoQuery) bool {
	if r["state"] != any(q.State) {
		return false
	}
	if q.WindowEndedBy != nil {
		we, _ := jsNum(r["window_end"])
		if !(we <= float64(*q.WindowEndedBy)) {
			return false
		}
	}
	if q.GrantRef != "" && r["grant_ref"] != any(q.GrantRef) {
		return false
	}
	return q.BondRef == "" || r["bond_ref"] == any(q.BondRef)
}

func undoCopy(r map[string]any) map[string]any { return normalizeJSON(r).(map[string]any) }

// undoDecodeRecord is a well-formed stored record: version 1, a good id, a known state, a safe-integer ver and a receipt list.
func undoDecodeRecord(raw any) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	v, _ := jsNum(m["v"])
	_, recs := m["receipts"].([]any)
	if !ok || v != 1 || !undoIDOk(m["id"]) || !contains(undoStates, func() string { s, _ := m["state"].(string); return s }()) || !jsIsInt(m["ver"]) || !recs {
		return nil, undoErr("store_corrupt", "an undo record has the wrong shape")
	}
	return m, nil
}

func undoCheckID(id any) error {
	if !undoIDOk(id) {
		return undoErr("invalid", "an undo record id is a non-empty string without control characters")
	}
	return nil
}

func undoSorted(in []map[string]any, limit int) []map[string]any {
	sort.Slice(in, func(i, j int) bool { return dsCmpStr(in[i]["id"].(string), in[j]["id"].(string)) < 0 })
	if limit > 0 && len(in) > limit {
		in = in[:limit]
	}
	return in
}

// dsCmpStr orders two strings by UTF-16 code units (JavaScript's default string order).
func dsCmpStr(a, b string) int {
	x, y := utf16Units(a), utf16Units(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return len(x) - len(y)
}

// ---- the in-memory store ------------------------------------------------------------------------------------------------------

// MemoryUndoStore is a process-memory UndoStore: Durable is false, so the coordinator refuses it unless the caller says, for a
// test, that it accepts losing every open window on restart. Never use it in production.
type MemoryUndoStore struct {
	mu sync.Mutex
	m  map[string]map[string]any
}

// NewMemoryUndoStore returns an empty MemoryUndoStore.
func NewMemoryUndoStore() *MemoryUndoStore { return &MemoryUndoStore{m: map[string]map[string]any{}} }

// Durable implements UndoStore (false).
func (s *MemoryUndoStore) Durable() bool { return false }

// Get implements UndoStore.
func (s *MemoryUndoStore) Get(id string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.m[id]; ok {
		return undoCopy(r), nil
	}
	return nil, nil
}

// Create implements UndoStore.
func (s *MemoryUndoStore) Create(rec map[string]any) (bool, map[string]any, error) {
	if err := undoCheckID(rec["id"]); err != nil {
		return false, nil, err
	}
	id := rec["id"].(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[id]; ok {
		return false, undoCopy(cur), nil
	}
	s.m[id] = undoCopy(rec)
	return true, nil, nil
}

// Replace implements UndoStore.
func (s *MemoryUndoStore) Replace(id string, expectedVer int64, next map[string]any) (bool, error) {
	if next["id"] != any(id) {
		return false, undoErr("invalid", "replace: the record id cannot change")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[id]
	if !ok {
		return false, nil
	}
	if ver, _ := jsNum(cur["ver"]); ver != float64(expectedVer) {
		return false, nil
	}
	s.m[id] = undoCopy(next)
	return true, nil
}

// List implements UndoStore.
func (s *MemoryUndoStore) List(q UndoQuery) ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, r := range s.m {
		if undoMatches(r, q) {
			out = append(out, undoCopy(r))
		}
	}
	return undoSorted(out, q.Limit), nil
}

// ---- the kv store ----------------------------------------------------------------------------------------------------------------

// UndoKv is the key-value seam of KvUndoStore: the AtomicKV contract plus a key listing. MemoryAtomicKV and DurableAtomicKV
// implement it.
type UndoKv interface {
	AtomicKV
	// Keys lists every key.
	Keys() ([]string, error)
}

// Keys lists every key of the in-memory store.
func (s *MemoryAtomicKV) Keys() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out, nil
}

const undoKvPrefix = "pca-undo/v1/"

// KvUndoStore is the reference UndoStore over any UndoKv (one document per record, every write one atomic read-modify-write).
// Durable is declared by the caller because a kv cannot tell: true only over a persistent kv (OpenDurableState(...) through
// NewDurableAtomicKV), false over an in-memory one.
//
// shortcut: List scans every key (fine for a single host's backlog); a database store indexes (state, window_end).
type KvUndoStore struct {
	kv      UndoKv
	durable bool
}

// NewKvUndoStore builds the store; kv is required.
func NewKvUndoStore(kv UndoKv, durable bool) (*KvUndoStore, error) {
	if kv == nil {
		return nil, undoErr("store_missing", "KvUndoStore needs a key-value store")
	}
	return &KvUndoStore{kv: kv, durable: durable}, nil
}

// Durable implements UndoStore.
func (s *KvUndoStore) Durable() bool { return s.durable }

func undoDecodeBytes(b []byte) (map[string]any, error) {
	if b == nil {
		return nil, nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil, undoErr("store_corrupt", "an undo record has the wrong shape")
	}
	return undoDecodeRecord(normalizeJSON(v))
}

func undoEncode(r map[string]any) ([]byte, error) { return json.Marshal(normalizeJSON(r)) }

// Get implements UndoStore.
func (s *KvUndoStore) Get(id string) (map[string]any, error) {
	if err := undoCheckID(id); err != nil {
		return nil, err
	}
	b, ok, err := s.kv.Get(undoKvPrefix + id)
	if err != nil || !ok {
		return nil, err
	}
	return undoDecodeBytes(b)
}

// Create implements UndoStore.
func (s *KvUndoStore) Create(rec map[string]any) (bool, map[string]any, error) {
	if err := undoCheckID(rec["id"]); err != nil {
		return false, nil, err
	}
	enc, err := undoEncode(rec)
	if err != nil {
		return false, nil, err
	}
	var existing map[string]any
	var derr error
	err = s.kv.Update(undoKvPrefix+rec["id"].(string), func(prev []byte) []byte {
		existing, derr = undoDecodeBytes(prev)
		if derr != nil || existing != nil {
			return nil
		}
		return enc
	})
	if err == nil {
		err = derr
	}
	if err != nil {
		return false, nil, err
	}
	return existing == nil, existing, nil
}

// Replace implements UndoStore.
func (s *KvUndoStore) Replace(id string, expectedVer int64, next map[string]any) (bool, error) {
	if err := undoCheckID(id); err != nil {
		return false, err
	}
	if next["id"] != any(id) {
		return false, undoErr("invalid", "replace: the record id cannot change")
	}
	enc, err := undoEncode(next)
	if err != nil {
		return false, err
	}
	done := false
	var derr error
	err = s.kv.Update(undoKvPrefix+id, func(prev []byte) []byte {
		cur, e := undoDecodeBytes(prev)
		if e != nil {
			derr = e
			return nil
		}
		ver, _ := jsNum(cur["ver"])
		done = cur != nil && ver == float64(expectedVer)
		if !done {
			return nil
		}
		return enc
	})
	if err == nil {
		err = derr
	}
	return done && err == nil, err
}

// List implements UndoStore.
func (s *KvUndoStore) List(q UndoQuery) ([]map[string]any, error) {
	keys, err := s.kv.Keys()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, k := range keys {
		if strings.HasPrefix(k, undoKvPrefix) {
			names = append(names, k)
		}
	}
	sort.Slice(names, func(i, j int) bool { return dsCmpStr(names[i], names[j]) < 0 })
	var out []map[string]any
	for _, k := range names {
		b, ok, err := s.kv.Get(k)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		r, err := undoDecodeBytes(b)
		if err != nil {
			return nil, err
		}
		if r != nil && undoMatches(r, q) {
			out = append(out, r)
		}
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

// IsUndoStore reports whether s is a usable store (a non-nil UndoStore).
func IsUndoStore(s any) bool {
	st, ok := s.(UndoStore)
	return ok && st != nil
}

// WithReceipt appends the signed receipt of an applied transition (linked to the previous one by its digest, "" for the first):
// rec is the record AFTER the transition, event and note are those the transition returned, at the trusted clock. It returns a
// copy of rec with the receipt added; rec itself is not modified.
func WithReceipt(rec map[string]any, event, note string, at int64, key *KeyPair) (map[string]any, error) {
	if key == nil {
		return nil, undoErr("signer_missing", "the undo service key must be a 32-byte Ed25519 secret")
	}
	out := undoCopy(rec)
	receipts, _ := out["receipts"].([]any)
	prev := ""
	if n := len(receipts); n > 0 {
		last, _ := receipts[n-1].(map[string]any)
		d, err := UndoReceiptDigest(last)
		if err != nil {
			return nil, err
		}
		prev = d
	}
	id, _ := out["id"].(string)
	state, _ := out["state"].(string)
	cd, _ := out["compensation_digest"].(string)
	r, err := SignUndoReceipt(UndoReceiptBody{Record: id, Event: event, State: state, At: at, CompensationDigest: cd, Prev: prev, Note: note}, key)
	if err != nil {
		return nil, err
	}
	out["receipts"] = append(append([]any{}, receipts...), normalizeJSON(r))
	return out, nil
}
