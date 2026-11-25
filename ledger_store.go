package pca

// The durable transparency ledger (the reference ledger-store): KvLedgerStore, the reference LedgerStore over an atomic key-value
// store, and StoredLedger, the checkpoint-verified log over any LedgerStore.
//
// CLAIMED: TAMPER EVIDENCE, given at least one honest independent witness. The ledger is an append-only Merkle log with
// guardian-signed checkpoints. A party holding a checkpoint can later demand a consistency proof and catch a log that was
// rewritten, truncated or forked.
//
// THE STORE: Append and AppendCheckpoint are compare-and-swap on the current length (all entries of a batch or none, so two writers
// never assign one index twice and a log never has holes); committing the same batch again at the same position is a replay.
//
// OpenStoredLedger rebuilds the Merkle tree from the stored commits and checks it against EVERY stored checkpoint (guardian
// signature, signed prev_root chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each root): a
// store that lost entries after a checkpoint (rollback), edited an entry (tamper) or holds a forged checkpoint FAILS CLOSED with a
// typed error. Checkpoint refuses to sign a head that is not consistent with the previous one.

import (
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"
)

// LedgerDocKey is the key KvLedgerStore keeps its single document under by default.
const LedgerDocKey = "pca-ledger-store/v1"

type ledgerDoc struct {
	commits     []string
	checkpoints []map[string]any
}

func ledgerCorrupt(why string) error { return &LedgerStoreError{"store_corrupt", why} }

func ledgerDocDecode(raw []byte) (*ledgerDoc, error) {
	d := &ledgerDoc{commits: []string{}, checkpoints: []map[string]any{}}
	if raw == nil {
		return d, nil
	}
	v, err := ParseJSONLenient(raw)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, ledgerCorrupt("ledger document has the wrong shape")
	}
	ver, isNum := jsNum(m["v"])
	cs, csOK := m["commits"].([]any)
	cps, cpsOK := m["checkpoints"].([]any)
	if !isNum || ver != 1 || !csOK || !cpsOK {
		return nil, ledgerCorrupt("ledger document has the wrong shape")
	}
	for _, c := range cs {
		s, isStr := c.(string)
		if !isStr || s == "" {
			return nil, ledgerCorrupt("ledger document has the wrong shape")
		}
		d.commits = append(d.commits, s)
	}
	for _, c := range cps {
		cm, isMap := c.(map[string]any)
		if !isMap {
			return nil, ledgerCorrupt("malformed checkpoint entry")
		}
		if _, hasSth := cm["sth"].(map[string]any); !hasSth {
			return nil, ledgerCorrupt("malformed checkpoint entry")
		}
		d.checkpoints = append(d.checkpoints, normalizeJSON(cm).(map[string]any))
	}
	return d, nil
}

func (d *ledgerDoc) encode() ([]byte, error) {
	cs := make([]any, len(d.commits))
	for i, c := range d.commits {
		cs[i] = c
	}
	cps := make([]any, len(d.checkpoints))
	for i, c := range d.checkpoints {
		cps[i] = c
	}
	return json.Marshal(map[string]any{"v": jsNumber(1), "commits": cs, "checkpoints": cps})
}

func ledgerOutcome(outcome, key string, n int) map[string]any {
	return map[string]any{"outcome": outcome, key: jsNumber(float64(n))}
}

// ledgerDocAppend appends commits to d iff it has exactly expected entries (all or none); a batch already stored there is a replay.
func ledgerDocAppend(d *ledgerDoc, expected, commits any) (map[string]any, error) {
	exp, ok := storeSafeInt(expected)
	if !ok || exp < 0 {
		return nil, storeRange("append: expectedSize must be a non-negative safe integer")
	}
	list, isList := commits.([]any)
	if !isList || len(list) == 0 {
		return nil, storeRange("append: commits must be a non-empty array of non-empty strings")
	}
	strs := make([]string, 0, len(list))
	for _, c := range list {
		s, isStr := c.(string)
		if !isStr || s == "" {
			return nil, storeRange("append: commits must be a non-empty array of non-empty strings")
		}
		strs = append(strs, s)
	}
	size := int64(len(d.commits))
	if exp < size {
		same := true
		for i, c := range strs {
			if exp+int64(i) >= size || d.commits[exp+int64(i)] != c {
				same = false
				break
			}
		}
		if same {
			return ledgerOutcome("replayed", "size", int(size)), nil
		}
		return ledgerOutcome("conflict", "size", int(size)), nil
	}
	if exp > size {
		return ledgerOutcome("conflict", "size", int(size)), nil
	}
	d.commits = append(d.commits, strs...)
	return ledgerOutcome("appended", "size", len(d.commits)), nil
}

func ledgerConflict(count int, reason string) map[string]any {
	m := ledgerOutcome("conflict", "count", count)
	m["reason"] = reason
	return m
}

// ledgerDocCheckpoint appends a checkpoint at position expected: it must lie inside the log and extend the previous checkpoint.
func ledgerDocCheckpoint(d *ledgerDoc, expected, cp any) (map[string]any, error) {
	exp, ok := storeSafeInt(expected)
	if !ok || exp < 0 {
		return nil, storeRange("appendCheckpoint: expectedCount must be a non-negative safe integer")
	}
	count := int64(len(d.checkpoints))
	if exp < count {
		a, e1 := HashCanonical(d.checkpoints[exp])
		b, e2 := HashCanonical(cp)
		if e1 != nil {
			return nil, e1
		}
		if e2 != nil {
			return nil, e2
		}
		if a == b {
			return ledgerOutcome("replayed", "count", int(count)), nil
		}
		return ledgerConflict(int(count), "another checkpoint holds that position"), nil
	}
	if exp > count {
		return ledgerConflict(int(count), "the checkpoint position is ahead of the log"), nil
	}
	cpm, _ := cp.(map[string]any)
	sth, _ := cpm["sth"].(map[string]any)
	size, sizeOK := storeSafeInt(sth["size"])
	_, rootOK := sth["root"].(string)
	sf, _ := jsNum(sth["size"])
	if sth == nil || !sizeOK || size < 0 || (sf == 0 && math.Signbit(sf)) || !rootOK {
		return ledgerConflict(int(count), "malformed checkpoint"), nil
	}
	if size > int64(len(d.commits)) {
		return ledgerConflict(int(count), "the checkpoint is beyond the end of the log"), nil
	}
	if count > 0 {
		last, _ := d.checkpoints[count-1]["sth"].(map[string]any)
		lastSize, _ := jsNum(last["size"])
		if float64(size) < lastSize || (float64(size) == lastSize && sth["root"] != last["root"]) {
			return ledgerConflict(int(count), "the checkpoint does not extend the previous one"), nil
		}
	}
	d.checkpoints = append(d.checkpoints, normalizeJSON(cpm).(map[string]any))
	return ledgerOutcome("appended", "count", len(d.checkpoints)), nil
}

// KvLedgerStore is the reference LedgerStore: the whole log is one document in an atomic key-value store, so every write is one
// atomic read-modify-write. LIMIT: rewritten on every write; a production log lives in a database with a unique index on the
// position.
type KvLedgerStore struct {
	kv  AtomicKV
	key string
}

var _ LedgerStore = (*KvLedgerStore)(nil)

// NewKvLedgerStore returns a ledger store over kv under LedgerDocKey (store_missing without a kv).
func NewKvLedgerStore(kv AtomicKV) (*KvLedgerStore, error) {
	return NewKvLedgerStoreAt(kv, LedgerDocKey)
}

// NewKvLedgerStoreAt is NewKvLedgerStore under another key.
func NewKvLedgerStoreAt(kv AtomicKV, key string) (*KvLedgerStore, error) {
	if kv == nil {
		return nil, &LedgerStoreError{"store_missing", "KvLedgerStore needs an atomic kv"}
	}
	return &KvLedgerStore{kv: kv, key: key}, nil
}

func (s *KvLedgerStore) doc() (*ledgerDoc, error) {
	raw, ok, err := s.kv.Get(s.key)
	if err != nil {
		return nil, err
	}
	if !ok {
		raw = nil
	}
	return ledgerDocDecode(raw)
}

// Size is the number of stored commits.
func (s *KvLedgerStore) Size() (int, error) {
	d, err := s.doc()
	if err != nil {
		return 0, err
	}
	return len(d.commits), nil
}

func (s *KvLedgerStore) readAny(from, to any) ([]string, error) {
	d, err := s.doc()
	if err != nil {
		return nil, err
	}
	f, ok1 := storeSafeInt(from)
	t, ok2 := storeSafeInt(to)
	if !ok1 || !ok2 || f < 0 || f > t || t > int64(len(d.commits)) {
		return nil, storeRange("read: range is not inside the log")
	}
	return append([]string{}, d.commits[f:t]...), nil
}

// Read returns the commits in [from, to); a range outside the log is an error.
func (s *KvLedgerStore) Read(from, to int) ([]string, error) { return s.readAny(from, to) }

func (s *KvLedgerStore) appendAny(expected, commits any) (map[string]any, error) {
	var out map[string]any
	err := storeKvTxn(s.kv, s.key, func(prev []byte) ([]byte, error) {
		d, e := ledgerDocDecode(prev)
		if e != nil {
			return nil, e
		}
		r, e := ledgerDocAppend(d, expected, commits)
		if e != nil {
			return nil, e
		}
		out = r
		if r["outcome"] != any("appended") {
			return nil, nil
		}
		return d.encode()
	})
	return out, err
}

// Append appends commits iff the log has exactly expected entries: {outcome: appended | replayed | conflict, size}.
func (s *KvLedgerStore) Append(expected int, commits []string) (map[string]any, error) {
	list := make([]any, len(commits))
	for i, c := range commits {
		list[i] = c
	}
	return s.appendAny(expected, list)
}

// CheckpointCount is the number of stored checkpoints.
func (s *KvLedgerStore) CheckpointCount() (int, error) {
	d, err := s.doc()
	if err != nil {
		return 0, err
	}
	return len(d.checkpoints), nil
}

func (s *KvLedgerStore) checkpointsAny(from any) ([]map[string]any, error) {
	d, err := s.doc()
	if err != nil {
		return nil, err
	}
	f, ok := storeSafeInt(from)
	if !ok || f < 0 || f > int64(len(d.checkpoints)) {
		return nil, storeRange("checkpoints: from is not inside the list")
	}
	out := make([]map[string]any, 0, len(d.checkpoints)-int(f))
	for _, c := range d.checkpoints[f:] {
		out = append(out, normalizeJSON(c).(map[string]any))
	}
	return out, nil
}

// Checkpoints returns copies of the checkpoints from position from on.
func (s *KvLedgerStore) Checkpoints(from int) ([]map[string]any, error) {
	return s.checkpointsAny(from)
}

func (s *KvLedgerStore) appendCheckpointAny(expected, cp any) (map[string]any, error) {
	var out map[string]any
	err := storeKvTxn(s.kv, s.key, func(prev []byte) ([]byte, error) {
		d, e := ledgerDocDecode(prev)
		if e != nil {
			return nil, e
		}
		r, e := ledgerDocCheckpoint(d, expected, cp)
		if e != nil {
			return nil, e
		}
		out = r
		if r["outcome"] != any("appended") {
			return nil, nil
		}
		return d.encode()
	})
	return out, err
}

// AppendCheckpoint stores a checkpoint at position expected: {outcome: appended | replayed | conflict, count, reason?}.
func (s *KvLedgerStore) AppendCheckpoint(expected int, checkpoint map[string]any) (map[string]any, error) {
	return s.appendCheckpointAny(expected, checkpoint)
}

// ---- the stored ledger -------------------------------------------------------------------------------------------------------------

// StoredLedgerOptions configures OpenStoredLedger.
type StoredLedgerOptions struct {
	// Store holds the log (there is no in-memory default).
	Store LedgerStore
	// Guardian signs the checkpoints; its public key is the identity every checkpoint verifies under.
	Guardian *KeyPair
	// InstanceID and Principal name the log every checkpoint must belong to.
	InstanceID, Principal string
	// Clock returns the checkpoint time in milliseconds (nil: the wall clock).
	Clock func() float64
	// Suite chooses a post-quantum or hybrid checkpoint suite (nil: Ed25519); it needs Pin.
	Suite *SuiteOpts
	// Pin is the PQ pin {ed25519 b64u: pq public key} the checkpoints verify against.
	Pin map[string]string
}

// StoredLedger is a transparency log over a LedgerStore. Obtain it with OpenStoredLedger, so that no instance exists whose state
// was not verified against the stored checkpoints. Every handle serializes its operations.
type StoredLedger struct {
	mu       sync.Mutex
	opts     StoredLedgerOptions
	guardian string
	log      *MerkleLog
	cps      []map[string]any
}

func ledUnavailable(err error) error {
	var le *LedgerStoreError
	if errors.As(err, &le) {
		return err
	}
	msg := err.Error()
	if msg == "" {
		msg = "store failed"
	}
	return &LedgerStoreError{"store_unavailable", msg}
}

// OpenStoredLedger loads the log and verifies it against every stored checkpoint. It fails with a *LedgerStoreError: store_missing,
// guardian_key_missing, pin_missing, rollback, tamper, forged_checkpoint, inconsistent, store_corrupt or store_unavailable.
func OpenStoredLedger(o StoredLedgerOptions) (*StoredLedger, error) {
	if o.Store == nil {
		return nil, &LedgerStoreError{"store_missing", "a LedgerStore is required (there is no in-memory default)"}
	}
	if o.Guardian == nil || o.Guardian.Public == "" {
		return nil, &LedgerStoreError{"guardian_key_missing", "a guardian secret key is required"}
	}
	if alg := o.Suite.alg(); alg != "ed25519" {
		if _, known := resolveSigAlg(alg, true); !known || len(o.Pin) == 0 {
			return nil, &LedgerStoreError{"pin_missing", "a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)"}
		}
	}
	l := &StoredLedger{opts: o, guardian: o.Guardian.Public}
	size, err := o.Store.Size()
	if err != nil {
		return nil, ledUnavailable(err)
	}
	commits, err := o.Store.Read(0, size)
	if err != nil {
		return nil, ledUnavailable(err)
	}
	cps, err := o.Store.Checkpoints(0)
	if err != nil {
		return nil, ledUnavailable(err)
	}
	log, err := MerkleLogOf(commits)
	if err != nil {
		return nil, ledUnavailable(err)
	}
	l.log, l.cps = log, cps
	if err := l.verifyAgainstCheckpoints(); err != nil {
		return nil, ledUnavailable(err)
	}
	return l, nil
}

func (l *StoredLedger) pins() []map[string]string {
	if l.opts.Pin == nil {
		return nil
	}
	return []map[string]string{l.opts.Pin}
}

// verifyChain checks the guardian signature of every checkpoint and the consistency proof between neighbours.
func (l *StoredLedger) verifyChain(cps []map[string]any) (ok bool, at int, reason string) {
	pins := l.pins()
	for i, cp := range cps {
		if !VerifyTreeHead(cp["sth"], l.guardian, nil, pins...) {
			return false, i, "head"
		}
		if i == 0 {
			continue
		}
		if cp["proof"] == nil {
			return false, i, "proof_missing"
		}
		if !VerifyHeadConsistency(cps[i-1]["sth"], cp["sth"], cp["proof"], l.guardian, nil, pins...) {
			return false, i, "inconsistent"
		}
	}
	return true, 0, ""
}

func (l *StoredLedger) verifyAgainstCheckpoints() error {
	attested := int64(0)
	for _, cp := range l.cps {
		sth, _ := cp["sth"].(map[string]any)
		if n, ok := storeSafeInt(sth["size"]); ok && n > attested {
			attested = n
		}
	}
	if int64(l.log.Size()) < attested {
		return &LedgerStoreError{"rollback", "the log has fewer entries than a checkpoint attests"}
	}
	for i, cp := range l.cps {
		sth, _ := cp["sth"].(map[string]any)
		inst, _ := sth["instance_id"].(string)
		pr, _ := sth["principal"].(string)
		if sth["instance_id"] == nil || inst != l.opts.InstanceID || pr != l.opts.Principal {
			return &LedgerStoreError{"forged_checkpoint", "a checkpoint belongs to another log (position " + itoa(i) + ")"}
		}
		n, ok := storeSafeInt(sth["size"])
		if !ok {
			return errors.New("rootAt: size out of range")
		}
		root, err := l.log.RootAt(int(n))
		if err != nil {
			return err
		}
		if want, _ := sth["root"].(string); root != want {
			return &LedgerStoreError{"tamper", "the stored entries do not reproduce the root of checkpoint " + itoa(i)}
		}
	}
	if len(l.cps) == 0 {
		return nil
	}
	if ok, at, reason := l.verifyChain(l.cps); !ok {
		code := "forged_checkpoint"
		if reason == "inconsistent" {
			code = "inconsistent"
		}
		return &LedgerStoreError{code, "checkpoint " + itoa(at) + ": " + reason}
	}
	return nil
}

// Size is the number of entries.
func (l *StoredLedger) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.log.Size()
}

// Guardian is the guardian public key (b64u) every checkpoint verifies under.
func (l *StoredLedger) Guardian() string { return l.guardian }

// LatestCheckpoint is the newest signed tree head (nil before the first checkpoint).
func (l *StoredLedger) LatestCheckpoint() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.cps) == 0 {
		return nil
	}
	sth, _ := l.cps[len(l.cps)-1]["sth"].(map[string]any)
	return sth
}

// CheckpointChain returns a copy of every checkpoint ({sth, proof?}) in order.
func (l *StoredLedger) CheckpointChain() []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]map[string]any, len(l.cps))
	for i, c := range l.cps {
		out[i] = normalizeJSON(c).(map[string]any)
	}
	return out
}

// Head is {size, root} of the current log.
func (l *StoredLedger) Head() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.log.Head()
}

func (l *StoredLedger) inclusionAny(index any) (map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := storeSafeInt(index)
	if !ok {
		return nil, storeRange("merkleProof: index out of range")
	}
	p, err := l.log.InclusionProof(int(n))
	if err != nil {
		return nil, storeRange(err.Error())
	}
	return p, nil
}

// InclusionProof is the RFC 9162 audit path of entry index.
func (l *StoredLedger) InclusionProof(index int) (map[string]any, error) {
	return l.inclusionAny(index)
}

func (l *StoredLedger) consistencyAny(oldSize any) (map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := storeSafeInt(oldSize)
	if !ok {
		return nil, storeRange("consistencyProof: invalid sizes")
	}
	p, err := l.log.ConsistencyProof(int(n), l.log.Size())
	if err != nil {
		return nil, storeRange(err.Error())
	}
	return p, nil
}

// ConsistencyProofFrom is the RFC 9162 proof from a size the caller already pinned to the current log.
func (l *StoredLedger) ConsistencyProofFrom(oldSize int) (map[string]any, error) {
	return l.consistencyAny(oldSize)
}

// Commits returns every commit in order.
func (l *StoredLedger) Commits() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.log.Commits()
}

// Append appends an opaque commitment leaf and returns its index. It is idempotent under retry at the position the caller read; if
// another writer took that position the ledger reloads and appends at the new tail.
func (l *StoredLedger) Append(commit string) (int, error) {
	if commit == "" {
		return 0, &LedgerStoreError{"invalid_commit", "a commit must be a non-empty string"}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := 0; i < 16; i++ {
		index := l.log.Size()
		out, err := l.opts.Store.Append(index, []string{commit})
		if err != nil {
			return 0, ledUnavailable(err)
		}
		if o, _ := out["outcome"].(string); o == "appended" || o == "replayed" {
			if _, err := l.log.AppendCommitment(commit); err != nil {
				return 0, err
			}
			return index, nil
		}
		if err := l.catchUpLocked(); err != nil { // another writer advanced the log: pick up its entries, then try the new tail
			return 0, err
		}
	}
	return 0, &LedgerStoreError{"conflict", "the log kept moving; could not append"}
}

// CatchUp reloads the entries other writers appended since this handle last looked (and re-verifies them against the checkpoints).
func (l *StoredLedger) CatchUp() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.catchUpLocked()
}

func (l *StoredLedger) catchUpLocked() error {
	st := l.opts.Store
	size, err := st.Size()
	if err != nil {
		return ledUnavailable(err)
	}
	if size < l.log.Size() {
		return &LedgerStoreError{"rollback", "the store shrank below this handle's log"}
	}
	more, err := st.Read(l.log.Size(), size)
	if err != nil {
		return ledUnavailable(err)
	}
	for _, c := range more {
		if _, err := l.log.AppendCommitment(c); err != nil {
			return ledUnavailable(err)
		}
	}
	cps, err := st.Checkpoints(len(l.cps))
	if err != nil {
		return ledUnavailable(err)
	}
	l.cps = append(l.cps, cps...)
	if err := l.verifyAgainstCheckpoints(); err != nil {
		return ledUnavailable(err)
	}
	return nil
}

func (l *StoredLedger) assertStoreMatchesMemory() error {
	stored, err := l.opts.Store.Read(0, l.log.Size())
	if err != nil {
		return ledUnavailable(err)
	}
	mine := l.log.Commits()
	same := len(stored) == len(mine)
	for i := 0; same && i < len(mine); i++ {
		same = stored[i] == mine[i]
	}
	if !same {
		return &LedgerStoreError{"tamper", "the stored entries no longer match this handle; refusing to sign a checkpoint over them"}
	}
	return nil
}

// Checkpoint signs and persists a checkpoint of the current head and returns it. It is verified BEFORE it is stored: the new head
// must be consistent with the previous checkpoint, so a log that was rewritten under this handle is refused (inconsistent). An
// unchanged head returns the existing checkpoint.
func (l *StoredLedger) Checkpoint() (map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.catchUpLocked(); err != nil {
		return nil, err
	}
	if err := l.assertStoreMatchesMemory(); err != nil {
		return nil, err
	}
	var prev map[string]any
	prevSize, prevRoot := 0, ""
	if len(l.cps) > 0 {
		prev = l.cps[len(l.cps)-1]
		psth, _ := prev["sth"].(map[string]any)
		n, _ := storeSafeInt(psth["size"])
		prevSize = int(n)
		prevRoot, _ = psth["root"].(string)
	}
	size := l.log.Size()
	if prev != nil && prevSize == size {
		sth, _ := prev["sth"].(map[string]any)
		return sth, nil
	}
	t := float64(time.Now().UnixMilli())
	if l.opts.Clock != nil {
		t = l.opts.Clock()
	}
	if math.IsNaN(t) || math.IsInf(t, 0) {
		return nil, &LedgerStoreError{"clock_invalid", "the clock returned a non-finite time"}
	}
	sth, err := SignTreeHead(l.opts.Guardian, map[string]any{"instance_id": l.opts.InstanceID, "principal": l.opts.Principal,
		"size": size, "root": l.log.Root(), "prev_root": prevRoot, "timestamp": math.Floor(t)}, l.opts.Suite) // whole milliseconds: the signed form carries integers
	if err != nil {
		return nil, err
	}
	cp := map[string]any{"sth": sth}
	if prev != nil {
		proof, err := l.log.ConsistencyProof(prevSize, size)
		if err != nil {
			return nil, err
		}
		cp["proof"] = proof
	}
	if ok, at, reason := l.verifyChain(append(append([]map[string]any{}, l.cps...), cp)); !ok {
		if reason == "head" {
			return nil, &LedgerStoreError{"forged_checkpoint", "the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)"}
		}
		return nil, &LedgerStoreError{"inconsistent", "the new head is not consistent with checkpoint " + itoa(at-1)}
	}
	out, err := l.opts.Store.AppendCheckpoint(len(l.cps), cp)
	if err != nil {
		return nil, ledUnavailable(err)
	}
	if o, _ := out["outcome"].(string); o == "conflict" {
		reason, _ := out["reason"].(string)
		return nil, &LedgerStoreError{"conflict", reason}
	}
	l.cps = append(l.cps, cp)
	return sth, nil
}

// SignTreeHead signs a tree head {instance_id, principal, size, root, prev_root, timestamp} as the guardian and returns it with
// `guardian` and the signature fields (`sig`, plus `alg` / `pq_pk` / `pq_sig` under a post-quantum or hybrid suite, which are bound
// into the signed bytes). Any other member of head is ignored. VerifyTreeHead is the check.
func SignTreeHead(guardian *KeyPair, head map[string]any, suite *SuiteOpts) (map[string]any, error) {
	if guardian == nil || guardian.Public == "" {
		return nil, errors.New("signTreeHead: a guardian key is required")
	}
	body := map[string]any{}
	for _, k := range []string{"instance_id", "principal", "size", "root", "prev_root", "timestamp"} {
		v, ok := head[k]
		if !ok || v == nil {
			return nil, errors.New("signTreeHead: the head lacks " + k)
		}
		body[k] = v
	}
	sth, err := SignArtifact(sthDomain, body, guardian, suite)
	if err != nil {
		return nil, err
	}
	sth["guardian"] = guardian.Public
	return sth, nil
}

// SignTreeHeadWithSeed is SignTreeHead for a guardian given as its 32-byte Ed25519 seed.
func SignTreeHeadWithSeed(guardianSeed []byte, head map[string]any, suite *SuiteOpts) (map[string]any, error) {
	k, err := KeyPairFromSeed(guardianSeed)
	if err != nil {
		return nil, err
	}
	return SignTreeHead(k, head, suite)
}

type storedAnchorLedger struct{ l *StoredLedger }

func (a storedAnchorLedger) Head() (int64, string) {
	a.l.mu.Lock()
	defer a.l.mu.Unlock()
	return int64(a.l.log.Size()), a.l.log.Root()
}

func (a storedAnchorLedger) AppendCommitment(commit string) (int64, error) {
	i, err := a.l.Append(commit)
	return int64(i), err
}

func (a storedAnchorLedger) Principal() string { return a.l.opts.Principal }

// AnchorLedger is this ledger as the log AnchorAttestationEvidence appends to.
func (l *StoredLedger) AnchorLedger() AttestationAnchorLedger { return storedAnchorLedger{l} }
