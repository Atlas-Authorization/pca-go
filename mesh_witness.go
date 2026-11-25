package pca

// The issuing and witnessing side of the agent mesh (the reference mesh.ts): an append-only RFC 9162 Merkle log, the sorted
// revocation set a domain commits to with rev_root, the independent log witness that cosigns a domain head, its stores
// (memory, one file, any AtomicKV) and the issuing domain (MeshDomain) that publishes heads against witnesses. VerifyMeshProof
// (mesh.go) checks what these produce.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// ---- the append-only log ------------------------------------------------------------------------------------------------------

// MerkleLog is an append-only RFC 9162 Merkle log over opaque commitment strings: head, root at an earlier size, inclusion and
// consistency proofs, in the wire shapes the verifiers read. It holds only commitments (no openings). Not safe for concurrent
// use; MeshDomain guards its own.
type MerkleLog struct {
	commits []string
	hashes  [][]byte
}

// NewMerkleLog returns an empty log.
func NewMerkleLog() *MerkleLog { return &MerkleLog{} }

// MerkleLogOf rebuilds a log from stored commitments.
func MerkleLogOf(commits []string) (*MerkleLog, error) {
	l := NewMerkleLog()
	for _, c := range commits {
		if _, err := l.AppendCommitment(c); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// Size is the number of entries.
func (l *MerkleLog) Size() int { return len(l.commits) }

// Commits returns a copy of the commitments.
func (l *MerkleLog) Commits() []string { return append([]string(nil), l.commits...) }

// AppendCommitment appends an opaque commitment leaf (a non-empty string) and returns its index.
func (l *MerkleLog) AppendCommitment(commit string) (int, error) {
	if commit == "" {
		return 0, errors.New("appendCommitment: commit must be a non-empty string")
	}
	h, err := leafHash(commit)
	if err != nil {
		return 0, err
	}
	l.commits = append(l.commits, commit)
	l.hashes = append(l.hashes, h)
	return len(l.commits) - 1, nil
}

func merkleMTH(hs [][]byte) []byte {
	if len(hs) == 0 {
		return sha(nil)
	}
	return build(hs)
}

// Root is the current root (base64url; the root of the empty log is the hash of the empty string).
func (l *MerkleLog) Root() string { return b64.EncodeToString(merkleMTH(l.hashes)) }

// Head is {size, root}.
func (l *MerkleLog) Head() map[string]any {
	return map[string]any{"size": jsNumber(float64(l.Size())), "root": l.Root()}
}

// RootAt is the root the log had when it held only the first size entries.
func (l *MerkleLog) RootAt(size int) (string, error) {
	if size < 0 || size > l.Size() {
		return "", errors.New("rootAt: size out of range")
	}
	return b64.EncodeToString(merkleMTH(l.hashes[:size])), nil
}

func merkleProve(hs [][]byte, idx int, out *[]any) {
	if len(hs) == 1 {
		return
	}
	k := split(len(hs))
	step := map[string]any{}
	if idx < k {
		merkleProve(hs[:k], idx, out)
		step["side"], step["hash"] = "R", b64.EncodeToString(build(hs[k:]))
	} else {
		merkleProve(hs[k:], idx-k, out)
		step["side"], step["hash"] = "L", b64.EncodeToString(build(hs[:k]))
	}
	*out = append(*out, step)
}

// InclusionProof is {index, size, path: [{side, hash}]}.
func (l *MerkleLog) InclusionProof(index int) (map[string]any, error) {
	if index < 0 || index >= l.Size() {
		return nil, errors.New("merkleProof: index out of range")
	}
	path := []any{}
	merkleProve(l.hashes, index, &path)
	return map[string]any{"index": jsNumber(float64(index)), "size": jsNumber(float64(l.Size())), "path": path}, nil
}

func merkleSub(m int, hs [][]byte, b bool, out *[]any) {
	n := len(hs)
	if m == n {
		if !b {
			*out = append(*out, b64.EncodeToString(merkleMTH(hs)))
		}
		return
	}
	k := split(n)
	if m <= k {
		merkleSub(m, hs[:k], b, out)
		*out = append(*out, b64.EncodeToString(merkleMTH(hs[k:])))
	} else {
		merkleSub(m-k, hs[k:], false, out)
		*out = append(*out, b64.EncodeToString(merkleMTH(hs[:k])))
	}
}

// ConsistencyProof is the RFC 9162 SUBPROOF between two sizes: {oldSize, newSize, path: [b64u]}.
func (l *MerkleLog) ConsistencyProof(oldSize, newSize int) (map[string]any, error) {
	if oldSize < 0 || oldSize > newSize || newSize > l.Size() {
		return nil, errors.New("consistencyProof: invalid sizes")
	}
	out := []any{}
	if oldSize > 0 && oldSize < newSize {
		merkleSub(oldSize, l.hashes[:newSize], true, &out)
	}
	return map[string]any{"oldSize": jsNumber(float64(oldSize)), "newSize": jsNumber(float64(newSize)), "path": out}, nil
}

// ---- the revocation set ----------------------------------------------------------------------------------------------------

// RevocationSet is a sorted, size-bound set of revoked ids: what a mesh domain commits to with rev_root. Not safe for concurrent
// use.
type RevocationSet struct{ ids []string }

// NewRevocationSet builds a set from initial ids.
func NewRevocationSet(initial ...string) *RevocationSet {
	s := &RevocationSet{}
	for _, id := range initial {
		s.Revoke(id)
	}
	return s
}

// Size is the number of revoked ids.
func (s *RevocationSet) Size() int { return len(s.ids) }

func (s *RevocationSet) lowerBound(id string) int {
	return sort.Search(len(s.ids), func(i int) bool { return compareUtf8(s.ids[i], id) >= 0 })
}

// Revoke is idempotent; it reports whether id was newly revoked.
func (s *RevocationSet) Revoke(id string) bool {
	lo := s.lowerBound(id)
	if lo < len(s.ids) && s.ids[lo] == id {
		return false
	}
	s.ids = append(s.ids, "")
	copy(s.ids[lo+1:], s.ids[lo:])
	s.ids[lo] = id
	return true
}

// Has reports whether id is revoked.
func (s *RevocationSet) Has(id string) bool {
	lo := s.lowerBound(id)
	return lo < len(s.ids) && s.ids[lo] == id
}

// List is the sorted revoked ids (a copy).
func (s *RevocationSet) List() []string { return append([]string(nil), s.ids...) }

// Root is the size-bound root.
func (s *RevocationSet) Root() string {
	r, _ := revsetRoot(s.ids)
	return r
}

func (s *RevocationSet) leaf(hs [][]byte, i int) map[string]any {
	path := []any{}
	merkleProve(hs, i, &path)
	return map[string]any{"id": s.ids[i], "proof": map[string]any{"index": jsNumber(float64(i)), "size": jsNumber(float64(len(hs))), "path": path}}
}

// NonMembershipProof proves id is NOT in the set: {size, lo?, hi?}, the bracketing leaves {id, proof} (lo = the greatest id below,
// hi = the least id above). It fails when id IS revoked (no such proof can exist).
func (s *RevocationSet) NonMembershipProof(id string) (map[string]any, error) {
	if s.Has(id) {
		return nil, errors.New("nonMembershipProof: id is revoked")
	}
	n := len(s.ids)
	lo := s.lowerBound(id)
	hs := make([][]byte, n)
	for i, x := range s.ids {
		h, err := leafHash(x)
		if err != nil {
			return nil, err
		}
		hs[i] = h
	}
	p := map[string]any{"size": jsNumber(float64(n))}
	if lo > 0 {
		p["lo"] = s.leaf(hs, lo-1)
	}
	if lo < n {
		p["hi"] = s.leaf(hs, lo)
	}
	return p, nil
}

// ---- the witness stores ------------------------------------------------------------------------------------------------------------

// MeshWitnessStore is where a mesh log witness keeps what it has cosigned. Save MUST be durable and atomic: when it returns, a
// restarted witness loads exactly this state. A witness that forgets across a restart can be walked back to cosign a fork. The
// state is the JSON object {seen: [{head, rev_ids}]}. Load returns nil for a store that has never been written and fails on
// corrupt data (it never returns a partial state).
type MeshWitnessStore interface {
	Load() (map[string]any, error)
	Save(state map[string]any) error
}

// MemoryMeshWitnessStore is the in-process store: a test double and the default when no store is given. It does not survive a restart.
type MemoryMeshWitnessStore struct {
	mu    sync.Mutex
	state map[string]any
}

// Load implements MeshWitnessStore.
func (s *MemoryMeshWitnessStore) Load() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, nil
	}
	return normalizeJSON(s.state).(map[string]any), nil
}

// Save implements MeshWitnessStore.
func (s *MemoryMeshWitnessStore) Save(state map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = normalizeJSON(state).(map[string]any)
	return nil
}

// meshWitnessDocWrap is the stored form shared by the durable stores: {v: 1, state, digest} with the digest of the state.
func meshWitnessDocWrap(state map[string]any) (map[string]any, error) {
	st := normalizeJSON(state)
	d, err := HashCanonical(st)
	if err != nil {
		return nil, err
	}
	return map[string]any{"v": jsNumber(1), "state": st, "digest": d}, nil
}

// meshWitnessDocState is the state of a stored document; it fails (never an empty state) on a wrong shape or a failed digest.
func meshWitnessDocState(doc any, who string) (map[string]any, error) {
	d, _ := doc.(map[string]any)
	st, stOK := d["state"].(map[string]any)
	digest, dgOK := d["digest"].(string)
	if v, _ := jsNum(d["v"]); d == nil || !jsIsInt(d["v"]) || v != 1 || !dgOK || !stOK {
		return nil, fmt.Errorf("%s has an unexpected shape; refusing to start empty", who)
	}
	st = normalizeJSON(st).(map[string]any)
	got, err := HashCanonical(st)
	if err != nil || got != digest {
		return nil, fmt.Errorf("%s fails its digest; refusing to start empty", who)
	}
	return st, nil
}

// FileMeshWitnessStore is a MeshWitnessStore on one file. Save writes a temp file, fsyncs it, renames it over the state file (atomic
// on one filesystem) and fsyncs the directory, so after it returns a restarted witness loads exactly this state and a crash
// mid-write leaves the old or the new file, never a mix. The file carries a digest of its state: Load refuses damaged, edited or
// foreign content (it fails; a witness never starts empty over it).
type FileMeshWitnessStore struct {
	mu   sync.Mutex
	path string
}

// NewFileMeshWitnessStore returns the store on path.
func NewFileMeshWitnessStore(path string) *FileMeshWitnessStore {
	return &FileMeshWitnessStore{path: path}
}

// Load implements MeshWitnessStore.
func (s *FileMeshWitnessStore) Load() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty")
	}
	doc, perr := ParseJSONLenient(b)
	if perr != nil {
		return nil, errors.New("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty")
	}
	return meshWitnessDocState(doc, "FileMeshWitnessStore: the state file")
}

// Save implements MeshWitnessStore.
func (s *FileMeshWitnessStore) Save(state map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := meshWitnessDocWrap(state)
	if err != nil {
		return err
	}
	canon, err := canonBytes(doc)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	fail := func(e error) error {
		return fmt.Errorf("FileMeshWitnessStore: could not write the state file: %v", e)
	}
	f, err := CreateOwnerOnly(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
	if err != nil {
		return fail(err)
	}
	if _, err := f.Write(canon); err != nil {
		f.Close()
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fail(err)
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync() // some platforms cannot fsync a directory; the rename above is already atomic
		d.Close()
	}
	return nil
}

// KvMeshWitnessDocKey is the default key of KvMeshWitnessStore.
const KvMeshWitnessDocKey = "pca-mesh-witness/v1"

// KvMeshWitnessStore is a durable MeshWitnessStore over an AtomicKV: the state is one document with a digest. Save returns only
// after the kv acknowledged the write; Load refuses damaged or edited content (it fails, so a witness never starts empty over it).
type KvMeshWitnessStore struct {
	kv  AtomicKV
	key string
}

// NewKvMeshWitnessStore builds the store; key "" is KvMeshWitnessDocKey.
func NewKvMeshWitnessStore(kv AtomicKV, key string) (*KvMeshWitnessStore, error) {
	if kv == nil {
		return nil, errors.New("KvMeshWitnessStore needs an AtomicKV")
	}
	if key == "" {
		key = KvMeshWitnessDocKey
	}
	return &KvMeshWitnessStore{kv: kv, key: key}, nil
}

// Load implements MeshWitnessStore.
func (s *KvMeshWitnessStore) Load() (map[string]any, error) {
	b, ok, err := s.kv.Get(s.key)
	if err != nil || !ok {
		return nil, err
	}
	doc, perr := ParseJSONLenient(b)
	if perr != nil {
		return nil, errors.New("KvMeshWitnessStore: the stored state has an unexpected shape; refusing to start empty")
	}
	return meshWitnessDocState(doc, "KvMeshWitnessStore: the stored state")
}

// Save implements MeshWitnessStore.
func (s *KvMeshWitnessStore) Save(state map[string]any) error {
	doc, err := meshWitnessDocWrap(state)
	if err != nil {
		return err
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return s.kv.Update(s.key, func([]byte) []byte { return b })
}

// ---- the witness --------------------------------------------------------------------------------------------------------------

// MeshWitnessDefaultMaxClockSkewMs is the default clock-skew allowance of a witness that has a clock.
const MeshWitnessDefaultMaxClockSkewMs = 60_000

const meshMaxRevIDs = 1_000_000

// MeshWitnessOptions is the optional witness configuration.
type MeshWitnessOptions struct {
	Store MeshWitnessStore
	// Clock is the witness's own clock (epoch ms); when set, heads timestamped beyond now + MaxClockSkewMs are refused.
	Clock          func() float64
	MaxClockSkewMs *float64
}

type meshSeen struct {
	head map[string]any
	rev  []string
}

// MeshWitness is an independent mesh log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162
// verified append-only extension of the last head THIS witness cosigned for that domain, (3) its revocation list reproduces
// rev_root and is a superset of the previously cosigned list, and (4) the timestamp does not regress (nor run ahead of the
// witness's own clock, when configured). State is committed only after every check passes, and (with a store) persisted BEFORE the
// cosignature is returned. First sight of a domain is trust-on-first-use. Every refusal is an error "witness: <why>". Safe for
// concurrent use.
type MeshWitness struct {
	// ID is the witness's public key.
	ID   string
	key  *KeyPair
	opts MeshWitnessOptions
	mu   sync.Mutex
	seen map[string]*meshSeen
}

// NewMeshWitness builds a witness; with a store it restores what the store holds (a corrupt store is an error).
func NewMeshWitness(key *KeyPair, opts MeshWitnessOptions) (*MeshWitness, error) {
	w := &MeshWitness{ID: key.Public, key: key, opts: opts, seen: map[string]*meshSeen{}}
	if opts.Store != nil {
		loaded, err := opts.Store.Load()
		if err != nil {
			return nil, err
		}
		if loaded != nil {
			if err := w.ImportState(loaded); err != nil {
				return nil, err
			}
		}
	}
	return w, nil
}

func meshRefuse(why string) error { return errors.New("witness: " + why) }

func meshStateOf(seen map[string]*meshSeen) map[string]any {
	all := make([]*meshSeen, 0, len(seen))
	for _, s := range seen {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool {
		return dsCmpStr(all[i].head["domain"].(string), all[j].head["domain"].(string)) < 0
	})
	out := make([]any, len(all))
	for i, s := range all {
		ids := make([]any, len(s.rev))
		for j, r := range s.rev {
			ids[j] = r
		}
		out[i] = map[string]any{"head": normalizeJSON(s.head), "rev_ids": ids}
	}
	return map[string]any{"seen": out}
}

// LastSeen returns the newest head this witness cosigned for domain (a copy), nil when none.
func (w *MeshWitness) LastSeen(domain string) map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.seen[domain]; ok {
		return normalizeJSON(s.head).(map[string]any)
	}
	return nil
}

func meshStringList(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(l))
	for i, x := range l {
		s, isStr := x.(string)
		if !isStr {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// Cosign cosigns the head request {head: {head, sig, cosigs}, consistency?, rev_ids} and returns {witness, sig}. It fails (and
// changes nothing) if any rule is violated.
func (w *MeshWitness) Cosign(req map[string]any) (map[string]any, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch, _ := req["head"].(map[string]any)
	h, ok := meshValidHead(ch["head"])
	sig, sigOK := ch["sig"].(string)
	if ch == nil || !ok || !sigOK {
		return nil, meshRefuse("malformed head")
	}
	domain := h["domain"].(string)
	msg, mok := meshMsg(meshHeadDomain, h)
	if !mok || !verifyB64u(domain, msg, sig) {
		return nil, meshRefuse("head not signed by its domain")
	}
	ts, _ := jsNum(h["timestamp"])
	if w.opts.Clock != nil {
		skew := float64(MeshWitnessDefaultMaxClockSkewMs)
		if w.opts.MaxClockSkewMs != nil {
			skew = *w.opts.MaxClockSkewMs
		}
		if clk := w.opts.Clock(); !(finite(clk) && finite(skew) && ts <= clk+skew) {
			return nil, meshRefuse("head timestamp is in the future")
		}
	}
	raw, isList := req["rev_ids"].([]any)
	if !isList || len(raw) > meshMaxRevIDs {
		return nil, meshRefuse("malformed revocation list")
	}
	ids, idsOK := meshStringList(raw)
	if !idsOK {
		return nil, meshRefuse("malformed revocation list")
	}
	set := NewRevocationSet(ids...)
	if rs, _ := jsNum(h["rev_size"]); float64(set.Size()) != rs || set.Root() != h["rev_root"] {
		return nil, meshRefuse("revocation list does not match head")
	}
	if prev, had := w.seen[domain]; had {
		if why := meshCheckHeadAdvance(prev.head, h, req["consistency"]); why != "" {
			return nil, meshRefuse(why)
		}
		if pts, _ := jsNum(prev.head["timestamp"]); !(ts >= pts) {
			return nil, meshRefuse("timestamp regresses")
		}
		now := map[string]bool{}
		for _, x := range set.List() {
			now[x] = true
		}
		for _, r := range prev.rev {
			if !now[r] {
				return nil, meshRefuse("revocation set drops a previously cosigned revocation")
			}
		}
	}
	next := &meshSeen{head: normalizeJSON(h).(map[string]any), rev: set.List()}
	if w.opts.Store != nil {
		// Persist first, commit to memory second: if the disk write fails nothing was cosigned and nothing changed.
		cp := make(map[string]*meshSeen, len(w.seen)+1)
		for k, v := range w.seen {
			cp[k] = v
		}
		cp[domain] = next
		if err := w.opts.Store.Save(meshStateOf(cp)); err != nil {
			return nil, meshRefuse("could not persist state; refusing to cosign")
		}
	}
	w.seen[domain] = next
	cm, _ := meshMsg(meshCosigDomain, h)
	return map[string]any{"witness": w.ID, "sig": b64.EncodeToString(w.key.Sign(cm))}, nil
}

// ExportState exports the witness memory for persistence, in a deterministic order.
func (w *MeshWitness) ExportState() map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	return meshStateOf(w.seen)
}

// ImportState restores the memory; each record must be internally consistent (its revocation list reproduces its root).
func (w *MeshWitness) ImportState(state map[string]any) error {
	next := map[string]*meshSeen{}
	if lv, has := state["seen"]; has && lv != nil {
		list, ok := lv.([]any)
		if !ok {
			return meshRefuse("malformed state")
		}
		for _, so := range list {
			s, _ := so.(map[string]any)
			head, hok := meshValidHead(s["head"])
			ids, idsOK := meshStringList(s["rev_ids"])
			if s == nil || !hok || !idsOK {
				return meshRefuse("malformed state")
			}
			set := NewRevocationSet(ids...)
			if rs, _ := jsNum(head["rev_size"]); float64(set.Size()) != rs || set.Root() != head["rev_root"] {
				return meshRefuse("malformed state")
			}
			next[head["domain"].(string)] = &meshSeen{head: normalizeJSON(head).(map[string]any), rev: set.List()}
		}
	}
	w.mu.Lock()
	w.seen = next
	w.mu.Unlock()
	return nil
}

// ---- the issuing domain ------------------------------------------------------------------------------------------------------------

type meshSnapshot struct {
	log []string
	rev *RevocationSet
}

// MeshDomain is the issuing side of a mesh domain (an organisation): an append-only delegation log, a revocation set, and head
// publication against MeshWitnesses. In production this is the deployed signed-tree-head and revocation-epoch machinery; here it is
// in memory so the witness protocol can be exercised end to end. Safe for concurrent use.
type MeshDomain struct {
	// ID is the domain's public key; Name its label.
	ID   string
	Name string
	key  *KeyPair
	mu   sync.Mutex
	log  *MerkleLog
	rev  *RevocationSet
	// snaps is what each published head saw, keyed by the head's signature (what Evidence and PinProof prove against).
	snaps map[string]meshSnapshot
}

// NewMeshDomain creates a domain.
func NewMeshDomain(name string, key *KeyPair) *MeshDomain {
	return &MeshDomain{ID: key.Public, Name: name, key: key, log: NewMerkleLog(), rev: NewRevocationSet(), snaps: map[string]meshSnapshot{}}
}

// Enroll vouches that an agent key belongs to this domain: {agent, domain, role, sig} (for domain policy, not authority).
func (d *MeshDomain) Enroll(agent, role string) (map[string]any, error) {
	body := map[string]any{"agent": agent, "domain": d.ID, "role": role}
	m, ok := meshMsg(meshBindingDomain, body)
	if !ok {
		return nil, errors.New("enroll: the binding is not canonical JSON")
	}
	body["sig"] = b64.EncodeToString(d.key.Sign(m))
	return body, nil
}

// PinProof is the proof a verifier holding pin (a head of this domain) needs to accept head (a cosigned head this domain
// published, larger than the pin): {domain, proof}. It fails if the head is unknown or the pin is not a prefix of that head's log.
func (d *MeshDomain) PinProof(pin, head map[string]any) (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	sig, _ := head["sig"].(string)
	snap, ok := d.snaps[sig]
	if !ok {
		return nil, errors.New("pinProof: unknown head")
	}
	inner, _ := head["head"].(map[string]any)
	log, err := MerkleLogOf(snap.log)
	if err != nil {
		return nil, err
	}
	ps, psOK := safeInt(pin["size"])
	ns, nsOK := safeInt(inner["size"])
	if !psOK || !nsOK { // the reference's consistency proof refuses a size that is not a safe integer
		return nil, errors.New("pinProof: size must be a safe integer")
	}
	proof, err := log.ConsistencyProof(int(ps), int(ns))
	if err != nil {
		return nil, err
	}
	return map[string]any{"domain": d.ID, "proof": proof}, nil
}

// Evidence is the per-hop evidence against a previously published head: {domain, head, inclusion, binding?, revocation: {cap,
// issuer_key}}. It fails if the head is unknown, the capability is not in that head's log, or the capability or its issuer key is
// revoked as of that head. binding may be nil.
func (d *MeshDomain) Evidence(cap, head, binding map[string]any) (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	sig, _ := head["sig"].(string)
	snap, ok := d.snaps[sig]
	if !ok {
		return nil, errors.New("evidence: unknown head")
	}
	ch, err := CapHash(cap)
	if err != nil {
		return nil, err
	}
	idx := -1
	for i, c := range snap.log {
		if c == ch {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, errors.New("evidence: capability not in this head")
	}
	capID, _ := cap["id"].(string)
	issuer, _ := cap["issuer"].(string)
	capProof, err := snap.rev.NonMembershipProof(capID)
	if err != nil {
		return nil, err
	}
	keyProof, err := snap.rev.NonMembershipProof("key:" + issuer)
	if err != nil {
		return nil, err
	}
	log, err := MerkleLogOf(snap.log)
	if err != nil {
		return nil, err
	}
	incl, err := log.InclusionProof(idx)
	if err != nil {
		return nil, err
	}
	ev := map[string]any{"domain": d.ID, "head": head, "inclusion": incl, "revocation": map[string]any{"cap": capProof, "issuer_key": keyProof}}
	if binding != nil {
		ev["binding"] = binding
	}
	return ev, nil
}

// Record logs a delegation hop issued in this domain (identified by its capability hash). It is idempotent and returns the index.
func (d *MeshDomain) Record(cap map[string]any) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	h, err := CapHash(cap)
	if err != nil {
		return 0, err
	}
	for i, c := range d.log.commits {
		if c == h {
			return i, nil
		}
	}
	return d.log.AppendCommitment(h)
}

// RevocationSetCopy is a copy of the current revocation set (for proofs about it).
func (d *MeshDomain) RevocationSetCopy() *RevocationSet {
	d.mu.Lock()
	defer d.mu.Unlock()
	return NewRevocationSet(d.rev.List()...)
}

// Revoke revokes a capability id or an agent key.
func (d *MeshDomain) Revoke(revokedID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rev.Revoke(revokedID)
}

// ConsistencyProof is the RFC 9162 consistency proof between two sizes of this domain's current log.
func (d *MeshDomain) ConsistencyProof(oldSize, newSize int) (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.log.ConsistencyProof(oldSize, newSize)
}

// PublishHead publishes a head: domain-signed, then cosigned by witnesses, each shown a real consistency proof from ITS last-seen
// head plus the revocation list. It fails if a witness refuses (unless threshold, the number of cosignatures needed, tolerates it;
// nil: all of them). It returns {head, sig, cosigs}.
func (d *MeshDomain) PublishHead(witnesses []*MeshWitness, timestamp float64, threshold *int) (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	size := d.log.Size()
	root := ""
	if size > 0 {
		root = d.log.Root()
	}
	head := map[string]any{"domain": d.ID, "size": jsNumber(float64(size)), "root": root, "rev_root": d.rev.Root(),
		"rev_size": jsNumber(float64(d.rev.Size())), "timestamp": jsNumber(timestamp)}
	m, ok := meshMsg(meshHeadDomain, head)
	if !ok {
		return nil, errors.New("publishHead: the head is not canonical JSON")
	}
	sig := b64.EncodeToString(d.key.Sign(m))
	cosigs := []any{}
	ch := map[string]any{"head": head, "sig": sig, "cosigs": cosigs}
	revIDs := d.rev.List()
	ids := make([]any, len(revIDs))
	for i, r := range revIDs {
		ids[i] = r
	}
	var errs []error
	for _, w := range witnesses {
		var consistency map[string]any
		if prev := w.LastSeen(d.ID); prev != nil {
			ps64, _ := safeInt(prev["size"])
			ps := int(ps64)
			switch {
			case ps < size:
				c, err := d.log.ConsistencyProof(ps, size)
				if err != nil {
					return nil, err
				}
				consistency = c
			case ps > size: // will be refused as rollback
				consistency = map[string]any{"oldSize": jsNumber(float64(ps)), "newSize": jsNumber(float64(size)), "path": []any{}}
			}
		}
		req := map[string]any{"head": ch, "rev_ids": ids}
		if consistency != nil {
			req["consistency"] = consistency
		}
		cos, err := w.Cosign(req)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cosigs = append(cosigs, cos)
		ch["cosigs"] = cosigs
	}
	need := len(witnesses)
	if threshold != nil {
		need = *threshold
	}
	if len(cosigs) < need {
		if len(errs) == 0 {
			return nil, errors.New("publishHead: not enough witnesses")
		}
		return nil, errs[0]
	}
	d.snaps[sig] = meshSnapshot{log: d.log.Commits(), rev: NewRevocationSet(d.rev.List()...)}
	return ch, nil
}
