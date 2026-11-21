package pca

// SCITT transparency services and log stores (port of the TypeScript @atlasauth/pca-scitt service, durable and file-store
// modules). ScittTransparencyService is the in-memory reference log (tests and demos, loses everything on restart); the
// production log is ScittDurableService over a ScittLogStore you provide. ScittFileLogStore is a file-backed store: one
// append-only file of checksummed transactions (entry plus its new subtree hashes), fsynced before Append returns, with the
// byte-identical on-disk format of the reference. SINGLE PROCESS: the file is not locked.
//
// shortcut: the file store reads entry bytes from disk on demand and keeps one 32-byte hash per stored subtree in memory.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Stable codes of the errors the durable service and the stores return (a *CodedError).
const (
	ScittErrStoreRequired   = "store_required"
	ScittErrStoreCorrupt    = "store_corrupt"
	ScittErrAppendContended = "append_contention"
	ScittErrOutOfRange      = "out_of_range"
	ScittErrBadStatement    = "bad_statement"
)

func scLogErr(code, format string, a ...any) error {
	return &CodedError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// ScittRegistration is the outcome of registering a statement or re-issuing a receipt.
type ScittRegistration struct {
	Index   int64
	Receipt []byte
	Root    string
}

// ScittAppendResult is a registration plus the statement that was signed and registered.
type ScittAppendResult struct {
	ScittRegistration
	Statement []byte
}

// ScittConsistencyProofResult carries both roots (b64u) and the proof in the RFC 9942 consistency-proof-content encoding.
type ScittConsistencyProofResult struct {
	OldSize int64
	NewSize int64
	OldRoot string
	NewRoot string
	Proof   []byte
}

// ---- in-memory reference service ---------------------------------------------------------------------------------

// ScittTransparencyService is the in-memory reference log. It recomputes the tree on every registration; use it to produce
// receipts for tests and demos, never as a production transparency service.
type ScittTransparencyService struct {
	mu         sync.Mutex
	statements [][]byte
	leaves     [][]byte
	signer     ScittReceiptSigner
}

// NewScittTransparencyService creates an empty in-memory service that signs receipts with signer.
func NewScittTransparencyService(signer ScittReceiptSigner) *ScittTransparencyService {
	return &ScittTransparencyService{signer: signer}
}

// Size is the number of registered statements.
func (s *ScittTransparencyService) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.statements))
}

// Root is the current tree root (b64u); the empty-log root for an empty service.
func (s *ScittTransparencyService) Root() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return b64.EncodeToString(ScittTreeHash(s.leaves))
}

// Snapshot lists the b64u of every registered statement, in order.
func (s *ScittTransparencyService) Snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.statements))
	for _, st := range s.statements {
		out = append(out, b64.EncodeToString(st))
	}
	return out
}

func (s *ScittTransparencyService) receiptFor(index int64) (*ScittRegistration, error) {
	root := ScittTreeHash(s.leaves)
	size := int64(len(s.leaves))
	sides := ScittSiblingSides(index, size)
	hashes, err := ScittInclusionPath(s.leaves, index)
	if err != nil {
		return nil, err
	}
	path := make([]ScittProofStep, 0, len(hashes))
	for i, h := range hashes {
		path = append(path, ScittProofStep{Side: sides[i], Hash: b64.EncodeToString(h)})
	}
	r, err := ScittBuildReceipt(b64.EncodeToString(root), ScittInclusionProof{Index: index, Size: size, Path: path}, s.signer)
	if err != nil {
		return nil, err
	}
	return &ScittRegistration{Index: index, Receipt: r, Root: b64.EncodeToString(root)}, nil
}

func (s *ScittTransparencyService) register(statement []byte) (*ScittRegistration, error) {
	c, err := ScittDecodeCoseSign1(statement)
	if err != nil {
		return nil, err
	}
	if c.Detached {
		return nil, errors.New("scitt: cannot register a statement with a detached payload")
	}
	index := int64(len(s.statements))
	s.statements = append(s.statements, append([]byte(nil), statement...))
	s.leaves = append(s.leaves, ScittLeafHash(statement))
	return s.receiptFor(index)
}

// Register appends an already-signed Signed Statement (validated structurally first) and returns its inclusion receipt.
func (s *ScittTransparencyService) Register(statement []byte) (*ScittRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.register(statement)
}

// AppendAndReceipt signs payload as a Signed Statement, registers it and returns the statement with its receipt.
func (s *ScittTransparencyService) AppendAndReceipt(payload any, stmt ScittSignStatementOpts) (*ScittAppendResult, error) {
	st, err := ScittSignStatement(payload, stmt)
	if err != nil {
		return nil, err
	}
	r, err := s.Register(st)
	if err != nil {
		return nil, err
	}
	return &ScittAppendResult{ScittRegistration: *r, Statement: st}, nil
}

// GetReceipt re-issues a receipt for a registered statement, against the CURRENT ledger root.
func (s *ScittTransparencyService) GetReceipt(index int64) (*ScittRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= int64(len(s.statements)) {
		return nil, errors.New("getReceipt: index out of range")
	}
	return s.receiptFor(index)
}

// ConsistencyProof proves that the log at oldSize entries is a prefix of the current log.
func (s *ScittTransparencyService) ConsistencyProof(oldSize int64) (*ScittConsistencyProofResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int64(len(s.statements))
	if oldSize < 1 || oldSize > n {
		return nil, errors.New("consistencyProof: size out of range")
	}
	path, err := ScittConsistencyPath(s.leaves, oldSize)
	if err != nil {
		return nil, err
	}
	hs := make([]any, 0, len(path))
	for _, h := range path {
		hs = append(hs, h)
	}
	proof, err := ScittCborEncode([]any{oldSize, n, hs})
	if err != nil {
		return nil, err
	}
	return &ScittConsistencyProofResult{
		OldSize: oldSize, NewSize: n,
		OldRoot: b64.EncodeToString(ScittTreeHash(s.leaves[:oldSize])),
		NewRoot: b64.EncodeToString(ScittTreeHash(s.leaves)),
		Proof:   proof,
	}, nil
}

// ---- log store contract and the durable service -------------------------------------------------------------------

// ScittStoredNode is the hash of the complete subtree at Level covering leaves [Index * 2^Level, (Index + 1) * 2^Level).
type ScittStoredNode struct {
	Level int64
	Index int64
	Hash  []byte
}

// ScittLogStore is durable, append-only storage for a transparency log. Append is atomic: it succeeds only when the log has
// exactly expectedSize entries (a compare-and-set) and stores the entry and the new subtree hashes together, or none of them.
// GetEntry and GetNode report absence as found == false.
type ScittLogStore interface {
	Size() (int64, error)
	GetEntry(index int64) (entry []byte, found bool, err error)
	GetNode(level, index int64) (hash []byte, found bool, err error)
	Append(expectedSize int64, entry []byte, nodes []ScittStoredNode) (bool, error)
}

const scMaxAppendAttempts = 16

func scPow2Below(n int64) int64 {
	k := int64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

func scIsPow2(n int64) bool { return n > 0 && n&(n-1) == 0 }

func scLog2(n int64) int64 {
	l := int64(0)
	for n > 1 {
		n >>= 1
		l++
	}
	return l
}

// scLogReader holds the read-side algorithms over a store (hashes of ranges, root, proofs).
type scLogReader struct{ store ScittLogStore }

func (r *scLogReader) node(level, index int64) ([]byte, error) {
	h, found, err := r.store.GetNode(level, index)
	if err != nil {
		return nil, err
	}
	if !found || len(h) != 32 {
		return nil, scLogErr(ScittErrStoreCorrupt, "missing or malformed subtree hash (%d, %d)", level, index)
	}
	return h, nil
}

// rng is the MTH over leaves [lo, lo + n): lo is a multiple of the split points, which every caller guarantees.
func (r *scLogReader) rng(lo, n int64) ([]byte, error) {
	if n == 1 {
		return r.node(0, lo)
	}
	if scIsPow2(n) && lo%n == 0 {
		return r.node(scLog2(n), lo/n)
	}
	k := scPow2Below(n)
	a, err := r.rng(lo, k)
	if err != nil {
		return nil, err
	}
	b, err := r.rng(lo+k, n-k)
	if err != nil {
		return nil, err
	}
	return ScittNodeHash(a, b), nil
}

func (r *scLogReader) root(size int64) ([]byte, error) {
	if size == 0 {
		return ScittEmptyRoot(), nil
	}
	return r.rng(0, size)
}

func (r *scLogReader) inclusion(index, size int64) ([][]byte, error) {
	var walk func(lo, n, idx int64) ([][]byte, error)
	walk = func(lo, n, idx int64) ([][]byte, error) {
		if n == 1 {
			return [][]byte{}, nil
		}
		k := scPow2Below(n)
		if idx < k {
			p, err := walk(lo, k, idx)
			if err != nil {
				return nil, err
			}
			h, err := r.rng(lo+k, n-k)
			if err != nil {
				return nil, err
			}
			return append(p, h), nil
		}
		p, err := walk(lo+k, n-k, idx-k)
		if err != nil {
			return nil, err
		}
		h, err := r.rng(lo, k)
		if err != nil {
			return nil, err
		}
		return append(p, h), nil
	}
	return walk(0, size, index)
}

func (r *scLogReader) consistency(m, size int64) ([][]byte, error) {
	var sub func(lo, n, mm int64, complete bool) ([][]byte, error)
	sub = func(lo, n, mm int64, complete bool) ([][]byte, error) {
		if mm == n {
			if complete {
				return [][]byte{}, nil
			}
			h, err := r.rng(lo, n)
			if err != nil {
				return nil, err
			}
			return [][]byte{h}, nil
		}
		k := scPow2Below(n)
		if mm <= k {
			p, err := sub(lo, k, mm, complete)
			if err != nil {
				return nil, err
			}
			h, err := r.rng(lo+k, n-k)
			if err != nil {
				return nil, err
			}
			return append(p, h), nil
		}
		p, err := sub(lo+k, n-k, mm-k, false)
		if err != nil {
			return nil, err
		}
		h, err := r.rng(lo, k)
		if err != nil {
			return nil, err
		}
		return append(p, h), nil
	}
	return sub(0, size, m, true)
}

// ScittDurableService is a durable SCITT Transparency Service. The log keeps the hash of every complete aligned subtree in
// the store, so an append is O(log n) store operations, the root is O(log n) and a proof O(log^2 n). All state lives in the
// store: a restart loses nothing.
type ScittDurableService struct {
	store  ScittLogStore
	reader *scLogReader
	signer ScittReceiptSigner
}

// NewScittDurableService creates a durable service over store (required: there is no in-memory default).
func NewScittDurableService(store ScittLogStore, signer ScittReceiptSigner) (*ScittDurableService, error) {
	if store == nil {
		return nil, scLogErr(ScittErrStoreRequired, "a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default")
	}
	return &ScittDurableService{store: store, reader: &scLogReader{store: store}, signer: signer}, nil
}

// Size is the number of entries; a negative size reported by the store is store_corrupt.
func (d *ScittDurableService) Size() (int64, error) {
	n, err := d.store.Size()
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, scLogErr(ScittErrStoreCorrupt, "the store reported an invalid size")
	}
	return n, nil
}

// Root is the current tree root (b64u).
func (d *ScittDurableService) Root() (string, error) {
	n, err := d.Size()
	if err != nil {
		return "", err
	}
	r, err := d.reader.root(n)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(r), nil
}

func (d *ScittDurableService) receiptFor(index, size int64) (*ScittRegistration, error) {
	root, err := d.reader.root(size)
	if err != nil {
		return nil, err
	}
	sides := ScittSiblingSides(index, size)
	hashes, err := d.reader.inclusion(index, size)
	if err != nil {
		return nil, err
	}
	path := make([]ScittProofStep, 0, len(hashes))
	for i, h := range hashes {
		path = append(path, ScittProofStep{Side: sides[i], Hash: b64.EncodeToString(h)})
	}
	r, err := ScittBuildReceipt(b64.EncodeToString(root), ScittInclusionProof{Index: index, Size: size, Path: path}, d.signer)
	if err != nil {
		return nil, err
	}
	return &ScittRegistration{Index: index, Receipt: r, Root: b64.EncodeToString(root)}, nil
}

// Register appends a Signed Statement (validated structurally first) and returns its receipt against the new root.
func (d *ScittDurableService) Register(statement []byte) (*ScittRegistration, error) {
	c, err := ScittDecodeCoseSign1(statement)
	if err == nil && c.Detached {
		err = errors.New("detached payload")
	}
	if err != nil {
		return nil, scLogErr(ScittErrBadStatement, "cannot register: %s", err.Error())
	}
	for attempt := 0; attempt < scMaxAppendAttempts; attempt++ {
		n, err := d.Size()
		if err != nil {
			return nil, err
		}
		hash := ScittLeafHash(statement)
		nodes := []ScittStoredNode{{Level: 0, Index: n, Hash: hash}}
		// completing a subtree at level l: the new leaf is its last leaf, so its left sibling is already stored
		for level := int64(1); (n+1)%(int64(1)<<uint(level)) == 0; level++ {
			idx := (n+1)/(int64(1)<<uint(level)) - 1
			left, found, err := d.store.GetNode(level-1, 2*idx)
			if err != nil {
				return nil, err
			}
			if !found || len(left) != 32 {
				return nil, scLogErr(ScittErrStoreCorrupt, "missing subtree hash (%d, %d)", level-1, 2*idx)
			}
			hash = ScittNodeHash(left, hash)
			nodes = append(nodes, ScittStoredNode{Level: level, Index: idx, Hash: hash})
		}
		ok, err := d.store.Append(n, statement, nodes)
		if err != nil {
			return nil, err
		}
		if ok {
			return d.receiptFor(n, n+1)
		}
	}
	return nil, scLogErr(ScittErrAppendContended, "could not append: the log kept changing")
}

// AppendAndReceipt signs payload, registers the statement and returns it with its receipt.
func (d *ScittDurableService) AppendAndReceipt(payload any, stmt ScittSignStatementOpts) (*ScittAppendResult, error) {
	st, err := ScittSignStatement(payload, stmt)
	if err != nil {
		return nil, err
	}
	r, err := d.Register(st)
	if err != nil {
		return nil, err
	}
	return &ScittAppendResult{ScittRegistration: *r, Statement: st}, nil
}

// GetReceipt issues a receipt for an entry, against the CURRENT root.
func (d *ScittDurableService) GetReceipt(index int64) (*ScittRegistration, error) {
	size, err := d.Size()
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= size {
		return nil, scLogErr(ScittErrOutOfRange, "getReceipt: index out of range")
	}
	return d.receiptFor(index, size)
}

// GetEntry reads a stored statement.
func (d *ScittDurableService) GetEntry(index int64) ([]byte, error) {
	size, err := d.Size()
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= size {
		return nil, scLogErr(ScittErrOutOfRange, "getEntry: index out of range")
	}
	e, found, err := d.store.GetEntry(index)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, scLogErr(ScittErrStoreCorrupt, "entry %d is missing", index)
	}
	return e, nil
}

// ConsistencyProof proves that the first oldSize entries are a prefix of the current log.
func (d *ScittDurableService) ConsistencyProof(oldSize int64) (*ScittConsistencyProofResult, error) {
	size, err := d.Size()
	if err != nil {
		return nil, err
	}
	if oldSize < 1 || oldSize > size {
		return nil, scLogErr(ScittErrOutOfRange, "consistencyProof: size out of range")
	}
	path, err := d.reader.consistency(oldSize, size)
	if err != nil {
		return nil, err
	}
	oldR, err := d.reader.root(oldSize)
	if err != nil {
		return nil, err
	}
	nr, err := d.reader.root(size)
	if err != nil {
		return nil, err
	}
	hs := make([]any, 0, len(path))
	for _, h := range path {
		hs = append(hs, h)
	}
	proof, err := ScittCborEncode([]any{oldSize, size, hs})
	if err != nil {
		return nil, err
	}
	return &ScittConsistencyProofResult{OldSize: oldSize, NewSize: size, OldRoot: b64.EncodeToString(oldR), NewRoot: b64.EncodeToString(nr), Proof: proof}, nil
}

// ---- in-memory store ----------------------------------------------------------------------------------------------

// ScittMemoryLogStore is the in-memory ScittLogStore: single process, forgets everything on restart. For tests only.
type ScittMemoryLogStore struct {
	mu      sync.Mutex
	entries [][]byte
	nodes   map[[2]int64][]byte
}

// NewScittMemoryLogStore returns an empty in-memory store.
func NewScittMemoryLogStore() *ScittMemoryLogStore {
	return &ScittMemoryLogStore{nodes: map[[2]int64][]byte{}}
}

func (m *ScittMemoryLogStore) Size() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.entries)), nil
}

func (m *ScittMemoryLogStore) GetEntry(index int64) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if index < 0 || index >= int64(len(m.entries)) {
		return nil, false, nil
	}
	return append([]byte(nil), m.entries[index]...), true, nil
}

func (m *ScittMemoryLogStore) GetNode(level, index int64) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.nodes[[2]int64{level, index}]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), h...), true, nil
}

func (m *ScittMemoryLogStore) Append(expectedSize int64, entry []byte, nodes []ScittStoredNode) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if int64(len(m.entries)) != expectedSize {
		return false, nil
	}
	m.entries = append(m.entries, append([]byte(nil), entry...))
	for _, n := range nodes {
		m.nodes[[2]int64{n.Level, n.Index}] = append([]byte(nil), n.Hash...)
	}
	return true, nil
}

// ---- file store ----------------------------------------------------------------------------------------------------

type scFileOffset struct{ at, n int64 }

// ScittFileLogStore is a file-backed ScittLogStore: one append-only file of checksummed transactions, fsynced before Append
// returns, so a crash leaves either the whole transaction or none of it. A torn final record is discarded on open; corruption
// anywhere else is store_corrupt.
type ScittFileLogStore struct {
	mu      sync.Mutex
	f       *os.File
	nodes   map[[2]int64][]byte
	offsets []scFileOffset
	end     int64
}

// OpenScittFileLogStore opens (creating if absent) the log file at path and rebuilds the index.
func OpenScittFileLogStore(path string) (*ScittFileLogStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	s := &ScittFileLogStore{f: f, nodes: map[[2]int64][]byte{}}
	if err := s.load(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the log file.
func (s *ScittFileLogStore) Close() error { return s.f.Close() }

func (s *ScittFileLogStore) read(at, n int64) []byte {
	b := make([]byte, n)
	got := 0
	for int64(got) < n {
		k, err := s.f.ReadAt(b[got:], at+int64(got))
		got += k
		if k == 0 || err != nil {
			break
		}
	}
	return b[:got]
}

func (s *ScittFileLogStore) load() error {
	st, err := s.f.Stat()
	if err != nil {
		return err
	}
	total := st.Size()
	pos := int64(0)
	for pos < total {
		head := s.read(pos, 4)
		length := int64(-1)
		if len(head) == 4 {
			length = int64(binary.BigEndian.Uint32(head))
		}
		recEnd := pos + 4 + length + 32
		if length < 6 || recEnd > total {
			return s.discardTail(pos, recEnd > total)
		}
		payload := s.read(pos+4, length)
		sum := s.read(pos+4+length, 32)
		h := sha256.Sum256(payload)
		if !bytes.Equal(h[:], sum) {
			return s.discardTail(pos, recEnd == total)
		}
		entryLen := int64(binary.BigEndian.Uint32(payload[0:4]))
		p := 4 + entryLen
		if p+2 > length {
			return scLogErr(ScittErrStoreCorrupt, "a log record has an inconsistent length")
		}
		count := int64(binary.BigEndian.Uint16(payload[p : p+2]))
		p += 2
		if p+count*40 != length {
			return scLogErr(ScittErrStoreCorrupt, "a log record has an inconsistent length")
		}
		s.offsets = append(s.offsets, scFileOffset{at: pos + 8, n: entryLen})
		for i := int64(0); i < count; i, p = i+1, p+40 {
			lvl := int64(payload[p])
			idx := int64(binary.BigEndian.Uint32(payload[p+1 : p+5]))
			s.nodes[[2]int64{lvl, idx}] = append([]byte(nil), payload[p+8:p+40]...)
		}
		pos = recEnd
	}
	s.end = pos
	return nil
}

func (s *ScittFileLogStore) discardTail(pos int64, isTail bool) error {
	if !isTail {
		return scLogErr(ScittErrStoreCorrupt, "the log file is corrupt at offset %d", pos)
	}
	if err := s.f.Truncate(pos); err != nil {
		return err
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	s.end = pos
	return nil
}

func (s *ScittFileLogStore) Size() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.offsets)), nil
}

func (s *ScittFileLogStore) GetEntry(index int64) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= int64(len(s.offsets)) {
		return nil, false, nil
	}
	o := s.offsets[index]
	return s.read(o.at, o.n), true, nil
}

func (s *ScittFileLogStore) GetNode(level, index int64) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.nodes[[2]int64{level, index}]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), h...), true, nil
}

func (s *ScittFileLogStore) Append(expectedSize int64, entry []byte, nodes []ScittStoredNode) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int64(len(s.offsets)) != expectedSize {
		return false, nil
	}
	if len(nodes) > 0xffff || int64(len(entry)) > 0xffffffff {
		return false, scLogErr(ScittErrStoreCorrupt, "a subtree node is malformed")
	}
	for _, n := range nodes {
		if n.Level < 0 || n.Level > 255 || n.Index < 0 || n.Index > 0xffffffff || len(n.Hash) != 32 {
			return false, scLogErr(ScittErrStoreCorrupt, "a subtree node is malformed")
		}
	}
	payload := make([]byte, 4+len(entry)+2+len(nodes)*40)
	binary.BigEndian.PutUint32(payload[0:4], uint32(len(entry)))
	copy(payload[4:], entry)
	p := 4 + len(entry)
	binary.BigEndian.PutUint16(payload[p:p+2], uint16(len(nodes)))
	p += 2
	for _, n := range nodes {
		payload[p] = byte(n.Level)
		binary.BigEndian.PutUint32(payload[p+1:p+5], uint32(n.Index))
		copy(payload[p+8:p+40], n.Hash)
		p += 40
	}
	sum := sha256.Sum256(payload)
	record := make([]byte, 0, 4+len(payload)+32)
	record = binary.BigEndian.AppendUint32(record, uint32(len(payload)))
	record = append(record, payload...)
	record = append(record, sum[:]...)
	if _, err := s.f.WriteAt(record, s.end); err != nil {
		return false, err
	}
	if err := s.f.Sync(); err != nil {
		return false, err
	}
	s.offsets = append(s.offsets, scFileOffset{at: s.end + 8, n: int64(len(entry))})
	for _, n := range nodes {
		s.nodes[[2]int64{n.Level, n.Index}] = append([]byte(nil), n.Hash...)
	}
	s.end += int64(len(record))
	return true, nil
}

// ---- store contract check ------------------------------------------------------------------------------------------

// ScittCheckLogStore checks a store implementation against the contract the service relies on and returns the failures
// (empty = conforms): compare-and-set, atomic entry-plus-nodes, immutability and one winner among concurrent appends.
func ScittCheckLogStore(newStore func() (ScittLogStore, error)) []string {
	failures := []string{}
	fail := func(m string) { failures = append(failures, m) }
	s, err := newStore()
	if err != nil {
		return append(failures, "the store threw: "+err.Error())
	}
	h := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	thrown := func(err error) []string { return append(failures, "the store threw: "+err.Error()) }

	n, err := s.Size()
	if err != nil {
		return thrown(err)
	}
	if n != 0 {
		fail("a new store is not empty")
	}
	ok, err := s.Append(0, []byte{1}, []ScittStoredNode{{Level: 0, Index: 0, Hash: h(1)}})
	if err != nil {
		return thrown(err)
	}
	if !ok {
		fail("append at the right size was refused")
	}
	ok, err = s.Append(0, []byte{2}, []ScittStoredNode{{Level: 0, Index: 1, Hash: h(2)}})
	if err != nil {
		return thrown(err)
	}
	if ok {
		fail("append at a stale size was accepted (no compare-and-set)")
	}
	if n, err = s.Size(); err != nil {
		return thrown(err)
	} else if n != 1 {
		fail("a refused append changed the size")
	}
	if _, found, err := s.GetNode(0, 1); err != nil {
		return thrown(err)
	} else if found {
		fail("a refused append left a node behind (not atomic)")
	}
	if _, found, err := s.GetEntry(1); err != nil {
		return thrown(err)
	} else if found {
		fail("a refused append left an entry behind")
	}
	e0, found, err := s.GetEntry(0)
	if err != nil {
		return thrown(err)
	}
	if !found || len(e0) != 1 || e0[0] != 1 {
		fail("the stored entry does not read back")
	}
	if found && len(e0) > 0 {
		e0[0] = 9
	}
	again, found2, err := s.GetEntry(0)
	if err != nil {
		return thrown(err)
	}
	if !found2 || len(again) < 1 || again[0] != 1 {
		fail("a returned entry aliases the stored one (mutable)")
	}
	var wg sync.WaitGroup
	won := make([]bool, 4)
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			won[i], errs[i] = s.Append(1, []byte{byte(11 + i)}, []ScittStoredNode{{Level: 0, Index: 1, Hash: h(byte(11 + i))}})
		}(i)
	}
	wg.Wait()
	winners := 0
	for i := range won {
		if errs[i] != nil {
			return thrown(errs[i])
		}
		if won[i] {
			winners++
		}
	}
	if winners != 1 {
		fail("concurrent appends at the same size did not produce exactly one winner")
	}
	if n, err = s.Size(); err != nil {
		return thrown(err)
	} else if n != 2 {
		fail("the size after a race is not 2")
	}
	return failures
}
