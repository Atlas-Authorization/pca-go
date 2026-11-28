package pca

import (
	"errors"
	"fmt"
	"sync"
)

// Chain compaction: a long delegation chain folds into one handle, a Merkle root over the ordered hop hashes, plus the leaf hop.
// A verifier that has verified the full chain once remembers it under that root; later presentations carry only
// {depth, hops_root, leaf}. Nothing is trusted from the presentation: it is accepted only when the verifier's own memo holds an
// entry that its own chain verification produced.

// ChainHopLeaf is the Merkle leaf of one hop: its content hash under a domain tag.
func ChainHopLeaf(hop map[string]any) (map[string]any, error) {
	h, err := CapHash(hop)
	if err != nil {
		return nil, err
	}
	return map[string]any{"d": ChainHopDomain, "hop": h}, nil
}

// HopLeaf is ChainHopLeaf.
func HopLeaf(hop map[string]any) (map[string]any, error) { return ChainHopLeaf(hop) }

// HopsRoot is the handle of a chain: the Merkle root over its ordered hop leaves.
func HopsRoot(chain []any) (string, error) {
	leaves := make([]any, len(chain))
	for i, h := range chain {
		hm, ok := h.(map[string]any)
		if !ok {
			return "", errors.New("hopsRoot: a hop is not an object")
		}
		l, err := ChainHopLeaf(hm)
		if err != nil {
			return "", err
		}
		leaves[i] = l
	}
	return MerkleRoot(leaves)
}

// CompactChain folds a chain into {v, kind, depth, hops_root, leaf}. It errors on an empty or over-deep chain and does not
// verify the chain (the memo does).
func CompactChain(chain []any) (map[string]any, error) {
	if len(chain) == 0 || len(chain) > MaxChainHops {
		return nil, errors.New("compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops")
	}
	root, err := HopsRoot(chain)
	if err != nil {
		return nil, err
	}
	return map[string]any{"v": jsonOne(), "kind": "pca-chain-compact", "depth": jsNumber(float64(len(chain))), "hops_root": root, "leaf": chain[len(chain)-1]}, nil
}

// CompactChainShapeError is "" for a well-formed compact chain, else the reason.
func CompactChainShapeError(c any) string {
	o, ok := c.(map[string]any)
	if !ok {
		return "not an object"
	}
	if e := closedMembersMsg(o, "compact chain", []string{"v", "kind", "depth", "hops_root", "leaf"}); e != "" {
		return e
	}
	if v, ok := jsNum(o["v"]); !ok || v != 1 || o["kind"] != "pca-chain-compact" {
		return "not a pca-chain-compact v1"
	}
	d, ok := jsNum(o["depth"])
	if !ok || d != float64(int64(d)) || d < 1 || d > MaxChainHops {
		return fmt.Sprintf("depth must be 1..%d", MaxChainHops)
	}
	if hr, isStr := o["hops_root"].(string); !isStr || len(hr) != 43 {
		return "hops_root must be a 43 character digest"
	}
	if _, isObj := o["leaf"].(map[string]any); !isObj {
		return "leaf must be a capability"
	}
	return ""
}

// ChainMemoEntry is what a verifier remembers about a chain it verified.
type ChainMemoEntry struct {
	Depth    int
	HopsRoot string
	// Hashes is the capability hash of every hop, root first.
	Hashes []string
	// Counts is the length of every hop's (cumulative) caveat list.
	Counts    []int
	ExpiresAt int64
}

// ChainMemoOptions bound a ChainMemo. Zero values mean the defaults (ChainMemoDefaultMaxEntries, ChainMemoMaxTTLMs).
type ChainMemoOptions struct {
	MaxEntries int
	TTLMs      int64
}

// ChainPolicy is the optional policy of the full chain verification a memo runs (see VerifyChainPolicy).
type ChainPolicy struct {
	// Allowed is the allowed-suites list (nil = none; a present, even empty, list enforces).
	Allowed []string
	// PqPins maps a root issuer to the PQ public key the verifier pins for it.
	PqPins map[string]string
	// TrustedRoot is the verifier's own stored copy of the root capability.
	TrustedRoot map[string]any
}

// ChainMemo is a verifier-side memo that remembers a chain only after its own chain verification passed. It fails closed when
// full: a full memo never evicts a live entry, so one tenant cannot push another out. Safe for concurrent use.
type ChainMemo struct {
	mu      sync.Mutex
	entries map[string]ChainMemoEntry
	opts    ChainMemoOptions
}

// NewChainMemo returns an empty memo.
func NewChainMemo(opts ChainMemoOptions) *ChainMemo {
	return &ChainMemo{entries: map[string]ChainMemoEntry{}, opts: opts}
}

// Size is the number of remembered chains.
func (m *ChainMemo) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// RememberVerified verifies chain (rooted at expectedRootIssuer) with the full verifier and remembers it. It errors when the
// chain does not verify or the memo is full of live entries. It returns the compact form a holder presents.
func (m *ChainMemo) RememberVerified(chain []any, expectedRootIssuer string, now int64, policy *ChainPolicy) (map[string]any, error) {
	if now > maxSafeInt || now < -maxSafeInt {
		return nil, errors.New("rememberVerified: the clock is not a safe integer")
	}
	var allowed []string
	var pins map[string]string
	var trusted map[string]any
	if policy != nil {
		allowed, pins, trusted = policy.Allowed, policy.PqPins, policy.TrustedRoot
	}
	if why, ok := VerifyChainPolicy(chain, expectedRootIssuer, true, allowed, pins, trusted); !ok {
		if why == "" {
			why = "invalid"
		}
		return nil, errors.New("rememberVerified: the chain does not verify: " + why)
	}
	compact, err := CompactChain(chain)
	if err != nil {
		return nil, err
	}
	ttl := m.opts.TTLMs
	if ttl <= 0 || ttl > ChainMemoMaxTTLMs {
		ttl = ChainMemoMaxTTLMs
	}
	maxEntries := m.opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = ChainMemoDefaultMaxEntries
	}
	hashes := make([]string, len(chain))
	counts := make([]int, len(chain))
	for i, h := range chain {
		hm, _ := h.(map[string]any)
		if hashes[i], err = CapHash(hm); err != nil {
			return nil, err
		}
		if cs, isList := hm["caveats"].([]any); isList {
			counts[i] = len(cs)
		}
	}
	root := compact["hops_root"].(string)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	if _, has := m.entries[root]; !has && len(m.entries) >= maxEntries {
		return nil, errors.New("rememberVerified: the memo is full of live entries")
	}
	m.entries[root] = ChainMemoEntry{Depth: len(chain), HopsRoot: root, Hashes: hashes, Counts: counts, ExpiresAt: now + ttl}
	return compact, nil
}

func (m *ChainMemo) pruneLocked(now int64) {
	for k, e := range m.entries {
		if e.ExpiresAt < now {
			delete(m.entries, k)
		}
	}
}

// Prune drops the entries whose time is up.
func (m *ChainMemo) Prune(now int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
}

// Forget removes a chain (for example when it is revoked); it reports whether the chain was remembered.
func (m *ChainMemo) Forget(hopsRoot string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, had := m.entries[hopsRoot]
	delete(m.entries, hopsRoot)
	return had
}

// ChainResolveVerdict is the result of resolving a presented compact chain.
type ChainResolveVerdict struct {
	OK     bool
	View   ChainView
	Reason string
}

// Resolve resolves a presented compact chain against the memo. It is total: any error is a refusal.
func (m *ChainMemo) Resolve(compact any, now int64) (v ChainResolveVerdict) {
	defer func() {
		if r := recover(); r != nil {
			v = ChainResolveVerdict{Reason: fmt.Sprintf("compact chain error (fail closed): %v", r)}
		}
	}()
	no := func(r string) ChainResolveVerdict { return ChainResolveVerdict{Reason: r} }
	if now > maxSafeInt || now < -maxSafeInt {
		return no("the verifier clock is not a safe integer (fail closed)")
	}
	c := normalizeJSON(compact)
	if e := CompactChainShapeError(c); e != "" {
		return no("malformed compact chain: " + e)
	}
	cm := c.(map[string]any)
	root := cm["hops_root"].(string)
	m.mu.Lock()
	e, found := m.entries[root]
	if found && e.ExpiresAt < now {
		delete(m.entries, root)
	}
	m.mu.Unlock()
	if !found {
		return no("the chain is not in this verifier memo (present the full chain)")
	}
	if e.ExpiresAt < now {
		return no("the memoized chain has expired (present the full chain)")
	}
	if d, _ := jsNum(cm["depth"]); int(d) != e.Depth {
		return no("the depth differs from the memoized chain")
	}
	leaf := cm["leaf"].(map[string]any)
	if h, err := CapHash(leaf); err != nil || h != e.Hashes[e.Depth-1] {
		return no("the leaf is not the memoized last hop")
	}
	if cs, isList := leaf["caveats"].([]any); !isList || len(cs) != e.Counts[e.Depth-1] {
		return no("the leaf caveats differ from the memoized chain")
	}
	return ChainResolveVerdict{OK: true, View: ChainView{
		N:     e.Depth,
		Leaf:  leaf,
		Hash:  func(i int) (string, error) { return e.Hashes[i], nil },
		Count: func(i int) int { return e.Counts[i] },
	}}
}

// ViewOfChain is the view of a full chain, for symmetry with ChainMemo.Resolve (both feed the caveat language).
func ViewOfChain(grant, chain any) ChainView { return NewChainView(grant, chain) }
