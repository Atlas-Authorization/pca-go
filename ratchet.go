package pca

// The PCA Capability Ratchet (the reference @atlasauth/pca-ratchet): puncturable forward-secure one-time capability keys (a GGM
// tree of Ed25519 leaf keys under a Merkle-root commitment), the verifier-side spent-leaf and attested-risk bindings, and the
// adapters to the PCActn counter and the risk budget. Signatures and proofs are JSON objects in the reference's wire shape.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// RatchetMaxDepth bounds the tree depth; RatchetRiskScale is the accumulator units per unit of risk.
const (
	RatchetMaxDepth  = 20
	RatchetRiskScale = 1000
)

func ratchetErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

func jsIsInteger(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Floor(f) }

// jsBigInt is BigInt(x) for a JSON value: an integral number, a boolean, a numeric string or a *big.Int.
func jsBigInt(x any) (*big.Int, error) {
	switch v := x.(type) {
	case *big.Int:
		return v, nil
	case bool:
		if v {
			return big.NewInt(1), nil
		}
		return big.NewInt(0), nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return big.NewInt(0), nil
		}
		base := 10
		if len(s) > 2 && s[0] == '0' {
			switch s[1] {
			case 'x', 'X':
				base = 16
			case 'o', 'O':
				base = 8
			case 'b', 'B':
				base = 2
			}
			if base != 10 {
				s = s[2:]
			}
		}
		body := s
		if base == 10 && len(s) > 1 && (s[0] == '+' || s[0] == '-') {
			body = s[1:] // only a decimal may carry a sign
		}
		if strings.ContainsAny(body, "+-") {
			return nil, errors.New("Cannot convert " + v + " to a BigInt")
		}
		n, ok := new(big.Int).SetString(s, base)
		if !ok {
			return nil, errors.New("Cannot convert " + v + " to a BigInt")
		}
		return n, nil
	}
	f, ok := jsNum(x)
	if !ok || !jsIsInteger(f) {
		return nil, fmt.Errorf("The number %s cannot be converted to a BigInt because it is not an integer", jsValueString(x))
	}
	n, _ := new(big.Float).SetFloat64(f).Int(nil)
	return n, nil
}

func ratchetU64(n *big.Int) []byte {
	m := new(big.Int).Mod(n, new(big.Int).Lsh(big.NewInt(1), 64))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], m.Uint64())
	return b[:]
}

// ---- GGM puncturable PRF tree --------------------------------------------------------------------------------------------

var (
	ggmPrgDomain     = []byte("atlas-pca-ratchet/ggm-prg/v1")
	ggmLeafKeyDomain = []byte("atlas-pca-ratchet/ggm-leafkey/v1")
	ggmRootDomain    = []byte("atlas-pca-ratchet/ggm-root/v1")
)

func ggmHMAC(key []byte, msg ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, x := range msg {
		m.Write(x)
	}
	return m.Sum(nil)
}

func ggmLeft(seed []byte) []byte  { return ggmHMAC(seed, ggmPrgDomain, []byte{0}) }
func ggmRight(seed []byte) []byte { return ggmHMAC(seed, ggmPrgDomain, []byte{1}) }

func ggmLeafPublicKey(leafSeed []byte) string {
	k := ed25519.NewKeyFromSeed(ggmHMAC(leafSeed, ggmLeafKeyDomain))
	return b64.EncodeToString(k.Public().(ed25519.PublicKey))
}

// RatchetNode is a covering node of the GGM tree (its seed signs every leaf under it).
type RatchetNode struct {
	Level, NodeIndex int
	Seed             []byte
}

// RatchetState is a ratchet: SignAtLeaf returns the punctured successor, the old state must be discarded.
type RatchetState struct {
	Depth          int
	LeafCount      int
	RootCommitment string
	LeafPubKeys    []string
	Covering       map[string]RatchetNode
}

func ratchetCoverKey(level, nodeIndex int) string {
	return strconv.Itoa(level) + ":" + strconv.Itoa(nodeIndex)
}

// covers uses JS semantics: floor(leaf / 2^k) (a fraction still lands in a subtree).
func ratchetCovers(n RatchetNode, leaf float64, depth int) bool {
	q := leaf / math.Pow(2, float64(depth-n.Level))
	return !math.IsNaN(q) && !math.IsInf(q, 0) && math.Floor(q) == float64(n.NodeIndex)
}

func ratchetBit(level, leaf, depth int) int { return (leaf >> uint(depth-level-1)) & 1 }

// DeriveRatchetRoot builds a ratchet from >= 32 bytes of entropy and a tree depth in [1, RatchetMaxDepth].
func DeriveRatchetRoot(seed []byte, depth float64) (*RatchetState, error) {
	if !jsIsInteger(depth) || depth < 1 || depth > RatchetMaxDepth {
		return nil, ratchetErr("invalid_depth", fmt.Sprintf("depth must be an integer in [1, %d]", RatchetMaxDepth))
	}
	if len(seed) < 32 {
		return nil, ratchetErr("invalid_seed", "seed must be a Uint8Array of at least 32 bytes")
	}
	d := int(depth)
	root := ggmHMAC(seed, ggmRootDomain)
	pubs := make([]string, 1<<d)
	var rec func(s []byte, level, base int)
	rec = func(s []byte, level, base int) {
		if level == d {
			pubs[base] = ggmLeafPublicKey(s)
			return
		}
		rec(ggmLeft(s), level+1, base)
		rec(ggmRight(s), level+1, base+1<<(d-level-1))
	}
	rec(root, 0, 0)
	leaves := make([]any, len(pubs))
	for i, p := range pubs {
		leaves[i] = p
	}
	rc, err := MerkleRoot(leaves)
	if err != nil {
		return nil, err
	}
	return &RatchetState{Depth: d, LeafCount: 1 << d, RootCommitment: rc, LeafPubKeys: pubs,
		Covering: map[string]RatchetNode{ratchetCoverKey(0, 0): {Level: 0, NodeIndex: 0, Seed: root}}}, nil
}

func (s *RatchetState) findCovering(leaf float64) (RatchetNode, bool) {
	for _, n := range s.Covering {
		if ratchetCovers(n, leaf, s.Depth) {
			return n, true
		}
	}
	return RatchetNode{}, false
}

var (
	ratchetNullifierDomain = []byte("atlas-pca-ratchet/nullifier/v1\x00")
	ratchetSigDomain       = []byte("atlas-pca-ratchet/leaf-sig/v1\x00")
)

// LeafNullifier is b64u(sha256(domain || len32(root) || root || index64)): what a verifier records to detect leaf reuse.
// leafIndex is read as BigInt(leafIndex) reads it.
func LeafNullifier(rootCommitment string, leafIndex any) (string, error) {
	n, err := jsBigInt(leafIndex)
	if err != nil {
		return "", err
	}
	root := []byte(wellFormedUTF8(rootCommitment))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(root)))
	h := sha256.Sum256(append(append(append(append([]byte{}, ratchetNullifierDomain...), l[:]...), root...), ratchetU64(n)...))
	return b64.EncodeToString(h[:]), nil
}

func ratchetSigMessage(leaf *big.Int, msg []byte) []byte {
	return append(append(append([]byte{}, ratchetSigDomain...), ratchetU64(leaf)...), msg...)
}

func ratchetMerkleProof(leaves []string, index int) (map[string]any, error) {
	hs := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := leafHash(l)
		if err != nil {
			return nil, err
		}
		hs[i] = h
	}
	path := []any{}
	var prove func(hs [][]byte, idx int)
	prove = func(hs [][]byte, idx int) {
		if len(hs) == 1 {
			return
		}
		k := split(len(hs))
		if idx < k {
			prove(hs[:k], idx)
			path = append(path, map[string]any{"side": "R", "hash": b64.EncodeToString(build(hs[k:]))})
		} else {
			prove(hs[k:], idx-k)
			path = append(path, map[string]any{"side": "L", "hash": b64.EncodeToString(build(hs[:k]))})
		}
	}
	prove(hs, index)
	return map[string]any{"index": json.Number(strconv.Itoa(index)), "size": json.Number(strconv.Itoa(len(leaves))), "path": path}, nil
}

// SignAtLeaf signs message at a leaf, then punctures it: the signature {edSig, leafPubKey, merklePath, nullifier} and the successor
// state. leaf_out_of_range / leaf_punctured refuse.
func SignAtLeaf(state *RatchetState, leafIndex float64, message []byte) (map[string]any, *RatchetState, error) {
	if state == nil {
		return nil, nil, errors.New("signAtLeaf needs a ratchet state")
	}
	if !jsIsInteger(leafIndex) || leafIndex < 0 || leafIndex >= float64(state.LeafCount) {
		return nil, nil, ratchetErr("leaf_out_of_range", fmt.Sprintf("leaf %s is out of range [0, %d)", jsLenientNumber(leafIndex), state.LeafCount))
	}
	leaf := int(leafIndex)
	node, ok := state.findCovering(float64(leaf))
	if !ok {
		return nil, nil, ratchetErr("leaf_punctured", fmt.Sprintf("leaf %d is already punctured (spent) and cannot sign", leaf))
	}
	seed := node.Seed
	for level := node.Level; level < state.Depth; level++ {
		if ratchetBit(level, leaf, state.Depth) == 0 {
			seed = ggmLeft(seed)
		} else {
			seed = ggmRight(seed)
		}
	}
	bl := big.NewInt(int64(leaf))
	edSig := ed25519.Sign(ed25519.NewKeyFromSeed(ggmHMAC(seed, ggmLeafKeyDomain)), ratchetSigMessage(bl, message))
	mp, err := ratchetMerkleProof(state.LeafPubKeys, leaf)
	if err != nil {
		return nil, nil, err
	}
	nul, _ := LeafNullifier(state.RootCommitment, bl)
	covering := make(map[string]RatchetNode, len(state.Covering)+state.Depth)
	for k, v := range state.Covering {
		covering[k] = v
	}
	delete(covering, ratchetCoverKey(node.Level, node.NodeIndex))
	s, idx := node.Seed, node.NodeIndex
	for level := node.Level; level < state.Depth; level++ {
		bit := ratchetBit(level, leaf, state.Depth)
		left, right := ggmLeft(s), ggmRight(s)
		sib := RatchetNode{Level: level + 1, NodeIndex: idx*2 + (1 - bit), Seed: right}
		s = left
		if bit == 1 {
			sib.Seed, s = left, right
		}
		covering[ratchetCoverKey(sib.Level, sib.NodeIndex)] = sib
		idx = idx*2 + bit
	}
	next := *state
	next.Covering = covering
	sig := map[string]any{"edSig": b64.EncodeToString(edSig), "leafPubKey": ggmLeafPublicKey(seed), "merklePath": mp, "nullifier": nul}
	return sig, &next, nil
}

// VerifyLeafSignature checks a leaf signature offline against the root commitment; malformed input is false.
func VerifyLeafSignature(rootCommitment string, leafIndex any, message []byte, signature any) bool {
	sig, ok := signature.(map[string]any)
	if !ok {
		return false
	}
	nul, _ := sig["nullifier"].(string)
	want, err := LeafNullifier(rootCommitment, leafIndex)
	if err != nil || nul == "" || nul != want {
		return false
	}
	edSig, ok1 := sig["edSig"].(string)
	pub, ok2 := sig["leafPubKey"].(string)
	mp, ok3 := sig["merklePath"].(map[string]any)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	_, b1 := mp["index"].(bool)
	_, b2 := leafIndex.(bool)
	mi, ok4 := jsNum(mp["index"])
	li, ok5 := jsNum(leafIndex)
	if b1 || b2 || !ok4 || !ok5 || mi != li {
		return false
	}
	// the root commits under sha256: a proof naming any other hash suite cannot belong to it
	if hs, has := mp["hash_suite"]; has && hs != "sha256" {
		return false
	}
	n, _ := jsBigInt(leafIndex)
	if !verifyB64u(pub, ratchetSigMessage(n, message), edSig) {
		return false
	}
	return VerifyInclusion(rootCommitment, mp, pub)
}

// AvailableLeaves lists the leaves that can still sign, ascending.
func AvailableLeaves(state *RatchetState) []int {
	out := []int{}
	for _, n := range state.Covering {
		span := 1 << (state.Depth - n.Level)
		for i := 0; i < span; i++ {
			out = append(out, n.NodeIndex*span+i)
		}
	}
	sort.Ints(out)
	return out
}

// IsLeafAvailable: a covering node still holds the leaf.
func IsLeafAvailable(state *RatchetState, leafIndex float64) bool {
	_, ok := state.findCovering(leafIndex)
	return ok
}

// ---- adapters: ratchet leaf <-> PCActn counter, accumulator units <-> RiskPolicy budget ----------------------------------

const jsMaxSafe = 1<<53 - 1

// CounterToLeafIndex maps a PCActn counter to a leaf of a depth-`depth` ratchet.
func CounterToLeafIndex(counter, depth float64) (int, error) {
	if !jsIsInteger(depth) || depth < 1 || depth > RatchetMaxDepth {
		return 0, ratchetErr("invalid_depth", fmt.Sprintf("depth must be an integer in [1, %d]", RatchetMaxDepth))
	}
	if !jsIsInteger(counter) || math.Abs(counter) > jsMaxSafe || counter < 0 || math.Signbit(counter) {
		return 0, ratchetErr("leaf_out_of_range", "counter must be a non-negative safe integer")
	}
	if counter >= math.Pow(2, depth) {
		return 0, ratchetErr("leaf_out_of_range", fmt.Sprintf("counter %s exceeds the ratchet capacity 2^%s", jsLenientNumber(counter), jsLenientNumber(depth)))
	}
	return int(counter), nil
}

// LeafIndexToCounter is the inverse map.
func LeafIndexToCounter(leafIndex float64) (int, error) {
	if !jsIsInteger(leafIndex) || math.Abs(leafIndex) > jsMaxSafe || leafIndex < 0 || math.Signbit(leafIndex) {
		return 0, ratchetErr("leaf_out_of_range", "leafIndex must be a non-negative safe integer")
	}
	return int(leafIndex), nil
}

// LeafIndexForAction is CounterToLeafIndex over a PCActn's counter member.
func LeafIndexForAction(actn map[string]any, depth float64) (int, error) {
	c := math.NaN()
	if _, isBool := actn["counter"].(bool); !isBool {
		if f, ok := jsNum(actn["counter"]); ok {
			c = f
		}
	}
	return CounterToLeafIndex(c, depth)
}

func jsRound(v float64) float64 {
	f := math.Floor(v)
	if v-f >= 0.5 {
		return f + 1
	}
	return f
}

func bigOfFloat(f float64) (*big.Int, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("The number %s cannot be converted to a BigInt because it is not an integer", jsLenientNumber(f))
	}
	n, _ := new(big.Float).SetFloat64(f).Int(nil)
	return n, nil
}

// RiskToUnits quantizes a risk score to integer accumulator units, rounding UP so the sum never under-counts (float noise tolerated).
func RiskToUnits(r float64) (*big.Int, error) {
	if math.IsNaN(r) || math.IsInf(r, 0) || r < 0 {
		return nil, accErr("invalid_value", "risk must be a finite number >= 0")
	}
	v := float64(r * RatchetRiskScale)
	nearest := jsRound(v)
	if math.Abs(v-nearest) <= 1e-9*math.Max(1, v) {
		return bigOfFloat(nearest)
	}
	return bigOfFloat(math.Ceil(v))
}

// RiskQuantizer is a carry-forward quantizer: the running total of emitted units is always ceil(sum(true risk) * scale).
type RiskQuantizer struct{ nano, emitted *big.Int }

var ratchetNano = big.NewInt(1_000_000)

// Next emits the units for one more risk.
func (q *RiskQuantizer) Next(r float64) (*big.Int, error) {
	if q.nano == nil {
		q.nano, q.emitted = big.NewInt(0), big.NewInt(0)
	}
	if math.IsNaN(r) || math.IsInf(r, 0) || r < 0 {
		return nil, accErr("invalid_value", "risk must be a finite number >= 0")
	}
	add, err := bigOfFloat(math.Ceil(float64(r*RatchetRiskScale*1e6) - 1e-3))
	if err != nil {
		return nil, err
	}
	q.nano.Add(q.nano, add)
	total := new(big.Int).Add(q.nano, new(big.Int).Sub(ratchetNano, big.NewInt(1)))
	total.Quo(total, ratchetNano)
	out := new(big.Int).Sub(total, q.emitted)
	q.emitted = total
	return out, nil
}

// TotalUnits is the units emitted so far.
func (q *RiskQuantizer) TotalUnits() *big.Int {
	if q.emitted == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(q.emitted)
}

// BudgetCeilingUnits is the accumulator ceiling in units: floor(SafetyBound(bMax, kappa) * scale). The members are read with
// JavaScript number semantics (a missing or non-numeric bMax refuses; a kappa that is not > 0 gives 0).
func BudgetCeilingUnits(policy map[string]any) (*big.Int, error) {
	if policy == nil {
		return nil, errors.New("policy must be an object")
	}
	num := func(k string) float64 {
		if v, has := policy[k]; has {
			return jsToNumber(v)
		}
		return math.NaN()
	}
	bound := SafetyBound(num("bMax"), num("kappa"))
	if math.IsNaN(bound) || math.IsInf(bound, 0) || bound < 0 {
		return nil, accErr("invalid_value", "safety bound (bMax/kappa) must be finite and >= 0")
	}
	return bigOfFloat(math.Floor(bound * RatchetRiskScale))
}

// ---- verifier-side bindings ----------------------------------------------------------------------------------------------

// SpentLeafStore records the first message signed at each leaf nullifier (first claim wins). A fleet of verifiers shares one.
type SpentLeafStore interface {
	// Claim records record under nullifier when it is new (first true); otherwise it returns the record already there.
	Claim(nullifier, record string) (first bool, previous string, err error)
}

// MemorySpentLeafStore is an in-process SpentLeafStore.
type MemorySpentLeafStore struct {
	mu   sync.Mutex
	seen map[string]string
}

// Claim implements SpentLeafStore.
func (m *MemorySpentLeafStore) Claim(nullifier, record string) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]string{}
	}
	if p, has := m.seen[nullifier]; has {
		return false, p, nil
	}
	m.seen[nullifier] = record
	return true, "", nil
}

// LeafVerdict is the result of VerifyLeafSignatureOnce.
type LeafVerdict struct {
	OK                  bool   `json:"ok"`
	Reason              string `json:"reason,omitempty"` // invalid | replay | equivocation | store-error
	Nullifier           string `json:"nullifier,omitempty"`
	FirstMessageDigest  string `json:"firstMessageDigest,omitempty"`
	SecondMessageDigest string `json:"secondMessageDigest,omitempty"`
}

// VerifyLeafSignatureOnce verifies a leaf signature and enforces one-time use: a second signature at a leaf is replay (same
// message) or equivocation (different message). Fail closed: a store error denies with store-error.
func VerifyLeafSignatureOnce(rootCommitment string, leafIndex any, message []byte, signature any, store SpentLeafStore) LeafVerdict {
	if !VerifyLeafSignature(rootCommitment, leafIndex, message, signature) {
		return LeafVerdict{Reason: "invalid"}
	}
	nul, _ := LeafNullifier(rootCommitment, leafIndex)
	h := sha256.Sum256(message)
	idx := jsValueString(leafIndex)
	if f, ok := jsNum(leafIndex); ok {
		idx = jsLenientNumber(f)
	}
	mine := b64.EncodeToString(h[:]) + "@" + idx
	if store == nil {
		return LeafVerdict{Reason: "store-error"}
	}
	first, prev, err := store.Claim(nul, mine)
	switch {
	case err != nil:
		return LeafVerdict{Reason: "store-error"}
	case first:
		return LeafVerdict{OK: true}
	case prev == mine:
		return LeafVerdict{Reason: "replay", Nullifier: nul}
	}
	return LeafVerdict{Reason: "equivocation", Nullifier: nul, FirstMessageDigest: prev, SecondMessageDigest: mine}
}

var ratchetAttestDomain = []byte("atlas-pca-ratchet/risk-attestation/v1\x00")

func ratchetAttestMessage(digest, commitment string) []byte {
	a, c := []byte(wellFormedUTF8(digest)), []byte(wellFormedUTF8(commitment))
	out := append([]byte{}, ratchetAttestDomain...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(a)))
	out = append(append(out, l[:]...), a...)
	binary.BigEndian.PutUint32(l[:], uint32(len(c)))
	return append(append(out, l[:]...), c...)
}

// IssuedRiskCommitment is what a risk authority hands out for one action.
type IssuedRiskCommitment struct {
	Commitment  string            `json:"commitment"`
	Blinding    *big.Int          `json:"blinding"`
	RangeProof  map[string]any    `json:"rangeProof"`
	Attestation map[string]string `json:"attestation"` // {actionDigest, sig}
}

// IssueRiskCommitment (risk authority side) commits to the risk, proves its range and signs (actionDigest, commitment) with the
// authority's 32-byte Ed25519 seed.
func IssueRiskCommitment(risk any, actionDigest string, authoritySecretKey []byte) (*IssuedRiskCommitment, error) {
	c, err := CommitRisk(risk, nil)
	if err != nil {
		return nil, err
	}
	if len(authoritySecretKey) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key of length 32 expected, got %d", len(authoritySecretKey))
	}
	rp, err := ProveRiskRange(risk, c.Blinding)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(authoritySecretKey), ratchetAttestMessage(actionDigest, c.Commitment))
	return &IssuedRiskCommitment{Commitment: c.Commitment, Blinding: c.Blinding, RangeProof: rp,
		Attestation: map[string]string{"actionDigest": actionDigest, "sig": b64.EncodeToString(sig)}}, nil
}

// VerifyRiskAttestation checks the authority signature over (attestation.actionDigest, commitment). Never fails open.
func VerifyRiskAttestation(commitment any, attestation any, authorityPublicKey any) bool {
	a, ok := attestation.(map[string]any)
	c, okc := commitment.(string)
	pk, okp := authorityPublicKey.(string)
	if !ok || !okc || !okp {
		return false
	}
	d, ok1 := a["actionDigest"].(string)
	s, ok2 := a["sig"].(string)
	return ok1 && ok2 && verifyB64u(pk, ratchetAttestMessage(d, c), s)
}

// VerifyAttestedBudget: every item {commitment, rangeProof, attestation} carries a valid authority attestation for exactly the
// expected digest and its commitment, then the bounded-budget proof must hold. Never fails open.
func VerifyAttestedBudget(items any, expectedActionDigests any, authorityPublicKey any, bMax any, budgetProof any) bool {
	its, ok1 := items.([]any)
	ds, ok2 := expectedActionDigests.([]any)
	if !ok1 || !ok2 || len(its) != len(ds) {
		return false
	}
	cs := make([]any, len(its))
	rps := make([]any, len(its))
	for i, x := range its {
		it, ok := x.(map[string]any)
		if !ok {
			return false
		}
		att, ok := it["attestation"].(map[string]any)
		if !ok || !jsStrictEq(att["actionDigest"], ds[i]) {
			return false
		}
		if !VerifyRiskAttestation(it["commitment"], att, authorityPublicKey) {
			return false
		}
		cs[i], rps[i] = it["commitment"], it["rangeProof"]
	}
	return VerifyBoundedBudget(cs, rps, bMax, budgetProof)
}
