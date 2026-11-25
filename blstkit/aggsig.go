// Package blstkit holds the pairing-based PCA packages (BLS aggregation, BBS signatures, attribute-based encryption) on
// supranational/blst through its cgo bindings. It is a separate module so the core module stays cgo-free.
package blstkit

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	pca "github.com/Atlas-Authorization/pca-go"
	blst "github.com/supranational/blst/bindings/go"
)

// BLS signatures on BLS12-381, proof-of-possession ciphersuite, public keys in G1 (48 bytes), signatures in G2 (96 bytes).
// Rogue-key safety by construction: aggregate verification only accepts *RegisteredKey, which only RegisterKey /
// KeyRegistry.Register can produce, and both verify a proof of possession first.

const (
	// SigDST is the hash-to-curve domain separation tag for signatures.
	SigDST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
	// PopDST is the distinct tag for proofs of possession.
	PopDST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
	// PublicKeyLength is the compressed G1 key length.
	PublicKeyLength = 48
	// SignatureLength is the compressed G2 signature length.
	SignatureLength = 96
)

var (
	sigDST = []byte(SigDST)
	popDST = []byte(PopDST)
	b64u   = base64.RawURLEncoding
)

func isCompressed(b []byte, n int) bool { return len(b) == n && b[0]&0x80 != 0 }

// IsCanonicalSignature: a 96-byte compressed G2 point whose encoding is exactly the re-encoding of the point it decodes to.
func IsCanonicalSignature(sig []byte) bool {
	if !isCompressed(sig, SignatureLength) {
		return false
	}
	s := new(blst.P2Affine).Uncompress(sig)
	return s != nil && bytes.Equal(s.Compress(), sig)
}

// KeyValidate: a canonical compressed G1 point, not the identity, in the prime-order subgroup. Never panics.
func KeyValidate(publicKey []byte) bool {
	if !isCompressed(publicKey, PublicKeyLength) {
		return false
	}
	p := new(blst.P1Affine).Uncompress(publicKey)
	if p == nil || !p.KeyValidate() {
		return false
	}
	return bytes.Equal(p.Compress(), publicKey)
}

func secretOf(sk []byte) (*blst.SecretKey, error) {
	if len(sk) != 32 {
		return nil, errors.New("invalid private key: expected 32 bytes")
	}
	s := new(blst.SecretKey).Deserialize(sk) // refuses 0 and values >= r
	if s == nil {
		return nil, errors.New("invalid private key: expected 1 <= n < r")
	}
	return s, nil
}

// PublicKeyOf is the compressed G1 public key of a 32-byte big-endian secret scalar.
func PublicKeyOf(secretKey []byte) ([]byte, error) {
	s, err := secretOf(secretKey)
	if err != nil {
		return nil, err
	}
	return new(blst.P1Affine).From(s).Compress(), nil
}

// KeyGen draws a fresh key pair; it refuses the degenerate scalar 1 (a stuck-at-zero entropy source).
func KeyGen() (secretKey, publicKey []byte, err error) {
	for {
		b := make([]byte, 32)
		if _, err = crand.Read(b); err != nil {
			return nil, nil, err
		}
		b[0] &= 0x7f // < 2^255; r is just under 2^255, so most draws are in range and the rest retry
		if _, e := secretOf(b); e != nil {
			continue
		}
		if bytes.Equal(b, append(make([]byte, 31), 1)) {
			return nil, nil, errors.New("keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue")
		}
		pk, e := PublicKeyOf(b)
		return b, pk, e
	}
}

func signWith(secretKey, msg, dst []byte) ([]byte, error) {
	s, err := secretOf(secretKey)
	if err != nil {
		return nil, err
	}
	return new(blst.P2Affine).Sign(s, msg, dst).Compress(), nil
}

// Sign is CoreSign: H(msg) in G2 under SigDST times the secret scalar.
func Sign(secretKey, msg []byte) ([]byte, error) { return signWith(secretKey, msg, sigDST) }

func verifyWith(publicKey, msg, sig, dst []byte) bool {
	if !IsCanonicalSignature(sig) || !KeyValidate(publicKey) {
		return false
	}
	p := new(blst.P1Affine).Uncompress(publicKey)
	s := new(blst.P2Affine).Uncompress(sig)
	if p == nil || s == nil {
		return false
	}
	return s.Verify(true, p, false, msg, dst) // signature subgroup-checked; the key was just KeyValidate'd
}

// Verify is CoreVerify of one signature. Never panics.
func Verify(publicKey, msg, sig []byte) bool { return verifyWith(publicKey, msg, sig, sigDST) }

// Aggregate sums G2 signatures into one 96-byte aggregate (order independent); at least one is required.
func Aggregate(sigs [][]byte) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, errors.New("aggregate: need at least one signature")
	}
	ps := make([]*blst.P2Affine, len(sigs))
	for i, sg := range sigs {
		if !IsCanonicalSignature(sg) {
			return nil, errors.New("aggregate: every signature must be a 96-byte compressed G2 point")
		}
		ps[i] = new(blst.P2Affine).Uncompress(sg)
	}
	agg := new(blst.P2Aggregate)
	if !agg.Aggregate(ps, true) {
		return nil, errors.New("aggregate: a signature is not in the prime-order subgroup")
	}
	return agg.ToAffine().Compress(), nil
}

// AggregatePublicKeys sums G1 public keys into one 48-byte key.
func AggregatePublicKeys(publicKeys [][]byte) ([]byte, error) {
	if len(publicKeys) == 0 {
		return nil, errors.New("aggregatePublicKeys: need at least one key")
	}
	ps := make([]*blst.P1Affine, len(publicKeys))
	for i, pk := range publicKeys {
		if !isCompressed(pk, PublicKeyLength) {
			return nil, errors.New("aggregatePublicKeys: bad key")
		}
		if ps[i] = new(blst.P1Affine).Uncompress(pk); ps[i] == nil {
			return nil, errors.New("aggregatePublicKeys: bad key")
		}
	}
	agg := new(blst.P1Aggregate)
	if !agg.Aggregate(ps, true) {
		return nil, errors.New("aggregatePublicKeys: a key is not in the prime-order subgroup")
	}
	return agg.ToAffine().Compress(), nil
}

// PopProve signs one's own public key under PopDST.
func PopProve(secretKey []byte) ([]byte, error) {
	pk, err := PublicKeyOf(secretKey)
	if err != nil {
		return nil, err
	}
	return signWith(secretKey, pk, popDST)
}

// PopVerify checks a proof of possession. Never panics.
func PopVerify(publicKey, pop []byte) bool { return verifyWith(publicKey, publicKey, pop, popDST) }

func distinctMessages(msgs [][]byte) bool {
	seen := make(map[string]struct{}, len(msgs))
	for _, m := range msgs {
		if _, dup := seen[string(m)]; dup {
			return false
		}
		seen[string(m)] = struct{}{}
	}
	return true
}

func rawAggregateVerify(pks, msgs [][]byte, aggSig []byte) bool {
	if !IsCanonicalSignature(aggSig) || len(pks) == 0 || len(pks) != len(msgs) || !distinctMessages(msgs) {
		return false
	}
	ps := make([]*blst.P1Affine, len(pks))
	bm := make([]blst.Message, len(msgs))
	for i, pk := range pks {
		if !KeyValidate(pk) {
			return false
		}
		ps[i] = new(blst.P1Affine).Uncompress(pk)
		bm[i] = msgs[i]
	}
	s := new(blst.P2Affine).Uncompress(aggSig)
	if s == nil {
		return false
	}
	return s.AggregateVerify(true, ps, false, bm, sigDST)
}

func rawFastAggregateVerify(pks [][]byte, msg, aggSig []byte) bool {
	if !IsCanonicalSignature(aggSig) || len(pks) == 0 {
		return false
	}
	for _, pk := range pks {
		if !KeyValidate(pk) {
			return false
		}
	}
	aggPk, err := AggregatePublicKeys(pks)
	// the aggregate must itself pass KeyValidate: {P, -P} sums to the identity, for which the identity "signature" verifies anything
	if err != nil || !KeyValidate(aggPk) {
		return false
	}
	return verifyWith(aggPk, msg, aggSig, sigDST)
}

// RegisteredKey is a public key whose proof of possession was verified. The zero value is NOT registered; only RegisterKey
// and KeyRegistry.Register produce a registered one (its fields are unexported).
type RegisteredKey struct {
	b  []byte
	ok bool
}

// Bytes is a copy of the 48-byte compressed key (nil for an unregistered value).
func (k *RegisteredKey) Bytes() []byte {
	if k == nil || !k.ok {
		return nil
	}
	return append([]byte(nil), k.b...)
}

func (k *RegisteredKey) registered() bool { return k != nil && k.ok && len(k.b) == PublicKeyLength }

// RegisterKey admits a key: it must pass KeyValidate and carry a valid PoP. The error text is the refusal reason.
func RegisterKey(publicKey, pop []byte) (*RegisteredKey, error) {
	if !KeyValidate(publicKey) {
		return nil, errors.New("public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)")
	}
	if len(pop) != SignatureLength {
		return nil, errors.New("proof of possession is not a 96-byte compressed G2 signature")
	}
	if !PopVerify(publicKey, pop) {
		return nil, errors.New("proof of possession does not verify for this key")
	}
	return &RegisteredKey{b: append([]byte(nil), publicKey...), ok: true}, nil
}

// KeyRegistry is a verifier's pinned set of admitted keys, indexed by key bytes.
type KeyRegistry struct {
	mu   sync.RWMutex
	keys map[string]*RegisteredKey
}

// NewKeyRegistry returns an empty registry.
func NewKeyRegistry() *KeyRegistry { return &KeyRegistry{keys: map[string]*RegisteredKey{}} }

// Register verifies the PoP and admits the key (idempotent).
func (r *KeyRegistry) Register(publicKey, pop []byte) (*RegisteredKey, error) {
	k, err := RegisterKey(publicKey, pop)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.keys[string(publicKey)] = k
	r.mu.Unlock()
	return k, nil
}

// Get is the registered key for these bytes, or nil if it was never admitted.
func (r *KeyRegistry) Get(publicKey []byte) *RegisteredKey {
	if r == nil || len(publicKey) != PublicKeyLength {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keys[string(publicKey)]
}

// Has reports whether the key was admitted.
func (r *KeyRegistry) Has(publicKey []byte) bool { return r.Get(publicKey) != nil }

// Size is the number of admitted keys.
func (r *KeyRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.keys)
}

// checkRegistered returns why keys cannot be used for aggregate verification, or "".
func checkRegistered(keys []*RegisteredKey) string {
	if len(keys) == 0 {
		return "no keys"
	}
	for i, k := range keys {
		if !k.registered() {
			return fmt.Sprintf("key %d is not a registered key: it was not admitted through registerKey (proof of possession)", i)
		}
	}
	return ""
}

func rawOf(keys []*RegisteredKey) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = k.b
	}
	return out
}

// AggregateVerify (distinct messages) over registered keys only. Never panics; false on any failure.
func AggregateVerify(keys []*RegisteredKey, msgs [][]byte, aggSig []byte) bool {
	if checkRegistered(keys) != "" {
		return false
	}
	return rawAggregateVerify(rawOf(keys), msgs, aggSig)
}

func noDuplicateKeys(keys []*RegisteredKey) bool {
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if _, dup := seen[string(k.b)]; dup {
			return false
		}
		seen[string(k.b)] = struct{}{}
	}
	return true
}

// FastAggregateVerify (one message, many signers) over registered keys only; a signer may not be counted twice.
func FastAggregateVerify(keys []*RegisteredKey, msg, aggSig []byte) bool {
	if checkRegistered(keys) != "" || !noDuplicateKeys(keys) {
		return false
	}
	return rawFastAggregateVerify(rawOf(keys), msg, aggSig)
}

// ---- capability chain -----------------------------------------------------------------------------------------------

const capBlsDomain = "atlas-pca/cap-bls/v1\x00"

// BlsSuite tags every BLS hop.
const BlsSuite = "bls12-381-pop"

// MaxChainDepth bounds verification cost.
const MaxChainDepth = 16

// ChainResult is the outcome of VerifyAggregatedChain.
type ChainResult struct {
	Ok     bool
	Reason string
}

func unb64u(s string) ([]byte, bool) { return pca.DecodeB64uStrict(s, -1) }

func bodyOf(c map[string]any) map[string]any {
	return map[string]any{"issuer": c["issuer"], "holder": c["holder"], "caveats": c["caveats"], "parent": c["parent"]}
}

func sigMessage(bodyDigest string) ([]byte, error) {
	d, ok := unb64u(bodyDigest)
	if !ok {
		return nil, errors.New("bad body digest")
	}
	return append([]byte(capBlsDomain), d...), nil
}

// CapHash is the identity of a capability: the hash of everything except sig.
func CapHash(c map[string]any) (string, error) {
	rest := make(map[string]any, len(c))
	for k, v := range c {
		if k != "sig" {
			rest[k] = v
		}
	}
	return pca.HashCanonical(rest)
}

func cloneCaveats(cs any) ([]any, error) {
	s, err := pca.Canonicalize(cs)
	if err != nil {
		return nil, err
	}
	v, err := pca.StrictParse(s)
	if err != nil {
		return nil, err
	}
	out, ok := v.([]any)
	if !ok {
		return nil, errors.New("caveats must be an array")
	}
	return out, nil
}

func seal(issuer, holder string, caveats []any, parent any, signer []byte) (map[string]any, error) {
	digest, err := pca.HashCanonical(map[string]any{"issuer": issuer, "holder": holder, "caveats": caveats, "parent": parent})
	if err != nil {
		return nil, err
	}
	m, err := sigMessage(digest)
	if err != nil {
		return nil, err
	}
	sig, err := Sign(signer, m)
	if err != nil {
		return nil, err
	}
	cap := map[string]any{"id": digest, "issuer": issuer, "holder": holder, "caveats": caveats, "body_digest": digest, "sig": b64u.EncodeToString(sig), "suite": BlsSuite}
	if parent != nil {
		cap["parent"] = parent
	}
	return cap, nil
}

// BlsPublicKey is the b64u G1 public key of a secret scalar.
func BlsPublicKey(secretKey []byte) (string, error) {
	pk, err := PublicKeyOf(secretKey)
	if err != nil {
		return "", err
	}
	return b64u.EncodeToString(pk), nil
}

// MintBlsRoot mints a root capability signed by the principal.
func MintBlsRoot(principalSecret []byte, principalPublic, holder string, caveats []any) (map[string]any, error) {
	cl, err := cloneCaveats(caveats)
	if err != nil {
		return nil, err
	}
	return seal(principalPublic, holder, cl, nil, principalSecret)
}

// BlsAttenuate is a child with the same holder; caveats = parent.caveats ++ added; signed by the parent's holder.
func BlsAttenuate(parent map[string]any, added []any, signerSecret []byte) (map[string]any, error) {
	h, _ := parent["holder"].(string)
	return BlsDelegate(parent, h, added, signerSecret)
}

// BlsDelegate is like BlsAttenuate but rebinds the holder to a new key.
func BlsDelegate(parent map[string]any, toHolder string, added []any, signerSecret []byte) (map[string]any, error) {
	issuer, ok := parent["holder"].(string)
	if !ok {
		return nil, errors.New("parent has no holder")
	}
	pc, err := cloneCaveats(parent["caveats"])
	if err != nil {
		return nil, err
	}
	ac, err := cloneCaveats(added)
	if err != nil {
		return nil, err
	}
	ph, err := CapHash(parent)
	if err != nil {
		return nil, err
	}
	return seal(issuer, toHolder, append(pc, ac...), ph, signerSecret)
}

func wellTyped(x any) (map[string]any, bool) {
	c, ok := x.(map[string]any)
	if !ok {
		return nil, false
	}
	for _, k := range []string{"id", "issuer", "holder", "body_digest", "sig"} {
		if _, ok := c[k].(string); !ok {
			return nil, false
		}
	}
	if s, _ := c["suite"].(string); s != BlsSuite {
		return nil, false
	}
	if p, present := c["parent"]; present {
		if _, ok := p.(string); !ok {
			return nil, false
		}
	}
	cavs, ok := c["caveats"].([]any)
	if !ok {
		return nil, false
	}
	for _, cv := range cavs {
		m, ok := cv.(map[string]any)
		if !ok {
			return nil, false
		}
		if _, ok := m["type"].(string); !ok {
			return nil, false
		}
	}
	return c, true
}

func hopSigs(chain []any) ([][]byte, bool) {
	out := make([][]byte, len(chain))
	for i, h := range chain {
		c, ok := h.(map[string]any)
		if !ok {
			return nil, false
		}
		s, ok := c["sig"].(string)
		if !ok {
			return nil, false
		}
		if out[i], ok = unb64u(s); !ok {
			return nil, false
		}
	}
	return out, true
}

// AggregateChainSignatures collapses every per-hop signature of chain into one 96-byte aggregate.
func AggregateChainSignatures(chain []any) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("aggregateChainSignatures: empty chain")
	}
	sigs, ok := hopSigs(chain)
	if !ok {
		return nil, errors.New("aggregateChainSignatures: hop sig is not valid base64url")
	}
	return Aggregate(sigs)
}

// VerifyAggregatedChain verifies an entire BLS capability chain against one aggregate signature: structure (depth,
// well-typedness, links, holder to issuer continuity, append-only caveats) then one AggregateVerify over every hop. Every
// hop issuer must be in registry. expectedRoot, when non-nil, pins the root issuer. Never panics.
func VerifyAggregatedChain(chain []any, aggSig []byte, registry *KeyRegistry, expectedRoot *string) ChainResult {
	fail := func(f string, a ...any) ChainResult { return ChainResult{Reason: fmt.Sprintf(f, a...)} }
	if registry == nil {
		return fail("a KeyRegistry of proof-of-possession-verified keys is required")
	}
	if len(chain) == 0 {
		return fail("empty chain")
	}
	if len(chain) > MaxChainDepth {
		return fail("chain too long (max %d hops)", MaxChainDepth)
	}
	caps := make([]map[string]any, len(chain))
	for i, h := range chain {
		c, ok := wellTyped(h)
		if !ok {
			return fail("hop %d: malformed capability", i)
		}
		caps[i] = c
	}
	if _, has := caps[0]["parent"]; has {
		return fail("hop 0: root must not have a parent")
	}
	if expectedRoot != nil && caps[0]["issuer"] != *expectedRoot {
		return fail("hop 0: root issuer is not the expected principal")
	}
	pks := make([]*RegisteredKey, 0, len(caps))
	msgs := make([][]byte, 0, len(caps))
	for i, c := range caps {
		digest, err := pca.HashCanonical(bodyOf(c))
		if err != nil {
			return fail("hop %d: malformed body", i)
		}
		if digest != c["body_digest"] || c["id"] != c["body_digest"] {
			return fail("hop %d: body digest mismatch", i)
		}
		ib, ok := unb64u(c["issuer"].(string))
		if !ok {
			return fail("hop %d: malformed issuer key", i)
		}
		pk := registry.Get(ib)
		if pk == nil {
			return fail("hop %d: issuer key has no verified proof of possession (not in the registry)", i)
		}
		if i > 0 {
			parent := caps[i-1]
			ph, err := CapHash(parent)
			if err != nil || c["parent"] != ph {
				return fail("hop %d: broken parent link", i)
			}
			if c["issuer"] != parent["holder"] {
				return fail("hop %d: issuer is not the parent's bound holder", i)
			}
			cc, pc := c["caveats"].([]any), parent["caveats"].([]any)
			if len(cc) < len(pc) {
				return fail("hop %d: drops parent caveat(s)", i)
			}
			for j := range pc {
				a, e1 := pca.HashCanonical(cc[j])
				b, e2 := pca.HashCanonical(pc[j])
				if e1 != nil || e2 != nil || a != b {
					return fail("hop %d: caveat %d altered or reordered", i, j)
				}
			}
		}
		m, err := sigMessage(c["body_digest"].(string))
		if err != nil {
			return fail("hop %d: body digest mismatch", i)
		}
		pks = append(pks, pk)
		msgs = append(msgs, m)
	}
	// the per-hop sig fields must sum to the aggregate that is verified
	hs, ok := hopSigs(chain)
	if !ok {
		return fail("malformed hop sig")
	}
	sum, err := Aggregate(hs)
	if err != nil {
		return fail("malformed hop sig")
	}
	if !bytes.Equal(sum, aggSig) {
		return fail("hop sig fields do not sum to the aggregate signature")
	}
	if !AggregateVerify(pks, msgs, aggSig) {
		return fail("aggregate signature does not verify over all hops")
	}
	return ChainResult{Ok: true}
}

// ---- witness cosignatures -------------------------------------------------------------------------------------------

const sthWitnessBlsDomain = "atlas-pca/sth-witness-bls/v1\x00"

func witnessMessage(h map[string]any) ([]byte, error) {
	ge := h["guardian_epoch"]
	if ge == nil {
		ge = json.Number("0")
	}
	body, err := pca.Canonicalize(map[string]any{"size": h["size"], "root": h["root"], "prev_root": h["prev_root"], "guardian_epoch": ge})
	if err != nil {
		return nil, err
	}
	return append([]byte(sthWitnessBlsDomain), body...), nil
}

// CosignTreeHead has a witness cosign the tree-head statement {size, root, prev_root, guardian_epoch} with its BLS key.
func CosignTreeHead(statement map[string]any, witnessSecret []byte) (map[string]any, error) {
	m, err := witnessMessage(statement)
	if err != nil {
		return nil, err
	}
	pk, err := PublicKeyOf(witnessSecret)
	if err != nil {
		return nil, err
	}
	sig, err := Sign(witnessSecret, m)
	if err != nil {
		return nil, err
	}
	return map[string]any{"key": b64u.EncodeToString(pk), "sig": b64u.EncodeToString(sig), "suite": BlsSuite}, nil
}

// VerifyWitnessCosignature verifies ONE cosignature against the exact statement. Never panics.
func VerifyWitnessCosignature(statement, cosig map[string]any) bool {
	if cosig == nil {
		return false
	}
	if s, _ := cosig["suite"].(string); s != BlsSuite {
		return false
	}
	ks, _ := cosig["key"].(string)
	ss, _ := cosig["sig"].(string)
	k, ok1 := unb64u(ks)
	s, ok2 := unb64u(ss)
	m, err := witnessMessage(statement)
	return ok1 && ok2 && err == nil && Verify(k, m, s)
}

// AggregateWitnessCosignatures collapses a quorum of cosignatures into one 96-byte aggregate.
func AggregateWitnessCosignatures(cosigs []any) ([]byte, error) {
	if len(cosigs) == 0 {
		return nil, errors.New("aggregateWitnessCosignatures: empty set")
	}
	sigs, ok := hopSigs(cosigs)
	if !ok {
		return nil, errors.New("aggregateWitnessCosignatures: cosignature sig is not valid base64url")
	}
	return Aggregate(sigs)
}

// VerifyAggregatedWitnessCosignatures verifies an aggregate over one statement with a single FastAggregateVerify.
func VerifyAggregatedWitnessCosignatures(statement map[string]any, witnessKeys []*RegisteredKey, aggSig []byte) bool {
	m, err := witnessMessage(statement)
	if err != nil {
		return false
	}
	return FastAggregateVerify(witnessKeys, m, aggSig)
}
