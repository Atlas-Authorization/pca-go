package pca

// SCITT transparency receipts for Proof-Carrying Authority (port of the TypeScript @atlasauth/pca-scitt): COSE Signed Statements
// (RFC 9943) and COSE Receipts (RFC 9942) over an RFC 9162 SHA-256 Merkle tree, with the deterministic CBOR codec they need
// (RFC 8949 section 4.2.1: minimal heads, map keys sorted by encoded bytes, no floats, no indefinite lengths). The in-memory and
// durable transparency services and the log stores live in scitt_log.go.
//
// Verification FAILS CLOSED: ScittVerifyReceipt / ScittVerifyStatement / ScittVerifyConsistencyProof return false on anything
// unexpected. A verification key that is present but unusable (a nil or empty key, the wrong key type, a curve other than
// P-256) is a refusal, never a skipped check.
//
// CBOR values are int64 (safe integers only), string (well-formed UTF-8), []byte, bool, nil, []any, ScittCborMap and ScittCborTag.
// A decoded map lists its entries in wire order.
//
// shortcut: a CBOR value nested deeper than 512 levels is refused (the reference only fails on stack exhaustion).
// shortcut: an ES256 verification key must be an *ecdsa.PublicKey on P-256 and an EdDSA key an ed25519.PublicKey; the reference
// also lets an EC key verify an "EdDSA"-labelled statement carrying a DER signature, this port refuses it.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"
	"unicode/utf8"
)

const (
	// ScittCoseSign1Tag is the COSE_Sign1 CBOR tag (RFC 9052 section 4.2).
	ScittCoseSign1Tag = 18
	// ScittHdrAlg, ScittHdrContentType and ScittHdrCwtClaims are COSE header labels.
	ScittHdrAlg         = 1
	ScittHdrContentType = 3
	ScittHdrCwtClaims   = 15
	// ScittCwtIss and ScittCwtSub are CWT claim keys.
	ScittCwtIss = 1
	ScittCwtSub = 2
	// ScittHdrVds and ScittHdrVdsProofs are the RFC 9942 receipt header parameters.
	ScittHdrVds       = 395
	ScittHdrVdsProofs = 396
	// ScittVdsRfc9162Sha256 identifies the RFC 9162 SHA-256 tree; ScittProofTypeInclusion is the inclusion-proof key.
	ScittVdsRfc9162Sha256   = 1
	ScittProofTypeInclusion = -1
	// ScittDefaultContentType is stamped on a Signed Statement unless the caller names another.
	ScittDefaultContentType = "application/pca+json"
	// ScittAlgEdDSA and ScittAlgES256 are the supported signature suites.
	ScittAlgEdDSA = "EdDSA"
	ScittAlgES256 = "ES256"

	scMaxDepth = 512
)

// ---- deterministic CBOR ------------------------------------------------------------------------------------------

// ScittCborTag is a tagged value (major type 6).
type ScittCborTag struct {
	Tag   int64
	Value any
}

// ScittCborEntry is one map entry; Key is an int64 or a string.
type ScittCborEntry struct {
	Key   any
	Value any
}

// ScittCborMap is a CBOR map as an ordered entry list.
type ScittCborMap []ScittCborEntry

func scNormKey(k any) any {
	if i, ok := k.(int); ok {
		return int64(i)
	}
	return k
}

// Get returns the value stored under key (an int or string).
func (m ScittCborMap) Get(key any) (any, bool) {
	k := scNormKey(key)
	for _, e := range m {
		switch kk := e.Key.(type) {
		case int64:
			if k2, ok := k.(int64); ok && k2 == kk {
				return e.Value, true
			}
		case string:
			if k2, ok := k.(string); ok && k2 == kk {
				return e.Value, true
			}
		}
	}
	return nil, false
}

func scKeyEq(a, b any) bool {
	switch x := a.(type) {
	case int64:
		y, ok := b.(int64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	}
	return false
}

func scIsInt(n int64) bool { return n >= -maxSafeInt && n <= maxSafeInt }

func scHead(major byte, arg uint64) []byte {
	mt := major << 5
	switch {
	case arg < 24:
		return []byte{mt | byte(arg)}
	case arg < 0x100:
		return []byte{mt | 24, byte(arg)}
	case arg < 0x10000:
		return []byte{mt | 25, byte(arg >> 8), byte(arg)}
	case arg < 0x100000000:
		return []byte{mt | 26, byte(arg >> 24), byte(arg >> 16), byte(arg >> 8), byte(arg)}
	}
	b := make([]byte, 9)
	b[0] = mt | 27
	binary.BigEndian.PutUint64(b[1:], arg)
	return b
}

func scEncInt(n int64) ([]byte, error) {
	if !scIsInt(n) {
		return nil, errors.New("cbor: only safe-integer numbers are supported")
	}
	if n >= 0 {
		return scHead(0, uint64(n)), nil
	}
	return scHead(1, uint64(-1-n)), nil
}

func scEncText(s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, errors.New("cbor: text string contains a lone surrogate")
	}
	return append(scHead(3, uint64(len(s))), s...), nil
}

func scEncKey(k any) ([]byte, error) {
	switch t := k.(type) {
	case int64:
		if !scIsInt(t) {
			return nil, errors.New("cbor: bad integer map key")
		}
		return scEncInt(t)
	case string:
		return scEncText(t)
	}
	return nil, errors.New("cbor: bad integer map key")
}

// ScittCborEncode deterministically encodes a CBOR value; anything outside the supported profile is an error.
func ScittCborEncode(v any) ([]byte, error) { return scEnc(v, 0) }

func scEnc(v any, depth int) ([]byte, error) {
	if depth > scMaxDepth {
		return nil, errors.New("cbor: nesting too deep")
	}
	switch t := v.(type) {
	case nil:
		return []byte{0xf6}, nil
	case bool:
		if t {
			return []byte{0xf5}, nil
		}
		return []byte{0xf4}, nil
	case int:
		return scEncInt(int64(t))
	case int64:
		return scEncInt(t)
	case string:
		return scEncText(t)
	case []byte:
		return append(scHead(2, uint64(len(t))), t...), nil
	case []any:
		out := scHead(4, uint64(len(t)))
		for _, x := range t {
			b, err := scEnc(x, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	case ScittCborMap:
		// a JS Map keeps one entry per key (a later set replaces the value): dedupe first, then encode.
		var uniq []ScittCborEntry
		for _, e := range t {
			k := scNormKey(e.Key)
			found := false
			for i := range uniq {
				if scKeyEq(uniq[i].Key, k) {
					uniq[i].Value = e.Value
					found = true
					break
				}
			}
			if !found {
				uniq = append(uniq, ScittCborEntry{Key: k, Value: e.Value})
			}
		}
		type kv struct{ k, v []byte }
		ents := make([]kv, 0, len(uniq))
		for _, e := range uniq {
			kb, err := scEncKey(e.Key)
			if err != nil {
				return nil, err
			}
			vb, err := scEnc(e.Value, depth+1)
			if err != nil {
				return nil, err
			}
			ents = append(ents, kv{kb, vb})
		}
		sort.SliceStable(ents, func(i, j int) bool { return bytes.Compare(ents[i].k, ents[j].k) < 0 })
		for i := 1; i < len(ents); i++ {
			if bytes.Equal(ents[i-1].k, ents[i].k) {
				return nil, errors.New("cbor: duplicate map key")
			}
		}
		out := scHead(5, uint64(len(ents)))
		for _, e := range ents {
			out = append(out, e.k...)
			out = append(out, e.v...)
		}
		return out, nil
	case ScittCborTag:
		return scEncTag(t, depth)
	case *ScittCborTag:
		if t == nil {
			return nil, errors.New("cbor: unsupported value")
		}
		return scEncTag(*t, depth)
	}
	return nil, errors.New("cbor: unsupported value")
}

func scEncTag(t ScittCborTag, depth int) ([]byte, error) {
	if !scIsInt(t.Tag) || t.Tag < 0 {
		return nil, errors.New("cbor: bad tag")
	}
	b, err := scEnc(t.Value, depth+1)
	if err != nil {
		return nil, err
	}
	return append(scHead(6, uint64(t.Tag)), b...), nil
}

type scReader struct {
	buf []byte
	pos int
}

var errScEOF = errors.New("cbor: unexpected end of input")

func (r *scReader) byte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, errScEOF
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *scReader) bytes(n uint64) ([]byte, error) {
	if uint64(r.pos)+n > uint64(len(r.buf)) {
		return nil, errScEOF
	}
	out := make([]byte, n)
	copy(out, r.buf[r.pos:r.pos+int(n)])
	r.pos += int(n)
	return out, nil
}

func (r *scReader) readUint(n int) (uint64, error) {
	var v uint64
	for i := 0; i < n; i++ {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	if v > maxSafeInt {
		return 0, errors.New("cbor: integer out of safe range")
	}
	return v, nil
}

var errScNonMinimal = errors.New("cbor: non-minimal integer")

func (r *scReader) readHead() (byte, uint64, error) {
	ib, err := r.byte()
	if err != nil {
		return 0, 0, err
	}
	major := ib >> 5
	info := ib & 0x1f
	if major == 7 && info >= 24 {
		return 0, 0, errors.New("cbor: unsupported simple/float value")
	}
	if info < 24 {
		return major, uint64(info), nil
	}
	var width int
	var min uint64
	switch info {
	case 24:
		width, min = 1, 24
	case 25:
		width, min = 2, 0x100
	case 26:
		width, min = 4, 0x10000
	case 27:
		width, min = 8, 0x100000000
	default:
		return 0, 0, errors.New("cbor: unsupported additional information (indefinite/reserved)")
	}
	arg, err := r.readUint(width)
	if err != nil {
		return 0, 0, err
	}
	if arg < min {
		return 0, 0, errScNonMinimal
	}
	return major, arg, nil
}

func (r *scReader) value(depth int) (any, error) {
	if depth > scMaxDepth {
		return nil, errors.New("cbor: nesting too deep")
	}
	major, arg, err := r.readHead()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return int64(arg), nil
	case 1:
		if arg > maxSafeInt-1 {
			return nil, errors.New("cbor: integer out of safe range")
		}
		return -1 - int64(arg), nil
	case 2:
		return r.bytes(arg)
	case 3:
		b, err := r.bytes(arg)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, errors.New("The encoded data was not valid for encoding utf-8")
		}
		return string(b), nil
	case 4:
		out := []any{}
		for i := uint64(0); i < arg; i++ {
			x, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	case 5:
		out := ScittCborMap{}
		var prev []byte
		have := false
		for i := uint64(0); i < arg; i++ {
			start := r.pos
			key, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			switch key.(type) {
			case int64, string:
			default:
				return nil, errors.New("cbor: map key must be int or text")
			}
			kb := r.buf[start:r.pos]
			if have && bytes.Compare(prev, kb) >= 0 {
				return nil, errors.New("cbor: map keys not canonically ordered / duplicate")
			}
			prev, have = kb, true
			val, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, ScittCborEntry{Key: key, Value: val})
		}
		return out, nil
	case 6:
		x, err := r.value(depth + 1)
		if err != nil {
			return nil, err
		}
		return ScittCborTag{Tag: int64(arg), Value: x}, nil
	case 7:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, errors.New("cbor: unsupported simple/float value")
	}
	return nil, errors.New("cbor: unsupported major type")
}

// ScittCborDecode strictly decodes ONE canonical CBOR value and requires the whole buffer to be consumed.
func ScittCborDecode(b []byte) (any, error) {
	r := &scReader{buf: b}
	v, err := r.value(0)
	if err != nil {
		return nil, err
	}
	if r.pos != len(b) {
		return nil, errors.New("cbor: trailing bytes")
	}
	return v, nil
}

// ---- RFC 9162 Merkle tree ----------------------------------------------------------------------------------------

func scSha(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// ScittEmptyRoot is the root of the empty tree: SHA-256 of nothing.
func ScittEmptyRoot() []byte { return scSha() }

// ScittLeafHash is SHA-256(0x00 || entry).
func ScittLeafHash(entry []byte) []byte { return scSha([]byte{0}, entry) }

// ScittNodeHash is SHA-256(0x01 || left || right).
func ScittNodeHash(left, right []byte) []byte { return scSha([]byte{1}, left, right) }

func scSplit(n int64) int64 {
	k := int64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

// ScittTreeHash is the RFC 9162 MTH over already-hashed leaves.
func ScittTreeHash(leafHashes [][]byte) []byte {
	n := int64(len(leafHashes))
	if n == 0 {
		return ScittEmptyRoot()
	}
	if n == 1 {
		return leafHashes[0]
	}
	k := scSplit(n)
	return ScittNodeHash(ScittTreeHash(leafHashes[:k]), ScittTreeHash(leafHashes[k:]))
}

// ScittInclusionPath is the bottom-up inclusion path of leaf index (RFC 9162 section 2.1.3.1).
func ScittInclusionPath(leafHashes [][]byte, index int64) ([][]byte, error) {
	n := int64(len(leafHashes))
	if index < 0 || index >= n {
		return nil, errors.New("rfc9162: leaf index out of range")
	}
	if n == 1 {
		return [][]byte{}, nil
	}
	k := scSplit(n)
	if index < k {
		p, err := ScittInclusionPath(leafHashes[:k], index)
		if err != nil {
			return nil, err
		}
		return append(p, ScittTreeHash(leafHashes[k:])), nil
	}
	p, err := ScittInclusionPath(leafHashes[k:], index-k)
	if err != nil {
		return nil, err
	}
	return append(p, ScittTreeHash(leafHashes[:k])), nil
}

func scAll32(path [][]byte) bool {
	for _, p := range path {
		if len(p) != 32 {
			return false
		}
	}
	return true
}

// ScittRootFromInclusionPath recomputes the root from a leaf hash and its path (RFC 9162 section 2.1.3.2); nil when the
// (index, size, path) combination is invalid.
func ScittRootFromInclusionPath(leaf []byte, index, size int64, path [][]byte) []byte {
	if index < 0 || size < 1 || index >= size || index > maxSafeInt || size > maxSafeInt {
		return nil
	}
	if len(leaf) != 32 || !scAll32(path) {
		return nil
	}
	fn := uint64(index)
	sn := uint64(size) - 1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return nil
		}
		if fn&1 == 1 || fn == sn {
			r = ScittNodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = ScittNodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn == 0 {
		return r
	}
	return nil
}

// ScittVerifyInclusionPath verifies an inclusion proof: the recomputed root must equal root.
func ScittVerifyInclusionPath(leaf []byte, index, size int64, path [][]byte, root []byte) bool {
	c := ScittRootFromInclusionPath(leaf, index, size, path)
	return c != nil && bytes.Equal(c, root)
}

func scSubproof(m int64, d [][]byte, complete bool) [][]byte {
	n := int64(len(d))
	if m == n {
		if complete {
			return [][]byte{}
		}
		return [][]byte{ScittTreeHash(d)}
	}
	k := scSplit(n)
	if m <= k {
		return append(scSubproof(m, d[:k], complete), ScittTreeHash(d[k:]))
	}
	return append(scSubproof(m-k, d[k:], false), ScittTreeHash(d[:k]))
}

// ScittConsistencyPath is the consistency proof between the first m leaves and all of leafHashes (RFC 9162 section 2.1.4.1).
func ScittConsistencyPath(leafHashes [][]byte, m int64) ([][]byte, error) {
	if m < 1 || m > int64(len(leafHashes)) {
		return nil, errors.New("rfc9162: consistency size out of range")
	}
	return scSubproof(m, leafHashes, true), nil
}

// ScittVerifyConsistencyPath verifies a consistency proof between trees of first and second leaves (RFC 9162 section 2.1.4.2);
// a proof from an empty tree is rejected.
func ScittVerifyConsistencyPath(first, second int64, firstRoot, secondRoot []byte, path [][]byte) bool {
	if first < 1 || second < first || first > maxSafeInt || second > maxSafeInt {
		return false
	}
	if len(firstRoot) != 32 || len(secondRoot) != 32 || !scAll32(path) {
		return false
	}
	if first == second {
		return len(path) == 0 && bytes.Equal(firstRoot, secondRoot)
	}
	if len(path) == 0 {
		return false
	}
	nodes := make([][]byte, 0, len(path)+1)
	// the reference tests "first is an exact power of two" with 32-bit bitwise operators
	if int32(first)&int32(first-1) == 0 {
		nodes = append(nodes, firstRoot)
	}
	nodes = append(nodes, path...)
	fn := uint64(first) - 1
	sn := uint64(second) - 1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr := nodes[0]
	sr := nodes[0]
	for _, c := range nodes[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = ScittNodeHash(c, fr)
			sr = ScittNodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = ScittNodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(fr, firstRoot) && bytes.Equal(sr, secondRoot)
}

// ---- signature suites --------------------------------------------------------------------------------------------

func scAlgLabel(alg string) (int64, bool) {
	switch alg {
	case ScittAlgEdDSA:
		return -8, true
	case ScittAlgES256:
		return -7, true
	}
	return 0, false
}

var (
	scP256N    = elliptic.P256().Params().N
	scP256Half = new(big.Int).Rsh(elliptic.P256().Params().N, 1)
)

// scIsCanonicalEs256: a 64-byte IEEE-P1363 signature with 0 < r < n and 0 < s <= n/2 (low-S).
func scIsCanonicalEs256(sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return r.Sign() > 0 && r.Cmp(scP256N) < 0 && s.Sign() > 0 && s.Cmp(scP256Half) <= 0
}

func scSignBytes(alg string, key crypto.PrivateKey, msg []byte) ([]byte, error) {
	switch alg {
	case ScittAlgEdDSA:
		k, ok := key.(ed25519.PrivateKey)
		if !ok || len(k) != ed25519.PrivateKeySize {
			return nil, errors.New("scitt: EdDSA needs an ed25519 private key")
		}
		return ed25519.Sign(k, msg), nil
	case ScittAlgES256:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || k == nil || k.D == nil || k.Curve != elliptic.P256() {
			return nil, errors.New("scitt: ES256 needs a P-256 private key")
		}
		h := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return nil, err
		}
		if s.Cmp(scP256Half) > 0 { // low-S: one valid signature form per statement
			s = new(big.Int).Sub(scP256N, s)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}
	return nil, errors.New("scitt: unsupported alg")
}

func scVerifyBytes(alg string, pub crypto.PublicKey, msg, sig []byte, allowHighS bool) bool {
	switch alg {
	case ScittAlgEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(k, msg, sig)
	case ScittAlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k == nil || k.X == nil || k.Y == nil || k.Curve != elliptic.P256() {
			return false
		}
		// ECDSA is malleable: (r, s) and (r, n-s) both verify and would be two Merkle leaves for one statement.
		if !allowHighS && !scIsCanonicalEs256(sig) {
			return false
		}
		if allowHighS && len(sig) != 64 {
			return false
		}
		h := sha256.Sum256(msg)
		return ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	return false
}

func scSigStructure(protectedBytes, payload []byte) ([]byte, error) {
	return ScittCborEncode([]any{"Signature1", protectedBytes, []byte{}, payload})
}

// ---- Signed Statements -------------------------------------------------------------------------------------------

// ScittSignStatementOpts configures ScittSignStatement. Key is an ed25519.PrivateKey (EdDSA) or a P-256 *ecdsa.PrivateKey
// (ES256). Subject and ContentType are optional; a pointer to the empty string is carried, nil is omitted.
type ScittSignStatementOpts struct {
	Alg         string
	Key         crypto.PrivateKey
	Issuer      string
	Subject     *string
	ContentType *string
}

// ScittSignStatement signs payload (its strict canonical JSON form) as a COSE_Sign1 Signed Statement. ES256 signatures are
// randomized and normalized to low-S; EdDSA signatures are deterministic.
func ScittSignStatement(payload any, opts ScittSignStatementOpts) ([]byte, error) {
	label, ok := scAlgLabel(opts.Alg)
	if !ok {
		return nil, errors.New("cbor: unsupported value")
	}
	ct := ScittDefaultContentType
	if opts.ContentType != nil {
		ct = *opts.ContentType
	}
	claims := ScittCborMap{{Key: int64(ScittCwtIss), Value: opts.Issuer}}
	if opts.Subject != nil {
		claims = append(claims, ScittCborEntry{Key: int64(ScittCwtSub), Value: *opts.Subject})
	}
	prot := ScittCborMap{
		{Key: int64(ScittHdrAlg), Value: label},
		{Key: int64(ScittHdrContentType), Value: ct},
		{Key: int64(ScittHdrCwtClaims), Value: claims},
	}
	protectedBytes, err := ScittCborEncode(prot)
	if err != nil {
		return nil, err
	}
	canon, err := Canonicalize(payload)
	if err != nil {
		return nil, err
	}
	payloadBytes := []byte(canon)
	msg, err := scSigStructure(protectedBytes, payloadBytes)
	if err != nil {
		return nil, err
	}
	sig, err := scSignBytes(opts.Alg, opts.Key, msg)
	if err != nil {
		return nil, err
	}
	return ScittCborEncode(ScittCborTag{Tag: ScittCoseSign1Tag, Value: []any{protectedBytes, ScittCborMap{}, payloadBytes, sig}})
}

// ScittCoseSign1 is a decoded COSE_Sign1. Detached is true when the payload is nil.
type ScittCoseSign1 struct {
	ProtectedBytes []byte
	ProtectedMap   ScittCborMap
	Unprotected    ScittCborMap
	Payload        []byte
	Detached       bool
	Signature      []byte
}

// ScittDecodeCoseSign1 decodes and structurally validates a COSE_Sign1 (tag 18).
func ScittDecodeCoseSign1(b []byte) (*ScittCoseSign1, error) {
	top, err := ScittCborDecode(b)
	if err != nil {
		return nil, err
	}
	tag, ok := top.(ScittCborTag)
	if !ok || tag.Tag != ScittCoseSign1Tag {
		return nil, errors.New("cose: not a COSE_Sign1 (tag 18)")
	}
	arr, ok := tag.Value.([]any)
	if !ok || len(arr) != 4 {
		return nil, errors.New("cose: malformed COSE_Sign1 array")
	}
	protectedBytes, ok := arr[0].([]byte)
	if !ok {
		return nil, errors.New("cose: protected must be a bstr")
	}
	unprotected, ok := arr[1].(ScittCborMap)
	if !ok {
		return nil, errors.New("cose: unprotected must be a map")
	}
	c := &ScittCoseSign1{ProtectedBytes: protectedBytes, Unprotected: unprotected}
	switch p := arr[2].(type) {
	case nil:
		c.Detached = true
	case []byte:
		c.Payload = p
	default:
		return nil, errors.New("cose: payload must be a bstr or nil")
	}
	sig, ok := arr[3].([]byte)
	if !ok {
		return nil, errors.New("cose: signature must be a bstr")
	}
	c.Signature = sig
	if len(protectedBytes) == 0 {
		c.ProtectedMap = ScittCborMap{}
	} else {
		v, err := ScittCborDecode(protectedBytes)
		if err != nil {
			return nil, err
		}
		m, ok := v.(ScittCborMap)
		if !ok {
			return nil, errors.New("cbor: expected a map")
		}
		c.ProtectedMap = m
	}
	return c, nil
}

func scAlgOf(m ScittCborMap) (string, error) {
	label, ok := m.Get(ScittHdrAlg)
	if !ok {
		return "", errors.New("cose: missing alg header")
	}
	if n, ok := label.(int64); ok {
		switch n {
		case -8:
			return ScittAlgEdDSA, nil
		case -7:
			return ScittAlgES256, nil
		}
	}
	return "", errors.New("cose: unsupported alg")
}

// ScittStatementCheck is the outcome of ScittCheckStatement: OK, or the specific Reason it failed.
type ScittStatementCheck struct {
	OK     bool
	Reason string
}

// ScittCheckStatement verifies a Signed Statement and says why it failed. Reasons: "malformed: <detail>", "detached payload",
// "missing alg header", "unsupported alg", "non-canonical signature (high-S)" (an ES256 signature with s > n/2, unless
// allowHighS) and "bad signature". The COSE external_aad is always empty. A key of the wrong type, or nil, is "bad signature".
func ScittCheckStatement(statement []byte, pub crypto.PublicKey, allowHighS bool) ScittStatementCheck {
	s, err := ScittDecodeCoseSign1(statement)
	if err != nil {
		return ScittStatementCheck{Reason: "malformed: " + err.Error()}
	}
	if s.Detached {
		return ScittStatementCheck{Reason: "detached payload"}
	}
	alg, err := scAlgOf(s.ProtectedMap)
	if err != nil {
		if err.Error() == "cose: missing alg header" {
			return ScittStatementCheck{Reason: "missing alg header"}
		}
		return ScittStatementCheck{Reason: "unsupported alg"}
	}
	msg, err := scSigStructure(s.ProtectedBytes, s.Payload)
	if err != nil {
		return ScittStatementCheck{Reason: "bad signature"}
	}
	if scVerifyBytes(alg, pub, msg, s.Signature, allowHighS) {
		return ScittStatementCheck{OK: true}
	}
	if alg == ScittAlgES256 && !scIsCanonicalEs256(s.Signature) && scVerifyBytes(alg, pub, msg, s.Signature, true) {
		return ScittStatementCheck{Reason: "non-canonical signature (high-S)"}
	}
	return ScittStatementCheck{Reason: "bad signature"}
}

// ScittVerifyStatement reports whether a Signed Statement's COSE_Sign1 signature verifies against the issuer key.
func ScittVerifyStatement(statement []byte, pub crypto.PublicKey, allowHighS bool) bool {
	return ScittCheckStatement(statement, pub, allowHighS).OK
}

// ScittStatementPayload is the raw canonical payload carried by a Signed Statement.
func ScittStatementPayload(statement []byte) ([]byte, error) {
	c, err := ScittDecodeCoseSign1(statement)
	if err != nil {
		return nil, err
	}
	if c.Detached {
		return nil, errors.New("cose: statement payload is detached")
	}
	return c.Payload, nil
}

// ScittStatementLeaf is the b64u leaf a statement occupies in the transparency log.
func ScittStatementLeaf(statement []byte) string { return b64.EncodeToString(statement) }

// ---- inclusion proof codec ---------------------------------------------------------------------------------------

// ScittProofStep is one sibling of an inclusion path: its side ("L" or "R") and its 32-byte hash (b64u).
type ScittProofStep struct {
	Side string `json:"side"`
	Hash string `json:"hash"`
}

// ScittInclusionProof is a core-Merkle inclusion proof.
type ScittInclusionProof struct {
	Index int64            `json:"index"`
	Size  int64            `json:"size"`
	Path  []ScittProofStep `json:"path"`
}

// ScittSiblingSides are the sibling sides (leaf to root) for index in a tree of size leaves (RFC 6962 split).
func ScittSiblingSides(index, size int64) []string {
	out := []string{}
	idx, n := index, size
	for n > 1 {
		k := scSplit(n)
		if idx < k {
			out = append(out, "R")
			n = k
		} else {
			out = append(out, "L")
			idx -= k
			n -= k
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// ScittEncodeInclusionProof encodes a proof as an RFC 9162 inclusion proof: [tree_size, leaf_index, [sibling, ...]].
func ScittEncodeInclusionProof(p ScittInclusionProof) ([]byte, error) {
	sibs := make([]any, 0, len(p.Path))
	for _, st := range p.Path {
		h, ok := DecodeB64uStrict(st.Hash, 32)
		if !ok {
			return nil, errors.New("scitt: proof step hash is not a 32-byte b64u hash")
		}
		sibs = append(sibs, h)
	}
	return ScittCborEncode([]any{p.Size, p.Index, sibs})
}

// ScittDecodeInclusionProof decodes an RFC 9162 inclusion proof back into a core proof (sides re-derived).
func ScittDecodeInclusionProof(b []byte) (*ScittInclusionProof, error) {
	v, err := ScittCborDecode(b)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 3 {
		return nil, errors.New("scitt: malformed inclusion proof")
	}
	size, ok1 := arr[0].(int64)
	index, ok2 := arr[1].(int64)
	if !ok1 || !ok2 {
		return nil, errors.New("scitt: proof size/index must be integers")
	}
	if size < 1 || index < 0 || index >= size {
		return nil, errors.New("scitt: proof size/index out of range")
	}
	sibs, ok := arr[2].([]any)
	if !ok {
		return nil, errors.New("scitt: inclusion path must be an array")
	}
	sides := ScittSiblingSides(index, size)
	if len(sibs) != len(sides) {
		return nil, errors.New("scitt: inclusion path length does not match (index,size)")
	}
	path := make([]ScittProofStep, 0, len(sibs))
	for i, s := range sibs {
		h, ok := s.([]byte)
		if !ok || len(h) != 32 {
			return nil, errors.New("scitt: inclusion path entry must be a 32-byte bstr")
		}
		path = append(path, ScittProofStep{Side: sides[i], Hash: b64.EncodeToString(h)})
	}
	return &ScittInclusionProof{Index: index, Size: size, Path: path}, nil
}

// ---- COSE Receipts -----------------------------------------------------------------------------------------------

// ScittReceiptSigner is the Transparency Service signing key; Issuer is optional (nil = no CWT claims header).
type ScittReceiptSigner struct {
	Alg    string
	Key    crypto.PrivateKey
	Issuer *string
}

// ScittBuildReceipt builds a signed COSE Receipt for proof against ledger root (b64u, 32 bytes). The receipt's payload is
// detached; the signature covers the root a verifier recomputes from the inclusion proof.
func ScittBuildReceipt(root string, proof ScittInclusionProof, signer ScittReceiptSigner) ([]byte, error) {
	rootBytes, ok := DecodeB64uStrict(root, 32)
	if !ok {
		return nil, errors.New("scitt: tree root is not a 32-byte b64u hash")
	}
	label, ok := scAlgLabel(signer.Alg)
	if !ok {
		return nil, errors.New("cbor: unsupported value")
	}
	prot := ScittCborMap{{Key: int64(ScittHdrAlg), Value: label}, {Key: int64(ScittHdrVds), Value: int64(ScittVdsRfc9162Sha256)}}
	if signer.Issuer != nil {
		prot = append(prot, ScittCborEntry{Key: int64(ScittHdrCwtClaims), Value: ScittCborMap{{Key: int64(ScittCwtIss), Value: *signer.Issuer}}})
	}
	protectedBytes, err := ScittCborEncode(prot)
	if err != nil {
		return nil, err
	}
	pb, err := ScittEncodeInclusionProof(proof)
	if err != nil {
		return nil, err
	}
	unprotected := ScittCborMap{{Key: int64(ScittHdrVdsProofs), Value: ScittCborMap{{Key: int64(ScittProofTypeInclusion), Value: []any{pb}}}}}
	msg, err := scSigStructure(protectedBytes, rootBytes)
	if err != nil {
		return nil, err
	}
	sig, err := scSignBytes(signer.Alg, signer.Key, msg)
	if err != nil {
		return nil, err
	}
	// RFC 9942 section 4.4: the payload SHOULD be detached, so a verifier must recompute the root from the proof.
	return ScittCborEncode(ScittCborTag{Tag: ScittCoseSign1Tag, Value: []any{protectedBytes, unprotected, nil, sig}})
}

func scDecodeReceipt(receipt []byte) (*ScittCoseSign1, *ScittInclusionProof, error) {
	c, err := ScittDecodeCoseSign1(receipt)
	if err != nil {
		return nil, nil, err
	}
	vds, _ := c.ProtectedMap.Get(ScittHdrVds)
	if n, ok := vds.(int64); !ok || n != ScittVdsRfc9162Sha256 {
		return nil, nil, errors.New("scitt: receipt is not RFC9162_SHA256")
	}
	if !c.Detached && len(c.Payload) != 32 {
		return nil, nil, errors.New("scitt: receipt payload (root) must be 32 bytes")
	}
	raw, _ := c.Unprotected.Get(ScittHdrVdsProofs)
	proofs, ok := raw.(ScittCborMap)
	if !ok {
		return nil, nil, errors.New("scitt: missing verifiable-data-structure-proofs")
	}
	incl, _ := proofs.Get(ScittProofTypeInclusion)
	list, ok := incl.([]any)
	if !ok || len(list) < 1 {
		return nil, nil, errors.New("scitt: missing inclusion proof")
	}
	first, ok := list[0].([]byte)
	if !ok {
		return nil, nil, errors.New("scitt: inclusion proof must be a bstr")
	}
	p, err := ScittDecodeInclusionProof(first)
	if err != nil {
		return nil, nil, err
	}
	return c, p, nil
}

// ScittVerifyReceiptOpts selects what ScittVerifyReceipt checks. TreeRoot is the pinned root (b64u); VerificationKey is the
// Transparency Service public key (ed25519.PublicKey or *ecdsa.PublicKey); StatementKey is the statement issuer's. At least
// one of TreeRoot and VerificationKey must be supplied. A present but unusable key refuses.
type ScittVerifyReceiptOpts struct {
	TreeRoot        *string
	VerificationKey crypto.PublicKey
	StatementKey    crypto.PublicKey
	AllowHighS      bool
}

// ScittVerifyReceipt verifies a COSE Receipt for a Signed Statement and FAILS CLOSED. All of: an anchor is supplied; the
// receipt's TS signature over the root verifies (VerificationKey); the pinned root equals the receipt's (TreeRoot); the
// inclusion proof binds the EXACT statement bytes (leaf = SHA-256(0x00 || statement)) to that root; the statement's own
// signature verifies (StatementKey).
func ScittVerifyReceipt(receipt, statement []byte, opts ScittVerifyReceiptOpts) bool {
	if opts.TreeRoot == nil && opts.VerificationKey == nil {
		return false
	}
	c, proof, err := scDecodeReceipt(receipt)
	if err != nil {
		return false
	}
	hashes := make([][]byte, 0, len(proof.Path))
	for _, st := range proof.Path {
		h, ok := DecodeB64uStrict(st.Hash, 32)
		if !ok {
			return false
		}
		hashes = append(hashes, h)
	}
	root := ScittRootFromInclusionPath(ScittLeafHash(statement), proof.Index, proof.Size, hashes)
	if root == nil {
		return false
	}
	if !c.Detached && !bytes.Equal(c.Payload, root) {
		return false
	}
	if opts.VerificationKey != nil {
		alg, err := scAlgOf(c.ProtectedMap)
		if err != nil {
			return false
		}
		msg, err := scSigStructure(c.ProtectedBytes, root)
		if err != nil || !scVerifyBytes(alg, opts.VerificationKey, msg, c.Signature, opts.AllowHighS) {
			return false
		}
	}
	if opts.TreeRoot != nil && *opts.TreeRoot != b64.EncodeToString(root) {
		return false
	}
	if opts.StatementKey != nil && !ScittVerifyStatement(statement, opts.StatementKey, opts.AllowHighS) {
		return false
	}
	return true
}

// ScittVerifyConsistencyProof verifies an RFC 9942 consistency proof ([old-size, new-size, [hash, ...]]) between two pinned
// roots (b64u). Fail-closed boolean.
func ScittVerifyConsistencyProof(proof []byte, oldRoot, newRoot string) bool {
	v, err := ScittCborDecode(proof)
	if err != nil {
		return false
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 3 {
		return false
	}
	oldSize, ok1 := arr[0].(int64)
	newSize, ok2 := arr[1].(int64)
	list, ok3 := arr[2].([]any)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	path := make([][]byte, 0, len(list))
	for _, x := range list {
		h, ok := x.([]byte)
		if !ok {
			return false
		}
		path = append(path, h)
	}
	r1, ok1 := DecodeB64uStrict(oldRoot, 32)
	r2, ok2 := DecodeB64uStrict(newRoot, 32)
	if !ok1 || !ok2 {
		return false
	}
	return ScittVerifyConsistencyPath(oldSize, newSize, r1, r2, path)
}
