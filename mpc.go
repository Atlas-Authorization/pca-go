package pca

// Secure multi-party composition of stakeholder decisions (the deterministic layer of the reference @atlasauth/pca-mpc): the field
// F_p (p = 2^61 - 1) with its SplitMix64 / CSPRNG sources, additive sharing, GF(2^128), the OT choice-bit encoding, Beaver
// multiplication, thermometer encoding and the cleartext / semi-honest composition, and the SPDZ malicious-with-abort layer
// (authenticated shares, batched MAC-check, triple sacrifice, trusted-dealer runner). math/big and the standard library only.
// A runner is deterministic only behind an explicit seed; without one every share and MAC key comes from crypto/rand.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
)

// MpcMaxParties bounds the party count (and so the allocation) of a sharing.
const MpcMaxParties = 1024

// Compose constants.
const (
	MpcDefaultQ        = 100
	mpcTM              = 3
	MpcMacKeys         = 2
	MpcMinMacSoundness = 100
	MpcSacrificeParts  = 2
	MpcFieldBits       = 61
	MpcStatSec         = 64
	MpcMinStatSec      = 40
)

// MpcPrime is the field modulus 2^61 - 1.
var MpcPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 61), big.NewInt(1))

const mpcPrimeU64 = uint64(1)<<61 - 1

// mpcLimit is 2^64 - 8, the largest multiple of p in 64 bits plus one: draws at or above it are rejected so `% p` is uniform.
const mpcLimit = ^uint64(0) - 7

// MpcMod is the canonical representative in [0, p).
func MpcMod(x *big.Int) *big.Int     { return new(big.Int).Mod(x, MpcPrime) }
func MpcFAdd(a, b *big.Int) *big.Int { return MpcMod(new(big.Int).Add(a, b)) }
func MpcFSub(a, b *big.Int) *big.Int { return MpcMod(new(big.Int).Sub(a, b)) }
func MpcFMul(a, b *big.Int) *big.Int { return MpcMod(new(big.Int).Mul(a, b)) }
func MpcFNeg(a *big.Int) *big.Int    { return MpcMod(new(big.Int).Neg(a)) }

// MpcFieldSource is a source of uniform field elements.
type MpcFieldSource interface{ Next() *big.Int }

// MpcFieldRng is the deterministic SplitMix64 source (reproducible behind an explicit seed).
type MpcFieldRng struct{ s uint64 }

// NewMpcFieldRng seeds from the low 64 bits of the two's complement of seed (a negative seed is allowed); nil is the default seed.
func NewMpcFieldRng(seed *big.Int) *MpcFieldRng {
	if seed == nil {
		seed, _ = new(big.Int).SetString("243f6a8885a308d3", 16)
	}
	low := new(big.Int).And(seed, new(big.Int).SetUint64(^uint64(0)))
	return &MpcFieldRng{s: low.Uint64()}
}

func (r *MpcFieldRng) nextU64() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *MpcFieldRng) Next() *big.Int {
	for {
		if u := r.nextU64(); u < mpcLimit {
			return new(big.Int).SetUint64(u % mpcPrimeU64)
		}
	}
}

// MpcSecureFieldRng is the crypto/rand source (the default for protocol randomness).
type MpcSecureFieldRng struct{}

func (MpcSecureFieldRng) Next() *big.Int {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic("mpc: crypto/rand failed: " + err.Error())
		}
		if u := binary.BigEndian.Uint64(b[:]); u < mpcLimit {
			return new(big.Int).SetUint64(u % mpcPrimeU64)
		}
	}
}

// MpcFieldRandom is the CSPRNG by default and a reproducible seeded source only when testSeed is non-nil.
func MpcFieldRandom(testSeed *big.Int) MpcFieldSource {
	if testSeed == nil {
		return MpcSecureFieldRng{}
	}
	return NewMpcFieldRng(testSeed)
}

// ---- additive sharing (a shared value is a slice with x[i] held by party i)

func mpcParties(fn string, n int) error {
	if n < 1 || n > MpcMaxParties {
		return fmt.Errorf("%s: n must be an integer in [1, %d]", fn, MpcMaxParties)
	}
	return nil
}

func MpcShare(secret *big.Int, n int, rng MpcFieldSource) ([]*big.Int, error) {
	if err := mpcParties("share", n); err != nil {
		return nil, err
	}
	out := make([]*big.Int, n)
	acc := new(big.Int)
	for i := 0; i < n-1; i++ {
		out[i] = rng.Next()
		acc = MpcFAdd(acc, out[i])
	}
	out[n-1] = MpcFAdd(MpcMod(secret), MpcFNeg(acc))
	return out, nil
}

// MpcReconstruct sums the shares; an empty list or a nil (missing) share is refused.
func MpcReconstruct(shares []*big.Int) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errors.New("reconstruct: no shares (fail closed)")
	}
	acc := new(big.Int)
	for _, s := range shares {
		if s == nil {
			return nil, errors.New("reconstruct: missing share (fail closed)")
		}
		acc = MpcFAdd(acc, s)
	}
	return acc, nil
}

func MpcShareConstant(c *big.Int, n int) ([]*big.Int, error) {
	if err := mpcParties("shareConstant", n); err != nil {
		return nil, err
	}
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = new(big.Int)
	}
	out[0] = MpcMod(c)
	return out, nil
}

func mpcSame(x, y []*big.Int) error {
	if len(x) != len(y) {
		return errors.New("shared values must have the same party count")
	}
	return nil
}

func MpcAddSV(x, y []*big.Int) ([]*big.Int, error) {
	if err := mpcSame(x, y); err != nil {
		return nil, err
	}
	o := make([]*big.Int, len(x))
	for i := range x {
		o[i] = MpcFAdd(x[i], y[i])
	}
	return o, nil
}

func MpcSubSV(x, y []*big.Int) ([]*big.Int, error) {
	if err := mpcSame(x, y); err != nil {
		return nil, err
	}
	o := make([]*big.Int, len(x))
	for i := range x {
		o[i] = MpcFSub(x[i], y[i])
	}
	return o, nil
}

func MpcNegSV(x []*big.Int) []*big.Int {
	o := make([]*big.Int, len(x))
	for i := range x {
		o[i] = MpcFNeg(x[i])
	}
	return o
}

func MpcScaleSV(x []*big.Int, c *big.Int) []*big.Int {
	o := make([]*big.Int, len(x))
	for i := range x {
		o[i] = MpcFMul(x[i], c)
	}
	return o
}

// MpcAddPublicSV adds the public constant c to party 0's share.
func MpcAddPublicSV(x []*big.Int, c *big.Int) ([]*big.Int, error) {
	if len(x) == 0 {
		return nil, errors.New("addPublicSV: no shares")
	}
	o := append([]*big.Int(nil), x...)
	o[0] = MpcFAdd(o[0], MpcMod(c))
	return o, nil
}

func MpcNotBitSV(b []*big.Int) ([]*big.Int, error) { return MpcAddPublicSV(MpcNegSV(b), big.NewInt(1)) }

// ---- GF(2^128), reduction polynomial x^128 + x^7 + x^2 + x + 1

var (
	mpcGfMask = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	mpcGfRed  = big.NewInt(0x87)
)

func MpcGfAdd(a, b *big.Int) *big.Int { return new(big.Int).And(new(big.Int).Xor(a, b), mpcGfMask) }

func MpcGfMulX(v *big.Int) *big.Int {
	carry := v.Bit(127) == 1
	r := new(big.Int).And(new(big.Int).Lsh(v, 1), mpcGfMask)
	if carry {
		r.Xor(r, mpcGfRed)
	}
	return r
}

func MpcGfMulByXi(v *big.Int, i int) *big.Int {
	r := new(big.Int).And(v, mpcGfMask)
	for k := 0; k < i; k++ {
		r = MpcGfMulX(r)
	}
	return r
}

func MpcGfMul(a, b *big.Int) *big.Int {
	res := new(big.Int)
	v := new(big.Int).And(a, mpcGfMask)
	for i := 0; i < 128; i++ {
		if b.Bit(i) == 1 {
			res.Xor(res, v)
		}
		v = MpcGfMulX(v)
	}
	return res.And(res, mpcGfMask)
}

// ---- privacy-amplified OT choice-bit encoding

func MpcEncBits(s int) int { return MpcFieldBits + 3*s }

// MpcEncShare is a receiver operand: its field value with the choice bits that encode it.
type MpcEncShare struct {
	Value *big.Int
	Bits  []int
}

func MpcMakeGadget(s int, next MpcFieldSource, unsafe bool) ([]*big.Int, error) {
	if s < 0 || s > 64 {
		return nil, errors.New("statSec must be an integer in [0, 64]")
	}
	if s < MpcMinStatSec && !unsafe {
		return nil, fmt.Errorf("statSec %d is below %d: refused (tests may pass the explicit unsafe flag)", s, MpcMinStatSec)
	}
	g := make([]*big.Int, MpcEncBits(s))
	for k := range g {
		if s == 0 {
			g[k] = MpcMod(new(big.Int).Lsh(big.NewInt(1), uint(k)))
		} else {
			g[k] = next.Next()
		}
	}
	return g, nil
}

func MpcEncValue(g []*big.Int, bits []int) (*big.Int, error) {
	if len(g) != len(bits) {
		return nil, errors.New("encValue: gadget / bits length mismatch")
	}
	v := new(big.Int)
	for k := range g {
		if bits[k] == 1 {
			v.Add(v, g[k])
		}
	}
	return MpcMod(v), nil
}

func MpcPlainShare(x *big.Int) MpcEncShare {
	v := MpcMod(x)
	bits := make([]int, MpcFieldBits)
	for k := range bits {
		bits[k] = int(v.Bit(k))
	}
	return MpcEncShare{v, bits}
}

func MpcPlainGadget() []*big.Int {
	g := make([]*big.Int, MpcFieldBits)
	for k := range g {
		g[k] = MpcMod(new(big.Int).Lsh(big.NewInt(1), uint(k)))
	}
	return g
}

// MpcRandomBits draws m uniform bits from a field source (the 60 low bits of each draw are uniform).
func MpcRandomBits(m int, rng MpcFieldSource) []int {
	out := make([]int, m)
	for k := 0; k < m; {
		w := rng.Next()
		for i := 0; i < 60 && k < m; i, k = i+1, k+1 {
			out[k] = int(w.Bit(i))
		}
	}
	return out
}

func MpcSampleEnc(g []*big.Int, rng MpcFieldSource) MpcEncShare {
	bits := MpcRandomBits(len(g), rng)
	v, _ := MpcEncValue(g, bits)
	return MpcEncShare{v, bits}
}

// ---- Beaver multiplication

// MpcTriple is a Beaver triple (a, b, c = a*b), each component additively shared.
type MpcTriple struct{ A, B, C []*big.Int }

// MpcOpenedMsg is one opened (public) protocol message; Label is "d" or "e".
type MpcOpenedMsg struct {
	Label  string
	Value  *big.Int
	Shares []*big.Int
}

func MpcGenTriple(n int, rng MpcFieldSource) (*MpcTriple, error) {
	a, b := rng.Next(), rng.Next()
	c := MpcFMul(a, b)
	sa, err := MpcShare(a, n, rng)
	if err != nil {
		return nil, err
	}
	sb, err := MpcShare(b, n, rng)
	if err != nil {
		return nil, err
	}
	sc, err := MpcShare(c, n, rng)
	if err != nil {
		return nil, err
	}
	return &MpcTriple{sa, sb, sc}, nil
}

// MpcBeaverMul is x*y consuming triple; every opened value is appended to *transcript when it is non-nil.
func MpcBeaverMul(x, y []*big.Int, t *MpcTriple, transcript *[]MpcOpenedMsg) ([]*big.Int, error) {
	if len(x) != len(y) {
		return nil, errors.New("beaverMul: operand party counts differ")
	}
	for _, part := range [][]*big.Int{t.A, t.B, t.C} {
		if part == nil || len(part) != len(x) {
			return nil, errors.New("beaverMul: triple party count differs from the operands")
		}
	}
	dSh, err := MpcSubSV(x, t.A)
	if err != nil {
		return nil, err
	}
	eSh, err := MpcSubSV(y, t.B)
	if err != nil {
		return nil, err
	}
	d, err := MpcReconstruct(dSh)
	if err != nil {
		return nil, err
	}
	e, err := MpcReconstruct(eSh)
	if err != nil {
		return nil, err
	}
	if transcript != nil {
		*transcript = append(*transcript, MpcOpenedMsg{"d", d, dSh}, MpcOpenedMsg{"e", e, eSh})
	}
	de := MpcFMul(d, e)
	z := make([]*big.Int, len(x))
	for i := range z {
		zi := MpcFAdd(t.C[i], MpcFAdd(MpcFMul(d, t.B[i]), MpcFMul(e, t.A[i])))
		if i == 0 {
			zi = MpcFAdd(zi, de)
		}
		z[i] = zi
	}
	return z, nil
}

// ---- thermometer encoding, quantisation and the cleartext composition

// MpcThermometerEncode encodes v in {0..M}, clamping v into range (a NaN is all zeros); v is a JS number.
func MpcThermometerEncode(v float64, M int) ([]int, error) {
	if M < 0 {
		return nil, errors.New("thermometerEncode: M must be a non-negative integer")
	}
	c := math.Max(0, math.Min(float64(M), math.Trunc(v)))
	if math.IsNaN(v) {
		c = math.NaN()
	}
	bits := make([]int, M)
	for k := 1; k <= M; k++ {
		if c >= float64(k) {
			bits[k-1] = 1
		}
	}
	return bits, nil
}

// MpcThermometerDecode counts the 1s (robust to non-monotone input).
func MpcThermometerDecode(bits []int) int {
	c := 0
	for _, b := range bits {
		if b == 1 {
			c++
		}
	}
	return c
}

// MpcQuantizeR quantises r in [0,1] to {0..Q}; non-finite is the worst case (Q).
func MpcQuantizeR(r float64, Q int) int {
	if math.IsNaN(r) || math.IsInf(r, 0) {
		return Q
	}
	q := math.Floor(math.Max(0, math.Min(1, r))*float64(Q) + 0.5)
	return int(math.Max(0, math.Min(float64(Q), q)))
}

// MpcDecisionVector is a party's contribution: allow in {0,1}, t in {1,2,3}, rQuant in {0..Q}.
type MpcDecisionVector struct{ Allow, T, RQuant int }

// MpcComposedDecision is the meet of the parties' decisions.
type MpcComposedDecision struct{ Allow, T, RQuant int }

// MpcAssertDecisionVectors rejects a malformed decision vector.
func MpcAssertDecisionVectors(vs []MpcDecisionVector, Q int) error {
	for i, v := range vs {
		switch {
		case v.Allow != 0 && v.Allow != 1:
			return fmt.Errorf("party %d: allow must be 0 or 1", i)
		case v.T < 1 || v.T > 3:
			return fmt.Errorf("party %d: t must be 1, 2 or 3", i)
		case v.RQuant < 0 || v.RQuant > Q:
			return fmt.Errorf("party %d: rQuant must be an integer in [0, %d]", i, Q)
		}
	}
	return nil
}

// MpcComposeClear is allow = AND, t = MAX, rQuant = MAX: composition can only tighten.
func MpcComposeClear(vs []MpcDecisionVector, Q int) (MpcComposedDecision, error) {
	if len(vs) == 0 {
		return MpcComposedDecision{}, errors.New("composeClear: no parties (fail closed)")
	}
	if err := MpcAssertDecisionVectors(vs, Q); err != nil {
		return MpcComposedDecision{}, err
	}
	d := MpcComposedDecision{Allow: 1, T: 1}
	for _, v := range vs {
		if v.Allow == 0 {
			d.Allow = 0
		}
		d.T = max(d.T, v.T)
		d.RQuant = max(d.RQuant, v.RQuant)
	}
	return d, nil
}

// ---- semi-honest MPC runner (all parties in one process)

// MpcSharingRecord is the full additive sharing of one party's secret bit (test inspection only).
type MpcSharingRecord struct {
	Label  string
	Party  int
	Secret *big.Int
	Shares []*big.Int
}

// MpcPartyView is one party's complete view (a semi-honest corruption of that party).
type MpcPartyView struct {
	Party      int
	HeldShares []*big.Int
	Opened     []MpcOpenedMsg
	Output     MpcComposedDecision
}

type MpcResult struct {
	Composed        MpcComposedDecision
	Parties, Q      int
	Opened          []MpcOpenedMsg
	Sharings        []MpcSharingRecord
	Views           []MpcPartyView
	Multiplications int
}

// MpcComposeSecure composes under MPC. A nil q is the default; a nil seed means CSPRNG sharing randomness (a seed is for tests).
func MpcComposeSecure(vs []MpcDecisionVector, q *int, seed *big.Int) (*MpcResult, error) {
	n := len(vs)
	if n == 0 {
		return nil, errors.New("composeSecure: no parties (fail closed)")
	}
	Q := MpcDefaultQ
	if q != nil {
		Q = *q
	}
	if err := MpcAssertDecisionVectors(vs, Q); err != nil {
		return nil, err
	}
	rng := MpcFieldRandom(seed)
	res := &MpcResult{Parties: n, Q: Q}
	shareBit := func(bit int, label string, party int) ([]*big.Int, error) {
		s, err := MpcShare(big.NewInt(int64(bit)), n, rng)
		if err != nil {
			return nil, err
		}
		res.Sharings = append(res.Sharings, MpcSharingRecord{label, party, big.NewInt(int64(bit)), append([]*big.Int(nil), s...)})
		return s, nil
	}
	mul := func(a, b []*big.Int) ([]*big.Int, error) {
		t, err := MpcGenTriple(n, rng)
		if err != nil {
			return nil, err
		}
		res.Multiplications++
		return MpcBeaverMul(a, b, t, &res.Opened)
	}
	and := func(bits [][]*big.Int) ([]*big.Int, error) {
		if len(bits) == 0 {
			return MpcShareConstant(big.NewInt(1), n)
		}
		acc := bits[0]
		for _, b := range bits[1:] {
			var err error
			if acc, err = mul(acc, b); err != nil {
				return nil, err
			}
		}
		return acc, nil
	}
	or := func(bits [][]*big.Int) ([]*big.Int, error) {
		if len(bits) == 0 {
			return MpcShareConstant(new(big.Int), n)
		}
		prod, err := MpcNotBitSV(bits[0])
		if err != nil {
			return nil, err
		}
		for _, b := range bits[1:] {
			nb, err := MpcNotBitSV(b)
			if err != nil {
				return nil, err
			}
			if prod, err = mul(prod, nb); err != nil {
				return nil, err
			}
		}
		return MpcNotBitSV(prod)
	}
	one := func(sv []*big.Int) (int, error) {
		v, err := MpcReconstruct(sv)
		if err != nil {
			return 0, err
		}
		if v.Cmp(big.NewInt(1)) == 0 {
			return 1, nil
		}
		return 0, nil
	}
	allowBits := make([][]*big.Int, n)
	for p := 0; p < n; p++ {
		var err error
		if allowBits[p], err = shareBit(vs[p].Allow, fmt.Sprintf("p%d.allow", p), p); err != nil {
			return nil, err
		}
	}
	sv, err := and(allowBits)
	if err != nil {
		return nil, err
	}
	allow, err := one(sv)
	if err != nil {
		return nil, err
	}
	column := func(label string, enc func(p int) ([]int, error)) ([]int, error) {
		therm := make([][]int, n)
		for p := range therm {
			var err error
			if therm[p], err = enc(p); err != nil {
				return nil, err
			}
		}
		ge := make([]int, len(therm[0]))
		for k := range ge {
			bits := make([][]*big.Int, n)
			for p := 0; p < n; p++ {
				var err error
				if bits[p], err = shareBit(therm[p][k], fmt.Sprintf("p%d.%s.ge%d", p, label, k+1), p); err != nil {
					return nil, err
				}
			}
			o, err := or(bits)
			if err != nil {
				return nil, err
			}
			if ge[k], err = one(o); err != nil {
				return nil, err
			}
		}
		return ge, nil
	}
	tGe, err := column("t", func(p int) ([]int, error) { return MpcThermometerEncode(float64(vs[p].T), mpcTM) })
	if err != nil {
		return nil, err
	}
	rGe, err := column("r", func(p int) ([]int, error) { return MpcThermometerEncode(float64(vs[p].RQuant), Q) })
	if err != nil {
		return nil, err
	}
	res.Composed = MpcComposedDecision{allow, min(3, max(1, MpcThermometerDecode(tGe))), MpcThermometerDecode(rGe)}
	for p := 0; p < n; p++ {
		held := make([]*big.Int, len(res.Sharings))
		for i, s := range res.Sharings {
			held[i] = s.Shares[p]
		}
		res.Views = append(res.Views, MpcPartyView{p, held, res.Opened, res.Composed})
	}
	return res, nil
}

// ---- SPDZ: authenticated sharing, batched MAC-check, sacrifice

// MpcMacKey is one global MAC key, additively shared (Alpha is for dealer preprocessing and tests only).
type MpcMacKey struct {
	AlphaShares []*big.Int
	Alpha       *big.Int
}

// MpcMacContext holds the global MAC keys: key 0 is AlphaShares / Alpha; ExtraKeys are further independent keys.
type MpcMacContext struct {
	N           int
	AlphaShares []*big.Int
	Alpha       *big.Int
	ExtraKeys   []MpcMacKey
}

// MpcAuthSV: Value shares sum to x, Mac shares to alpha*x (key 0), ExtraMac[l-1] to ExtraKeys[l-1].Alpha*x.
type MpcAuthSV struct {
	Value, Mac []*big.Int
	ExtraMac   [][]*big.Int
}

type MpcAuthTriple struct{ A, B, C MpcAuthSV }

// MpcMacCheckAbort: the MAC-check detected an inconsistency, so the protocol aborts with no output.
type MpcMacCheckAbort struct{ Msg string }

func (e *MpcMacCheckAbort) Error() string { return e.Msg }

// MpcMacKeysOf lists key 0 followed by the extra keys.
func MpcMacKeysOf(c *MpcMacContext) []MpcMacKey {
	return append([]MpcMacKey{{c.AlphaShares, c.Alpha}}, c.ExtraKeys...)
}

// MpcMacSoundnessBits is keys * (log2 p - 1): the soundness in bits of the batched MAC-check.
func MpcMacSoundnessBits(keys int, p *big.Int) float64 {
	d, _ := new(big.Float).SetInt(p).Float64()
	l := math.Log2(d)
	if r := math.Round(l); math.Abs(l-r) < 1e-9 && math.Pow(2, r) == d {
		l = r
	}
	return float64(keys) * (l - 1)
}

func mpcMk(n int, rng MpcFieldSource) (MpcMacKey, error) {
	alpha := rng.Next()
	sh, err := MpcShare(alpha, n, rng)
	return MpcMacKey{sh, alpha}, err
}

func MpcSetupMac(n int, rng MpcFieldSource, keys int) (*MpcMacContext, error) {
	if n < 1 {
		return nil, errors.New("setupMac: n must be a positive integer")
	}
	if keys < 1 || keys > 16 {
		return nil, errors.New("setupMac: keys must be an integer in [1, 16]")
	}
	first, err := mpcMk(n, rng)
	if err != nil {
		return nil, err
	}
	c := &MpcMacContext{N: n, AlphaShares: first.AlphaShares, Alpha: first.Alpha, ExtraKeys: []MpcMacKey{}}
	for i := 0; i < keys-1; i++ {
		k, err := mpcMk(n, rng)
		if err != nil {
			return nil, err
		}
		c.ExtraKeys = append(c.ExtraKeys, k)
	}
	return c, nil
}

func MpcAuthShare(secret *big.Int, c *MpcMacContext, rng MpcFieldSource) (MpcAuthSV, error) {
	v := MpcMod(secret)
	value, err := MpcShare(v, c.N, rng)
	if err != nil {
		return MpcAuthSV{}, err
	}
	mac, err := MpcShare(MpcFMul(c.Alpha, v), c.N, rng)
	if err != nil {
		return MpcAuthSV{}, err
	}
	extra := make([][]*big.Int, len(c.ExtraKeys))
	for l := range extra {
		if extra[l], err = MpcShare(MpcFMul(c.ExtraKeys[l].Alpha, v), c.N, rng); err != nil {
			return MpcAuthSV{}, err
		}
	}
	return MpcAuthSV{value, mac, extra}, nil
}

func MpcAuthConstant(cst *big.Int, c *MpcMacContext) MpcAuthSV {
	v := MpcMod(cst)
	value := make([]*big.Int, c.N)
	for i := range value {
		value[i] = new(big.Int)
	}
	value[0] = v
	extra := make([][]*big.Int, len(c.ExtraKeys))
	for l := range extra {
		extra[l] = MpcScaleSV(c.ExtraKeys[l].AlphaShares, v)
	}
	return MpcAuthSV{value, MpcScaleSV(c.AlphaShares, v), extra}
}

func mpcAuthSame(x, y MpcAuthSV) error {
	if len(x.Value) != len(y.Value) || len(x.Mac) != len(y.Mac) {
		return errors.New("authenticated shared values must have the same party count")
	}
	if len(x.ExtraMac) != len(y.ExtraMac) {
		return errors.New("authenticated shared values must carry the same number of MAC keys")
	}
	for l := range x.ExtraMac {
		if len(x.ExtraMac[l]) != len(y.ExtraMac[l]) {
			return errors.New("authenticated shared values must have the same party count")
		}
	}
	return nil
}

func mpcAuthZip(x, y MpcAuthSV, f func(a, b *big.Int) *big.Int) (MpcAuthSV, error) {
	if err := mpcAuthSame(x, y); err != nil {
		return MpcAuthSV{}, err
	}
	zip := func(a, b []*big.Int) []*big.Int {
		o := make([]*big.Int, len(a))
		for i := range a {
			o[i] = f(a[i], b[i])
		}
		return o
	}
	extra := make([][]*big.Int, len(x.ExtraMac))
	for l := range extra {
		extra[l] = zip(x.ExtraMac[l], y.ExtraMac[l])
	}
	return MpcAuthSV{zip(x.Value, y.Value), zip(x.Mac, y.Mac), extra}, nil
}

func MpcAddAuth(x, y MpcAuthSV) (MpcAuthSV, error) { return mpcAuthZip(x, y, MpcFAdd) }
func MpcSubAuth(x, y MpcAuthSV) (MpcAuthSV, error) { return mpcAuthZip(x, y, MpcFSub) }

func MpcNegAuth(x MpcAuthSV) MpcAuthSV {
	extra := make([][]*big.Int, len(x.ExtraMac))
	for l := range extra {
		extra[l] = MpcNegSV(x.ExtraMac[l])
	}
	return MpcAuthSV{MpcNegSV(x.Value), MpcNegSV(x.Mac), extra}
}

func MpcScaleAuth(x MpcAuthSV, c *big.Int) MpcAuthSV {
	k := MpcMod(c)
	extra := make([][]*big.Int, len(x.ExtraMac))
	for l := range extra {
		extra[l] = MpcScaleSV(x.ExtraMac[l], k)
	}
	return MpcAuthSV{MpcScaleSV(x.Value, k), MpcScaleSV(x.Mac, k), extra}
}

// MpcAddPublicAuth is x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share.
func MpcAddPublicAuth(x MpcAuthSV, c *big.Int, ctx *MpcMacContext) (MpcAuthSV, error) {
	n := ctx.N
	if len(x.Value) != n || len(x.Mac) != n || len(ctx.AlphaShares) != n {
		return MpcAuthSV{}, errors.New("addPublicAuth: shared value and MAC context disagree on the party count")
	}
	if len(x.ExtraMac) != len(ctx.ExtraKeys) {
		return MpcAuthSV{}, errors.New("addPublicAuth: shared value and MAC context disagree on the key count")
	}
	k := MpcMod(c)
	value := append([]*big.Int(nil), x.Value...)
	value[0] = MpcFAdd(value[0], k)
	add := func(row, alphas []*big.Int) []*big.Int {
		o := make([]*big.Int, n)
		for i := range o {
			o[i] = MpcFAdd(row[i], MpcFMul(alphas[i], k))
		}
		return o
	}
	extra := make([][]*big.Int, len(x.ExtraMac))
	for l := range extra {
		if len(x.ExtraMac[l]) != n || len(ctx.ExtraKeys[l].AlphaShares) != n {
			return MpcAuthSV{}, errors.New("addPublicAuth: extra MAC party count mismatch")
		}
		extra[l] = add(x.ExtraMac[l], ctx.ExtraKeys[l].AlphaShares)
	}
	return MpcAuthSV{value, add(x.Mac, ctx.AlphaShares), extra}, nil
}

func MpcNotBitAuth(b MpcAuthSV, ctx *MpcMacContext) (MpcAuthSV, error) {
	return MpcAddPublicAuth(MpcNegAuth(b), big.NewInt(1), ctx)
}

func MpcGenAuthTriple(ctx *MpcMacContext, rng MpcFieldSource) (*MpcAuthTriple, error) {
	a, b := rng.Next(), rng.Next()
	as, err := MpcAuthShare(a, ctx, rng)
	if err != nil {
		return nil, err
	}
	bs, err := MpcAuthShare(b, ctx, rng)
	if err != nil {
		return nil, err
	}
	cs, err := MpcAuthShare(MpcFMul(a, b), ctx, rng)
	if err != nil {
		return nil, err
	}
	return &MpcAuthTriple{as, bs, cs}, nil
}

// MpcTripleWithPartners is a triple to deliver plus its sacrifice partners (every partner shares Keep.B).
type MpcTripleWithPartners struct {
	Keep     MpcAuthTriple
	Partners []MpcAuthTriple
}

// MpcDealerFault is the TEST-ONLY lying-dealer fault: the dealer authenticates a wrong product. A nil entry means no delta.
type MpcDealerFault struct {
	KeepCDelta    *big.Int
	PartnerCDelta []*big.Int
}

func MpcGenTripleWithPartners(ctx *MpcMacContext, rng MpcFieldSource, partners int, fault *MpcDealerFault) (*MpcTripleWithPartners, error) {
	if partners < 1 || partners > 8 {
		return nil, errors.New("genTripleWithPartners: partners must be in [1, 8]")
	}
	a, b := rng.Next(), rng.Next()
	bSV, err := MpcAuthShare(b, ctx, rng)
	if err != nil {
		return nil, err
	}
	kd := new(big.Int)
	if fault != nil && fault.KeepCDelta != nil {
		kd = fault.KeepCDelta
	}
	keepA, err := MpcAuthShare(a, ctx, rng)
	if err != nil {
		return nil, err
	}
	keepC, err := MpcAuthShare(MpcFAdd(MpcFMul(a, b), kd), ctx, rng)
	if err != nil {
		return nil, err
	}
	out := &MpcTripleWithPartners{Keep: MpcAuthTriple{keepA, bSV, keepC}}
	for r := 0; r < partners; r++ {
		ah := rng.Next()
		pd := new(big.Int)
		if fault != nil && r < len(fault.PartnerCDelta) && fault.PartnerCDelta[r] != nil {
			pd = fault.PartnerCDelta[r]
		}
		pa, err := MpcAuthShare(ah, ctx, rng)
		if err != nil {
			return nil, err
		}
		pc, err := MpcAuthShare(MpcFAdd(MpcFMul(ah, b), pd), ctx, rng)
		if err != nil {
			return nil, err
		}
		out.Partners = append(out.Partners, MpcAuthTriple{pa, bSV, pc})
	}
	return out, nil
}

// MpcDeviation models an active cheater's broadcast in the online phase. Nil deltas mean none; MacKey nil means key 0.
type MpcDeviation struct {
	OpenIndex, Party     int
	ValueDelta, MacDelta *big.Int
	MacKey               *int
}

// MpcOpenedValue is one partial opening as it reaches the MAC-check: the public value and MacShares[key][party].
type MpcOpenedValue struct {
	Value     *big.Int
	MacShares [][]*big.Int
	Label     string
}

// MpcMacResiduals is the arithmetic core of the batched MAC-check over an arbitrary modulus p: sigma[key][party].
func MpcMacResiduals(p *big.Int, alphaShares [][]*big.Int, opened []MpcOpenedValue, challenges [][]*big.Int) [][]*big.Int {
	out := make([][]*big.Int, len(alphaShares))
	for l := range alphaShares {
		r := challenges[l]
		a := new(big.Int)
		for j := range opened {
			a.Add(a, new(big.Int).Mul(r[j], opened[j].Value)).Mod(a, p)
		}
		out[l] = make([]*big.Int, len(alphaShares[l]))
		for i, al := range alphaShares[l] {
			gamma := new(big.Int)
			for j := range opened {
				gamma.Add(gamma, new(big.Int).Mul(r[j], opened[j].MacShares[l][i])).Mod(gamma, p)
			}
			out[l][i] = gamma.Sub(gamma, new(big.Int).Mul(al, a)).Mod(gamma, p)
		}
	}
	return out
}

// MpcSpdzEngine is the SPDZ online engine: partial openings and the batched MAC-check.
type MpcSpdzEngine struct {
	ctx        *MpcMacContext
	deviations []MpcDeviation
	opened     []MpcOpenedValue
	counter    int
}

func NewMpcSpdzEngine(ctx *MpcMacContext, deviations []MpcDeviation) (*MpcSpdzEngine, error) {
	if bits := MpcMacSoundnessBits(1+len(ctx.ExtraKeys), MpcPrime); bits < MpcMinMacSoundness {
		return nil, fmt.Errorf("SpdzEngine: MAC context gives only %d bits of statistical soundness (< %d); use setupMac(n, rng) with the default %d keys",
			int(math.Round(bits)), MpcMinMacSoundness, MpcMacKeys)
	}
	return &MpcSpdzEngine{ctx: ctx, deviations: deviations}, nil
}

func (e *MpcSpdzEngine) OpenCount() int { return e.counter }

// Open reveals x (with every configured deviation applied) and records the partial opening for the MAC-check.
func (e *MpcSpdzEngine) Open(x MpcAuthSV, label string) (*big.Int, error) {
	idx := e.counter
	e.counter++
	if len(x.ExtraMac) != len(e.ctx.ExtraKeys) {
		return nil, errors.New("open: value and MAC context disagree on the key count")
	}
	valueShares := append([]*big.Int(nil), x.Value...)
	macShares := make([][]*big.Int, 1+len(x.ExtraMac))
	macShares[0] = append([]*big.Int(nil), x.Mac...)
	for l := range x.ExtraMac {
		macShares[l+1] = append([]*big.Int(nil), x.ExtraMac[l]...)
	}
	for _, d := range e.deviations {
		if d.OpenIndex != idx {
			continue
		}
		if d.Party < 0 || d.Party >= e.ctx.N {
			return nil, errors.New("Deviation.party out of range")
		}
		if d.ValueDelta != nil {
			valueShares[d.Party] = MpcFAdd(valueShares[d.Party], d.ValueDelta)
		}
		if d.MacDelta != nil {
			key := 0
			if d.MacKey != nil {
				key = *d.MacKey
			}
			if key < 0 || key >= len(macShares) {
				return nil, errors.New("Deviation.macKey out of range")
			}
			macShares[key][d.Party] = MpcFAdd(macShares[key][d.Party], d.MacDelta)
		}
	}
	value := new(big.Int)
	for _, s := range valueShares {
		value = MpcFAdd(value, s)
	}
	e.opened = append(e.opened, MpcOpenedValue{value, macShares, label})
	return value, nil
}

func mpcCommit(value, nonce *big.Int) string {
	h := sha256.Sum256([]byte(value.Text(16) + ":" + nonce.Text(16)))
	return hex.EncodeToString(h[:])
}

// MacCheck is the batched MAC-check over every partial open so far; it returns *MpcMacCheckAbort on any inconsistency.
func (e *MpcSpdzEngine) MacCheck(rng MpcFieldSource) error {
	if len(e.opened) == 0 {
		return nil
	}
	keys := MpcMacKeysOf(e.ctx)
	challenges := make([][]*big.Int, len(keys))
	alphas := make([][]*big.Int, len(keys))
	for l := range keys {
		challenges[l] = make([]*big.Int, len(e.opened))
		for j := range e.opened {
			challenges[l][j] = rng.Next()
		}
		alphas[l] = keys[l].AlphaShares
	}
	sigma := MpcMacResiduals(MpcPrime, alphas, e.opened, challenges)
	for l := range sigma {
		nonces := make([]*big.Int, len(sigma[l]))
		for i := range nonces {
			nonces[i] = rng.Next()
		}
		for i := range nonces {
			if mpcCommit(sigma[l][i], nonces[i]) != mpcCommit(sigma[l][i], nonces[i]) {
				return &MpcMacCheckAbort{fmt.Sprintf("MAC-check: commitment from party %d did not open consistently", i)}
			}
		}
	}
	for l := range sigma {
		residual := new(big.Int)
		for _, s := range sigma[l] {
			residual = MpcFAdd(residual, s)
		}
		if residual.Sign() != 0 {
			return &MpcMacCheckAbort{fmt.Sprintf("MAC-check FAILED (key %d): residual %s != 0 - an actively-malicious party was detected; aborting with no output", l, residual)}
		}
	}
	return nil
}

// MpcSacrificeVerify certifies the kept triples or returns *MpcMacCheckAbort, emitting nothing.
func MpcSacrificeVerify(batch []MpcTripleWithPartners, ctx *MpcMacContext, rng MpcFieldSource, deviations []MpcDeviation) ([]MpcAuthTriple, error) {
	engine, err := NewMpcSpdzEngine(ctx, deviations)
	if err != nil {
		return nil, err
	}
	var taus []*big.Int
	for _, t := range batch {
		keep := t.Keep
		if len(t.Partners) < 1 {
			return nil, &MpcMacCheckAbort{"sacrifice: a triple without partners cannot be certified"}
		}
		for _, sac := range t.Partners {
			if len(sac.B.Value) != len(keep.B.Value) {
				return nil, &MpcMacCheckAbort{"sacrifice: partner does not share b with the triple"}
			}
			for i := range sac.B.Value {
				if sac.B.Value[i].Cmp(keep.B.Value[i]) != 0 {
					return nil, &MpcMacCheckAbort{"sacrifice: partner does not share b with the triple"}
				}
			}
			e := rng.Next()
			if e.Sign() == 0 {
				e = big.NewInt(1)
			}
			d1, err := MpcSubAuth(MpcScaleAuth(keep.A, e), sac.A)
			if err != nil {
				return nil, err
			}
			rho, err := engine.Open(d1, "sacrifice:rho")
			if err != nil {
				return nil, err
			}
			tau, err := MpcSubAuth(MpcScaleAuth(keep.C, e), sac.C)
			if err != nil {
				return nil, err
			}
			if tau, err = MpcSubAuth(tau, MpcScaleAuth(keep.B, rho)); err != nil {
				return nil, err
			}
			tv, err := engine.Open(tau, "sacrifice:tau")
			if err != nil {
				return nil, err
			}
			taus = append(taus, tv)
		}
	}
	if err := engine.MacCheck(rng); err != nil {
		return nil, err
	}
	for _, t := range taus {
		if t.Sign() != 0 {
			return nil, &MpcMacCheckAbort{fmt.Sprintf("Beaver-triple sacrifice FAILED: residual tau=%s != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted", t)}
		}
	}
	out := make([]MpcAuthTriple, len(batch))
	for i, t := range batch {
		out[i] = t.Keep
	}
	return out, nil
}

// MpcAuthValue reconstructs the value of an authenticated sharing (test inspection only).
func MpcAuthValue(x MpcAuthSV) *big.Int {
	a := new(big.Int)
	for _, s := range x.Value {
		a = MpcFAdd(a, s)
	}
	return a
}

// MpcBeaverMulAuth is the authenticated Beaver multiplication consuming triple; the d and e openings are recorded for the MAC-check.
func MpcBeaverMulAuth(x, y MpcAuthSV, t *MpcAuthTriple, ctx *MpcMacContext, engine *MpcSpdzEngine, label string) (MpcAuthSV, error) {
	for _, o := range []MpcAuthSV{t.A, t.B, t.C, y} {
		if err := mpcAuthSame(x, o); err != nil {
			return MpcAuthSV{}, err
		}
	}
	dx, err := MpcSubAuth(x, t.A)
	if err != nil {
		return MpcAuthSV{}, err
	}
	d, err := engine.Open(dx, label+":d")
	if err != nil {
		return MpcAuthSV{}, err
	}
	ey, err := MpcSubAuth(y, t.B)
	if err != nil {
		return MpcAuthSV{}, err
	}
	e, err := engine.Open(ey, label+":e")
	if err != nil {
		return MpcAuthSV{}, err
	}
	s, err := MpcAddAuth(MpcScaleAuth(t.B, d), MpcScaleAuth(t.A, e))
	if err != nil {
		return MpcAuthSV{}, err
	}
	z, err := MpcAddAuth(t.C, s)
	if err != nil {
		return MpcAuthSV{}, err
	}
	return MpcAddPublicAuth(z, MpcFMul(d, e), ctx)
}

// ---- malicious-secure runner

// MpcOfflineProvider is a source of the SPDZ offline phase: the MAC key, authenticated triples and input sharings.
type MpcOfflineProvider interface {
	N() int
	MacContext() *MpcMacContext
	GenAuthTriple() (*MpcAuthTriple, error)
	// AuthInput is the authenticated sharing of value contributed by party owner.
	AuthInput(value *big.Int, owner int) (MpcAuthSV, error)
}

// MpcDealerOptions are the trusted-dealer options (honoured only with InsecureTrustedDealer). VerifyTriples nil means true.
type MpcDealerOptions struct {
	VerifyTriples *bool
	Partners      *int
	Fault         *MpcDealerFault
}

type MpcMaliciousConfig struct {
	Q                     *int // nil = MpcDefaultQ
	Seed                  *big.Int
	Deviations            []MpcDeviation
	Offline               MpcOfflineProvider
	InsecureTrustedDealer bool
	Dealer                *MpcDealerOptions
}

type MpcMaliciousResult struct {
	Composed        MpcComposedDecision
	Parties, Q      int
	Opens           int
	Multiplications int
	OfflineMode     string
	TriplesVerified bool
	MacChecked      bool
}

// MpcComposeSecureMalicious composes with every shared value MAC-authenticated: a correct result or an abort. The default
// is the OT-based no-dealer offline phase (MpcMakeNoDealerOffline); cfg.Offline substitutes another provider and the trusted dealer needs
// the explicit InsecureTrustedDealer opt-in (fail closed).
func MpcComposeSecureMalicious(vs []MpcDecisionVector, cfg *MpcMaliciousConfig) (*MpcMaliciousResult, error) {
	if cfg == nil {
		cfg = &MpcMaliciousConfig{}
	}
	n := len(vs)
	if n == 0 {
		return nil, errors.New("composeSecureMalicious: no parties (fail closed)")
	}
	Q := MpcDefaultQ
	if cfg.Q != nil {
		Q = *cfg.Q
	}
	if err := MpcAssertDecisionVectors(vs, Q); err != nil {
		return nil, err
	}
	rng := MpcFieldRandom(cfg.Seed)
	if cfg.Offline != nil && cfg.InsecureTrustedDealer {
		return nil, errors.New("composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)")
	}
	if cfg.Dealer != nil && !cfg.InsecureTrustedDealer && cfg.Offline == nil {
		return nil, errors.New("composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)")
	}
	offline := cfg.Offline
	if offline == nil && !cfg.InsecureTrustedDealer {
		nd, err := MpcMakeNoDealerOffline(n, cfg.Seed, nil)
		if err != nil {
			return nil, err
		}
		offline = nd
	}
	if offline != nil && offline.N() != n {
		return nil, errors.New("composeSecureMalicious: offline provider party count != number of vectors")
	}
	var ctx *MpcMacContext
	if offline != nil {
		ctx = offline.MacContext()
	} else {
		var err error
		if ctx, err = MpcSetupMac(n, rng, MpcMacKeys); err != nil {
			return nil, err
		}
	}
	engine, err := NewMpcSpdzEngine(ctx, cfg.Deviations)
	if err != nil {
		return nil, err
	}
	verify := cfg.Dealer == nil || cfg.Dealer.VerifyTriples == nil || *cfg.Dealer.VerifyTriples
	mults := 0
	nextTriple := func() (*MpcAuthTriple, error) {
		if offline != nil {
			return offline.GenAuthTriple()
		}
		if !verify {
			if cfg.Dealer != nil && cfg.Dealer.Fault != nil {
				d, err := MpcGenTripleWithPartners(ctx, rng, 1, cfg.Dealer.Fault)
				if err != nil {
					return nil, err
				}
				return &d.Keep, nil
			}
			return MpcGenAuthTriple(ctx, rng)
		}
		partners := MpcSacrificeParts
		if cfg.Dealer != nil && cfg.Dealer.Partners != nil {
			partners = *cfg.Dealer.Partners
		}
		var fault *MpcDealerFault
		if cfg.Dealer != nil {
			fault = cfg.Dealer.Fault
		}
		dealt, err := MpcGenTripleWithPartners(ctx, rng, partners, fault)
		if err != nil {
			return nil, err
		}
		cert, err := MpcSacrificeVerify([]MpcTripleWithPartners{*dealt}, ctx, rng, nil)
		if err != nil {
			return nil, err
		}
		return &cert[0], nil
	}
	shareBit := func(bit, owner int) (MpcAuthSV, error) {
		if offline != nil {
			return offline.AuthInput(big.NewInt(int64(bit)), owner)
		}
		return MpcAuthShare(big.NewInt(int64(bit)), ctx, rng)
	}
	and := func(bits []MpcAuthSV) (MpcAuthSV, error) {
		if len(bits) == 0 {
			return MpcAuthConstant(big.NewInt(1), ctx), nil
		}
		acc := bits[0]
		for i := 1; i < len(bits); i++ {
			t, err := nextTriple()
			if err != nil {
				return MpcAuthSV{}, err
			}
			if acc, err = MpcBeaverMulAuth(acc, bits[i], t, ctx, engine, fmt.Sprintf("and%d", i)); err != nil {
				return MpcAuthSV{}, err
			}
			mults++
		}
		return acc, nil
	}
	or := func(bits []MpcAuthSV) (MpcAuthSV, error) {
		if len(bits) == 0 {
			return MpcAuthConstant(new(big.Int), ctx), nil
		}
		prod, err := MpcNotBitAuth(bits[0], ctx)
		if err != nil {
			return MpcAuthSV{}, err
		}
		for i := 1; i < len(bits); i++ {
			nb, err := MpcNotBitAuth(bits[i], ctx)
			if err != nil {
				return MpcAuthSV{}, err
			}
			t, err := nextTriple()
			if err != nil {
				return MpcAuthSV{}, err
			}
			if prod, err = MpcBeaverMulAuth(prod, nb, t, ctx, engine, fmt.Sprintf("or%d", i)); err != nil {
				return MpcAuthSV{}, err
			}
			mults++
		}
		return MpcNotBitAuth(prod, ctx)
	}
	allowBits := make([]MpcAuthSV, n)
	for p := range allowBits {
		if allowBits[p], err = shareBit(vs[p].Allow, p); err != nil {
			return nil, err
		}
	}
	allowSV, err := and(allowBits)
	if err != nil {
		return nil, err
	}
	ge := func(m int, val func(p int) int) ([]MpcAuthSV, error) {
		therm := make([][]int, n)
		for p := range therm {
			var err error
			if therm[p], err = MpcThermometerEncode(float64(val(p)), m); err != nil {
				return nil, err
			}
		}
		out := make([]MpcAuthSV, m)
		for k := range out {
			bits := make([]MpcAuthSV, n)
			for p := range bits {
				var err error
				if bits[p], err = shareBit(therm[p][k], p); err != nil {
					return nil, err
				}
			}
			var err error
			if out[k], err = or(bits); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	tGe, err := ge(mpcTM, func(p int) int { return vs[p].T })
	if err != nil {
		return nil, err
	}
	rGe, err := ge(Q, func(p int) int { return vs[p].RQuant })
	if err != nil {
		return nil, err
	}
	isOne := func(sv MpcAuthSV, label string) (int, error) {
		v, err := engine.Open(sv, label)
		if err != nil {
			return 0, err
		}
		if v.Cmp(big.NewInt(1)) == 0 {
			return 1, nil
		}
		return 0, nil
	}
	allow, err := isOne(allowSV, "out:allow")
	if err != nil {
		return nil, err
	}
	tOpen := make([]int, mpcTM)
	for k := range tOpen {
		if tOpen[k], err = isOne(tGe[k], fmt.Sprintf("out:t.ge%d", k+1)); err != nil {
			return nil, err
		}
	}
	rOpen := make([]int, Q)
	for k := range rOpen {
		if rOpen[k], err = isOne(rGe[k], fmt.Sprintf("out:r.ge%d", k+1)); err != nil {
			return nil, err
		}
	}
	if err := engine.MacCheck(rng); err != nil {
		return nil, err
	}
	mode := "trusted-dealer"
	if offline != nil {
		mode = "no-dealer"
	}
	return &MpcMaliciousResult{
		Composed: MpcComposedDecision{allow, min(3, max(1, MpcThermometerDecode(tOpen))), MpcThermometerDecode(rOpen)},
		Parties:  n, Q: Q, Opens: engine.OpenCount(), Multiplications: mults, OfflineMode: mode, TriplesVerified: offline != nil || verify, MacChecked: true,
	}, nil
}
