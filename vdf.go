package pca

// Wesolowski VDF over an RSA group plus the PCA timelock. Pure big-integer math (math/big; not constant time, every input is
// public). Same domains, transcript, error texts and check order as the reference, so challenge primes, proofs and timelock inputs
// are byte-identical. A VDF in an RSA group needs a modulus of unknown factorisation (VdfRSA2048ChallengeModulus or a ceremony
// modulus); VdfInsecureDevSetup is for tests only.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"unicode/utf8"
)

const (
	VdfChallengePrimeBits       = 256
	VdfInsecureDevSetupBits     = 2048
	VdfMinProductionModulusBits = 2048
	vdfMaxSafe                  = 1<<53 - 1
)

// VdfRSA2048ChallengeModulus is the RSA-2048 challenge number (factorisation unknown).
var VdfRSA2048ChallengeModulus, _ = new(big.Int).SetString(
	"25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072"+
		"84499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686"+
		"99875491824224336372590851418654620435767984233871847744479207399342365848238242811981638150106748104516603773060562016196762561338441436038339044149526"+
		"34432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822"+
		"120720357", 10)

func vdfSafeInt(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > vdfMaxSafe || f != math.Trunc(f) {
		return 0, false
	}
	return int64(f), true
}

// vdfRem is JavaScript BigInt %: the sign follows the dividend.
func vdfRem(a, n *big.Int) (*big.Int, error) {
	if n.Sign() == 0 {
		return nil, errors.New("Division by zero")
	}
	r := new(big.Int).Mod(new(big.Int).Abs(a), new(big.Int).Abs(n))
	if a.Sign() < 0 {
		r.Neg(r)
	}
	return r, nil
}

func vdfUmod(x, n *big.Int) (*big.Int, error) {
	r, err := vdfRem(x, n)
	if err != nil {
		return nil, err
	}
	return vdfRem(r.Add(r, n), n)
}

// vdfUtf8 is TextEncoder.encode: each lone surrogate (three WTF-8 bytes in a Go string) becomes U+FFFD.
func vdfUtf8(s string) []byte {
	var out []byte
	for i := 0; i < len(s); {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			out = append(out, 0xEF, 0xBF, 0xBD)
			i += 3
			continue
		}
		if r, n := utf8.DecodeRuneInString(s[i:]); r == utf8.RuneError && n == 1 {
			out = append(out, 0xEF, 0xBF, 0xBD)
			i++
		} else {
			out = append(out, s[i:i+n]...)
			i += n
		}
	}
	return out
}

// VdfBytesToBigInt reads big-endian bytes.
func VdfBytesToBigInt(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// VdfBigIntToBytes is the minimal big-endian bytes of a non-negative integer (zero is one zero byte).
func VdfBigIntToBytes(v *big.Int) ([]byte, error) {
	if v.Sign() < 0 {
		return nil, errors.New("bigIntToBytes: negative value")
	}
	if v.Sign() == 0 {
		return []byte{0}, nil
	}
	return v.Bytes(), nil
}

func vdfBytes(v *big.Int) []byte { b, _ := VdfBigIntToBytes(v); return b }

func vdfU32(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }

func vdfLenPrefixed(b []byte) []byte { return append(vdfU32(uint32(len(b))), b...) }

func vdfSteps(t float64) (int64, error) {
	s, ok := vdfSafeInt(t)
	if !ok || s < 0 {
		return 0, fmt.Errorf("VDF: steps T must be a non-negative safe integer, got %v", t)
	}
	return s, nil
}

// VdfGcd is the greatest common divisor of |a| and |b|.
func VdfGcd(a, b *big.Int) *big.Int {
	return new(big.Int).GCD(nil, nil, new(big.Int).Abs(a), new(big.Int).Abs(b))
}

func vdfIsUnit(v, n *big.Int) bool {
	return v.Sign() > 0 && v.Cmp(n) < 0 && VdfGcd(v, n).Cmp(big.NewInt(1)) == 0
}

// VdfModpow is base^exp mod m (a negative exponent is refused: no inverse in a group of unknown order).
func VdfModpow(base, exp, mod *big.Int) (*big.Int, error) {
	if mod.Sign() <= 0 {
		return nil, errors.New("modpow: modulus must be positive")
	}
	if mod.Cmp(big.NewInt(1)) == 0 {
		return new(big.Int), nil
	}
	if exp.Sign() < 0 {
		return nil, errors.New("modpow: negative exponent (no inverse in a group of unknown order)")
	}
	return new(big.Int).Exp(new(big.Int).Mod(base, mod), exp, mod), nil
}

// ---- primality: Baillie-PSW (strong Miller-Rabin on the first 25 primes + strong Lucas)

var vdfSmallPrimes = []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97}

func vdfIsPerfectSquare(n *big.Int) bool {
	if n.Sign() < 0 {
		return false
	}
	r := new(big.Int).Sqrt(n)
	return r.Mul(r, r).Cmp(n) == 0
}

// VdfIsStrongLucasProbablePrime is the strong Lucas probable prime test (Selfridge parameters).
func VdfIsStrongLucasProbablePrime(n *big.Int) bool {
	if n.Cmp(big.NewInt(3)) < 0 || n.Bit(0) == 0 || vdfIsPerfectSquare(n) {
		return false
	}
	dd := int64(5)
	for {
		j := big.Jacobi(big.NewInt(dd), n)
		if j == -1 {
			break
		}
		if j == 0 {
			abs := dd
			if abs < 0 {
				abs = -abs
			}
			if big.NewInt(abs).Cmp(n) != 0 {
				return false
			}
		}
		if dd > 0 {
			dd = -(dd + 2)
		} else {
			dd = -dd + 2
		}
	}
	bigD := big.NewInt(dd)
	p := big.NewInt(1)
	q := big.NewInt((1 - dd) / 4) // exact: D = 1 (mod 4)
	mod := func(x *big.Int) *big.Int { return new(big.Int).Mod(x, n) }
	half := func(x *big.Int) *big.Int {
		if x.Bit(0) == 1 {
			x = new(big.Int).Add(x, n)
		}
		return new(big.Int).Rsh(x, 1)
	}
	d := new(big.Int).Add(n, big.NewInt(1))
	s := 0
	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}
	u, v, qk := big.NewInt(1), new(big.Int).Set(p), mod(q)
	for i := d.BitLen() - 2; i >= 0; i-- {
		u = mod(new(big.Int).Mul(u, v))
		v = mod(new(big.Int).Sub(new(big.Int).Mul(v, v), new(big.Int).Lsh(qk, 1)))
		qk = mod(new(big.Int).Mul(qk, qk))
		if d.Bit(i) == 1 {
			u1 := half(mod(new(big.Int).Add(new(big.Int).Mul(p, u), v)))
			v1 := half(mod(new(big.Int).Add(new(big.Int).Mul(bigD, u), new(big.Int).Mul(p, v))))
			u, v = u1, v1
			qk = mod(new(big.Int).Mul(qk, q))
		}
	}
	if u.Sign() == 0 || v.Sign() == 0 {
		return true
	}
	for i := 1; i < s; i++ {
		v = mod(new(big.Int).Sub(new(big.Int).Mul(v, v), new(big.Int).Lsh(qk, 1)))
		if v.Sign() == 0 {
			return true
		}
		qk = mod(new(big.Int).Mul(qk, qk))
	}
	return false
}

// VdfIsMillerRabinProbablePrime is strong Miller-Rabin to the first 25 prime bases.
func VdfIsMillerRabinProbablePrime(n *big.Int) bool {
	if n.Cmp(big.NewInt(3)) < 0 || n.Bit(0) == 0 {
		return false
	}
	nm1 := new(big.Int).Sub(n, big.NewInt(1))
	d := new(big.Int).Set(nm1)
	s := 0
	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}
	for _, a := range vdfSmallPrimes {
		base := new(big.Int).Mod(big.NewInt(a), n)
		if base.Sign() == 0 {
			continue
		}
		x := new(big.Int).Exp(base, d, n)
		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(nm1) == 0 {
			continue
		}
		witness := true
		for i := 1; i < s; i++ {
			x.Mul(x, x).Mod(x, n)
			if x.Cmp(nm1) == 0 {
				witness = false
				break
			}
		}
		if witness {
			return false
		}
	}
	return true
}

// VdfIsProbablePrime is trial division by the small primes, then the standard library's Baillie-PSW test (strong base-2 Miller-Rabin
// plus strong Lucas; ProbablyPrime(0) is deterministic, with no known counterexample). The 25-base Miller-Rabin and the Lucas test stay
// exported on their own because their verdicts are individually specified.
func VdfIsProbablePrime(n *big.Int) bool {
	if n.Cmp(big.NewInt(2)) < 0 {
		return false
	}
	for _, p := range vdfSmallPrimes {
		bp := big.NewInt(p)
		if n.Cmp(bp) == 0 {
			return true
		}
		if new(big.Int).Mod(n, bp).Sign() == 0 {
			return false
		}
	}
	return n.ProbablyPrime(0)
}

// ---- Fiat-Shamir challenge prime

const vdfHashToPrimeDomain = "atlas-pca/vdf/wesolowski/hash-to-prime/v1\x00"

// VdfHashToPrime is the challenge prime of (x, y, T, N); bits defaults to 256 and must be in [8, 8192].
func VdfHashToPrime(x, y *big.Int, t float64, n *big.Int, bits float64) (*big.Int, error) {
	b, ok := vdfSafeInt(bits)
	if !ok || b < 8 || b > 8192 {
		return nil, errors.New("hashToPrime: bits must be an integer in [8, 8192]")
	}
	steps, err := vdfSteps(t)
	if err != nil {
		return nil, err
	}
	xr, err := vdfUmod(x, n)
	if err != nil {
		return nil, err
	}
	yr, err := vdfUmod(y, n)
	if err != nil {
		return nil, err
	}
	nb, err := VdfBigIntToBytes(n)
	if err != nil {
		return nil, err
	}
	xb, err := VdfBigIntToBytes(xr)
	if err != nil {
		return nil, err
	}
	yb, err := VdfBigIntToBytes(yr)
	if err != nil {
		return nil, err
	}
	var tr []byte
	tr = append(tr, vdfHashToPrimeDomain...)
	tr = append(tr, vdfLenPrefixed(xb)...)
	tr = append(tr, vdfLenPrefixed(yb)...)
	tr = append(tr, vdfLenPrefixed(vdfBytes(big.NewInt(steps)))...)
	tr = append(tr, vdfLenPrefixed(nb)...)
	tr = append(tr, vdfLenPrefixed(vdfU32(uint32(b)))...)
	seed := sha256.Sum256(tr)
	need := int((b + 7) / 8)
	top := new(big.Int).Lsh(big.NewInt(1), uint(b-1))
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(b)), big.NewInt(1))
	for counter := uint64(0); ; counter++ {
		var chunks []byte
		for blockIndex := uint32(0); len(chunks) < need; blockIndex++ {
			in := append(append(append([]byte{}, seed[:]...), binary.BigEndian.AppendUint64(nil, counter)...), vdfU32(blockIndex)...)
			h := sha256.Sum256(in)
			chunks = append(chunks, h[:]...)
		}
		cand := VdfBytesToBigInt(chunks[:need])
		cand.And(cand, mask).Or(cand, top).SetBit(cand, 0, 1)
		if VdfIsProbablePrime(cand) {
			return cand, nil
		}
	}
}

// ---- the VDF

// VdfSequentialSquare is x^(2^T) mod N by T squarings.
func VdfSequentialSquare(x *big.Int, t float64, n *big.Int) (*big.Int, error) {
	if n.Cmp(big.NewInt(1)) <= 0 {
		return nil, errors.New("VDF: modulus N must be > 1")
	}
	steps, err := vdfSteps(t)
	if err != nil {
		return nil, err
	}
	y, err := vdfUmod(x, n)
	if err != nil {
		return nil, err
	}
	for i := int64(0); i < steps; i++ {
		y.Mul(y, y).Mod(y, n)
	}
	return y, nil
}

func vdfWesolowskiProof(x *big.Int, t int64, l, n *big.Int) (*big.Int, error) {
	xr, err := vdfUmod(x, n)
	if err != nil {
		return nil, err
	}
	pi := new(big.Int).Mod(big.NewInt(1), n)
	r := new(big.Int).Mod(big.NewInt(1), l)
	for i := int64(0); i < t; i++ {
		twoR := new(big.Int).Lsh(r, 1)
		b := new(big.Int).Div(twoR, l)
		r = twoR.Mod(twoR, l)
		pi.Mul(pi, pi).Mod(pi, n)
		if b.Cmp(big.NewInt(1)) == 0 {
			pi.Mul(pi, xr).Mod(pi, n)
		}
	}
	return pi, nil
}

func vdfCheckEvalInput(x, n *big.Int) error {
	xr, err := vdfUmod(x, n)
	if err != nil {
		return err
	}
	if !vdfIsUnit(xr, n) || xr.Cmp(big.NewInt(1)) == 0 || xr.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
		return errors.New("VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)")
	}
	return nil
}

func vdfBadModulus(n *big.Int) bool { return n.Cmp(big.NewInt(3)) <= 0 || n.Bit(0) == 0 }

// VdfEval is y = x^(2^T) mod N with the Wesolowski proof pi.
func VdfEval(x *big.Int, t float64, n *big.Int) (y, pi *big.Int, err error) {
	return vdfEval(x, t, n, false)
}

// VdfEvalCanonical is VdfEval with y and pi folded to the smaller of v and N - v.
func VdfEvalCanonical(x *big.Int, t float64, n *big.Int) (y, pi *big.Int, err error) {
	return vdfEval(x, t, n, true)
}

func vdfEval(x *big.Int, t float64, n *big.Int, canonical bool) (*big.Int, *big.Int, error) {
	if vdfBadModulus(n) {
		return nil, nil, errors.New("VDF: modulus N must be odd and > 3")
	}
	steps, err := vdfSteps(t)
	if err != nil {
		return nil, nil, err
	}
	if err := vdfCheckEvalInput(x, n); err != nil {
		return nil, nil, err
	}
	y, err := VdfSequentialSquare(x, t, n)
	if err != nil {
		return nil, nil, err
	}
	if canonical {
		y = VdfCanonicalOutput(y, n)
	}
	l, err := VdfHashToPrime(x, y, t, n, VdfChallengePrimeBits)
	if err != nil {
		return nil, nil, err
	}
	pi, err := vdfWesolowskiProof(x, steps, l, n)
	if err != nil {
		return nil, nil, err
	}
	if canonical {
		pi = VdfCanonicalOutput(pi, n)
	}
	return y, pi, nil
}

// VdfCanonicalOutput is the smaller of y and N - y.
func VdfCanonicalOutput(y, n *big.Int) *big.Int {
	c := new(big.Int).Sub(n, y)
	if y.Cmp(c) > 0 {
		return c
	}
	return new(big.Int).Set(y)
}

// VdfVerdict is a verification result: ok, or the reason it failed.
type VdfVerdict struct {
	OK     bool
	Reason string
}

func vdfFail(reason string) VdfVerdict { return VdfVerdict{Reason: reason} }

// vdfVerify takes nil big integers as malformed (a non-integer reached the reference); it never fails otherwise.
func vdfVerify(x, y, pi *big.Int, t float64, n *big.Int, canonical bool) (v VdfVerdict) {
	defer func() {
		if recover() != nil {
			v = vdfFail("malformed-input")
		}
	}()
	if x == nil || y == nil || pi == nil || n == nil {
		return vdfFail("malformed-input")
	}
	if vdfBadModulus(n) {
		return vdfFail("bad-modulus")
	}
	steps, ok := vdfSafeInt(t)
	if !ok || steps < 0 {
		return vdfFail("bad-steps")
	}
	half := func(v *big.Int) bool { return v.Cmp(new(big.Int).Sub(n, v)) > 0 }
	if !vdfIsUnit(y, n) || (canonical && half(y)) {
		return vdfFail("non-canonical-y")
	}
	if !vdfIsUnit(pi, n) || (canonical && half(pi)) {
		return vdfFail("non-canonical-pi")
	}
	xr, err := vdfUmod(x, n)
	if err != nil {
		return vdfFail("malformed-input")
	}
	if !vdfIsUnit(xr, n) || xr.Cmp(big.NewInt(1)) == 0 || xr.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
		return vdfFail("bad-input-x")
	}
	l, err := VdfHashToPrime(x, y, float64(steps), n, VdfChallengePrimeBits)
	if err != nil {
		return vdfFail("malformed-input")
	}
	r, err := VdfModpow(big.NewInt(2), big.NewInt(steps), l)
	if err != nil {
		return vdfFail("malformed-input")
	}
	a, err := VdfModpow(pi, l, n)
	if err != nil {
		return vdfFail("malformed-input")
	}
	b, err := VdfModpow(xr, r, n)
	if err != nil {
		return vdfFail("malformed-input")
	}
	lhs := a.Mul(a, b).Mod(a, n)
	good := lhs.Cmp(y) == 0
	if canonical {
		good = good || lhs.Cmp(new(big.Int).Sub(n, y)) == 0
	}
	if good {
		return VdfVerdict{OK: true}
	}
	return vdfFail("equation-mismatch")
}

// VdfVerifyDetailed verifies (y, pi) for x, T, N; it never fails except by returning a refusal reason.
func VdfVerifyDetailed(x, y, pi *big.Int, t float64, n *big.Int) VdfVerdict {
	return vdfVerify(x, y, pi, t, n, false)
}

// VdfVerifyCanonicalDetailed is VdfVerifyDetailed requiring the canonical (smaller-half) y and pi.
func VdfVerifyCanonicalDetailed(x, y, pi *big.Int, t float64, n *big.Int) VdfVerdict {
	return vdfVerify(x, y, pi, t, n, true)
}

// ---- modulus screening

var (
	vdfMu       sync.Mutex
	vdfDevMods  = map[string]bool{}
	vdfScreened = map[string]bool{}
	vdfScreenPr []int64
)

func vdfScreenPrimes() []int64 {
	if vdfScreenPr == nil {
		const limit = 1 << 16
		sieve := make([]bool, limit)
		for i := 2; i < limit; i++ {
			if sieve[i] {
				continue
			}
			vdfScreenPr = append(vdfScreenPr, int64(i))
			for j := i * i; j < limit; j += i {
				sieve[j] = true
			}
		}
	}
	return vdfScreenPr
}

// VdfInsecureDevSetup is TEST ONLY: a modulus whose factors the caller knows (so it delays nobody), registered so the production
// screen refuses it. randomBytes nil = crypto/rand.
func VdfInsecureDevSetup(bits int, randomBytes func(n int) []byte) (n, p, q *big.Int, err error) {
	if bits == 0 {
		bits = VdfInsecureDevSetupBits
	}
	if bits < 32 {
		return nil, nil, nil, errors.New("insecureDevSetup: bits must be a safe integer >= 32")
	}
	if randomBytes == nil {
		randomBytes = func(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
	}
	randPrime := func(bits int) (*big.Int, error) {
		nb := (bits + 7) / 8
		top := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
		for i := 0; i < 50000; i++ {
			c := VdfBytesToBigInt(randomBytes(nb))
			c.And(c, mask).Or(c, top).SetBit(c, 0, 1)
			if VdfIsProbablePrime(c) {
				return c, nil
			}
		}
		return nil, errors.New("insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)")
	}
	half := bits / 2
	if p, err = randPrime(half); err != nil {
		return nil, nil, nil, err
	}
	if q, err = randPrime(bits - half); err != nil {
		return nil, nil, nil, err
	}
	for i := 0; p.Cmp(q) == 0; i++ {
		if i >= 8 {
			return nil, nil, nil, errors.New("insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)")
		}
		if q, err = randPrime(bits - half); err != nil {
			return nil, nil, nil, err
		}
	}
	n = new(big.Int).Mul(p, q)
	vdfMu.Lock()
	vdfDevMods[n.String()] = true
	vdfMu.Unlock()
	return n, p, q, nil
}

// VdfCheckProductionModulus screens a modulus for production use; reason is empty when ok.
func VdfCheckProductionModulus(n *big.Int) (ok bool, reason string) {
	if n == nil {
		return false, "modulus is not a bigint"
	}
	key := n.String()
	vdfMu.Lock()
	dev, passed := vdfDevMods[key], vdfScreened[key]
	vdfMu.Unlock()
	if !dev && passed {
		return true, ""
	}
	switch {
	case dev:
		return false, "modulus came from insecureDevSetup(): its factors are known, so it provides no delay"
	case n.Cmp(big.NewInt(3)) <= 0:
		return false, "modulus is too small"
	case n.BitLen() < VdfMinProductionModulusBits:
		return false, fmt.Sprintf("modulus is below %d bits", VdfMinProductionModulusBits)
	case n.Bit(0) == 0:
		return false, "modulus is even"
	case vdfIsPerfectSquare(n):
		return false, "modulus is a perfect square"
	case VdfIsProbablePrime(n):
		return false, "modulus is prime (group order N-1 is public)"
	}
	vdfMu.Lock()
	primes := vdfScreenPrimes()
	vdfMu.Unlock()
	for _, p := range primes {
		if new(big.Int).Mod(n, big.NewInt(p)).Sign() == 0 {
			return false, fmt.Sprintf("modulus has the small prime factor %d", p)
		}
	}
	vdfMu.Lock()
	vdfScreened[key] = true
	vdfMu.Unlock()
	return true, ""
}

// ---- PCA timelock: the VDF challenge is bound to the action and to an unpredictable beacon

const vdfXDerivationDomain = "atlas-pca/vdf/timelock/input/v2\x00"

// VdfActionDigest: a string is an opaque, precomputed digest; anything else is a PCActn digested like the ledger.
func VdfActionDigest(action any) (string, error) {
	if s, ok := action.(string); ok {
		return s, nil
	}
	return HashCanonical(action)
}

// VdfDeriveTimelockInput is x in [2, N) bound to the action and the beacon; deterministic.
func VdfDeriveTimelockInput(action any, n *big.Int, beacon []byte) (*big.Int, error) {
	if n == nil || n.Cmp(big.NewInt(3)) <= 0 {
		return nil, errors.New("deriveTimelockInput: modulus N must be a bigint > 3")
	}
	digest, err := VdfActionDigest(action)
	if err != nil {
		return nil, err
	}
	if len(beacon) == 0 {
		return nil, errors.New("timelock: a non-empty beacon (unpredictable, post-action value) is required")
	}
	msg := append([]byte(vdfXDerivationDomain), vdfLenPrefixed(vdfUtf8(digest))...)
	msg = append(msg, vdfLenPrefixed(beacon)...)
	h := sha256.Sum256(msg)
	raw := VdfBytesToBigInt(h[:])
	raw.Mod(raw, n)
	if raw.Cmp(big.NewInt(1)) <= 0 {
		raw.Add(raw, big.NewInt(2))
	}
	return raw, nil
}

func vdfRequireProduction(n *big.Int, allowInsecureDev bool) error {
	if allowInsecureDev {
		return nil
	}
	if ok, why := VdfCheckProductionModulus(n); !ok {
		return fmt.Errorf("timelock: refusing this modulus: %s. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true.", why)
	}
	return nil
}

func vdfRequireSteps(steps float64) (int64, error) {
	s, ok := vdfSafeInt(steps)
	if !ok || s < 1 {
		return 0, fmt.Errorf("timelock: steps must be a safe integer >= 1, got %v", steps)
	}
	return s, nil
}

// VdfTimelock is a timelock requirement: the challenge input x, the step count, the modulus and the action digest.
type VdfTimelock struct {
	X            *big.Int
	Steps        int64
	N            *big.Int
	ActionDigest string
}

// VdfRequireTimelock is the requirement an action must be accompanied by a proof of.
func VdfRequireTimelock(action any, steps float64, n *big.Int, beacon []byte, allowInsecureDev bool) (*VdfTimelock, error) {
	s, err := vdfRequireSteps(steps)
	if err != nil {
		return nil, err
	}
	if err := vdfRequireProduction(n, allowInsecureDev); err != nil {
		return nil, err
	}
	x, err := VdfDeriveTimelockInput(action, n, beacon)
	if err != nil {
		return nil, err
	}
	d, err := VdfActionDigest(action)
	if err != nil {
		return nil, err
	}
	return &VdfTimelock{X: x, Steps: s, N: n, ActionDigest: d}, nil
}

// VdfTimelockProof is the proof an elapsed timelock produces.
type VdfTimelockProof struct {
	Y, Pi *big.Int
	Steps int64
}

// VdfProveTimelockElapsed runs the VDF: the squarings ARE the cooling-off, so this is deliberately slow.
func VdfProveTimelockElapsed(action any, steps float64, n *big.Int, beacon []byte, allowInsecureDev bool) (*VdfTimelockProof, error) {
	s, err := vdfRequireSteps(steps)
	if err != nil {
		return nil, err
	}
	if err := vdfRequireProduction(n, allowInsecureDev); err != nil {
		return nil, err
	}
	x, err := VdfDeriveTimelockInput(action, n, beacon)
	if err != nil {
		return nil, err
	}
	y, pi, err := VdfEvalCanonical(x, float64(s), n)
	if err != nil {
		return nil, err
	}
	return &VdfTimelockProof{Y: y, Pi: pi, Steps: s}, nil
}

// VdfVerifyTimelock fails closed: any malformed input or refused modulus is false. Offline, no clock.
func VdfVerifyTimelock(action any, proof *VdfTimelockProof, steps float64, n *big.Int, beacon []byte, allowInsecureDev bool) bool {
	required, err := vdfRequireSteps(steps)
	if err != nil {
		return false
	}
	if vdfRequireProduction(n, allowInsecureDev) != nil || proof == nil || proof.Y == nil || proof.Pi == nil || proof.Steps != required {
		return false
	}
	x, err := VdfDeriveTimelockInput(action, n, beacon)
	if err != nil {
		return false
	}
	return VdfVerifyCanonicalDetailed(x, proof.Y, proof.Pi, float64(required), n).OK
}
