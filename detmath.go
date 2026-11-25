package pca

// Deterministic math: ln, log2 and exp from integer arithmetic only, so that no platform's libm can move a decision that sits on a
// boundary (the drift threshold, the next question, a map weight, an integer cut point). A value is an integer scaled by 2^96
// (fixed point), division truncates toward zero, and the one final conversion of the integer to a double rounds to nearest even
// before an exact power-of-two scaling. The rule matches the reference's deterministic-math module bit for bit.

import (
	"math"
	"math/big"
)

const detFrac = 96

var (
	detOne = new(big.Int).Lsh(big.NewInt(1), detFrac)
	detLN2 = detAtanh2(big.NewInt(1), big.NewInt(3)) // ln 2 = 2 atanh(1/3)
)

// detAtanh2 is 2 * atanh(num/den) in fixed point: z + z^3/3 + z^5/5 + ... summed until a term is 0.
func detAtanh2(num, den *big.Int) *big.Int {
	z := new(big.Int).Quo(new(big.Int).Lsh(num, detFrac), den)
	z2 := new(big.Int).Rsh(new(big.Int).Mul(z, z), detFrac)
	term := new(big.Int).Set(z)
	sum := new(big.Int)
	t := new(big.Int)
	for i := int64(1); term.Sign() != 0; i += 2 {
		sum.Add(sum, t.Quo(term, big.NewInt(i)))
		term.Rsh(term.Mul(term, z2), detFrac)
	}
	return sum.Lsh(sum, 1)
}

// detToFloat is Number(bigint): one correct round-to-nearest-even conversion.
func detToFloat(x *big.Int) float64 {
	f, _ := new(big.Float).SetInt(x).Float64()
	return f
}

// detLnFixed is ln x as a fixed-point integer for a positive finite double, ok false otherwise.
func detLnFixed(x float64) (*big.Int, bool) {
	if !(x > 0) || math.IsInf(x, 1) {
		return nil, false
	}
	scale := int64(0)
	y := x
	if y < 0x1p-1022 {
		y *= 0x1p64
		scale = 64
	}
	bits := math.Float64bits(y)
	e := int64((bits>>52)&0x7ff) - 1023 - scale
	mant := new(big.Int).SetUint64(bits&(1<<52-1) | 1<<52)
	two52 := new(big.Int).Lsh(big.NewInt(1), 52)
	fixed := detAtanh2(new(big.Int).Sub(mant, two52), new(big.Int).Add(mant, two52))
	return fixed.Add(fixed, new(big.Int).Mul(big.NewInt(e), detLN2)), true
}

// DetLn is the natural logarithm (NaN for x <= 0 or NaN, +Inf for +Inf, exactly 0 for 1).
func DetLn(x float64) float64 {
	if x == 0 {
		return math.Inf(-1) // zero and negative zero, like Math.log
	}
	if !(x > 0) {
		return math.NaN()
	}
	if math.IsInf(x, 1) {
		return x
	}
	if x == 1 {
		return 0
	}
	l, _ := detLnFixed(x)
	return detToFloat(l) / detToFloat(detOne)
}

// DetLog2 is log2 x: the fixed-point ln divided by ln 2 in fixed point; an exact power of two gives its exponent exactly.
func DetLog2(x float64) float64 {
	if x == 0 {
		return math.Inf(-1) // zero and negative zero, like Math.log
	}
	if !(x > 0) {
		return math.NaN()
	}
	if math.IsInf(x, 1) {
		return x
	}
	if x == 1 {
		return 0
	}
	l, _ := detLnFixed(x)
	q := new(big.Int).Quo(new(big.Int).Lsh(l, detFrac), detLN2)
	return detToFloat(q) / detToFloat(detOne)
}

// DetExp is e^x (+Inf above 709.782712893384, 0 below -745.2, NaN for NaN).
func DetExp(x float64) float64 {
	if math.IsNaN(x) {
		return x
	}
	if x > 709.782712893384 {
		return math.Inf(1)
	}
	if x < -745.2 {
		return 0
	}
	if x == 0 {
		return 1
	}
	bits := math.Float64bits(math.Abs(x))
	be := int((bits >> 52) & 0x7ff)
	frac := bits & (1<<52 - 1)
	m := frac
	if be != 0 {
		m = frac | 1<<52
	} else {
		be = 1
	}
	sh := be - 1075 + detFrac // |x| * 2^96 = m * 2^sh
	X := new(big.Int).SetUint64(m)
	if sh >= 0 {
		X.Lsh(X, uint(sh))
	} else {
		X.Rsh(X, uint(-sh))
	}
	if x < 0 {
		X.Neg(X)
	}
	half := new(big.Int).Rsh(detLN2, 1)
	k := new(big.Int).Div(new(big.Int).Add(X, half), detLN2) // floor division (the divisor is positive)
	r := new(big.Int).Sub(X, new(big.Int).Mul(k, detLN2))
	term := new(big.Int).Set(detOne)
	sum := new(big.Int).Set(detOne)
	for n := int64(1); term.Sign() != 0; n++ {
		term.Quo(term.Mul(term, r), detOne)
		term.Quo(term, big.NewInt(n))
		sum.Add(sum, term)
	}
	e := int(k.Int64()) - detFrac
	h := e / 2
	return math.Ldexp(math.Ldexp(detToFloat(sum), h), e-h)
}

// DetPowInt is b^n for an integer n >= 0: 1 multiplied by b, n times, in sequence (each product exactly rounded, never fused).
func DetPowInt(b float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r = float64(r * b)
	}
	return r
}
