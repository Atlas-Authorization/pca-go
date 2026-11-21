package pca

// Exact Clopper-Pearson upper bounds with their certificate, the binomial CDF guess, the dyadic form of a double, the Hoeffding
// half-width and the Wilson interval (the reference intent package numerics). The integer arithmetic is on math/big at the
// dyadic points a / 2^52; the float helpers follow the reference expression order.

import (
	"errors"
	"math"
	"math/big"
)

// IntentBinomialCdf is P(X <= k) for X ~ Binomial(n, p) in floating point (guesses and diagnostics, never decisions).
func IntentBinomialCdf(k, n, p float64) float64 {
	if k >= n {
		return 1
	}
	if k < 0 {
		return 0
	}
	if p <= 0 {
		return 1
	}
	if p >= 1 {
		return 0
	}
	nn := int(n)
	lf := cpLogFactorials(nn)
	lp := math.Log(p)
	lq := math.Log1p(-p)
	s := 0.0
	for i := 0; i <= int(math.Floor(k)); i++ {
		s += math.Exp(lf[nn] - lf[i] - lf[nn-i] + float64(float64(i)*lp) + float64((n-float64(i))*lq))
	}
	return math.Min(1, s)
}

// IntentDyadic is x = Num / 2^Exp exactly.
type IntentDyadic struct {
	Num *big.Int
	Exp int
}

// IntentDoubleToDyadic is the exact binary fraction of a finite double in (0, 1).
func IntentDoubleToDyadic(x float64) (IntentDyadic, error) {
	if math.IsNaN(x) || math.IsInf(x, 0) || !(x > 0 && x < 1) {
		return IntentDyadic{}, errors.New("doubleToDyadic: need 0 < x < 1")
	}
	r := new(big.Rat).SetFloat64(x)
	return IntentDyadic{Num: new(big.Int).Set(r.Num()), Exp: r.Denom().BitLen() - 1}, nil
}

// IntentCdfRecNumerator is the numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n).
func IntentCdfRecNumerator(n, k int, a *big.Int) (*big.Int, error) {
	if a.Sign() < 0 || a.Cmp(big.NewInt(cpA)) > 0 {
		return nil, errors.New("cdfRecNumerator: a must be in [0, 2^52]")
	}
	if n < 0 || k < 0 {
		return nil, errors.New("cdfRecNumerator: negative n or k")
	}
	return cpCdfRecNumeratorBig(n, k, a), nil
}

func cpCdfRecNumeratorBig(n, k int, ab *big.Int) *big.Int {
	A := big.NewInt(cpA)
	b := new(big.Int).Sub(A, ab)
	kk := k
	if n < kk {
		kk = n
	}
	row := make([]*big.Int, kk+1)
	for i := range row {
		row[i] = big.NewInt(1)
	}
	pw := big.NewInt(1)
	for m := 0; m < n; m++ {
		nxt := make([]*big.Int, kk+1)
		pwNext := new(big.Int).Mul(pw, A)
		for j := 0; j <= kk; j++ {
			if j >= m+1 {
				nxt[j] = new(big.Int).Set(pwNext)
			} else {
				left := big.NewInt(0)
				if j > 0 {
					left = row[j-1]
				}
				t := new(big.Int).Mul(ab, left)
				t.Add(t, new(big.Int).Mul(b, row[j]))
				nxt[j] = t
			}
		}
		row, pw = nxt, pwNext
	}
	return row[kk]
}

// IntentCdfExceeds decides exactly alpha < cdfRec(a / 2^52, n, k).
func IntentCdfExceeds(n, k int, a *big.Int, alpha IntentDyadic) (bool, error) {
	N, err := IntentCdfRecNumerator(n, k, a)
	if err != nil {
		return false, err
	}
	lhs := new(big.Int).Lsh(N, uint(alpha.Exp))
	rhs := new(big.Int).Mul(alpha.Num, new(big.Int).Exp(big.NewInt(cpA), big.NewInt(int64(n)), nil))
	return lhs.Cmp(rhs) > 0, nil
}

// IntentClopperCertificate is the upper bound with the grid points that bracket it.
type IntentClopperCertificate struct {
	Upper      float64
	UpperUnits int64
	LowerUnits int64
}

// IntentClopperPearsonCertified is the exact one-sided upper bound with its certificate.
func IntentClopperPearsonCertified(kf, nf, alpha float64) (IntentClopperCertificate, error) {
	if !(kf == math.Trunc(kf) && nf == math.Trunc(nf) && kf >= 0 && nf >= 0 && kf <= nf && nf < 1e6) {
		return IntentClopperCertificate{}, errors.New("clopperPearsonUpper: need integers 0 <= k <= n")
	}
	if !(alpha > 0 && alpha < 1) {
		return IntentClopperCertificate{}, errors.New("clopperPearsonUpper: alpha must be in (0, 1)")
	}
	k, n := int(kf), int(nf)
	if n == 0 || k == n {
		return IntentClopperCertificate{Upper: 1, UpperUnits: cpA, LowerUnits: cpA}, nil
	}
	al, err := IntentDoubleToDyadic(alpha)
	if err != nil {
		return IntentClopperCertificate{}, err
	}
	start := cpClamp(int64(math.Ceil(cpFloatGuess(k, n, alpha)*float64(cpA))) + cpTol)
	exceeds := func(a int64) bool { return cpExceeds(n, k, a, al.Num, uint(al.Exp)) }
	hi, lo := start, int64(0)
	step := cpTol
	for exceeds(hi) {
		hi = cpClamp(hi + step)
		step *= 2
	}
	lo = cpClamp(hi - cpTol)
	step = cpTol
	for lo > 0 && !exceeds(lo) {
		hi = lo
		lo = cpClamp(lo - step)
		step *= 2
	}
	if lo == 0 && !exceeds(0) {
		return IntentClopperCertificate{}, errors.New("clopperPearsonUpper: unreachable (cdfRec(0) = 1)")
	}
	for hi-lo > cpTol {
		mid := (lo + hi) / 2
		if exceeds(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return IntentClopperCertificate{Upper: float64(hi) / float64(cpA), UpperUnits: hi, LowerUnits: lo}, nil
}

// IntentHoeffdingHalfWidth is range * sqrt(ln(2/delta') / (2 samples)).
func IntentHoeffdingHalfWidth(rng, samples, deltaPrime float64) float64 {
	return rng * math.Sqrt(math.Log(2/deltaPrime)/(2*samples))
}

// IntentWilsonInterval is the Wilson score interval for k/n (z 1.959963984540054 is the 95% default).
func IntentWilsonInterval(k, n, z float64) (p, lo, hi float64) {
	if !(n > 0) {
		return math.NaN(), 0, 1
	}
	p = k / n
	z2 := z * z
	den := 1 + z2/n
	centre := (p + z2/(2*n)) / den
	half := (z * math.Sqrt((p*(1-p))/n+z2/(4*n*n))) / den
	return p, math.Max(0, centre-half), math.Min(1, centre+half)
}
