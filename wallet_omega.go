package pca

// The outcome space the wallet resolves question cells against (the Omega of the intent layer), the separable harm model and
// the exact Clopper-Pearson bound, as the wallet needs them. Floats follow the reference operation by operation (IEEE-754
// doubles), so the digests and verdicts built from them agree with the TypeScript reference.

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// WalletOtherValue is the categorical value standing for "any value not named".
const WalletOtherValue = "⊥"

const walletExactSpan = 4096

// WalletOmegaValue is one categorical cell of a dimension: kind exact | prefix | other.
type WalletOmegaValue struct {
	Kind  string
	Value string
}

// WalletDim is one dimension of a verb's outcome space: kind num (lo, hi, cuts, dist) or cat (values).
type WalletDim struct {
	Kind   string
	Path   string
	Lo, Hi float64
	Cuts   []float64
	Dist   string
	Values []WalletOmegaValue
}

// WalletVerb is the outcome space of one verb.
type WalletVerb struct {
	Verb          string
	Reversibility string
	Weight        float64
	Dims          []WalletDim
}

// WalletOmega is the wallet's outcome space.
type WalletOmega struct {
	Verbs []WalletVerb
}

// WalletCellRange is the inclusive integer range of one numeric cell.
type WalletCellRange struct {
	Lo float64 `json:"lo"`
	Hi float64 `json:"hi"`
}

// WalletOmegaFromJSON reads an outcome space from its JSON form; a malformed one is refused.
func WalletOmegaFromJSON(v any) (*WalletOmega, error) {
	bad := errors.New("wallet omega: malformed outcome space")
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad
	}
	verbs, ok := m["verbs"].([]any)
	if !ok {
		return nil, bad
	}
	om := &WalletOmega{}
	for _, x := range verbs {
		vm, ok := x.(map[string]any)
		if !ok {
			return nil, bad
		}
		vs := WalletVerb{}
		vs.Verb, _ = vm["verb"].(string)
		vs.Reversibility, _ = vm["reversibility"].(string)
		w, ok := jsNum(vm["weight"])
		if !ok {
			return nil, bad
		}
		vs.Weight = w
		dims, ok := vm["dims"].([]any)
		if !ok {
			return nil, bad
		}
		for _, y := range dims {
			dm, ok := y.(map[string]any)
			if !ok {
				return nil, bad
			}
			d := WalletDim{}
			d.Kind, _ = dm["kind"].(string)
			d.Path, _ = dm["path"].(string)
			d.Dist, _ = dm["dist"].(string)
			switch d.Kind {
			case "num":
				lo, ok1 := jsNum(dm["lo"])
				hi, ok2 := jsNum(dm["hi"])
				cuts, ok3 := dm["cuts"].([]any)
				if !ok1 || !ok2 || !ok3 {
					return nil, bad
				}
				d.Lo, d.Hi = lo, hi
				for _, c := range cuts {
					cf, ok := jsNum(c)
					if !ok {
						return nil, bad
					}
					d.Cuts = append(d.Cuts, cf)
				}
			case "cat":
				vals, ok := dm["values"].([]any)
				if !ok {
					return nil, bad
				}
				for _, z := range vals {
					zm, ok := z.(map[string]any)
					if !ok {
						return nil, bad
					}
					k, _ := zm["kind"].(string)
					s, _ := zm["value"].(string)
					d.Values = append(d.Values, WalletOmegaValue{Kind: k, Value: s})
				}
			default:
				return nil, bad
			}
			vs.Dims = append(vs.Dims, d)
		}
		om.Verbs = append(om.Verbs, vs)
	}
	return om, nil
}

// Verb finds the outcome space of a verb.
func (o *WalletOmega) Verb(verb string) *WalletVerb {
	for i := range o.Verbs {
		if o.Verbs[i].Verb == verb {
			return &o.Verbs[i]
		}
	}
	return nil
}

// ---- cells -----------------------------------------------------------------------------------------------------------------

// WalletNumCells splits a numeric dimension at its cuts (a cut outside [lo, hi] is ignored).
func WalletNumCells(d *WalletDim) []WalletCellRange {
	out := []WalletCellRange{}
	cur := d.Lo
	for _, c := range d.Cuts {
		if c < d.Lo || c > d.Hi {
			continue
		}
		if cur <= c-1 {
			out = append(out, WalletCellRange{cur, c - 1})
		}
		out = append(out, WalletCellRange{c, c})
		cur = c + 1
	}
	if cur <= d.Hi {
		out = append(out, WalletCellRange{cur, d.Hi})
	}
	return out
}

// WalletCellCount is the number of cells of a dimension.
func WalletCellCount(d *WalletDim) int {
	if d.Kind == "num" {
		return len(WalletNumCells(d))
	}
	return len(d.Values)
}

// WalletVerbCellCount is the number of cells of a verb (the product over its dimensions).
func WalletVerbCellCount(vs *WalletVerb) int {
	n := 1
	for i := range vs.Dims {
		n *= WalletCellCount(&vs.Dims[i])
	}
	return n
}

// WalletDecodeCell is the mixed-radix decoding of a flat cell index.
func WalletDecodeCell(vs *WalletVerb, flat int) []int {
	idx := make([]int, len(vs.Dims))
	for i := len(vs.Dims) - 1; i >= 0; i-- {
		n := WalletCellCount(&vs.Dims[i])
		idx[i] = flat % n
		flat /= n
	}
	return idx
}

func walletCatCellOf(d *WalletDim, s string) int {
	best, bestLen := -1, -1
	for i, v := range d.Values {
		if v.Kind == "exact" && v.Value == s {
			return i
		}
		if v.Kind == "prefix" && strings.HasPrefix(s, v.Value) && jsLen(v.Value) > bestLen {
			best, bestLen = i, jsLen(v.Value)
		}
	}
	if best >= 0 {
		return best
	}
	for i, v := range d.Values {
		if v.Kind == "other" {
			return i
		}
	}
	return -1
}

func walletCellOfValue(d *WalletDim, x any) int {
	if d.Kind == "num" {
		f, ok := jsNum(x)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return -1
		}
		for i, c := range WalletNumCells(d) {
			if f >= c.Lo && f <= c.Hi {
				return i
			}
		}
		return -1
	}
	s, ok := x.(string)
	if !ok {
		return -1
	}
	return walletCatCellOf(d, s)
}

// WalletCellOf is the cell a concrete outcome falls in (values: path -> value); ok is false outside the space.
func WalletCellOf(vs *WalletVerb, values any) ([]int, bool) {
	m, _ := values.(map[string]any)
	idx := make([]int, 0, len(vs.Dims))
	for i := range vs.Dims {
		var x any
		if m != nil {
			x = m[vs.Dims[i].Path]
		}
		c := walletCellOfValue(&vs.Dims[i], x)
		if c < 0 {
			return nil, false
		}
		idx = append(idx, c)
	}
	return idx, true
}

func walletCatRep(d *WalletDim, i int) string {
	v := d.Values[i]
	if v.Kind == "exact" {
		return v.Value
	}
	base := "other"
	if v.Kind == "prefix" {
		base = v.Value + "x"
	}
	for k := 0; k < 64; k++ {
		s := base
		if k != 0 {
			s += fmt.Sprint(k)
		}
		if walletCatCellOf(d, s) == i {
			return s
		}
	}
	return base
}

func walletNumRep(d *WalletDim, i int) float64 {
	c := WalletNumCells(d)[i]
	if i > 0 {
		return c.Lo
	}
	return c.Hi
}

func walletRepValue(d *WalletDim, i int) any {
	if d.Kind == "num" {
		return jsNumber(walletNumRep(d, i))
	}
	return walletCatRep(d, i)
}

// WalletCellRep is a concrete representative outcome of a cell: {verb, values}.
func WalletCellRep(vs *WalletVerb, idx []int) map[string]any {
	values := map[string]any{}
	for i := range vs.Dims {
		values[vs.Dims[i].Path] = walletRepValue(&vs.Dims[i], idx[i])
	}
	return map[string]any{"verb": vs.Verb, "values": values}
}

// WalletLabelOf is the human label of a path.
func WalletLabelOf(path string) string {
	if path == "action.resource" {
		return "resource"
	}
	parts := strings.Split(path, ".")
	return strings.ReplaceAll(parts[len(parts)-1], "_", " ")
}

// ---- workload and harm -----------------------------------------------------------------------------------------------------

const walletEulerGamma = 0.5772156649015329

func walletHarmonic(n float64) float64 {
	if n <= 0 {
		return 0
	}
	if n <= walletExactSpan {
		s := 0.0
		for k := int(n); k > 0; k-- {
			s += 1 / float64(k)
		}
		return s
	}
	n2 := n * n
	return math.Log(n) + walletEulerGamma + 1/(2*n) - 1/(12*n2) + 1/(120*n2*n2) - 1/(252*n2*n2*n2)
}

func walletLogUniform(d *WalletDim) bool { return d.Dist == "loguniform" && d.Lo >= 0 }

func walletIntervalWeight(d *WalletDim, a, b float64) float64 {
	if b < a {
		return 0
	}
	if !walletLogUniform(d) {
		return b - a + 1
	}
	if b-a+1 <= walletExactSpan {
		s := 0.0
		for x := b; x >= a; x-- {
			s += 1 / (x + 1)
		}
		return s
	}
	return walletHarmonic(b+1) - walletHarmonic(a)
}

func walletFirstMoment(d *WalletDim, a, b float64) float64 {
	if b < a {
		return 0
	}
	if !walletLogUniform(d) {
		return ((a + b) * (b - a + 1)) / 2
	}
	return (b - a + 1) - walletIntervalWeight(d, a, b)
}

func walletIntervalMeanX(d *WalletDim, a, b, cellLo float64) float64 {
	whole := walletIntervalWeight(d, cellLo, b)
	if whole > 0 {
		return walletFirstMoment(d, a, b) / whole
	}
	return 0
}

func walletLinearAmount(d *WalletDim) bool {
	return d.Kind == "num" && (d.Path == "amount" || strings.HasSuffix(d.Path, ".amount"))
}

// WalletHarm is the separable harm model: Verb is h_v, Dim is g_d at a concrete value (a float64 or a string), DimMean the
// optional closed-form mean of g_d over an interval of cells.
type WalletHarm struct {
	Verb    func(vs *WalletVerb) float64
	Dim     func(d *WalletDim, x any) float64
	DimMean func(d *WalletDim, lo, hi float64) float64
}

// WalletDefaultHarm is the reference's default harm model.
var WalletDefaultHarm = &WalletHarm{
	Verb: func(vs *WalletVerb) float64 {
		switch vs.Reversibility {
		case "irreversible":
			return 10
		case "rate_limited":
			return 3
		}
		return 1
	},
	Dim: func(d *WalletDim, x any) float64 {
		if f, ok := x.(float64); ok && walletLinearAmount(d) {
			return 1 + math.Max(0, f)/100
		}
		return 1
	},
	DimMean: func(d *WalletDim, lo, hi float64) float64 {
		if walletLinearAmount(d) {
			return 1 + math.Max(0, walletIntervalMeanX(d, math.Max(lo, 0), hi, lo))/100
		}
		return 1
	},
}

func walletPointWeight(d *WalletDim, x float64) float64 {
	if walletLogUniform(d) {
		return 1 / (x + 1)
	}
	return 1
}

func walletIntervalHarm(d *WalletDim, a, b float64, h *WalletHarm) float64 {
	if h.DimMean != nil {
		return h.DimMean(d, a, b)
	}
	n := b - a + 1
	wTot := walletIntervalWeight(d, a, b)
	if !(wTot > 0) {
		return h.Dim(d, a)
	}
	if n <= walletExactSpan {
		s := 0.0
		for x := a; x <= b; x++ {
			s += walletPointWeight(d, x) * h.Dim(d, x)
		}
		return s / wTot
	}
	s := 0.0
	for i := 0; i < 1024; i++ {
		pa := a + math.Floor(float64(i)*n/1024)
		pb := a + math.Floor(float64(i+1)*n/1024) - 1
		if pb < pa {
			continue
		}
		s += walletIntervalWeight(d, pa, pb) * h.Dim(d, math.Floor((pa+pb)/2+0.5))
	}
	return s / wTot
}

// WalletDimCellStats is the exact mass and mean harm of one cell of one dimension.
func WalletDimCellStats(d *WalletDim, i int, h *WalletHarm) (mass, harm float64) {
	if d.Kind == "cat" {
		return 1 / float64(len(d.Values)), h.Dim(d, walletCatRep(d, i))
	}
	c := WalletNumCells(d)[i]
	wm := walletIntervalWeight(d, c.Lo, c.Hi)
	total := walletIntervalWeight(d, d.Lo, d.Hi)
	if wm > 0 {
		return wm / total, walletIntervalHarm(d, c.Lo, c.Hi, h)
	}
	return wm / total, h.Dim(d, c.Lo)
}

// WalletCellStats is mu(cell) and E[h | cell] for a whole cell (product measure, separable harm); h nil = the default.
func WalletCellStats(vs *WalletVerb, idx []int, h *WalletHarm) (mass, harm float64) {
	if h == nil {
		h = WalletDefaultHarm
	}
	mass = vs.Weight
	harm = h.Verb(vs)
	for k := range vs.Dims {
		m, hh := WalletDimCellStats(&vs.Dims[k], idx[k], h)
		mass *= m
		harm *= hh
	}
	return mass, harm
}

// ---- exact Clopper-Pearson upper bound -------------------------------------------------------------------------------------

const (
	cpGridBits = 52
	cpA        = int64(1) << cpGridBits
	cpTol      = int64(1) << (cpGridBits - 44)
)

func cpLogFactorials(n int) []float64 {
	lf := make([]float64, n+1)
	for i := 1; i <= n; i++ {
		lf[i] = lf[i-1] + math.Log(float64(i))
	}
	return lf
}

func cpBinomialCdf(k, n int, p float64, lf []float64) float64 {
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
	lp := math.Log(p)
	lq := math.Log1p(-p)
	s := 0.0
	for i := 0; i <= k; i++ {
		s += math.Exp(lf[n] - lf[i] - lf[n-i] + float64(i)*lp + float64(n-i)*lq)
	}
	return math.Min(1, s)
}

func cpCdfRecNumerator(n, k int, a int64) *big.Int {
	A := big.NewInt(cpA)
	ab := big.NewInt(a)
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

func cpExceeds(n, k int, a int64, num *big.Int, exp uint) bool {
	lhs := new(big.Int).Lsh(cpCdfRecNumerator(n, k, a), exp)
	rhs := new(big.Int).Mul(num, new(big.Int).Exp(big.NewInt(cpA), big.NewInt(int64(n)), nil))
	return lhs.Cmp(rhs) > 0
}

func cpFloatGuess(k, n int, alpha float64) float64 {
	lf := cpLogFactorials(n)
	lo := float64(k) / float64(n)
	hi := 1.0
	for it := 0; it < 200 && hi-lo > 1e-13; it++ {
		mid := (lo + hi) / 2
		if cpBinomialCdf(k, n, mid, lf) > alpha {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi
}

func cpClamp(a int64) int64 {
	if a < 0 {
		return 0
	}
	if a > cpA {
		return cpA
	}
	return a
}

func cpCertifyBracket(start int64, exceeds func(int64) bool) (int64, error) {
	hi := start
	step := cpTol
	for exceeds(hi) {
		hi = cpClamp(hi + step)
		step *= 2
	}
	lo := cpClamp(hi - cpTol)
	step = cpTol
	for lo > 0 && !exceeds(lo) {
		hi = lo
		lo = cpClamp(lo - step)
		step *= 2
	}
	if lo == 0 && !exceeds(0) {
		return 0, errors.New("clopperPearsonUpper: unreachable (cdfRec(0) = 1)")
	}
	for hi-lo > cpTol {
		mid := (lo + hi) / 2
		if exceeds(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi, nil
}

// ClopperPearsonUpper is the one-sided Clopper-Pearson upper bound after k successes in n, rounded outward on the 2^-52 grid
// (exact integer arithmetic).
func ClopperPearsonUpper(kf, nf, alpha float64) (float64, error) {
	if !(kf == math.Trunc(kf) && nf == math.Trunc(nf) && kf >= 0 && nf >= 0 && kf <= nf && nf < 1e6) {
		return 0, errors.New("clopperPearsonUpper: need integers 0 <= k <= n")
	}
	k, n := int(kf), int(nf)
	if !(alpha > 0 && alpha < 1) {
		return 0, errors.New("clopperPearsonUpper: alpha must be in (0, 1)")
	}
	if n == 0 || k == n {
		return 1, nil
	}
	rat := new(big.Rat).SetFloat64(alpha)
	num := new(big.Int).Set(rat.Num())
	exp := uint(rat.Denom().BitLen() - 1)
	start := cpClamp(int64(math.Ceil(cpFloatGuess(k, n, alpha)*float64(cpA))) + cpTol)
	hi, err := cpCertifyBracket(start, func(a int64) bool { return cpExceeds(n, k, a, num, exp) })
	if err != nil {
		return 0, err
	}
	return float64(hi) / float64(cpA), nil
}
