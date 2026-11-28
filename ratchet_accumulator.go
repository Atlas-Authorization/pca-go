package pca

// The homomorphic risk accumulator with a zero-knowledge spend ceiling (Pedersen commitments on ristretto255 plus a 32-bit
// bit-decomposition range proof), wire format of the reference included: proofs are JSON objects with camelCase members, a
// blinding is a *big.Int. Verifiers never fail open: malformed input is false.

import (
	"errors"
	"math"
	"math/big"

	ed "filippo.io/edwards25519"
)

// RatchetNBits is the range-proof width; RatchetMaxProvableCeiling = 2^RatchetNBits - 1.
const RatchetNBits = 32

var RatchetMaxProvableCeiling = big.NewInt(1<<RatchetNBits - 1)

func accErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// ratchetUnits reads a risk / budget: a non-negative *big.Int or a non-negative integral JSON number.
func ratchetUnits(x any) (*big.Int, error) {
	if b, ok := x.(*big.Int); ok {
		if b.Sign() < 0 {
			return nil, accErr("invalid_value", "risk/budget must be >= 0")
		}
		return new(big.Int).Set(b), nil
	}
	if _, isBool := x.(bool); !isBool {
		if f, ok := jsNum(x); ok && !math.IsInf(f, 0) && f == math.Floor(f) && f >= 0 {
			n, _ := new(big.Float).SetFloat64(f).Int(nil)
			return n, nil
		}
	}
	return nil, accErr("invalid_value", "risk/budget must be a non-negative integer")
}

func pedersen(v, b rScalar) rPoint { return rAdd(rScalarMul(rG, v), rScalarMul(rH, b)) }

// RiskCommitment is a commitment with its (secret) blinding.
type RiskCommitment struct {
	Commitment string   `json:"commitment"`
	Blinding   *big.Int `json:"blinding"`
}

// CommitRisk commits to a non-negative integer risk in units with blinding (nil = fresh random).
func CommitRisk(risk any, blinding *big.Int) (*RiskCommitment, error) {
	v, err := ratchetUnits(risk)
	if err != nil {
		return nil, err
	}
	b := rRandScalar()
	if blinding != nil {
		b = rScalarOfBig(blinding)
	}
	return &RiskCommitment{Commitment: rEncodePoint(pedersen(rScalarOfBig(v), b)), Blinding: rBigOfScalar(b)}, nil
}

// AddCommitments is the homomorphic sum; an empty input commits to (0, 0), the identity.
func AddCommitments(commitments []any) (string, error) {
	acc := rZero
	for _, c := range commitments {
		p, err := rDecodePoint(c)
		if err != nil {
			return "", err
		}
		acc = rAdd(acc, p)
	}
	return rEncodePoint(acc), nil
}

// OpenCommitment checks commitment == risk*G + blinding*H; malformed input is false.
func OpenCommitment(commitment any, risk any, blinding *big.Int) bool {
	v, err := ratchetUnits(risk)
	if err != nil || blinding == nil {
		return false
	}
	c, err := rDecodePoint(commitment)
	return err == nil && rEquals(c, pedersen(rScalarOfBig(v), rScalarOfBig(blinding)))
}

var (
	accCtxDomain     = []byte("atlas-pca-ratchet/budget/ctx/v1")
	accRiskCtxDomain = []byte("atlas-pca-ratchet/risk-range/ctx/v1")
	accOrDomain      = []byte("atlas-pca-ratchet/budget/bit-or/v1")
	accAggDomain     = []byte("atlas-pca-ratchet/budget/agg/v1")
)

// a ceiling above the range is clamped: "sum <= 2^N-1" is strictly stronger, so a verifier is never weakened
func accCeiling(b *big.Int) *big.Int {
	if b.Cmp(RatchetMaxProvableCeiling) > 0 {
		return new(big.Int).Set(RatchetMaxProvableCeiling)
	}
	return b
}

type accCtx func(bits []rPoint) []byte

func accBudgetCtx(ceiling *big.Int, sum rPoint) accCtx {
	return func(bits []rPoint) []byte {
		parts := [][]byte{accCtxDomain, {RatchetNBits}, rScalarOfBig(ceiling).Bytes(), rEncode(sum)}
		for _, b := range bits {
			parts = append(parts, rEncode(b))
		}
		return rHashToScalar(parts...).Bytes()
	}
}

func accRiskCtx(c rPoint) accCtx {
	return func(bits []rPoint) []byte {
		parts := [][]byte{accRiskCtxDomain, {RatchetNBits}, rEncode(c)}
		for _, b := range bits {
			parts = append(parts, rEncode(b))
		}
		return rHashToScalar(parts...).Bytes()
	}
}

func accProveBit(ctx []byte, index int, bPt rPoint, bit uint, s rScalar) map[string]any {
	p0, p1 := bPt, rSub(bPt, rG)
	eFake, zFake := rRandScalar(), rRandScalar()
	pFake := p1
	if bit == 1 {
		pFake = p0
	}
	aFake := rSub(rScalarMul(rH, zFake), rScalarMul(pFake, eFake))
	k := rRandScalar()
	aReal := rScalarMul(rH, k)
	a0, a1 := aFake, aReal
	if bit == 0 {
		a0, a1 = aReal, aFake
	}
	e := rHashToScalar(accOrDomain, ctx, []byte{byte(index)}, rEncode(a0), rEncode(a1))
	eReal := new(ed.Scalar).Subtract(e, eFake)
	zReal := new(ed.Scalar).MultiplyAdd(eReal, s, k)
	e0, e1, z0, z1 := eFake, eReal, zFake, zReal
	if bit == 0 {
		e0, e1, z0, z1 = eReal, eFake, zReal, zFake
	}
	return map[string]any{"e0": rEncodeScalar(e0), "e1": rEncodeScalar(e1), "z0": rEncodeScalar(z0), "z1": rEncodeScalar(z1)}
}

func accVerifyBit(ctx []byte, index int, bPt rPoint, proof any) bool {
	m, ok := proof.(map[string]any)
	if !ok {
		return false
	}
	var sc [4]rScalar
	for i, k := range []string{"e0", "e1", "z0", "z1"} {
		v, err := rDecodeScalar(m[k])
		if err != nil {
			return false
		}
		sc[i] = v
	}
	a0 := rSub(rScalarMul(rH, sc[2]), rScalarMul(bPt, sc[0]))
	a1 := rSub(rScalarMul(rH, sc[3]), rScalarMul(rSub(bPt, rG), sc[1]))
	e := rHashToScalar(accOrDomain, ctx, []byte{byte(index)}, rEncode(a0), rEncode(a1))
	return new(ed.Scalar).Add(sc[0], sc[1]).Equal(e) == 1
}

func accVerifySchnorr(ctx []byte, d rPoint, proof any) bool {
	m, ok := proof.(map[string]any)
	if !ok {
		return false
	}
	a, err := rDecodePoint(m["a"])
	if err != nil {
		return false
	}
	z, err := rDecodeScalar(m["z"])
	if err != nil {
		return false
	}
	e := rHashToScalar(accAggDomain, ctx, rEncode(d), rEncode(a))
	return rEquals(rScalarMul(rH, z), rAdd(a, rScalarMul(d, e)))
}

func accRangeProve(makeCtx accCtx, vPt rPoint, value *big.Int, gamma rScalar) map[string]any {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), RatchetNBits), big.NewInt(1))
	vm := new(big.Int).And(value, mask) // the low N bits (big.Int And is two's complement for a negative slack)
	bitPts := make([]rPoint, RatchetNBits)
	blinds := make([]rScalar, RatchetNBits)
	for i := 0; i < RatchetNBits; i++ {
		blinds[i] = rRandScalar()
		bitPts[i] = pedersen(rScalarOfU64(uint64(vm.Bit(i))), blinds[i])
	}
	ctx := makeCtx(bitPts)
	or := make([]any, RatchetNBits)
	sStar := ed.NewScalar()
	agg := rZero
	for i := 0; i < RatchetNBits; i++ {
		or[i] = accProveBit(ctx, i, bitPts[i], vm.Bit(i), blinds[i])
		sStar = new(ed.Scalar).MultiplyAdd(rPow2[i], blinds[i], sStar)
		agg = rAdd(agg, rScalarMul(bitPts[i], rPow2[i]))
	}
	d := rSub(agg, vPt)
	k := rRandScalar()
	a := rScalarMul(rH, k)
	e := rHashToScalar(accAggDomain, ctx, rEncode(d), rEncode(a))
	z := new(ed.Scalar).MultiplyAdd(e, new(ed.Scalar).Subtract(sStar, gamma), k)
	bc := make([]any, RatchetNBits)
	for i, p := range bitPts {
		bc[i] = rEncodePoint(p)
	}
	return map[string]any{"n": RatchetNBits, "bitCommitments": bc, "or": or, "agg": map[string]any{"a": rEncodePoint(a), "z": rEncodeScalar(z)}}
}

func accRangeVerify(makeCtx accCtx, vPt rPoint, proof any) bool {
	m, ok := proof.(map[string]any)
	if !ok {
		return false
	}
	if _, isBool := m["n"].(bool); isBool {
		return false
	}
	if n, ok := jsNum(m["n"]); !ok || n != RatchetNBits {
		return false
	}
	bc, ok1 := m["bitCommitments"].([]any)
	or, ok2 := m["or"].([]any)
	if !ok1 || !ok2 || len(bc) != RatchetNBits || len(or) != RatchetNBits {
		return false
	}
	if _, ok := m["agg"].(map[string]any); !ok {
		return false
	}
	b := make([]rPoint, RatchetNBits)
	for i, x := range bc {
		p, err := rDecodePoint(x)
		if err != nil {
			return false
		}
		b[i] = p
	}
	ctx := makeCtx(b)
	for i := 0; i < RatchetNBits; i++ {
		if !accVerifyBit(ctx, i, b[i], or[i]) {
			return false
		}
	}
	agg := rZero
	for i := 0; i < RatchetNBits; i++ {
		agg = rAdd(agg, rScalarMul(b[i], rPow2[i]))
	}
	return accVerifySchnorr(ctx, rSub(agg, vPt), m["agg"])
}

// ProveBudget proves sum(risks) <= bMax over the committed values (an over-budget input yields a well-formed proof the verifier
// rejects).
func ProveBudget(risks []any, blindings []*big.Int, bMax any) (map[string]any, error) {
	if len(risks) != len(blindings) {
		return nil, accErr("length_mismatch", "risks and blindings must have equal length")
	}
	bm, err := ratchetUnits(bMax)
	if err != nil {
		return nil, err
	}
	ceiling := accCeiling(bm)
	sumRisk, sumBlind := big.NewInt(0), ed.NewScalar()
	for i, r := range risks {
		v, err := ratchetUnits(r)
		if err != nil {
			return nil, err
		}
		if blindings[i] == nil {
			return nil, errors.New("blinding must be a bigint")
		}
		sumRisk.Add(sumRisk, v)
		sumBlind = new(ed.Scalar).Add(sumBlind, rScalarOfBig(blindings[i]))
	}
	cSum := pedersen(rScalarOfBig(sumRisk), sumBlind)
	vPt := rSub(rScalarMul(rG, rScalarOfBig(ceiling)), cSum)
	slack := new(big.Int).Sub(ceiling, sumRisk)
	return accRangeProve(accBudgetCtx(ceiling, cSum), vPt, slack, new(ed.Scalar).Negate(sumBlind)), nil
}

// VerifyBudget checks a budget proof for a commitment sum and a ceiling (ceilings above 2^32-1 are clamped). Never fails open.
func VerifyBudget(commitmentSum any, bMax any, proof any) bool {
	bm, err := ratchetUnits(bMax)
	if err != nil {
		return false
	}
	ceiling := accCeiling(bm)
	c, err := rDecodePoint(commitmentSum)
	if err != nil {
		return false
	}
	return accRangeVerify(accBudgetCtx(ceiling, c), rSub(rScalarMul(rG, rScalarOfBig(ceiling)), c), proof)
}

// ProveRiskRange proves that CommitRisk(risk, blinding) holds a value in [0, 2^32).
func ProveRiskRange(risk any, blinding *big.Int) (map[string]any, error) {
	v, err := ratchetUnits(risk)
	if err != nil {
		return nil, err
	}
	if blinding == nil {
		return nil, errors.New("blinding must be a bigint")
	}
	b := rScalarOfBig(blinding)
	c := pedersen(rScalarOfBig(v), b)
	return accRangeProve(accRiskCtx(c), c, v, b), nil
}

// VerifyRiskRange checks a range proof for a commitment. Never fails open.
func VerifyRiskRange(commitment any, proof any) bool {
	c, err := rDecodePoint(commitment)
	return err == nil && accRangeVerify(accRiskCtx(c), c, proof)
}

// VerifyBoundedBudget: every commitment carries a valid range proof and the budget proof verifies for their sum.
func VerifyBoundedBudget(commitments any, rangeProofs any, bMax any, budgetProof any) bool {
	cs, ok1 := commitments.([]any)
	rs, ok2 := rangeProofs.([]any)
	if !ok1 || !ok2 || len(cs) != len(rs) {
		return false
	}
	for i := range cs {
		if !VerifyRiskRange(cs[i], rs[i]) {
			return false
		}
	}
	sum, err := AddCommitments(cs)
	return err == nil && VerifyBudget(sum, bMax, budgetProof)
}
