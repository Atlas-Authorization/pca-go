package pca

// Public forms of the remaining pca-mpc primitives: batched trusted-dealer triples, the curve field reduction and extended-point
// check, per-party local policy evaluation, and PEM reading.

import (
	"math/big"
	"os"
)

// MpcSSEC is the KOS statistical security parameter (the number of extra random check rows).
const MpcSSEC = MpcOtSsec

// MpcGenTriples is trusted-dealer preprocessing: count correct multiplication triples for n parties.
func MpcGenTriples(count, n int, rng MpcFieldSource) ([]*MpcTriple, error) {
	out := make([]*MpcTriple, 0, count)
	for i := 0; i < count; i++ {
		t, err := MpcGenTriple(n, rng)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// MpcModFq is the canonical representative of x in [0, q) for the curve field q = 2^255 - 19.
func MpcModFq(x *big.Int) *big.Int { return new(big.Int).Mod(x, mpcEcQ) }

// mpcEcD is the Edwards curve constant d = -121665 / 121666 mod q.
var mpcEcD = func() *big.Int {
	inv := new(big.Int).ModInverse(big.NewInt(121666), mpcEcQ)
	return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Neg(big.NewInt(121665)), inv), mpcEcQ)
}()

// MpcEcIsOnCurve reports whether the extended coordinates (x = X/Z, y = Y/Z, T = XY/Z) describe a point of the curve
// -x^2 + y^2 = 1 + d x^2 y^2: Z is not 0, T Z = X Y, and (Y^2 - X^2) Z^2 = Z^4 + d X^2 Y^2, all mod q. An off-curve or malformed
// point fails here before any scalar work. (A *ed.Point can only be on the curve; this is for raw coordinates off the wire.)
func MpcEcIsOnCurve(X, Y, Z, T *big.Int) bool {
	if X == nil || Y == nil || Z == nil || T == nil {
		return false
	}
	m := MpcModFq
	mul := func(a, b *big.Int) *big.Int { return m(new(big.Int).Mul(a, b)) }
	if m(Z).Sign() == 0 {
		return false
	}
	if mul(T, Z).Cmp(mul(X, Y)) != 0 {
		return false
	}
	x2, y2, z2 := mul(X, X), mul(Y, Y), mul(Z, Z)
	lhs := mul(new(big.Int).Sub(y2, x2), z2)
	rhs := m(new(big.Int).Add(mul(z2, z2), mul(mul(mpcEcD, x2), y2)))
	return lhs.Cmp(rhs) == 0
}

// MpcPartyPolicy is a stakeholder and its PRIVATE Policy-VM input (never shared with other parties).
type MpcPartyPolicy struct {
	// ID is a human-readable label (user, org, regulator).
	ID string
	// DecideInput is the party's own decision input: its envelope, risk inputs and budget.
	DecideInput map[string]any
}

// MpcEvaluateParty runs a party's own policy through the Policy VM and distills the small decision vector it contributes to the
// MPC: allow (releaseGuardianShare), t (the demanded proof strength) and the quantized risk. A Q of 0 means MpcDefaultQ. It never
// panics; a result the VM did not fill in is the worst case (deny, t 3, risk Q).
func MpcEvaluateParty(policy MpcPartyPolicy, Q int) MpcDecisionVector {
	if Q <= 0 {
		Q = MpcDefaultQ
	}
	d := DecideNative(policy.DecideInput, nil)
	v := MpcDecisionVector{Allow: 0, T: 3, RQuant: Q}
	if b, ok := d["releaseGuardianShare"].(bool); ok && b {
		v.Allow = 1
	}
	if rt, ok := d["requiredThreshold"].(map[string]any); ok {
		if t, ok := jsNum(rt["t"]); ok && t >= 1 && t <= 3 {
			v.T = int(t)
		}
	}
	if r, ok := jsNum(d["r"]); ok {
		v.RQuant = MpcQuantizeR(r, Q)
	}
	return v
}

// MpcReadPem reads a PEM file as text.
func MpcReadPem(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
