package blstkit

import (
	"crypto/rand"
	"errors"
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
)

// FAME (Agrawal and Chase, CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the asymmetric (type-3) pairing, adaptively
// secure in the random-oracle model, for monotone span programs with an injective row labelling. Group work is blst; GT work
// (parse, multiply, exponentiate, multi-pairing) is the cgo shim over blst's public API. This file is only the scheme's
// arithmetic; the wire format and AEAD are in abe.go. Scalar arithmetic is math/big (not constant time).

const abeAttrDST = "ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1"

var abeG1 = blst.P1Generator()

type (
	abeG1x3 [3]*blst.P1
	abeG2x3 [3]*blst.P2
)

type fameMpk struct {
	h1, h2 *blst.P2 // h^a1, h^a2
	t1, t2 []byte   // GT: e(g,h)^(d1*a1+d3), e(g,h)^(d2*a2+d3)
}

type fameMsk struct {
	a, b [2]*big.Int
	g    abeG1x3 // g^d1, g^d2, g^d3
}

type fameKey struct {
	k0    abeG2x3
	kp    abeG1x3
	attrs map[string]abeG1x3
}

type fameCt struct {
	ct0  abeG2x3
	rows []abeG1x3
}

func abeRandomScalar() (*big.Int, error) {
	for {
		b := make([]byte, 48)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if v := fr(new(big.Int).SetBytes(b)); v.Sign() != 0 {
			return v, nil
		}
	}
}

// abeHashToG1 is the RFC 9380 hash-to-curve of msg into G1 under the package's tag (a random oracle).
func abeHashToG1(msg []byte) (*blst.P1, error) {
	a := new(blst.P1Affine).Uncompress(blst.HashToG1(msg, []byte(abeAttrDST)).Compress())
	if a == nil {
		return nil, errors.New("abe: hash to curve failed")
	}
	return g1FromAffine(a), nil
}

func u32(n int) []byte { return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)} }

// hAttr is H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t.
func hAttr(attr string, l, t int) (*blst.P1, error) {
	msg := append([]byte{1}, u32(len(attr))...)
	msg = append(append(msg, attr...), byte(l), byte(t))
	return abeHashToG1(msg)
}

// hCol is H0(j, l, t): the column-indexed oracle (kind byte 2).
func hCol(j, l, t int) (*blst.P1, error) {
	return abeHashToG1(append(append([]byte{2}, u32(j)...), byte(l), byte(t)))
}

func g1MulK(p *blst.P1, k *big.Int) *blst.P1 { return g1Mul(p, k) } // zero scalar gives the identity
func g2MulK(p *blst.P2, k *big.Int) *blst.P2 { return g2Mul(p, k) }

func gtOfGenerators() ([]byte, bool) {
	return gtPairing([][]byte{g1Bytes(abeG1)}, [][]byte{g2Bytes(bbsBP2)})
}

func scalarBE(k *big.Int) []byte { return fr(k).FillBytes(make([]byte, 32)) }

func fameSetup(a, b [2]*big.Int, d [3]*big.Int) (*fameMpk, *fameMsk, error) {
	egh, ok := gtOfGenerators()
	if !ok {
		return nil, nil, errors.New("abe: pairing failed")
	}
	t1, ok1 := gtPow(egh, scalarBE(frAdd(frMul(d[0], a[0]), d[2])))
	t2, ok2 := gtPow(egh, scalarBE(frAdd(frMul(d[1], a[1]), d[2])))
	if !ok1 || !ok2 {
		return nil, nil, errors.New("abe: GT exponentiation failed")
	}
	mpk := &fameMpk{h1: g2Mul(bbsBP2, a[0]), h2: g2Mul(bbsBP2, a[1]), t1: t1, t2: t2}
	msk := &fameMsk{a: a, b: b, g: abeG1x3{g1Mul(abeG1, d[0]), g1Mul(abeG1, d[1]), g1Mul(abeG1, d[2])}}
	return mpk, msk, nil
}

// keyTerm is (sum_l oracle(l)^pow[l] + g^sigma)^aInv.
func keyTerm(oracle func(l int) (*blst.P1, error), pow [3]*big.Int, sigma, aInv *big.Int) (*blst.P1, error) {
	sum := g1Mul(abeG1, sigma)
	for l := 0; l < 3; l++ {
		h, err := oracle(l)
		if err != nil {
			return nil, err
		}
		sum = g1Add(sum, g1MulK(h, pow[l]))
	}
	return g1Mul(sum, aInv), nil
}

func fameKeygen(msk *fameMsk, attrs []string, r [2]*big.Int, sigmas []*big.Int, sigmaPrime *big.Int) (*fameKey, error) {
	pow := [3]*big.Int{frMul(msk.b[0], r[0]), frMul(msk.b[1], r[1]), frAdd(r[0], r[1])}
	a0, err := frInv(msk.a[0])
	if err != nil {
		return nil, err
	}
	a1, err := frInv(msk.a[1])
	if err != nil {
		return nil, err
	}
	aInv := [2]*big.Int{a0, a1}
	key := &fameKey{attrs: map[string]abeG1x3{}}
	for l := 0; l < 3; l++ {
		key.k0[l] = g2Mul(bbsBP2, pow[l])
	}
	for i, y := range attrs {
		if i >= len(sigmas) {
			return nil, errors.New("fameKeygen: one sigma per attribute is required")
		}
		var comp abeG1x3
		for t := 0; t < 2; t++ {
			tt := t
			if comp[t], err = keyTerm(func(l int) (*blst.P1, error) { return hAttr(y, l, tt) }, pow, sigmas[i], aInv[t]); err != nil {
				return nil, err
			}
		}
		comp[2] = g1Mul(abeG1, frSub(new(big.Int), sigmas[i]))
		key.attrs[y] = comp
	}
	for t := 0; t < 2; t++ {
		tt := t
		k, err := keyTerm(func(l int) (*blst.P1, error) { return hCol(0, l, tt) }, pow, sigmaPrime, aInv[t])
		if err != nil {
			return nil, err
		}
		key.kp[t] = g1Add(k, msk.g[t])
	}
	key.kp[2] = g1Add(g1Mul(abeG1, frSub(new(big.Int), sigmaPrime)), msk.g[2])
	return key, nil
}

// ---- span program from the threshold tree -----------------------------------------------------------------------------

type mspRow struct {
	attr string
	vec  map[int]*big.Int // column -> coefficient; column 0 is the secret column and is always 1
}

// buildRows lists the leaves in depth-first order with their span-program rows (Shamir down the tree).
func buildRows(tree *abeTree) []mspRow {
	var rows []mspRow
	ncols := 1
	var walk func(n *abeTree, vec map[int]*big.Int)
	walk = func(n *abeTree, vec map[int]*big.Int) {
		if n.leaf {
			rows = append(rows, mspRow{n.attr, vec})
			return
		}
		base := ncols
		ncols += n.t - 1
		for idx, child := range n.of {
			cv := make(map[int]*big.Int, len(vec)+n.t)
			for k, v := range vec {
				cv[k] = v
			}
			x := big.NewInt(int64(idx + 1))
			pw := big.NewInt(1)
			for k := 1; k < n.t; k++ {
				pw = frMul(pw, x)
				cv[base+k-1] = pw
			}
			walk(child, cv)
		}
	}
	walk(tree, map[int]*big.Int{0: big.NewInt(1)})
	return rows
}

func fameEncrypt(mpk *fameMpk, tree *abeTree, s [2]*big.Int) (*fameCt, []byte, error) {
	rows := buildRows(tree)
	colMemo := map[[2]int]*blst.P1{}
	colTerm := func(j, l int) (*blst.P1, error) {
		if v, ok := colMemo[[2]int{j, l}]; ok {
			return v, nil
		}
		h0, err := hCol(j, l, 0)
		if err != nil {
			return nil, err
		}
		h1, err := hCol(j, l, 1)
		if err != nil {
			return nil, err
		}
		v := g1Add(g1Mul(h0, s[0]), g1Mul(h1, s[1]))
		colMemo[[2]int{j, l}] = v
		return v, nil
	}
	ct := &fameCt{}
	for _, row := range rows {
		var out abeG1x3
		for l := 0; l < 3; l++ {
			h0, err := hAttr(row.attr, l, 0)
			if err != nil {
				return nil, nil, err
			}
			h1, err := hAttr(row.attr, l, 1)
			if err != nil {
				return nil, nil, err
			}
			acc := g1Add(g1Mul(h0, s[0]), g1Mul(h1, s[1]))
			for j, m := range row.vec {
				c, err := colTerm(j, l)
				if err != nil {
					return nil, nil, err
				}
				acc = g1Add(acc, g1Mul(c, m))
			}
			out[l] = acc
		}
		ct.rows = append(ct.rows, out)
	}
	ct.ct0 = abeG2x3{g2Mul(mpk.h1, s[0]), g2Mul(mpk.h2, s[1]), g2Mul(bbsBP2, frAdd(s[0], s[1]))}
	p1, ok1 := gtPow(mpk.t1, scalarBE(s[0]))
	p2, ok2 := gtPow(mpk.t2, scalarBE(s[1]))
	if !ok1 || !ok2 {
		return nil, nil, errors.New("abe: GT exponentiation failed")
	}
	k, ok := gtMul(p1, p2)
	if !ok {
		return nil, nil, errors.New("abe: GT multiplication failed")
	}
	return ct, k, nil
}

// ---- decrypt ----------------------------------------------------------------------------------------------------------

type fplan struct {
	row int // leaf row index
	of  []fplanChild
	gt  bool
}

type fplanChild struct {
	x   *big.Int
	sub *fplan
}

// lagrangeAtZero: L_i(0) = prod_{j!=i} x_j / (x_j - x_i). Nil on an empty set, a zero point or points that coincide mod r.
func lagrangeAtZero(xs []*big.Int) []*big.Int {
	if len(xs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, x := range xs {
		xr := fr(x)
		if xr.Sign() == 0 || seen[xr.String()] {
			return nil
		}
		seen[xr.String()] = true
	}
	out := make([]*big.Int, len(xs))
	for i := range xs {
		num, den := big.NewInt(1), big.NewInt(1)
		for j := range xs {
			if j != i {
				num = frMul(num, xs[j])
				den = frMul(den, frSub(xs[j], xs[i]))
			}
		}
		inv, err := frInv(den)
		if err != nil {
			return nil
		}
		out[i] = frMul(num, inv)
	}
	return out
}

// planFor chooses, bottom-up, the first t satisfiable children of every gate; nil when has does not satisfy the subtree.
func planFor(n *abeTree, has func(string) bool, offset int) *fplan {
	if n.leaf {
		if has(n.attr) {
			return &fplan{row: offset}
		}
		return nil
	}
	p := &fplan{gt: true}
	off := offset
	for i, child := range n.of {
		if sub := planFor(child, has, off); sub != nil {
			p.of = append(p.of, fplanChild{big.NewInt(int64(i + 1)), sub})
		}
		if len(p.of) >= n.t {
			break
		}
		off += child.leafCount()
	}
	if len(p.of) < n.t {
		return nil
	}
	return p
}

func planWeights(p *fplan, w *big.Int, out map[int]*big.Int) bool {
	if !p.gt {
		out[p.row] = w
		return true
	}
	xs := make([]*big.Int, len(p.of))
	for i, c := range p.of {
		xs[i] = c.x
	}
	lam := lagrangeAtZero(xs)
	if lam == nil {
		return false
	}
	for i, c := range p.of {
		if !planWeights(c.sub, frMul(w, lam[i]), out) {
			return false
		}
	}
	return true
}

// fameDecrypt recovers the KEM key (GT bytes), or false when the key does not satisfy the tree or a point is degenerate.
func fameDecrypt(key *fameKey, tree *abeTree, ct *fameCt) ([]byte, bool) {
	var rows []string
	tree.leafAttrs(&rows)
	if len(rows) != len(ct.rows) {
		return nil, false
	}
	p := planFor(tree, func(a string) bool { _, ok := key.attrs[a]; return ok }, 0)
	if p == nil {
		return nil, false
	}
	w := map[int]*big.Int{}
	if !planWeights(p, big.NewInt(1), w) {
		return nil, false
	}
	var g1s, g2s [][]byte
	for l := 0; l < 3; l++ {
		ctProd := new(blst.P1)
		keyProd := key.kp[l]
		for i, wi := range w {
			comp, ok := key.attrs[rows[i]]
			if !ok {
				return nil, false
			}
			ctProd = g1Add(ctProd, g1Mul(ct.rows[i][l], wi))
			keyProd = g1Add(keyProd, g1Mul(comp[l], wi))
		}
		g1s = append(g1s, g1Bytes(keyProd), g1Bytes(g1Neg(ctProd)))
		g2s = append(g2s, g2Bytes(ct.ct0[l]), g2Bytes(key.k0[l]))
	}
	return gtPairing(g1s, g2s)
}
