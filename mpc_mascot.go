package pca

// The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real oblivious
// transfers (Gilboa multiplication over OT extension), the MAC key is distributed and never reconstructed, and every produced
// triple is certified by the sacrifice check. When a check fails the OT transcripts are searched to blame the cheating party.

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// MpcOfflineCheatingAbort is a MAC-check abort raised by the offline phase, naming the parties the OT transcripts convict.
type MpcOfflineCheatingAbort struct {
	*MpcMacCheckAbort
	Blamed []int
}

func (e *MpcOfflineCheatingAbort) Unwrap() error { return e.MpcMacCheckAbort }

func newMpcOfflineCheatingAbort(msg string, blamed []int) *MpcOfflineCheatingAbort {
	if len(blamed) > 0 {
		names := make([]string, len(blamed))
		for i, b := range blamed {
			names[i] = fmt.Sprint(b)
		}
		msg += "; offline OT transcript names party " + strings.Join(names, ", ")
	}
	return &MpcOfflineCheatingAbort{&MpcMacCheckAbort{msg}, blamed}
}

// MpcOfflineDeviation is TEST-ONLY: the ProductMul-th product's claimed share is shifted by Delta (a party lying about a product).
type MpcOfflineDeviation struct {
	ProductMul int
	Delta      *big.Int
}

// MpcNoDealerOptions are the offline options; nil fields mean the defaults.
type MpcNoDealerOptions struct {
	Sacrifice         *bool
	SacrificePartners *int
	MacKeys           *int
	Deviation         *MpcOfflineDeviation
	StatSec           *int
	UnsafeStatSec     bool
}

type mpcOtRecord struct {
	sender       int
	msg0, msg1   []*big.Int
	received     []*big.Int
	receiverSide int
}

type mpcProductClaim struct{ claimed, implied []*big.Int }

// mpcOperand is one party's operand of a multiplication: an encoded (value, choice bits) share, or a plain value.
type mpcOperand struct {
	enc   *MpcEncShare
	plain *big.Int
}

type mpcMulReq struct {
	x []mpcOperand
	y []*big.Int
}

type mpcPart struct {
	bits []int
	gad  []*big.Int
}

type mpcPiece struct {
	value *big.Int
	parts []mpcPart
}

type mpcSeg struct {
	q, start, length int
	senderSum        *big.Int
}

// MpcNoDealerOffline is the OT-based offline provider; it implements MpcOfflineProvider.
type MpcNoDealerOffline struct {
	n                 int
	StatSec           int
	keyShares         [][]*big.Int
	keyEnc            [][]MpcEncShare
	gadget            []*big.Int
	sacrificePartners int
	rng               MpcFieldSource
	seed              *big.Int
	deterministic     bool
	channels          map[string]*MpcOtChannel
	sacrificeOn       bool
	deviation         *MpcOfflineDeviation
	productMulCount   int
	log               *[]mpcOtRecord
	claims            []mpcProductClaim
}

var _ MpcOfflineProvider = (*MpcNoDealerOffline)(nil)

// MpcMakeNoDealerOffline is the no-dealer offline provider of n parties; a non-nil seed makes every draw reproducible (tests only).
func MpcMakeNoDealerOffline(n int, seed *big.Int, opts *MpcNoDealerOptions) (*MpcNoDealerOffline, error) {
	if opts == nil {
		opts = &MpcNoDealerOptions{}
	}
	if n < 1 || n > MpcMaxParties {
		return nil, errors.New("NoDealerOffline: n must be a positive integer")
	}
	o := &MpcNoDealerOffline{n: n, deterministic: seed != nil, channels: map[string]*MpcOtChannel{}, deviation: opts.Deviation}
	if seed != nil {
		o.seed = seed
		o.rng = NewMpcFieldRng(seed)
	} else {
		o.seed = big.NewInt(0xabcdef12345)
		o.rng = MpcSecureFieldRng{}
	}
	o.sacrificeOn = opts.Sacrifice == nil || *opts.Sacrifice
	keys := MpcMacKeys
	if opts.MacKeys != nil {
		keys = *opts.MacKeys
	}
	if keys < 1 || keys > 16 {
		return nil, errors.New("NoDealerOffline: macKeys must be an integer in [1, 16]")
	}
	o.StatSec = MpcStatSec
	if opts.StatSec != nil {
		o.StatSec = *opts.StatSec
	}
	var err error
	if o.gadget, err = MpcMakeGadget(o.StatSec, o.rng, opts.UnsafeStatSec); err != nil {
		return nil, err
	}
	o.keyEnc = make([][]MpcEncShare, keys)
	o.keyShares = make([][]*big.Int, keys)
	for l := 0; l < keys; l++ {
		o.keyEnc[l] = make([]MpcEncShare, n)
		o.keyShares[l] = make([]*big.Int, n)
		for i := 0; i < n; i++ {
			o.keyEnc[l][i] = MpcSampleEnc(o.gadget, o.rng)
			o.keyShares[l][i] = o.keyEnc[l][i].Value
		}
	}
	o.sacrificePartners = MpcSacrificeParts
	if opts.SacrificePartners != nil {
		o.sacrificePartners = *opts.SacrificePartners
	}
	if o.sacrificePartners < 1 || o.sacrificePartners > 8 {
		return nil, errors.New("NoDealerOffline: sacrificePartners must be an integer in [1, 8]")
	}
	return o, nil
}

func (o *MpcNoDealerOffline) N() int { return o.n }

// MacContext is the shares of each key and (for tests and the check only) their sums.
func (o *MpcNoDealerOffline) MacContext() *MpcMacContext {
	keys := make([]MpcMacKey, len(o.keyShares))
	for l, shares := range o.keyShares {
		alpha := new(big.Int)
		for _, a := range shares {
			alpha = MpcFAdd(alpha, a)
		}
		keys[l] = MpcMacKey{slices.Clone(shares), alpha}
	}
	return &MpcMacContext{N: o.n, AlphaShares: keys[0].AlphaShares, Alpha: keys[0].Alpha, ExtraKeys: keys[1:]}
}

func (o *MpcNoDealerOffline) channel(i, j int) *MpcOtChannel {
	key := fmt.Sprintf("%d->%d", i, j)
	ch := o.channels[key]
	if ch == nil {
		var otRng MpcOtRandom
		if o.deterministic {
			mixI := new(big.Int).Mul(big.NewInt(int64(i+1)), mpcMustHex("100000001b3"))
			mixJ := new(big.Int).Mul(big.NewInt(int64(j+1)), mpcMustHex("1000000000"))
			otRng = MpcOtRandomFromSeed(new(big.Int).Xor(new(big.Int).Xor(o.seed, mixI), mixJ))
		} else {
			otRng = MpcSecureOtRandom()
		}
		ch = NewMpcOtChannel(otRng, nil, nil)
		o.channels[key] = ch
	}
	return ch
}

func mpcMustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("mpc: bad constant")
	}
	return v
}

// mulBatch is the batched Gilboa multiplication: one OT-extension call per ordered party pair for every request.
func (o *MpcNoDealerOffline) mulBatch(reqs []mpcMulReq) ([][]*big.Int, error) {
	n := o.n
	for _, r := range reqs {
		if len(r.x) != n || len(r.y) != n {
			return nil, errors.New("otShareMultiply: wrong length")
		}
	}
	pieces := make([][]mpcPiece, len(reqs))
	for q, r := range reqs {
		pieces[q] = make([]mpcPiece, n)
		for i, xi := range r.x {
			if xi.enc != nil {
				pieces[q][i] = mpcPiece{xi.enc.Value, []mpcPart{{xi.enc.Bits, o.gadget}}}
				continue
			}
			v := MpcMod(xi.plain)
			e := MpcSampleEnc(o.gadget, o.rng)
			d := MpcPlainShare(MpcFSub(v, e.Value))
			pieces[q][i] = mpcPiece{v, []mpcPart{{e.Bits, o.gadget}, {d.Bits, MpcPlainGadget()}}}
		}
	}
	z := make([][]*big.Int, len(reqs))
	for q := range reqs {
		z[q] = make([]*big.Int, n)
		for i := 0; i < n; i++ {
			z[q][i] = MpcFMul(pieces[q][i].value, reqs[q].y[i])
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			rows := 0
			for q := range reqs {
				for _, part := range pieces[q][i].parts {
					rows += len(part.bits)
				}
			}
			bits := make([]int, rows)
			msg0 := make([]*big.Int, rows)
			msg1 := make([]*big.Int, rows)
			var segs []mpcSeg
			at := 0
			for q := range reqs {
				y := MpcMod(reqs[q].y[j])
				for _, part := range pieces[q][i].parts {
					length := len(part.bits)
					senderSum := new(big.Int)
					for k := 0; k < length; k++ {
						rho := o.rng.Next()
						senderSum = MpcFAdd(senderSum, rho)
						bits[at+k] = part.bits[k]
						msg0[at+k] = rho
						msg1[at+k] = MpcFAdd(rho, MpcFMul(part.gad[k], y))
					}
					segs = append(segs, mpcSeg{q, at, length, senderSum})
					at += length
				}
			}
			ext, err := o.channel(i, j).Extend(bits, msg0, msg1)
			if err != nil {
				return nil, err
			}
			if o.log != nil {
				*o.log = append(*o.log, mpcOtRecord{sender: j, msg0: msg0, msg1: msg1, received: ext.Received, receiverSide: i})
			}
			for _, sg := range segs {
				receiverSum := new(big.Int)
				for k := 0; k < sg.length; k++ {
					receiverSum = MpcFAdd(receiverSum, MpcMod(ext.Received[sg.start+k]))
				}
				z[sg.q][i] = MpcFAdd(z[sg.q][i], receiverSum)
				z[sg.q][j] = MpcFAdd(z[sg.q][j], MpcFNeg(sg.senderSum))
			}
		}
	}
	return z, nil
}

func mpcPlainOperands(x []*big.Int) []mpcOperand {
	out := make([]mpcOperand, len(x))
	for i, v := range x {
		out[i] = mpcOperand{plain: v}
	}
	return out
}

// OtShareMultiply gives additive shares of x*y where party i holds x_i and y_i (all cross terms via OT).
func (o *MpcNoDealerOffline) OtShareMultiply(x, y []*big.Int) ([]*big.Int, error) {
	z, err := o.mulBatch([]mpcMulReq{{mpcPlainOperands(x), y}})
	if err != nil {
		return nil, err
	}
	return z[0], nil
}

func (o *MpcNoDealerOffline) keyReq(l int) []mpcOperand {
	out := make([]mpcOperand, o.n)
	for i := range out {
		out[i] = mpcOperand{enc: &o.keyEnc[l][i]}
	}
	return out
}

func (o *MpcNoDealerOffline) encOperands(e []MpcEncShare) []mpcOperand {
	out := make([]mpcOperand, len(e))
	for i := range e {
		out[i] = mpcOperand{enc: &e[i]}
	}
	return out
}

func mpcToAuth(value []*big.Int, macs [][]*big.Int) MpcAuthSV {
	return MpcAuthSV{Value: value, Mac: macs[0], ExtraMac: macs[1:]}
}

func (o *MpcNoDealerOffline) authenticate(valueShares []*big.Int) (MpcAuthSV, error) {
	reqs := make([]mpcMulReq, len(o.keyEnc))
	for l := range reqs {
		reqs[l] = mpcMulReq{o.keyReq(l), valueShares}
	}
	macs, err := o.mulBatch(reqs)
	if err != nil {
		return MpcAuthSV{}, err
	}
	return mpcToAuth(valueShares, macs), nil
}

func (o *MpcNoDealerOffline) claimProduct(implied []*big.Int) []*big.Int {
	z := slices.Clone(implied)
	idx := o.productMulCount
	o.productMulCount++
	if o.deviation != nil && o.deviation.ProductMul == idx {
		z[0] = MpcFAdd(z[0], o.deviation.Delta)
	}
	o.claims = append(o.claims, mpcProductClaim{z, implied})
	return z
}

func mpcMacOf(z [][]*big.Int, start, per, off, keys int) [][]*big.Int {
	out := make([][]*big.Int, keys)
	for l := range out {
		out[l] = z[start+l*per+off]
	}
	return out
}

func (o *MpcNoDealerOffline) sampleShares() []MpcEncShare {
	out := make([]MpcEncShare, o.n)
	for i := range out {
		out[i] = MpcSampleEnc(o.gadget, o.rng)
	}
	return out
}

func mpcEncValues(e []MpcEncShare) []*big.Int {
	out := make([]*big.Int, len(e))
	for i := range e {
		out[i] = e[i].Value
	}
	return out
}

func (o *MpcNoDealerOffline) rawTripleWithPartners(partners int) (*MpcTripleWithPartners, error) {
	n, K := o.n, len(o.keyEnc)
	aEnc := o.sampleShares()
	bShares := make([]*big.Int, n)
	for i := range bShares {
		bShares[i] = o.rng.Next()
	}
	ahEnc := make([][]MpcEncShare, partners)
	for r := range ahEnc {
		ahEnc[r] = o.sampleShares()
	}
	aVal := mpcEncValues(aEnc)
	ahVal := make([][]*big.Int, partners)
	for r := range ahVal {
		ahVal[r] = mpcEncValues(ahEnc[r])
	}
	reqs := []mpcMulReq{{o.encOperands(aEnc), bShares}}
	for r := 0; r < partners; r++ {
		reqs = append(reqs, mpcMulReq{o.encOperands(ahEnc[r]), bShares})
	}
	macStart := len(reqs)
	for l := 0; l < K; l++ {
		reqs = append(reqs, mpcMulReq{o.keyReq(l), aVal}, mpcMulReq{o.keyReq(l), bShares})
		for r := 0; r < partners; r++ {
			reqs = append(reqs, mpcMulReq{o.keyReq(l), ahVal[r]})
		}
	}
	z1, err := o.mulBatch(reqs)
	if err != nil {
		return nil, err
	}
	cShares := o.claimProduct(z1[0])
	chShares := make([][]*big.Int, partners)
	for r := range chShares {
		chShares[r] = o.claimProduct(z1[1+r])
	}
	per := 2 + partners
	var reqs2 []mpcMulReq
	for l := 0; l < K; l++ {
		reqs2 = append(reqs2, mpcMulReq{o.keyReq(l), cShares})
		for r := 0; r < partners; r++ {
			reqs2 = append(reqs2, mpcMulReq{o.keyReq(l), chShares[r]})
		}
	}
	z2, err := o.mulBatch(reqs2)
	if err != nil {
		return nil, err
	}
	per2 := 1 + partners
	b := mpcToAuth(bShares, mpcMacOf(z1, macStart, per, 1, K))
	keep := MpcAuthTriple{mpcToAuth(aVal, mpcMacOf(z1, macStart, per, 0, K)), b, mpcToAuth(cShares, mpcMacOf(z2, 0, per2, 0, K))}
	parts := make([]MpcAuthTriple, partners)
	for r := range parts {
		parts[r] = MpcAuthTriple{mpcToAuth(ahVal[r], mpcMacOf(z1, macStart, per, 2+r, K)), b, mpcToAuth(chShares[r], mpcMacOf(z2, 0, per2, 1+r, K))}
	}
	return &MpcTripleWithPartners{keep, parts}, nil
}

// attribute searches the OT transcripts and the product claims for the party that cheated.
func (o *MpcNoDealerOffline) attribute(abort *MpcMacCheckAbort) error {
	blamed := map[int]bool{}
	if o.log != nil {
		for _, r := range *o.log {
			for k := range r.received {
				got := MpcMod(r.received[k])
				if got.Cmp(r.msg0[k]) != 0 && got.Cmp(r.msg1[k]) != 0 {
					blamed[r.sender] = true
					break
				}
			}
		}
	}
	for _, c := range o.claims {
		for i := range c.claimed {
			if c.claimed[i].Cmp(c.implied[i]) != 0 {
				blamed[i] = true
			}
		}
	}
	list := make([]int, 0, len(blamed))
	for p := range blamed {
		list = append(list, p)
	}
	slices.Sort(list)
	return newMpcOfflineCheatingAbort(abort.Msg, list)
}

// GenAuthTriple is one authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off).
func (o *MpcNoDealerOffline) GenAuthTriple() (*MpcAuthTriple, error) {
	if !o.sacrificeOn {
		t, err := o.rawTripleWithPartners(0)
		if err != nil {
			return nil, err
		}
		return &t.Keep, nil
	}
	o.log = &[]mpcOtRecord{}
	o.claims = nil
	defer func() {
		o.log = nil
		o.claims = nil
	}()
	t, err := o.rawTripleWithPartners(o.sacrificePartners)
	if err != nil {
		return nil, err
	}
	cert, err := MpcSacrificeVerify([]MpcTripleWithPartners{*t}, o.MacContext(), o.rng, nil)
	if err != nil {
		var ab *MpcMacCheckAbort
		if errors.As(err, &ab) {
			return nil, o.attribute(ab)
		}
		return nil, err
	}
	return &cert[0], nil
}

// AuthInput is an authenticated sharing of a value contributed by owner, MACed by OT under the distributed key.
func (o *MpcNoDealerOffline) AuthInput(value *big.Int, owner int) (MpcAuthSV, error) {
	if owner < 0 || owner >= o.n {
		return MpcAuthSV{}, errors.New("authInput: owner out of range")
	}
	sh, err := MpcShare(MpcMod(value), o.n, o.rng)
	if err != nil {
		return MpcAuthSV{}, err
	}
	return o.authenticate(sh)
}

// CheckInputConsistency verifies that every supplied input's MAC matches its value via a random combination (aborting otherwise).
func (o *MpcNoDealerOffline) CheckInputConsistency(inputs []MpcAuthSV) error {
	if len(inputs) == 0 {
		return nil
	}
	for _, inp := range inputs {
		if len(inp.Value) != o.n || len(inp.Mac) != o.n {
			return errors.New("checkInputConsistency: input party count mismatch")
		}
	}
	ctx := o.MacContext()
	engine, err := NewMpcSpdzEngine(ctx, nil)
	if err != nil {
		return err
	}
	rShares := make([]*big.Int, o.n)
	for i := range rShares {
		rShares[i] = o.rng.Next()
	}
	w, err := o.authenticate(rShares)
	if err != nil {
		return err
	}
	for _, inp := range inputs {
		e := o.rng.Next()
		if e.Sign() == 0 {
			e = big.NewInt(1)
		}
		if w, err = MpcAddAuth(w, MpcScaleAuth(inp, e)); err != nil {
			return err
		}
	}
	if _, err := engine.Open(w, "input-check:w"); err != nil {
		return err
	}
	return engine.MacCheck(o.rng)
}
