package pca

// The NO-DEALER offline phase over the mutual-TLS mesh. Each party holds only its own shares and samples its own MAC-key and triple
// shares; the products needed for the triples and the MACs are computed by Gilboa OT multiplication between every ordered pair of
// parties (the in-process model is MpcNoDealerOffline):
//
//	ob-S / ob-R / ob-C   the kappa = 128 base OTs of every ordered pair (malicious-secure, session-bound Chou-Orlandi)
//	gd-c / gd-o / gd-e   signed commit / reveal / echo of the choice-bit gadget seeds
//	in-share             each owner splits every input bit into additive shares and sends one to each peer
//	ox<layer>.<chunk>.u  OT-extension receiver messages (u matrix + KOS pair) -> KOS correlation check
//	ox<layer>.<chunk>.y  OT-extension sender ciphertexts
//
// Layer 1: the triple products and the MACs of every value known before them; layer 2: the MACs of the products; layer 3: the
// pairwise tags (identifiable abort). Receivers do not choose with the bits of their share but with a gadget encoding of 253
// uniform bits, so whether a run aborts is statistically independent of the share. There is no security proof, and a wrong OT
// operand in the offline triple products is named only for n = 2 or through the post-abort disclosure audit.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"regexp"
	"strconv"

	ed "filippo.io/edwards25519"
)

// mpcOtRowsPerRound bounds the OT rows per extension round (frame size and memory).
const mpcOtRowsPerRound = 128 * MpcFieldBits

var mpcHex128 = regexp.MustCompile(`^(0|[1-9a-f][0-9a-f]{0,31})$`)

// MpcNetForensics is the OT transcript of the triple products, for attributing a failed sacrifice.
type MpcNetForensics struct {
	Gadget []*big.Int
	Rows   int
	Slots  int
	// Disclose is my disclosure for triple t (the triple is discarded when it is used).
	Disclose func(t int) []MpcSlotDisclosure
}

type mpcOfflineArgs struct {
	mesh      *MpcMesh
	id, n, C  int
	keys      int
	partners  int
	sessionID string
	input     MpcDecisionVector
	Q         int
	exchange  mpcExchange
	bad       func(p int, what string) error
	arr       func(p int, raw any, ln int) ([]*big.Int, error)
	fail      func(*MpcNetAbort) error
	// behavior is TEST ONLY (gated by the caller): "offline-lie", "ot-u-lie" or "ot-proof-lie", a malicious party's offline misbehaviour.
	behavior string
}

type mpcOtItem struct {
	bits []int
	gad  []*big.Int
	y    *big.Int
}

type mpcKept struct {
	recv map[int]map[int][]*big.Int
	rho  map[int]map[int][]*big.Int
}

type mpcGadgetStream struct {
	seed []byte
	ctr  uint64
}

func (g *mpcGadgetStream) Next() *big.Int {
	for {
		var c [8]byte
		binary.LittleEndian.PutUint64(c[:], g.ctr)
		g.ctr++
		h := sha256.Sum256(append(append([]byte(nil), g.seed...), c[:]...))
		v := binary.LittleEndian.Uint64(h[:8]) & (uint64(1)<<61 - 1)
		if v < mpcPrimeU64 {
			return new(big.Int).SetUint64(v)
		}
	}
}

// mpcGadgetFromSeeds is the public gadget H(all seeds in party order || session) expanded by a hash chain.
func mpcGadgetFromSeeds(sessionID string, seeds [][]byte) ([]*big.Int, error) {
	h := sha256.New()
	h.Write([]byte("atlas-pca-mpc/enc-gadget"))
	h.Write([]byte(wellFormedUTF8(sessionID)))
	for _, s := range seeds {
		h.Write(s)
	}
	return MpcMakeGadget(MpcStatSec, &mpcGadgetStream{seed: h.Sum(nil)}, false)
}

func mpcLeBig(v *big.Int, n int) []byte {
	out := make([]byte, n)
	b := v.Bytes() // big-endian
	for i := 0; i < len(b) && i < n; i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func mpcFromLe(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func mpcHex128Parse(s any) (*big.Int, error) {
	str, ok := s.(string)
	if !ok || !mpcHex128.MatchString(str) {
		return nil, errors.New("bad 128-bit value")
	}
	v, _ := new(big.Int).SetString(str, 16)
	return v, nil
}

func mpcEncodeU(msg *MpcExtRoundMsg, mExt int) any {
	cb := (mExt + 7) / 8
	buf := make([]byte, 0, len(msg.U)*cb)
	for _, c := range msg.U {
		buf = append(buf, mpcLeBig(c, cb)...)
	}
	return map[string]any{"u": MpcB64(buf), "x": msg.X.Text(16), "t": msg.TComb.Text(16)}
}

func mpcDecodeU(raw any, mExt int) (*MpcExtRoundMsg, error) {
	o, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("bad extension message")
	}
	cb := (mExt + 7) / 8
	b, err := MpcUnb64(o["u"], MpcOtKappa*cb)
	if err != nil {
		return nil, err
	}
	u := make([]*big.Int, MpcOtKappa)
	for i := range u {
		u[i] = mpcFromLe(b[i*cb : (i+1)*cb])
	}
	x, err := mpcHex128Parse(o["x"])
	if err != nil {
		return nil, err
	}
	t, err := mpcHex128Parse(o["t"])
	if err != nil {
		return nil, err
	}
	return &MpcExtRoundMsg{U: u, X: x, TComb: t}, nil
}

func mpcLe64s(v []uint64) []byte {
	out := make([]byte, 8*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint64(out[8*i:], x)
	}
	return out
}

func mpcEncodeY(y0, y1 []uint64) any {
	return map[string]any{"y0": MpcB64(mpcLe64s(y0)), "y1": MpcB64(mpcLe64s(y1))}
}

type mpcY struct{ y0, y1 []uint64 }

func mpcDecodeY(raw any, m int) (*mpcY, error) {
	o, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("bad ciphertext message")
	}
	a, err := MpcUnb64(o["y0"], m*8)
	if err != nil {
		return nil, err
	}
	b, err := MpcUnb64(o["y1"], m*8)
	if err != nil {
		return nil, err
	}
	y := &mpcY{make([]uint64, m), make([]uint64, m)}
	for i := 0; i < m; i++ {
		y.y0[i] = binary.LittleEndian.Uint64(a[8*i:])
		y.y1[i] = binary.LittleEndian.Uint64(b[8*i:])
	}
	return y, nil
}

func mpcPairsB64(ps []MpcOtPair) []any {
	out := make([]any, len(ps))
	for i, p := range ps {
		out[i] = []any{MpcB64(p[0]), MpcB64(p[1])}
	}
	return out
}

func mpcParsePairs(raw any, count, ln int) ([]MpcOtPair, error) {
	l, ok := raw.([]any)
	if !ok || len(l) != count {
		return nil, errors.New("bad pair array")
	}
	out := make([]MpcOtPair, count)
	for i, e := range l {
		p, ok := e.([]any)
		if !ok || len(p) != 2 {
			return nil, errors.New("bad pair")
		}
		a, err := MpcUnb64(p[0], ln)
		if err != nil {
			return nil, err
		}
		b, err := MpcUnb64(p[1], ln)
		if err != nil {
			return nil, err
		}
		out[i] = MpcOtPair{a, b}
	}
	return out, nil
}

func mpcRunOfflineNet(a mpcOfflineArgs) (*MpcNetPrep, error) {
	id, n, C, K, P := a.id, a.n, a.C, a.keys, a.partners
	mesh := a.mesh
	var others []int
	for i := 0; i < n; i++ {
		if i != id {
			others = append(others, i)
		}
	}
	rng := MpcSecureOtRandom()
	frng := MpcSecureFieldRng{}
	delta := frng.Next()
	for delta.Sign() == 0 {
		delta = frng.Next()
	}
	var gadget []*big.Int
	plainGadget := MpcPlainGadget()
	sidH := sha256.Sum256(append([]byte("atlas-pca-mpc/net-session/v2"), wellFormedUTF8(mesh.SessionID())...))
	sid := sidH[:]
	// binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is recv and extension sender is send
	chanB := func(recv, send int, round string) MpcBaseOtBinding {
		return MpcBaseOtBinding{SessionID: sid, SenderIndex: int64(recv), ReceiverIndex: int64(send), Round: round}
	}
	ex := func(rd string, mine func(int) any, parse mpcParse) (map[int]any, error) {
		return a.exchange(rd, mine, parse, 0)
	}
	// run a check that may fail with an OT error, turning it into an abort that names peer
	guard := func(peer int, what string, err error) error {
		if err == nil {
			return nil
		}
		var ne *MpcNetAbort
		if errors.As(err, &ne) {
			return err
		}
		kind := "malformed"
		var b1 *MpcBaseOtAbort
		var b2 *MpcMalOtAbort
		var b3 *MpcPointValidationError
		if errors.As(err, &b1) || errors.As(err, &b2) || errors.As(err, &b3) {
			kind = "ot-check"
		}
		return a.fail(mpcAbortF(kind, mpcIntP(peer), id, what+": "+err.Error(), ""))
	}

	// ---- base OTs (kappa per ordered pair, both roles)
	recvCh := map[int]*MpcOtExtReceiver{}
	sendCh := map[int]*MpcOtExtSender{}
	seeds := map[int][]MpcOtPair{}
	mySetup := map[int]*MpcBaseOtSenderSetup{}
	selector := map[int][]int{}
	for _, p := range others {
		kb, err := MpcBindingBytes(chanB(id, p, "iknp-kos"))
		if err != nil {
			return nil, err
		}
		r := NewMpcOtExtReceiver(rng, kb)
		seeds[p] = r.MakeSeeds()
		recvCh[p] = r
		if mySetup[p], err = MpcMalBaseOtSenderSetup(rng, chanB(id, p, "offline-kappa")); err != nil {
			return nil, err
		}
		kb2, err := MpcBindingBytes(chanB(p, id, "iknp-kos"))
		if err != nil {
			return nil, err
		}
		s := NewMpcOtExtSender(rng, kb2)
		selector[p] = s.MakeSelector()
		sendCh[p] = s
	}
	type sMsg struct {
		S     *ed.Point
		proof MpcSchnorrProof
	}
	proofZ := func(z *big.Int) *big.Int {
		if a.behavior == "ot-proof-lie" {
			return new(big.Int).Add(z, big.NewInt(1))
		}
		return z
	}
	theirS, err := ex("ob-S", func(peer int) any {
		st := mySetup[peer]
		return map[string]any{"S": MpcPtJ(st.S), "U": MpcPtJ(st.Proof.U), "z": MpcHx(proofZ(st.Proof.Z))}
	}, func(p int, raw any) (any, error) {
		o, ok := raw.(map[string]any)
		if !ok {
			return nil, a.bad(p, "bad S message")
		}
		U, err := MpcJPt(o["U"])
		if err != nil {
			return nil, err
		}
		z, err := MpcHexBig(o["z"])
		if err != nil {
			return nil, err
		}
		S, err := MpcJPt(o["S"])
		if err != nil {
			return nil, err
		}
		return sMsg{S, MpcSchnorrProof{U, z}}, nil
	})
	if err != nil {
		return nil, err
	}
	respR := map[int][]*ed.Point{}
	recvPads := map[int][][]byte{}
	for _, p := range others {
		st := theirS[p].(sMsg)
		R, pads, err := MpcMalBaseOtReceiverRespond(st.S, st.proof, selector[p], rng, chanB(p, id, "offline-kappa"))
		if err := guard(p, "base OT (receiver)", err); err != nil {
			return nil, err
		}
		respR[p], recvPads[p] = R, pads
	}
	theirR, err := ex("ob-R", func(peer int) any {
		out := make([]any, len(respR[peer]))
		for i, r := range respR[peer] {
			out[i] = MpcPtJ(r)
		}
		return out
	}, func(p int, raw any) (any, error) {
		l, ok := raw.([]any)
		if !ok || len(l) != MpcOtKappa {
			return nil, a.bad(p, "bad R array")
		}
		out := make([]*ed.Point, len(l))
		for i, x := range l {
			pt, err := MpcJPt(x)
			if err != nil {
				return nil, err
			}
			out[i] = pt
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	type ctMsg struct{ ct, com []MpcOtPair }
	encs := map[int]ctMsg{}
	for _, p := range others {
		st := mySetup[p]
		pads, err := MpcMalBaseOtSenderDerive(st.Y, st.T, theirR[p].([]*ed.Point), st.S, chanB(id, p, "offline-kappa"))
		if err := guard(p, "base OT (sender)", err); err != nil {
			return nil, err
		}
		ct, com, err := MpcBaseOtSenderEncrypt(seeds[p], pads)
		if err := guard(p, "base OT (sender)", err); err != nil {
			return nil, err
		}
		encs[p] = ctMsg{ct, com}
	}
	theirCt, err := ex("ob-C", func(peer int) any {
		return map[string]any{"ct": mpcPairsB64(encs[peer].ct), "com": mpcPairsB64(encs[peer].com)}
	}, func(p int, raw any) (any, error) {
		o, ok := raw.(map[string]any)
		if !ok {
			return nil, a.bad(p, "bad ciphertext message")
		}
		ct, err := mpcParsePairs(o["ct"], MpcOtKappa, 16)
		if err != nil {
			return nil, err
		}
		com, err := mpcParsePairs(o["com"], MpcOtKappa, 32)
		if err != nil {
			return nil, err
		}
		return ctMsg{ct, com}, nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range others {
		m := theirCt[p].(ctMsg)
		got, err := MpcBaseOtReceiverDecrypt(selector[p], recvPads[p], m.ct, m.com)
		if err := guard(p, "base OT (receiver)", err); err != nil {
			return nil, err
		}
		if err := guard(p, "base OT (receiver)", sendCh[p].SetSeeds(got)); err != nil {
			return nil, err
		}
	}

	// ---- the jointly contributed choice-bit gadget (signed commit / reveal / echo)
	agreed, err := mpcAgreeGadgetSeeds(mesh, id, n, a.exchange, a.bad)
	if err != nil {
		return nil, err
	}
	if gadget, err = mpcGadgetFromSeeds(mesh.SessionID(), agreed); err != nil {
		return nil, err
	}

	// ---- the OT multiplication layer (Gilboa)
	// For every peer p: as the OT RECEIVER towards p I choose with the bits of my items and get recv[p][t] = x_t*y^p_t + sum rho^p_t;
	// as the OT SENDER towards p I offer (rho_k, rho_k + gad_k*y) with fresh masks and keep sendSum[p][t] = sum rho.
	otRows := func(layer string, items []mpcOtItem, keep map[int]bool) (recv, sendSum map[int][]*big.Int, kept mpcKept, err error) {
		T := len(items)
		recv, sendSum = map[int][]*big.Int{}, map[int][]*big.Int{}
		kept = mpcKept{map[int]map[int][]*big.Int{}, map[int]map[int][]*big.Int{}}
		for _, p := range others {
			recv[p], sendSum[p] = make([]*big.Int, T), make([]*big.Int, T)
			for t := 0; t < T; t++ {
				recv[p][t], sendSum[p][t] = new(big.Int), new(big.Int)
			}
			kept.recv[p], kept.rho[p] = map[int][]*big.Int{}, map[int][]*big.Int{}
		}
		if T == 0 || len(others) == 0 {
			return
		}
		rows := 0
		for _, it := range items {
			rows += len(it.bits)
		}
		rowItem := make([]int, rows)
		choice := make([]int, rows)
		m0, m1 := map[int][]uint64{}, map[int][]uint64{}
		for _, p := range others {
			m0[p], m1[p] = make([]uint64, rows), make([]uint64, rows)
		}
		itemOff := make([]int, T)
		off := 0
		for t, it := range items {
			ln := len(it.bits)
			itemOff[t] = off
			if keep[t] {
				for _, p := range others {
					kept.recv[p][t] = make([]*big.Int, ln)
					for k := range kept.recv[p][t] {
						kept.recv[p][t][k] = new(big.Int)
					}
				}
			}
			for k := 0; k < ln; k++ {
				choice[off+k] = it.bits[k]
				rowItem[off+k] = t
			}
			for _, p := range others {
				sum := new(big.Int)
				var rhos []*big.Int
				for k := 0; k < ln; k++ {
					rho := frng.Next()
					sum = MpcFAdd(sum, rho)
					m0[p][off+k] = rho.Uint64()
					m1[p][off+k] = MpcFAdd(rho, MpcFMul(it.gad[k], it.y)).Uint64()
					rhos = append(rhos, rho)
				}
				sendSum[p][t] = sum
				if keep[t] {
					kept.rho[p][t] = rhos
				}
			}
			off += ln
		}
		chunk := 0
		for start := 0; start < rows; start, chunk = start+mpcOtRowsPerRound, chunk+1 {
			end := min(rows, start+mpcOtRowsPerRound)
			m := end - start
			mExt := m + MpcOtKappa + MpcOtSsec
			tag := "ox" + layer + "." + strconv.Itoa(chunk)
			msgs := map[int]*MpcExtRoundMsg{}
			pend := map[int]*MpcExtPending{}
			if a.behavior == "ot-u-lie" { // an inconsistent matrix: flip the first row in 64 of the 128 columns only
				for _, p := range others {
					recvCh[p].TamperU = func(u []*big.Int, _ int) {
						for i := 0; i < 64; i++ {
							u[i] = new(big.Int).Xor(u[i], big.NewInt(1))
						}
					}
				}
			}
			for _, p := range others {
				mg, pe, e := recvCh[p].Begin(choice[start:end])
				if e != nil {
					return nil, nil, kept, e
				}
				msgs[p], pend[p] = mg, pe
			}
			us, e := ex(tag+".u", func(peer int) any { return mpcEncodeU(msgs[peer], mExt) }, func(p int, raw any) (any, error) { return mpcDecodeU(raw, mExt) })
			if e != nil {
				return nil, nil, kept, e
			}
			y0s, y1s := map[int][]uint64{}, map[int][]uint64{}
			for _, p := range others {
				y0, y1, e := sendCh[p].Respond(us[p].(*MpcExtRoundMsg), m0[p][start:end], m1[p][start:end])
				if e = guard(p, "OT extension ("+tag+")", e); e != nil {
					return nil, nil, kept, e
				}
				y0s[p], y1s[p] = y0, y1
			}
			cts, e := ex(tag+".y", func(peer int) any { return mpcEncodeY(y0s[peer], y1s[peer]) }, func(p int, raw any) (any, error) { return mpcDecodeY(raw, m) })
			if e != nil {
				return nil, nil, kept, e
			}
			for _, p := range others {
				cy := cts[p].(*mpcY)
				got, e := recvCh[p].Finish(pend[p], cy.y0, cy.y1)
				if e = guard(p, "OT extension ("+tag+")", e); e != nil {
					return nil, nil, kept, e
				}
				for j := 0; j < m; j++ {
					t := rowItem[start+j]
					gv := MpcMod(new(big.Int).SetUint64(got[j]))
					recv[p][t] = MpcFAdd(recv[p][t], gv)
					if keep[t] {
						kept.recv[p][t][start+j-itemOff[t]] = gv
					}
				}
			}
		}
		return
	}

	// my additive share of X_t*Y_t = (sum x)(sum y): the diagonal locally plus, for every ordered pair, the Gilboa OT product
	mulLayer := func(layer string, xs []MpcEncShare, ys []*big.Int, lieAt int, keep map[int]bool) ([]*big.Int, mpcKept, error) {
		z := make([]*big.Int, len(xs))
		items := make([]mpcOtItem, len(xs))
		for t, x := range xs {
			z[t] = MpcFMul(x.Value, ys[t])
			items[t] = mpcOtItem{x.Bits, gadget, ys[t]}
			if t == lieAt {
				items[t].y = MpcFAdd(ys[t], big.NewInt(1))
			}
		}
		recv, sendSum, kept, err := otRows(layer, items, keep)
		if err != nil {
			return nil, kept, err
		}
		for _, p := range others {
			for t := range z {
				z[t] = MpcFSub(MpcFAdd(z[t], recv[p][t]), sendSum[p][t])
			}
		}
		return z, kept, nil
	}

	// pairwise tags for my shares xs: T_ij = K_ij + delta_j * x_i. A tag operand is an arbitrary derived value with no uniform
	// choice-bit encoding of its own, so each x is split as x = e + d with a fresh encoded e; both halves are multiplied with delta.
	tagLayer := func(layer string, xs []*big.Int) (tag, key map[int][]*big.Int, err error) {
		var items []mpcOtItem
		for _, x := range xs {
			e := MpcSampleEnc(gadget, frng)
			d := MpcPlainShare(MpcFSub(x, e.Value))
			items = append(items, mpcOtItem{e.Bits, gadget, delta}, mpcOtItem{d.Bits, plainGadget, delta})
		}
		recv, sendSum, _, err := otRows(layer, items, nil)
		if err != nil {
			return nil, nil, err
		}
		tag, key = map[int][]*big.Int{}, map[int][]*big.Int{}
		for _, p := range others {
			tag[p], key[p] = make([]*big.Int, len(xs)), make([]*big.Int, len(xs))
			for u := range xs {
				tag[p][u] = MpcFAdd(recv[p][2*u], recv[p][2*u+1])
				key[p][u] = MpcFAdd(sendSum[p][2*u], sendSum[p][2*u+1])
			}
		}
		return tag, key, nil
	}

	// ---- my randomness and the input sharings
	alphaEnc := make([]MpcEncShare, K)
	alphaShare := make([]*big.Int, K)
	for l := range alphaEnc {
		alphaEnc[l] = MpcSampleEnc(gadget, frng)
		alphaShare[l] = alphaEnc[l].Value
	}
	tb, _ := MpcThermometerEncode(float64(a.input.T), mpcTM)
	rb, _ := MpcThermometerEncode(float64(a.input.RQuant), a.Q)
	myBits := append(append([]int{a.input.Allow}, tb...), rb...)
	if len(myBits) != C {
		return nil, mpcAbortF("local", nil, id, "input chain count mismatch", "")
	}
	outShares := map[int][]*big.Int{}
	for _, p := range others {
		outShares[p] = make([]*big.Int, C)
		for c := range outShares[p] {
			outShares[p][c] = frng.Next()
		}
	}
	myOwn := make([]*big.Int, C)
	for c, b := range myBits {
		s := big.NewInt(int64(b))
		for _, p := range others {
			s = MpcFSub(s, outShares[p][c])
		}
		myOwn[c] = s
	}
	gotShares, err := ex("in-share", func(peer int) any { return mpcFlatHex(outShares[peer]) }, func(p int, raw any) (any, error) { return a.arr(p, raw, C) })
	if err != nil {
		return nil, err
	}
	var inputValue []*big.Int // my value share of every (owner, chain)
	for o := 0; o < n; o++ {
		for c := 0; c < C; c++ {
			if o == id {
				inputValue = append(inputValue, myOwn[c])
			} else {
				inputValue = append(inputValue, gotShares[o].([]*big.Int)[c])
			}
		}
	}
	maskShare := frng.Next() // my share of the input-check mask

	nT := (n - 1) * C
	aE := make([]MpcEncShare, nT)
	bS := make([]*big.Int, nT)
	ahE := make([][]MpcEncShare, nT)
	for t := 0; t < nT; t++ {
		aE[t] = MpcSampleEnc(gadget, frng)
		bS[t] = frng.Next()
		ahE[t] = make([]MpcEncShare, P)
		for r := range ahE[t] {
			ahE[t][r] = MpcSampleEnc(gadget, frng)
		}
	}
	aS := make([]*big.Int, nT)
	ahS := make([][]*big.Int, nT)
	for t := range aE {
		aS[t] = aE[t].Value
		ahS[t] = make([]*big.Int, P)
		for r := range ahS[t] {
			ahS[t][r] = ahE[t][r].Value
		}
	}

	// ---- layer 1: products and the MACs of known values
	var xs1 []MpcEncShare
	var ys1 []*big.Int
	push1 := func(x MpcEncShare, y *big.Int) int {
		xs1, ys1 = append(xs1, x), append(ys1, y)
		return len(xs1) - 1
	}
	macs1 := func(y *big.Int) []int {
		out := make([]int, len(alphaEnc))
		for l, al := range alphaEnc {
			out[l] = push1(al, y)
		}
		return out
	}
	iC := make([]int, nT)
	iCh := make([][]int, nT)
	iMa, iMb := make([][]int, nT), make([][]int, nT)
	iMah := make([][][]int, nT)
	for t := 0; t < nT; t++ {
		iC[t] = push1(aE[t], bS[t])
		iCh[t] = make([]int, P)
		for r := range iCh[t] {
			iCh[t][r] = push1(ahE[t][r], bS[t])
		}
		iMa[t] = macs1(aS[t])
		iMb[t] = macs1(bS[t])
		iMah[t] = make([][]int, P)
		for r := range iMah[t] {
			iMah[t][r] = macs1(ahS[t][r])
		}
	}
	iIn := make([][]int, len(inputValue))
	for q, val := range inputValue {
		iIn[q] = macs1(val)
	}
	iMask := macs1(maskShare)
	keepItems := map[int]bool{}
	for t := 0; t < nT; t++ {
		keepItems[iC[t]] = true
		for _, i := range iCh[t] {
			keepItems[i] = true
		}
	}
	lie := -1
	if a.behavior == "offline-lie" && len(iC) > 0 {
		lie = iC[0]
	}
	z1, kept1, err := mulLayer("1", xs1, ys1, lie, keepItems)
	if err != nil {
		return nil, err
	}

	// ---- layer 2: the MACs of the products
	cS := make([]*big.Int, nT)
	chS := make([][]*big.Int, nT)
	for t := 0; t < nT; t++ {
		cS[t] = z1[iC[t]]
		chS[t] = make([]*big.Int, P)
		for r := range chS[t] {
			chS[t][r] = z1[iCh[t][r]]
		}
	}
	var xs2 []MpcEncShare
	var ys2 []*big.Int
	macs2 := func(y *big.Int) []int {
		out := make([]int, len(alphaEnc))
		for l, al := range alphaEnc {
			xs2, ys2 = append(xs2, al), append(ys2, y)
			out[l] = len(xs2) - 1
		}
		return out
	}
	iMc := make([][]int, nT)
	iMch := make([][][]int, nT)
	for t := 0; t < nT; t++ {
		iMc[t] = macs2(cS[t])
		iMch[t] = make([][]int, P)
		for r := range iMch[t] {
			iMch[t][r] = macs2(chS[t][r])
		}
	}
	z2, _, err := mulLayer("2", xs2, ys2, -1, nil)
	if err != nil {
		return nil, err
	}

	// ---- assemble, then pairwise-tag every share
	pa := func(x *big.Int) MpcPA {
		tg, ky := make([]*big.Int, n), make([]*big.Int, n)
		for j := range tg {
			tg[j], ky[j] = new(big.Int), new(big.Int)
		}
		return MpcPA{x, tg, ky}
	}
	aw := func(value *big.Int, macIdx []int, z []*big.Int) MpcAW {
		m := make([]MpcPA, len(macIdx))
		for l, i := range macIdx {
			m[l] = pa(z[i])
		}
		return MpcAW{pa(value), m}
	}
	triples := make([][]MpcAW, nT)
	for t := 0; t < nT; t++ {
		sh := []MpcAW{aw(aS[t], iMa[t], z1), aw(bS[t], iMb[t], z1), aw(cS[t], iMc[t], z2)}
		for r := 0; r < P; r++ {
			sh = append(sh, aw(ahS[t][r], iMah[t][r], z1), aw(chS[t][r], iMch[t][r], z2))
		}
		if len(sh) != MpcSharingsPerTriple(P) {
			return nil, mpcAbortF("local", nil, id, "triple assembly mismatch", "")
		}
		triples[t] = sh
	}
	inputs := make([]MpcAW, len(inputValue))
	for q, val := range inputValue {
		inputs[q] = aw(val, iIn[q], z1)
	}
	checkMask := aw(maskShare, iMask, z1)
	alpha := make([]MpcPA, K)
	for l, s := range alphaShare {
		alpha[l] = pa(s)
	}
	// every PA is mutated in place below (its tag and key slices), exactly as the reference does
	all := make([]*MpcPA, 0, len(alpha))
	for l := range alpha {
		all = append(all, &alpha[l])
	}
	addW := func(w *MpcAW) {
		all = append(all, &w.V)
		for l := range w.M {
			all = append(all, &w.M[l])
		}
	}
	for t := range triples {
		for s := range triples[t] {
			addW(&triples[t][s])
		}
	}
	for q := range inputs {
		addW(&inputs[q])
	}
	addW(&checkMask)
	xsAll := make([]*big.Int, len(all))
	for u, x := range all {
		xsAll[u] = x.X
	}
	tags, keysOut, err := tagLayer("3", xsAll)
	if err != nil {
		return nil, err
	}
	for u, x := range all {
		for _, p := range others {
			x.Tag[p], x.Key[p] = tags[p][u], keysOut[p][u]
		}
	}
	myPlain := make([]*big.Int, len(myBits))
	for i, b := range myBits {
		myPlain[i] = big.NewInt(int64(b))
	}
	disclose := func(t int) []MpcSlotDisclosure {
		slot := func(item int, x MpcEncShare, z *big.Int) MpcSlotDisclosure {
			d := MpcSlotDisclosure{Bits: append([]int(nil), x.Bits...), Y: bS[t], Z: z}
			for _, p := range others {
				d.Recv = append(d.Recv, MpcPeerEntry{p, kept1.recv[p][item]})
				d.Rho = append(d.Rho, MpcPeerEntry{p, kept1.rho[p][item]})
			}
			return d
		}
		out := []MpcSlotDisclosure{slot(iC[t], aE[t], cS[t])}
		for r, item := range iCh[t] {
			out = append(out, slot(item, ahE[t][r], chS[t][r]))
		}
		return out
	}
	return &MpcNetPrep{Mode: "no-dealer", Tagged: true, Delta: delta, Alpha: alpha, Triples: triples, Inputs: inputs, MyPlain: myPlain, CheckMask: &checkMask,
		Forensics: &MpcNetForensics{Gadget: gadget, Rows: len(gadget), Slots: 1 + P, Disclose: disclose}}, nil
}
