package pca

// Replays the MPC oblivious-transfer corpus: the Ed25519 group and Schnorr proofs, the word-array kernels, the base OT, IKNP/KOS
// extension, the ML-KEM and hybrid base OTs, the MASCOT no-dealer offline phase and the no-dealer malicious runner. Every random draw
// comes from the seeded SplitMix64 stream, so points, pads, matrices and shares match the reference value for value. Big integers
// cross as DECIMAL STRINGS, bytes as {"$bytes": b64u} (or a bare b64u string where the reference passed a seed), u32 words as numbers.

import (
	"errors"
	"math/big"
	"testing"

	ed "filippo.io/edwards25519"
)

func otBytes(v any) ([]byte, error) {
	if s, ok := v.(string); ok {
		b, err := b64.DecodeString(s)
		if err != nil {
			return nil, errors.New("bad base64url")
		}
		return b, nil
	}
	b := baseBytes(v)
	if b == nil {
		return nil, errors.New("expected bytes")
	}
	return b, nil
}

func otWords(v any) ([]uint32, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([]uint32, len(l))
	for i, x := range l {
		f, ok := jsNum(x)
		if !ok || f < 0 || f > 4294967295 || f != float64(uint32(f)) {
			return nil, errors.New("not a u32 word")
		}
		out[i] = uint32(f)
	}
	return out, nil
}

func otWordsOut(w []uint32) []any {
	out := make([]any, len(w))
	for i, x := range w {
		out[i] = float64(x)
	}
	return out
}

// otPt reads an extended-coordinate point ["X", "Y", "Z", "T"].
func otPt(v any) (*ed.Point, error) {
	c, err := mpcBA(v)
	if err != nil || len(c) != 4 {
		return nil, errors.New("bad point")
	}
	return MpcEcFromExtended(c[0], c[1], c[2], c[3])
}

func otAff(p *ed.Point) map[string]any {
	x, y := MpcEcToAffine(p)
	return map[string]any{"x": x.String(), "y": y.String()}
}

func otAffs(ps []*ed.Point) []any {
	out := make([]any, len(ps))
	for i, p := range ps {
		out[i] = otAff(p)
	}
	return out
}

func otBL(l [][]byte) []any {
	out := make([]any, len(l))
	for i, b := range l {
		out[i] = frostOut(b)
	}
	return out
}

func otPairsOut(ps []MpcOtPair) []any {
	out := make([]any, len(ps))
	for i, p := range ps {
		out[i] = []any{frostOut(p[0]), frostOut(p[1])}
	}
	return out
}

func otPairs(v any) ([]MpcOtPair, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([]MpcOtPair, len(l))
	for i, e := range l {
		pr, ok := e.([]any)
		if !ok || len(pr) != 2 {
			return nil, errors.New("not a pair")
		}
		for s := 0; s < 2; s++ {
			b, err := otBytes(pr[s])
			if err != nil {
				return nil, err
			}
			out[i][s] = b
		}
	}
	return out, nil
}

func otRng(v any) (MpcOtRandom, error) {
	s, err := mpcB(v)
	if err != nil {
		return nil, err
	}
	return MpcOtRandomFromSeed(s), nil
}

func otFlip(b []byte, mask byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[i] = b[i] ^ mask
	}
	return o
}

func otOrder2() *ed.Point {
	p, err := MpcEcFromExtended(new(big.Int), new(big.Int).Sub(mpcEcQ, big.NewInt(1)), big.NewInt(1), new(big.Int))
	if err != nil {
		panic(err)
	}
	return p
}

func otTamper(name string) (*MpcBaseOtTamper, error) {
	t := &MpcBaseOtTamper{}
	switch name {
	case "none", "":
		return nil, nil
	case "S_identity":
		t.TamperS = func(*ed.Point) *ed.Point { return MpcEcIdentity() }
	case "S_order2":
		t.TamperS = func(*ed.Point) *ed.Point { return otOrder2() }
	case "S_other":
		t.TamperS = func(s *ed.Point) *ed.Point { return MpcEcAdd(s, MpcEcBase()) }
	case "proof_z":
		t.TamperProof = func(p MpcSchnorrProof) MpcSchnorrProof {
			return MpcSchnorrProof{p.U, new(big.Int).Mod(new(big.Int).Add(p.Z, big.NewInt(1)), MpcEcL)}
		}
	case "proof_U":
		t.TamperProof = func(p MpcSchnorrProof) MpcSchnorrProof { return MpcSchnorrProof{MpcEcAdd(p.U, MpcEcBase()), p.Z} }
	case "R0_identity":
		t.TamperR = func(R []*ed.Point) {
			if len(R) > 0 {
				R[0] = MpcEcIdentity()
			}
		}
	case "R1_order2":
		t.TamperR = func(R []*ed.Point) {
			if len(R) > 1 {
				R[1] = otOrder2()
			}
		}
	case "R_swap":
		t.TamperR = func(R []*ed.Point) {
			if len(R) > 1 {
				R[0], R[1] = R[1], R[0]
			}
		}
	case "ct_flip":
		t.TamperCiphertext = func(ct []MpcOtPair) {
			if len(ct) > 0 {
				ct[0][0] = otFlip(ct[0][0], 1)
			}
		}
	case "ct_flip1":
		t.TamperCiphertext = func(ct []MpcOtPair) {
			if len(ct) > 0 {
				ct[len(ct)-1][1] = otFlip(ct[len(ct)-1][1], 0x80)
			}
		}
	default:
		return nil, errors.New("unknown tamper " + name)
	}
	return t, nil
}

func otKemTamper(name any) *MpcKemMalTamper {
	switch name {
	case "badKey":
		return &MpcKemMalTamper{TamperOpenedKeys: func(pk []MpcOtPair) {
			if len(pk) > 0 {
				pk[0][0], pk[0][1] = pk[0][1], pk[0][0]
			}
		}}
	case "badSid":
		return &MpcKemMalTamper{TamperReceiverSid: func(s []byte) []byte { return otFlip(s, 1) }}
	}
	return nil
}

func otIdx(v any) (int64, error) {
	f, ok := jsNum(v)
	if !ok || f != float64(int64(f)) {
		return 0, errors.New("not an integer")
	}
	return int64(f), nil
}

func otEcOp(a []any) (any, error) {
	op, _ := vecArg(a, 0).(string)
	switch op {
	case "mulBase":
		k, err := mpcB(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		p := MpcEcMulBase(k)
		return map[string]any{"p": otAff(p), "enc": frostOut(MpcEcEncodePoint(p)), "comp": frostOut(MpcEcCompress(p))}, nil
	case "mul":
		k, err := mpcB(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		p, err := otPt(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		return otAff(MpcEcMul(k, p)), nil
	case "add", "sub":
		p, err := otPt(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		q, err := otPt(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		if op == "add" {
			return otAff(MpcEcAdd(p, q)), nil
		}
		return otAff(MpcEcSub(p, q)), nil
	case "neg", "dbl":
		p, err := otPt(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		if op == "neg" {
			return otAff(MpcEcNeg(p)), nil
		}
		return otAff(MpcEcDbl(p)), nil
	case "decompress":
		b, err := otBytes(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		p, err := MpcEcDecompress(b)
		if err != nil {
			return nil, err
		}
		return map[string]any{"p": otAff(p), "onCurve": true, "identity": MpcEcIsIdentity(p), "prime": MpcEcHasPrimeOrder(p), "inSub": MpcEcIsInSubgroup(p)}, nil
	}
	return nil, errors.New("unknown op " + op)
}

// otExtIdentity is the projective identity test on raw coordinates (an off-curve point can still equal the identity's coordinates).
func otExtIdentity(v any) bool {
	c, err := mpcBA(v)
	if err != nil || len(c) != 4 {
		return false
	}
	x, y, z := new(big.Int).Mod(c[0], mpcEcQ), new(big.Int).Mod(c[1], mpcEcQ), new(big.Int).Mod(c[2], mpcEcQ)
	return x.Sign() == 0 && y.Cmp(z) == 0
}

func otEcValidate(a []any) (any, error) {
	p, err := otPt(vecArg(a, 0))
	if err != nil {
		return map[string]any{"onCurve": false, "identity": otExtIdentity(vecArg(a, 0)), "prime": false, "inSubgroup": false}, nil
	}
	return map[string]any{"onCurve": true, "identity": MpcEcIsIdentity(p), "prime": MpcEcHasPrimeOrder(p), "inSubgroup": MpcEcIsInSubgroup(p)}, nil
}

func otSchnorr(a []any) (any, error) {
	y, err := mpcB(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	nonce, err := mpcB(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	ctx, err := otBytes(vecArg(a, 2))
	if err != nil {
		return nil, err
	}
	S := MpcEcMulBase(y)
	proof, err := MpcSchnorrProve(y, S, func() *big.Int { return nonce }, ctx)
	if err != nil {
		return nil, err
	}
	other := []byte("other-ctx")
	forged := &MpcSchnorrProof{proof.U, new(big.Int).Mod(new(big.Int).Add(proof.Z, big.NewInt(1)), MpcEcL)}
	oor := &MpcSchnorrProof{proof.U, MpcEcL}
	return map[string]any{"S": otAff(S), "U": otAff(proof.U), "z": proof.Z.String(), "ok": MpcSchnorrVerify(S, proof, ctx), "badCtx": MpcSchnorrVerify(S, proof, other),
		"forged": MpcSchnorrVerify(S, forged, ctx), "oor": MpcSchnorrVerify(S, oor, ctx),
		"wrongS":    MpcSchnorrVerify(MpcEcMulBase(new(big.Int).Add(y, big.NewInt(1))), proof, ctx),
		"identityS": MpcSchnorrVerify(MpcEcIdentity(), proof, ctx)}, nil
}

func otWordsOp(a []any, f func(w []uint32) ([]uint32, error)) (any, error) {
	w, err := otWords(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	out, err := f(w)
	if err != nil {
		return nil, err
	}
	return otWordsOut(out), nil
}

func otKernels() map[string]vecFn {
	return map[string]vecFn{
		"ecOp":       otEcOp,
		"ecValidate": otEcValidate,
		"ecAssert": func(a []any) (any, error) {
			p, err := otPt(vecArg(a, 0))
			if err != nil {
				return nil, errors.New("p: not on curve")
			}
			return true, MpcEcAssertInSubgroup(p, "p")
		},
		"schnorr": otSchnorr,
		"prg": func(a []any) (any, error) {
			seed, err := otBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			sb, ok := jsNum(vecArg(a, 1))
			if !ok || sb < 0 {
				return nil, errors.New("bad start block")
			}
			n, err := mpcI(vecArg(a, 2))
			if err != nil || n < 0 {
				return nil, errors.New("bad word count")
			}
			return otWordsOut(MpcOtxPrgColumn(seed, uint64(sb), n)), nil
		},
		"maskTail": func(a []any) (any, error) {
			nb, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return otWordsOp(a, func(w []uint32) ([]uint32, error) { MpcOtxMaskTail(w, nb); return w, nil })
		},
		"transpose32": func(a []any) (any, error) {
			return otWordsOp(a, func(w []uint32) ([]uint32, error) {
				if len(w) != 32 {
					return nil, errors.New("transpose32 needs 32 words")
				}
				MpcOtxTranspose32(w, 0)
				return w, nil
			})
		},
		"transposeCols": func(a []any) (any, error) {
			W, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			rows, err := mpcI(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return otWordsOp(a, func(w []uint32) ([]uint32, error) { return MpcOtxTransposeCols(w, W, rows) })
		},
		"gfMulX": func(a []any) (any, error) {
			return otWordsOp(a, func(w []uint32) ([]uint32, error) { MpcOtxGfMulX(w); return w, nil })
		},
		"gfXorInto": func(a []any) (any, error) {
			b, err := otWords(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return otWordsOp(a, func(w []uint32) ([]uint32, error) { MpcOtxGfXorInto(w, b, 0); return w, nil })
		},
		"gfBig": func(a []any) (any, error) {
			w, err := otWords(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			v := MpcOtxGfToBig(w)
			return map[string]any{"big": v.String(), "back": otWordsOut(MpcOtxGfFromBig(v))}, nil
		},
		"accumColumn": func(a []any) (any, error) {
			chi, err := otWords(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return otWordsOp(a, func(col []uint32) ([]uint32, error) {
				acc := make([]uint32, 4)
				MpcOtxAccumColumn(col, chi, acc)
				return acc, nil
			})
		},
		"kosCombine": func(a []any) (any, error) {
			W, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			chi, err := otWords(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return otWordsOp(a, func(w []uint32) ([]uint32, error) { return MpcOtxKosCombine(w, W, chi) })
		},
		"tmmo": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			off, ok := jsNum(vecArg(a, 2))
			if !ok || off != float64(int64(off)) {
				return nil, errors.New("tweak offset must be a non-negative safe integer")
			}
			dom, err := otWords(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			return otWordsOp(a, func(w []uint32) ([]uint32, error) { return MpcOtxTmmoCrh(w, n, &MpcOtTweak{int64(off), dom}) })
		},
		"tweakDomain": func(a []any) (any, error) {
			b, err := otBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return otWordsOut(MpcOtxTweakDomain(b)), nil
		},
		"bigBytes": func(a []any) (any, error) {
			v, err := mpcB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			n, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			b, err := MpcOtxBigToBytes(v, n)
			return frostOut(b), err
		},
		"bytesBig": func(a []any) (any, error) {
			b, err := otBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return MpcOtxBytesToBig(b).String(), nil
		},
		"word64": func(a []any) (any, error) {
			w, err := otWords(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			j, err := mpcI(vecArg(a, 1))
			if err != nil || j < 0 || 2*j+1 >= len(w) {
				return nil, errors.New("word64 index out of range")
			}
			return new(big.Int).SetUint64(MpcOtxWord64(w, j)).String(), nil
		},
	}
}

func otBaseFns() map[string]vecFn {
	return map[string]vecFn{
		"bindingBytes": func(a []any) (any, error) {
			sess, err := otBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			s, err := otIdx(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			r, err := otIdx(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			round, ok := vecArg(a, 3).(string)
			if !ok {
				return nil, errors.New("round must be a string")
			}
			b, err := MpcBindingBytes(MpcBaseOtBinding{sess, s, r, round})
			return frostOut(b), err
		},
		"baseOtKdf": func(a []any) (any, error) {
			i, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			b0 := MpcRandomBinding(MpcOtRandomFromSeed(big.NewInt(4242)), "base-ot")
			R := []*ed.Point{MpcEcMulBase(big.NewInt(5)), MpcEcMulBase(big.NewInt(6))}
			th, err := MpcBaseOtTranscriptHash(b0, MpcEcMulBase(big.NewInt(3)), R)
			if err != nil {
				return nil, err
			}
			return map[string]any{"th": frostOut(th), "k": frostOut(MpcBaseOtKdf(th, i, R[0], MpcEcMulBase(big.NewInt(9))))}, nil
		},
		"randomOt": func(a []any) (any, error) {
			choices, err := mpcIA(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			rng, err := otRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			name, _ := vecArg(a, 2).(string)
			tamper, err := otTamper(name)
			if err != nil {
				return nil, err
			}
			r, err := MpcMalBaseRandomOT(choices, rng, tamper, nil)
			if err != nil {
				return nil, err
			}
			return map[string]any{"S": otAff(r.S), "U": otAff(r.Proof.U), "z": r.Proof.Z.String(), "R": otAffs(r.R), "senderPads": otPairsOut(r.SenderPads), "recvPads": otBL(r.RecvPads)}, nil
		},
		"baseOt": func(a []any) (any, error) {
			msgs, err := otPairs(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			choices, err := mpcIA(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			rng, err := otRng(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			name, _ := vecArg(a, 3).(string)
			tamper, err := otTamper(name)
			if err != nil {
				return nil, err
			}
			res, err := MpcBaseOT(msgs, choices, rng, tamper, nil)
			if err != nil {
				return nil, err
			}
			t := res.Transcript
			return map[string]any{"received": otBL(res.Received), "S": otAff(t.S), "U": otAff(t.Proof.U), "z": t.Proof.Z.String(), "R": otAffs(t.R),
				"ct": otPairsOut(t.CT), "com": otPairsOut(t.Com)}, nil
		},
	}
}

func otChannel(a []any) (any, error) {
	choices, err := mpcIA(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	m0, err := mpcBA(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	m1, err := mpcBA(vecArg(a, 2))
	if err != nil {
		return nil, err
	}
	rng, err := otRng(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	rounds, err := mpcI(vecArg(a, 4))
	if err != nil {
		return nil, err
	}
	ch := NewMpcOtChannel(rng, nil, nil)
	tn, _ := vecArg(a, 5).(string)
	switch tn {
	case "flip00":
		ch.TamperU = func(u []*big.Int, _ int) { u[0] = new(big.Int).Xor(u[0], big.NewInt(1)) }
	case "flipLast":
		ch.TamperU = func(u []*big.Int, _ int) { u[127] = new(big.Int).Xor(u[127], big.NewInt(1<<5)) }
	case "oversize":
		ch.TamperU = func(u []*big.Int, _ int) { u[3] = new(big.Int).Or(u[3], new(big.Int).Lsh(big.NewInt(1), 5000)) }
	case "negative":
		ch.TamperU = func(u []*big.Int, _ int) { u[3] = big.NewInt(-1) }
	case "round2flip":
		ch.TamperU = func(u []*big.Int, round int) {
			if round == 1 {
				u[10] = new(big.Int).Xor(u[10], big.NewInt(2))
			}
		}
	}
	outs := []any{}
	for k := 0; k < rounds; k++ {
		e, err := ch.Extend(choices, m0, m1)
		if err != nil {
			return nil, err
		}
		outs = append(outs, map[string]any{"received": mpcL(e.Received), "uMatrix": mpcL(e.UMatrix)})
	}
	sel, err := ch.Selector()
	if err != nil {
		return nil, err
	}
	var base any
	if ch.BaseTranscript != nil {
		base = map[string]any{"S": otAff(ch.BaseTranscript.S), "R": len(ch.BaseTranscript.R)}
	}
	return map[string]any{"selector": sel.String(), "outs": outs, "base": base}, nil
}

func otKosChi(a []any) (any, error) {
	b, err := otBytes(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	round, err := mpcI(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	u, err := mpcBA(vecArg(a, 2))
	if err != nil {
		return nil, err
	}
	mExt, err := mpcI(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	w, err := MpcKosChiWords(b, round, u, mExt, nil)
	if err != nil {
		return nil, err
	}
	chi, err := MpcKosChallenges(b, round, u, mExt)
	if err != nil {
		return nil, err
	}
	return map[string]any{"w": otWordsOut(w), "chi": mpcL(chi)}, nil
}

func otKemFns() map[string]vecFn {
	return map[string]vecFn{
		"kemOt": func(a []any) (any, error) {
			fn, _ := vecArg(a, 0).(string)
			msgs, err := otPairs(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			choices, err := mpcIA(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			rng, err := otRng(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			tamper := otKemTamper(vecArg(a, 4))
			switch fn {
			case "kemBaseOT":
				r, err := MpcKemBaseOT(msgs, choices, rng)
				if err != nil {
					return nil, err
				}
				t := r.Transcript
				return map[string]any{"received": otBL(r.Received), "transcript": map[string]any{"publicKeys": otPairsOut(t.PublicKeys),
					"ciphertexts": otPairsOut(t.Ciphertexts), "encrypted": otPairsOut(t.Encrypted)}}, nil
			case "kemBaseOtMal":
				r, err := MpcKemBaseOtMal(msgs, choices, rng, tamper)
				if err != nil {
					return nil, err
				}
				t := r.Transcript
				return map[string]any{"received": otBL(r.Received), "transcript": map[string]any{"rn": frostOut(t.Rn), "commitments": otBL(t.Commitments),
					"sn": frostOut(t.Sn), "publicKeys": otPairsOut(t.PublicKeys), "ciphertexts": otPairsOut(t.Ciphertexts), "encrypted": otPairsOut(t.Encrypted)}}, nil
			case "kemBaseOtMalRandom":
				r, err := MpcKemBaseOtMalRandom(choices, rng, tamper)
				if err != nil {
					return nil, err
				}
				t := r.Transcript
				return map[string]any{"senderSecrets": otPairsOut(r.SenderSecrets), "recvSecrets": otBL(r.RecvSecrets), "sid": frostOut(r.Sid),
					"transcript": map[string]any{"rn": frostOut(t.Rn), "commitments": otBL(t.Commitments), "sn": frostOut(t.Sn),
						"publicKeys": otPairsOut(t.PublicKeys), "ciphertexts": otPairsOut(t.Ciphertexts)}}, nil
			}
			return nil, errors.New("unknown fn " + fn)
		},
		"kemPad": func(a []any) (any, error) {
			if len(a) == 1 {
				n, err := mpcI(a[0])
				if err != nil {
					return nil, err
				}
				b, err := MpcKemOtPad(0, 0, make([]byte, 32), n)
				return frostOut(b), err
			}
			idx, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			slot, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			n, err := mpcI(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			ss := make([]byte, 32)
			for k := range ss {
				ss[k] = byte(k)
			}
			b, err := MpcKemOtPad(idx, slot, ss, n)
			return frostOut(b), err
		},
		"hybridOt": func(a []any) (any, error) {
			msgs, err := otPairs(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			choices, err := mpcIA(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			rng, err := otRng(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			var t *MpcHybridBaseOtTamper
			if tn, ok := vecArg(a, 3).(string); ok {
				t = &MpcHybridBaseOtTamper{}
				switch tn {
				case "ec":
					t.EC, _ = otTamper("ct_flip")
				case "ecS":
					t.EC, _ = otTamper("S_identity")
				case "enc":
					t.TamperEncrypted = func(e []MpcOtPair) { e[0][0] = otFlip(e[0][0], 1) }
				case "kem":
					t.Kem = otKemTamper("badKey")
				}
			}
			r, err := MpcHybridBaseOT(msgs, choices, rng, t)
			if err != nil {
				return nil, err
			}
			tr := r.Transcript
			return map[string]any{"received": otBL(r.Received), "sid": frostOut(tr.Sid), "ecS": otAff(tr.EcS), "kemSid": frostOut(tr.KemSid),
				"encrypted": otPairsOut(tr.Encrypted), "commitments": otPairsOut(tr.Commitments)}, nil
		},
		"hybridKey": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			fill := func(l int, v byte) []byte {
				b := make([]byte, l)
				for i := range b {
					b[i] = v
				}
				return b
			}
			b, err := MpcHybridTransferKey(fill(32, 1), 3, 1, fill(16, 2), fill(32, 3), n)
			return frostOut(b), err
		},
	}
}

func otOfflineOptions(v any) (*MpcNoDealerOptions, map[string]any, error) {
	if v == nil {
		return nil, nil, nil
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, nil, errors.New("options must be an object")
	}
	opts := &MpcNoDealerOptions{UnsafeStatSec: o["unsafe"] == true}
	if b, ok := o["sacrifice"].(bool); ok {
		opts.Sacrifice = &b
	}
	for k, dst := range map[string]**int{"partners": &opts.SacrificePartners, "keys": &opts.MacKeys, "statSec": &opts.StatSec} {
		if o[k] == nil {
			continue
		}
		n, err := mpcI(o[k])
		if err != nil {
			return nil, nil, err
		}
		*dst = &n
	}
	if o["dev"] != nil {
		d, ok := o["dev"].([]any)
		if !ok || len(d) != 2 {
			return nil, nil, errors.New("bad deviation")
		}
		pm, err := mpcI(d[0])
		if err != nil {
			return nil, nil, err
		}
		delta, err := mpcB(d[1])
		if err != nil {
			return nil, nil, err
		}
		opts.Deviation = &MpcOfflineDeviation{pm, delta}
	}
	return opts, o, nil
}

func otOffline(a []any) (any, error) {
	n, err := mpcI(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	seed, err := mpcB(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	what, _ := vecArg(a, 2).(string)
	opts, o, err := otOfflineOptions(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	off, err := MpcMakeNoDealerOffline(n, seed, opts)
	if err != nil {
		return nil, err
	}
	base := map[string]any{"n": off.N(), "statSec": off.StatSec, "ctx": mpcCtxOut(off.MacContext())}
	switch what {
	case "ctx":
		return base, nil
	case "triple":
		t, err := off.GenAuthTriple()
		if err != nil {
			return nil, err
		}
		base["t"] = mpcTripleOut(*t)
		return base, nil
	case "input":
		val, err := mpcB(o["value"])
		if err != nil {
			return nil, err
		}
		owner, err := mpcI(o["owner"])
		if err != nil {
			return nil, err
		}
		v, err := off.AuthInput(val, owner)
		if err != nil {
			return nil, err
		}
		base["v"] = mpcSVOut(v)
		return base, nil
	case "multiply":
		x, err := mpcBA(o["x"])
		if err != nil {
			return nil, err
		}
		y, err := mpcBA(o["y"])
		if err != nil {
			return nil, err
		}
		z, err := off.OtShareMultiply(x, y)
		if err != nil {
			return nil, err
		}
		sum, sx, sy := new(big.Int), new(big.Int), new(big.Int)
		for _, v := range z {
			sum = MpcFAdd(sum, v)
		}
		for _, v := range x {
			sx = MpcFAdd(sx, v)
		}
		for _, v := range y {
			sy = MpcFAdd(sy, v)
		}
		base["z"], base["sum"], base["expect"] = mpcL(z), sum.String(), MpcFMul(sx, sy).String()
		return base, nil
	case "consistency":
		values, err := mpcBA(o["values"])
		if err != nil {
			return nil, err
		}
		ins := make([]MpcAuthSV, len(values))
		for i, v := range values {
			if ins[i], err = off.AuthInput(v, i%n); err != nil {
				return nil, err
			}
		}
		if o["tamper"] == true {
			ins[0].Value[0] = MpcFAdd(ins[0].Value[0], big.NewInt(1))
		}
		if err := off.CheckInputConsistency(ins); err != nil {
			return nil, err
		}
		base["ok"] = true
		return base, nil
	}
	return nil, errors.New("unknown what " + what)
}

func otOfflineBlame(a []any) (any, error) {
	n, err := mpcI(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	seed, err := mpcB(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	pm, err := mpcI(vecArg(a, 2))
	if err != nil {
		return nil, err
	}
	delta, err := mpcB(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	off, err := MpcMakeNoDealerOffline(n, seed, &MpcNoDealerOptions{Deviation: &MpcOfflineDeviation{pm, delta}})
	if err != nil {
		return nil, err
	}
	_, err = off.GenAuthTriple()
	var ab *MpcOfflineCheatingAbort
	if errors.As(err, &ab) {
		return map[string]any{"aborted": true, "name": "OfflineCheatingAbort", "blamed": mpcIL(ab.Blamed)}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"aborted": false}, nil
}

func otNoDealerRun(a []any) (any, error) {
	vs, err := mpcVectors(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	m, ok := vecArg(a, 1).(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	cfg, err := mpcConfig(m)
	if err != nil {
		return nil, err
	}
	r, err := MpcComposeSecureMalicious(vs, cfg)
	if err != nil {
		return nil, err
	}
	return map[string]any{"composed": mpcDecision(r.Composed), "parties": r.Parties, "Q": r.Q, "opens": r.Opens, "multiplications": r.Multiplications,
		"offlineMode": r.OfflineMode, "triplesVerified": r.TriplesVerified, "macChecked": r.MacChecked}, nil
}

func TestMpcOtVectors(t *testing.T) {
	fns := map[string]vecFn{"channel": otChannel, "kosChi": otKosChi, "offline": otOffline, "offlineBlame": otOfflineBlame, "noDealerRun": otNoDealerRun}
	for _, group := range []map[string]vecFn{otKernels(), otBaseFns(), otKemFns()} {
		for k, f := range group {
			fns[k] = f
		}
	}
	replayVectors(t, "ref-mpc-ot.json.gz", fns)
	replaySecretGen(t, "ref-mpc-ot.json.gz", func(t *testing.T, p string) { replayVectors(t, p, fns) })
}
