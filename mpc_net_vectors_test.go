package pca

// Replays the networked-runner corpus (wire codec, pairwise-authenticated shares, forensics, codecs, including the curve-point
// codec jPt / ptJ). Bytes cross as {"$bytes": b64u}; big integers as decimal strings.

import (
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"testing"
)

func mpcnBytes(v any) ([]byte, error) {
	b := baseBytes(v)
	if b == nil {
		return nil, errors.New("expected bytes")
	}
	return b, nil
}

func mpcnPA(v any) (MpcPA, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return MpcPA{}, errors.New("not an object")
	}
	x, err := mpcB(m["x"])
	if err != nil {
		return MpcPA{}, err
	}
	tag, err := mpcBA(m["tag"])
	if err != nil {
		return MpcPA{}, err
	}
	key, err := mpcBA(m["key"])
	return MpcPA{x, tag, key}, err
}

func mpcnAW(v any) (MpcAW, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return MpcAW{}, errors.New("not an object")
	}
	pv, err := mpcnPA(m["v"])
	if err != nil {
		return MpcAW{}, err
	}
	l, _ := m["m"].([]any)
	ms := make([]MpcPA, len(l))
	for i, x := range l {
		if ms[i], err = mpcnPA(x); err != nil {
			return MpcAW{}, err
		}
	}
	return MpcAW{pv, ms}, nil
}

func mpcnPAJ(p MpcPA) map[string]any {
	return map[string]any{"x": p.X.String(), "tag": mpcL(p.Tag), "key": mpcL(p.Key)}
}

func mpcnAWJ(a MpcAW) map[string]any {
	ms := []any{}
	for _, p := range a.M {
		ms = append(ms, mpcnPAJ(p))
	}
	return map[string]any{"v": mpcnPAJ(a.V), "m": ms}
}

func mpcnNums(l []*big.Int) []any { return mpcL(l) }

func mpcnPaOp(a []any) (any, error) {
	op, _ := vecArg(a, 0).(string)
	p, err := mpcnPA(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	n := len(p.Tag)
	two := func() (MpcPA, error) { return mpcnPA(vecArg(a, 2)) }
	switch op {
	case "add", "sub":
		q, err := two()
		if err != nil {
			return nil, err
		}
		if op == "add" {
			return mpcnPAJ(MpcPaAdd(p, q)), nil
		}
		return mpcnPAJ(MpcPaSub(p, q)), nil
	case "neg":
		return mpcnPAJ(MpcPaNeg(p)), nil
	case "scale":
		c, err := mpcB(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		return mpcnPAJ(MpcPaScale(p, c)), nil
	case "addPublic0":
		id, err := mpcI(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		d, err := mpcB(vecArg(a, 3))
		if err != nil {
			return nil, err
		}
		c, err := mpcB(vecArg(a, 5))
		if err != nil {
			return nil, err
		}
		return mpcnPAJ(MpcPaAddPublic0(MpcPaEnv{id, n, d, vecArg(a, 4) == true}, p, c)), nil
	case "verify":
		id, err := mpcI(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		d, err := mpcB(vecArg(a, 3))
		if err != nil {
			return nil, err
		}
		from, err := mpcI(vecArg(a, 4))
		if err != nil {
			return nil, err
		}
		x, err := mpcB(vecArg(a, 5))
		if err != nil {
			return nil, err
		}
		tag, err := mpcB(vecArg(a, 6))
		if err != nil {
			return nil, err
		}
		if from < 0 || from >= len(p.Key) {
			return nil, errors.New("peer out of range")
		}
		return MpcPaVerify(MpcPaEnv{id, n, d, true}, p, from, x, tag), nil
	case "flat":
		id, err := mpcI(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		tg := vecArg(a, 3) == true
		f := MpcPaFlat(p, id, n, tg)
		back, err := MpcPaParse(f, 0, id, n, tg)
		if err != nil {
			return nil, err
		}
		return map[string]any{"f": mpcnNums(f), "w": MpcPaWidth(n, tg), "back": mpcnPAJ(back)}, nil
	}
	return nil, errors.New("unknown op " + op)
}

func mpcnAwOp(a []any) (any, error) {
	if len(a) == 1 {
		p, err := mpcI(a[0])
		return MpcSharingsPerTriple(p), err
	}
	x, err := mpcnAW(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	n, keys := len(x.V.Tag), len(x.M)
	if len(a) == 3 {
		id, err := mpcI(a[1])
		if err != nil {
			return nil, err
		}
		tg := a[2] == true
		f := MpcAwFlat(x, id, n, tg)
		back, err := MpcAwParse(f, 0, id, n, keys, tg)
		if err != nil {
			return nil, err
		}
		return map[string]any{"f": mpcnNums(f), "w": MpcAwWidth(n, keys, tg), "back": mpcnAWJ(back)}, nil
	}
	y, err := mpcnAW(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	al, _ := vecArg(a, 2).([]any)
	alpha := make([]MpcPA, len(al))
	for i, v := range al {
		if alpha[i], err = mpcnPA(v); err != nil {
			return nil, err
		}
	}
	tg := vecArg(a, 3) == true
	c, err := mpcB(vecArg(a, 4))
	if err != nil {
		return nil, err
	}
	if len(alpha) < len(x.M) {
		return nil, errors.New("alpha has fewer keys than the value")
	}
	return map[string]any{
		"add": mpcnAWJ(MpcWAdd(x, y)), "sub": mpcnAWJ(MpcWSub(x, y)), "neg": mpcnAWJ(MpcWNeg(x)), "scale": mpcnAWJ(MpcWScale(x, c)),
		"addPublic":  mpcnAWJ(MpcWAddPublic(MpcPaEnv{1, n, big.NewInt(7), tg}, x, c, alpha)),
		"addPublic0": mpcnAWJ(MpcWAddPublic(MpcPaEnv{0, n, big.NewInt(7), tg}, x, c, alpha)),
	}, nil
}

func mpcnSideIn(v any) ([]MpcPeerEntry, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	var out []MpcPeerEntry
	for _, e := range l {
		pr, ok := e.([]any)
		if !ok || len(pr) != 2 {
			return nil, errors.New("bad entry")
		}
		p, err := mpcI(pr[0])
		if err != nil {
			return nil, err
		}
		vals, err := mpcBA(pr[1])
		if err != nil {
			return nil, err
		}
		out = append(out, MpcPeerEntry{p, vals})
	}
	return out, nil
}

func mpcnSideJ(es []MpcPeerEntry) []any {
	out := []any{}
	for _, e := range es {
		out = append(out, []any{e.Peer, mpcL(e.Vals)})
	}
	return out
}

func mpcnDis(v any) ([]MpcSlotDisclosure, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	var out []MpcSlotDisclosure
	for _, so := range l {
		s, ok := so.(map[string]any)
		if !ok {
			return nil, errors.New("not an object")
		}
		var d MpcSlotDisclosure
		var err error
		if d.Bits, err = mpcIA(s["bits"]); err != nil {
			return nil, err
		}
		if d.Y, err = mpcB(s["y"]); err != nil {
			return nil, err
		}
		if d.Z, err = mpcB(s["z"]); err != nil {
			return nil, err
		}
		if d.Recv, err = mpcnSideIn(s["recv"]); err != nil {
			return nil, err
		}
		if d.Rho, err = mpcnSideIn(s["rho"]); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func mpcnBlame(me int, r *MpcAuditResult) any {
	if p, ok := MpcBlameFrom(me, r); ok {
		return p
	}
	return nil
}

func mpcnForensics(a []any) (any, error) {
	switch len(a) {
	case 1:
		p, err := mpcI(a[0])
		return MpcSlotsFor(p), err
	case 3:
		if m, ok := a[0].(map[string]any); ok {
			all := map[int][]MpcSlotDisclosure{}
			for k, v := range m {
				id, err := mpcI(json.Number(k))
				if err != nil {
					return nil, err
				}
				if all[id], err = mpcnDis(v); err != nil {
					return nil, err
				}
			}
			if a[2] != nil {
				rm, err := mpcI(a[2])
				if err != nil {
					return nil, err
				}
				delete(all, rm)
			}
			gad, err := mpcBA(a[1])
			if err != nil {
				return nil, err
			}
			res, err := MpcAuditDisclosures(all, gad)
			if err != nil {
				return nil, err
			}
			pb := []any{}
			for _, p := range res.PairBad {
				pb = append(pb, []any{p[0], p[1]})
			}
			blame := []any{}
			for me := 0; me < 3; me++ {
				blame = append(blame, mpcnBlame(me, res))
			}
			sb := []any{}
			for _, p := range res.SelfBad {
				sb = append(sb, p)
			}
			return map[string]any{"selfBad": sb, "pairBad": pb, "blame": blame}, nil
		}
		me, err := mpcI(a[0])
		if err != nil {
			return nil, err
		}
		res := &MpcAuditResult{}
		sl, _ := a[1].([]any)
		for _, x := range sl {
			p, err := mpcI(x)
			if err != nil {
				return nil, err
			}
			res.SelfBad = append(res.SelfBad, p)
		}
		sort.Ints(res.SelfBad)
		pl, _ := a[2].([]any)
		for _, x := range pl {
			pr, _ := x.([]any)
			if len(pr) != 2 {
				return nil, errors.New("bad pair")
			}
			p0, err := mpcI(pr[0])
			if err != nil {
				return nil, err
			}
			p1, err := mpcI(pr[1])
			if err != nil {
				return nil, err
			}
			res.PairBad = append(res.PairBad, [2]int{p0, p1})
		}
		return mpcnBlame(me, res), nil
	case 4:
		slots, err := mpcI(a[1])
		if err != nil {
			return nil, err
		}
		rows, err := mpcI(a[2])
		if err != nil {
			return nil, err
		}
		peers, err := mpcIA(a[3])
		if err != nil {
			return nil, err
		}
		dd, err := MpcParseDisclosure(a[0], slots, rows, peers)
		if err != nil {
			return nil, err
		}
		ddj := []any{}
		for _, s := range dd {
			ddj = append(ddj, map[string]any{"bits": mpcIL(s.Bits), "y": s.Y.String(), "z": s.Z.String(), "recv": mpcnSideJ(s.Recv), "rho": mpcnSideJ(s.Rho)})
		}
		return map[string]any{"dd": ddj, "back": MpcWireDisclosure(dd)}, nil
	case 6:
		sid, _ := a[0].(string)
		party, err := mpcI(a[1])
		if err != nil {
			return nil, err
		}
		idx, err := mpcI(a[2])
		if err != nil {
			return nil, err
		}
		dl, ok := jsNum(a[3])
		if !ok {
			return nil, errors.New("not a number")
		}
		nonce, _ := a[4].(string)
		return MpcDisclosureCommit(sid, party, idx, int64(dl), nonce, a[5])
	}
	return nil, errors.New("forensics arity")
}

func TestMpcNetVectors(t *testing.T) {
	replayVectors(t, "ref-mpc-net.json.gz", map[string]vecFn{
		"encodeFrame": func(a []any) (any, error) {
			f, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("not an object")
			}
			ty, ok1 := f["ty"].(string)
			sid, ok2 := f["sid"].(string)
			rd, ok3 := f["rd"].(string)
			if !ok1 || !ok2 || !ok3 {
				return nil, errors.New("frame fields must be strings")
			}
			b, err := MpcEncodeFrame(f["v"], ty, sid, f["seq"], rd, f["d"])
			return frostOut(b), err
		},
		"split": func(a []any) (any, error) {
			var s MpcFrameSplitter
			frames := []any{}
			l, _ := vecArg(a, 0).([]any)
			for _, c := range l {
				b, err := mpcnBytes(c)
				if err != nil {
					return nil, err
				}
				out, err := s.Push(b)
				if err != nil {
					return nil, err
				}
				for _, f := range out {
					frames = append(frames, frostOut(f))
				}
			}
			return map[string]any{"frames": frames}, nil
		},
		"peekVersion": func(a []any) (any, error) {
			b, err := mpcnBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			if v, ok := MpcPeekVersion(b); ok {
				return v, nil
			}
			return nil, nil
		},
		"parseFrame": func(a []any) (any, error) {
			b, err := mpcnBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			if m := MpcParseFrame(b); m != nil {
				return m, nil
			}
			return nil, nil
		},
		"versionMismatch": func(a []any) (any, error) {
			b, err := mpcnBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			if v, ok := MpcVersionMismatch(b); ok {
				return v, nil
			}
			return nil, nil
		},
		"hx": func(a []any) (any, error) {
			x, err := mpcB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return MpcHx(x), nil
		},
		"unhx": func(a []any) (any, error) {
			if v := MpcUnhx(vecArg(a, 0)); v != nil {
				return v.String(), nil
			}
			return nil, nil
		},
		"unhxArray": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			if v := MpcUnhxArray(vecArg(a, 0), n); v != nil {
				return mpcL(v), nil
			}
			return nil, nil
		},
		"netAbort": func(a []any) (any, error) {
			kind, _ := vecArg(a, 0).(string)
			var blamed *int
			if vecArg(a, 1) != nil {
				b, err := mpcI(a[1])
				if err != nil {
					return nil, err
				}
				blamed = &b
			}
			reporter, err := mpcI(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			detail, _ := vecArg(a, 3).(string)
			var ck *string
			if s, ok := vecArg(a, 4).(string); ok {
				ck = &s
			}
			var cb *int
			if _, isNum := jsNum(vecArg(a, 5)); isNum {
				b, err := mpcI(a[5])
				if err != nil {
					return nil, err
				}
				cb = &b
			}
			var reason *string
			var evidence any
			var dl *int
			if op, ok := vecArg(a, 6).(map[string]any); ok {
				if s, ok := op["reason"].(string); ok {
					reason = &s
				}
				evidence = op["evidence"]
				if op["deadlineMs"] != nil {
					d, err := mpcI(op["deadlineMs"])
					if err != nil {
						return nil, err
					}
					dl = &d
				}
			}
			e := NewMpcNetAbort(kind, blamed, reporter, detail, ck, cb, reason, evidence, dl)
			out := map[string]any{"message": e.Error(), "name": "NetAbort", "kind": e.Kind, "blamed": nil, "reporter": e.Reporter, "reason": nil,
				"claimedKind": nil, "claimedBlame": nil, "evidence": e.Evidence, "deadlineMs": nil}
			if e.Blamed != nil {
				out["blamed"] = *e.Blamed
			}
			if e.Reason != nil {
				out["reason"] = *e.Reason
			}
			if e.ClaimedKind != nil {
				out["claimedKind"] = *e.ClaimedKind
			}
			if e.ClaimedBlame != nil {
				out["claimedBlame"] = *e.ClaimedBlame
			}
			if e.DeadlineMs != nil {
				out["deadlineMs"] = *e.DeadlineMs
			}
			return out, nil
		},
		"abortKinds": func(a []any) (any, error) {
			out := []any{}
			for _, k := range MpcAbortKinds {
				out = append(out, k)
			}
			return out, nil
		},
		"pa":        mpcnPaOp,
		"aw":        mpcnAwOp,
		"forensics": mpcnForensics,
		"codec": func(a []any) (any, error) {
			op, _ := vecArg(a, 0).(string)
			switch op {
			case "unb64":
				n := -1
				if vecArg(a, 2) != nil {
					var err error
					if n, err = mpcI(a[2]); err != nil {
						return nil, err
					}
				}
				b, err := MpcUnb64(vecArg(a, 1), n)
				return frostOut(b), err
			case "b64":
				b, err := mpcnBytes(vecArg(a, 1))
				return MpcB64(b), err
			case "hexBig":
				v, err := MpcHexBig(vecArg(a, 1))
				if err != nil {
					return nil, err
				}
				return v.String(), nil
			case "gadgetCommit":
				party, err := mpcI(vecArg(a, 2))
				if err != nil {
					return nil, err
				}
				seed, err := mpcnBytes(vecArg(a, 3))
				if err != nil {
					return nil, err
				}
				sid, _ := vecArg(a, 1).(string)
				return MpcGadgetCommit(sid, party, seed), nil
			case "gadgetStatement":
				signer, err := mpcI(vecArg(a, 3))
				if err != nil {
					return nil, err
				}
				sid, _ := vecArg(a, 1).(string)
				round, _ := vecArg(a, 2).(string)
				val, _ := vecArg(a, 4).(string)
				b, err := MpcGadgetStatement(sid, round, signer, val)
				return frostOut(b), err
			case "jPt":
				p, err := MpcJPt(vecArg(a, 1))
				if err != nil {
					return nil, err
				}
				return MpcPtJ(p), nil
			case "ptJ":
				k, err := mpcB(vecArg(a, 1))
				if err != nil {
					return nil, err
				}
				return MpcPtJ(MpcEcMulBase(k)), nil
			}
			return nil, errors.New("unknown op " + op)
		},
	})
}
