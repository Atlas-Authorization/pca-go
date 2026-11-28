package pca

// Replays the MPC deterministic-layer corpus: every random draw comes from the seeded SplitMix64 field source, so shares, MAC keys
// and transcripts match the reference value for value. Big integers cross as DECIMAL STRINGS (arguments and results).

import (
	"errors"
	"math"
	"math/big"
	"testing"
)

func mpcB(v any) (*big.Int, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("bigint arg")
	}
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, errors.New("bigint arg")
	}
	return b, nil
}

// mpcI is a JS integer argument (a non-integer is the reference's Number.isInteger failure; huge values clamp).
func mpcI(v any) (int, error) {
	f, ok := jsNum(v)
	if !ok || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) {
		return 0, errors.New("not an integer")
	}
	if math.Abs(f) > 1e9 {
		if f > 0 {
			return math.MaxInt32, nil
		}
		return math.MinInt32, nil
	}
	return int(f), nil
}

func mpcRng(v any) (*MpcFieldRng, error) {
	s, err := mpcB(v)
	if err != nil {
		return nil, err
	}
	return NewMpcFieldRng(s), nil
}

func mpcBA(v any) ([]*big.Int, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([]*big.Int, len(l))
	for i, x := range l {
		if x == nil {
			continue
		}
		var err error
		if out[i], err = mpcB(x); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func mpcBAA(v any) ([][]*big.Int, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([][]*big.Int, len(l))
	for i, x := range l {
		var err error
		if out[i], err = mpcBA(x); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func mpcIA(v any) ([]int, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([]int, len(l))
	for i, x := range l {
		var err error
		if out[i], err = mpcI(x); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func mpcL(a []*big.Int) []any {
	out := make([]any, len(a))
	for i, x := range a {
		if x != nil {
			out[i] = x.String()
		}
	}
	return out
}

func mpcLL(a [][]*big.Int) []any {
	out := make([]any, len(a))
	for i, x := range a {
		out[i] = mpcL(x)
	}
	return out
}

func mpcIL(a []int) []any {
	out := make([]any, len(a))
	for i, x := range a {
		out[i] = x
	}
	return out
}

func mpcVectors(v any) ([]MpcDecisionVector, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("decision vectors must be an array")
	}
	out := make([]MpcDecisionVector, len(l))
	for i, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, errors.New("decision vector must be an object")
		}
		var err error
		if out[i].Allow, err = mpcI(m["allow"]); err != nil {
			return nil, err
		}
		if out[i].T, err = mpcI(m["t"]); err != nil {
			return nil, err
		}
		if out[i].RQuant, err = mpcI(m["rQuant"]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func mpcOpenedOut(l []MpcOpenedMsg) []any {
	out := []any{}
	for _, m := range l {
		out = append(out, map[string]any{"label": m.Label, "value": m.Value.String(), "shares": mpcL(m.Shares)})
	}
	return out
}

func mpcSVOut(x MpcAuthSV) map[string]any {
	return map[string]any{"value": mpcL(x.Value), "mac": mpcL(x.Mac), "extraMac": mpcLL(x.ExtraMac)}
}

func mpcTripleOut(t MpcAuthTriple) map[string]any {
	return map[string]any{"a": mpcSVOut(t.A), "b": mpcSVOut(t.B), "c": mpcSVOut(t.C)}
}

func mpcCtxOut(c *MpcMacContext) map[string]any {
	extra := []any{}
	for _, k := range c.ExtraKeys {
		extra = append(extra, map[string]any{"alphaShares": mpcL(k.AlphaShares), "alpha": k.Alpha.String()})
	}
	return map[string]any{"n": c.N, "alphaShares": mpcL(c.AlphaShares), "alpha": c.Alpha.String(), "extraKeys": extra}
}

func mpcDevs(v any) ([]MpcDeviation, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("deviations must be a list")
	}
	var out []MpcDeviation
	for _, e := range l {
		d, ok := e.([]any)
		if !ok || len(d) < 5 {
			return nil, errors.New("malformed deviation")
		}
		var dv MpcDeviation
		var err error
		if dv.OpenIndex, err = mpcI(d[0]); err != nil {
			return nil, err
		}
		if dv.Party, err = mpcI(d[1]); err != nil {
			return nil, err
		}
		if d[2] != nil {
			if dv.ValueDelta, err = mpcB(d[2]); err != nil {
				return nil, err
			}
		}
		if d[3] != nil {
			if dv.MacDelta, err = mpcB(d[3]); err != nil {
				return nil, err
			}
		}
		if d[4] != nil {
			k, err := mpcI(d[4])
			if err != nil {
				return nil, err
			}
			dv.MacKey = &k
		}
		out = append(out, dv)
	}
	return out, nil
}

func mpcFault(v any) (*MpcDealerFault, error) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	f := &MpcDealerFault{}
	var err error
	if m["keepCDelta"] != nil {
		if f.KeepCDelta, err = mpcB(m["keepCDelta"]); err != nil {
			return nil, err
		}
	}
	if m["partnerCDelta"] != nil {
		if f.PartnerCDelta, err = mpcBA(m["partnerCDelta"]); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func mpcPartnered(t *MpcTripleWithPartners) map[string]any {
	ps := []any{}
	for _, p := range t.Partners {
		ps = append(ps, mpcTripleOut(p))
	}
	return map[string]any{"keep": mpcTripleOut(t.Keep), "partners": ps}
}

func mpcConfig(m map[string]any) (*MpcMaliciousConfig, error) {
	c := &MpcMaliciousConfig{InsecureTrustedDealer: m["insecureTrustedDealer"] == true}
	var err error
	if m["Q"] != nil {
		q, err := mpcI(m["Q"])
		if err != nil {
			return nil, err
		}
		c.Q = &q
	}
	if m["seed"] != nil {
		if c.Seed, err = mpcB(m["seed"]); err != nil {
			return nil, err
		}
	}
	if m["deviations"] != nil {
		if c.Deviations, err = mpcDevs(m["deviations"]); err != nil {
			return nil, err
		}
	}
	if m["dealer"] != nil {
		d, ok := m["dealer"].(map[string]any)
		if !ok {
			return nil, errors.New("dealer must be an object")
		}
		c.Dealer = &MpcDealerOptions{}
		if b, ok := d["verifyTriples"].(bool); ok {
			c.Dealer.VerifyTriples = &b
		}
		if d["partners"] != nil {
			p, err := mpcI(d["partners"])
			if err != nil {
				return nil, err
			}
			c.Dealer.Partners = &p
		}
		if c.Dealer.Fault, err = mpcFault(d["fault"]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func mpcTwo(a []any, f func(x, y *big.Int) *big.Int) (any, error) {
	x, err := mpcB(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	y, err := mpcB(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	return f(x, y).String(), nil
}

func mpcOne(a []any, f func(x *big.Int) *big.Int) (any, error) {
	x, err := mpcB(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	return f(x).String(), nil
}

func mpcDecision(d MpcComposedDecision) map[string]any {
	return map[string]any{"allow": d.Allow, "t": d.T, "rQuant": d.RQuant}
}

func mpcGfOp(a []any) (any, error) {
	op, _ := vecArg(a, 0).(string)
	x, err := mpcB(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	switch op {
	case "mulX":
		return MpcGfMulX(x).String(), nil
	case "mulByXi":
		i, err := mpcI(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		return MpcGfMulByXi(x, i).String(), nil
	case "add", "mul":
		y, err := mpcB(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		if op == "add" {
			return MpcGfAdd(x, y).String(), nil
		}
		return MpcGfMul(x, y).String(), nil
	}
	return nil, errors.New("unknown op " + op)
}

func mpcSVOp(a []any) (any, error) {
	op, _ := vecArg(a, 0).(string)
	x, err := mpcBA(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	var r []*big.Int
	switch op {
	case "add", "sub":
		y, err := mpcBA(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		if op == "add" {
			r, err = MpcAddSV(x, y)
		} else {
			r, err = MpcSubSV(x, y)
		}
		if err != nil {
			return nil, err
		}
	case "neg":
		r = MpcNegSV(x)
	case "scale", "addPublic":
		c, err := mpcB(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		if op == "scale" {
			r = MpcScaleSV(x, c)
		} else if r, err = MpcAddPublicSV(x, c); err != nil {
			return nil, err
		}
	case "notBit":
		if r, err = MpcNotBitSV(x); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown op " + op)
	}
	return mpcL(r), nil
}

func mpcAuthOp(a []any) (any, error) {
	op, _ := vecArg(a, 0).(string)
	n, err := mpcI(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	g, err := mpcRng(vecArg(a, 2))
	if err != nil {
		return nil, err
	}
	c, err := MpcSetupMac(n, g, MpcMacKeys)
	if err != nil {
		return nil, err
	}
	xv, err := mpcB(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	yv, err := mpcB(vecArg(a, 4))
	if err != nil {
		return nil, err
	}
	k, err := mpcB(vecArg(a, 5))
	if err != nil {
		return nil, err
	}
	x, err := MpcAuthShare(xv, c, g)
	if err != nil {
		return nil, err
	}
	y, err := MpcAuthShare(yv, c, g)
	if err != nil {
		return nil, err
	}
	if op == "open" {
		return map[string]any{"val": MpcAuthValue(x).String()}, nil
	}
	var res MpcAuthSV
	switch op {
	case "add":
		res, err = MpcAddAuth(x, y)
	case "sub":
		res, err = MpcSubAuth(x, y)
	case "neg":
		res = MpcNegAuth(x)
	case "scale":
		res = MpcScaleAuth(x, k)
	case "addPublic":
		res, err = MpcAddPublicAuth(x, k, c)
	case "notBit":
		res, err = MpcNotBitAuth(x, c)
	default:
		return nil, errors.New("unknown op " + op)
	}
	if err != nil {
		return nil, err
	}
	val := MpcAuthValue(res)
	rows := append([][]*big.Int{res.Mac}, res.ExtraMac...)
	ok := true
	for l, row := range rows {
		sum := new(big.Int)
		for _, m := range row {
			sum = MpcFAdd(sum, m)
		}
		ok = ok && sum.Cmp(MpcFMul(MpcMacKeysOf(c)[l].Alpha, val)) == 0
	}
	return map[string]any{"res": mpcSVOut(res), "val": val.String(), "okMac": ok}, nil
}

func mpcSacrifice(a []any) (any, error) {
	n, err := mpcI(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	g, err := mpcRng(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	c, err := MpcSetupMac(n, g, MpcMacKeys)
	if err != nil {
		return nil, err
	}
	count, err := mpcI(vecArg(a, 2))
	if err != nil {
		return nil, err
	}
	partners, err := mpcI(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	f, err := mpcFault(vecArg(a, 4))
	if err != nil {
		return nil, err
	}
	devs, err := mpcDevs(vecArg(a, 5))
	if err != nil {
		return nil, err
	}
	var batch []MpcTripleWithPartners
	for i := 0; i < count; i++ {
		ff := f
		if i != 0 {
			ff = nil
		}
		t, err := MpcGenTripleWithPartners(c, g, partners, ff)
		if err != nil {
			return nil, err
		}
		batch = append(batch, *t)
	}
	cert, err := MpcSacrificeVerify(batch, c, g, devs)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, t := range cert {
		out = append(out, mpcTripleOut(t))
	}
	return map[string]any{"certified": out}, nil
}

func mpcEngineRun(a []any) (any, error) {
	n, err := mpcI(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	g, err := mpcRng(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	keys := MpcMacKeys
	if len(a) > 4 {
		if keys, err = mpcI(a[4]); err != nil {
			return nil, err
		}
	}
	c, err := MpcSetupMac(n, g, keys)
	if err != nil {
		return nil, err
	}
	devs, err := mpcDevs(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	e, err := NewMpcSpdzEngine(c, devs)
	if err != nil {
		return nil, err
	}
	values, _ := vecArg(a, 2).([]any)
	outs := []any{}
	for i, v := range values {
		b, err := mpcB(v)
		if err != nil {
			return nil, err
		}
		sv, err := MpcAuthShare(b, c, g)
		if err != nil {
			return nil, err
		}
		o, err := e.Open(sv, "v"+itoa(i))
		if err != nil {
			return nil, err
		}
		outs = append(outs, o.String())
	}
	if err := e.MacCheck(g); err != nil {
		return nil, err
	}
	return map[string]any{"outs": outs, "count": e.OpenCount()}, nil
}

func mpcBeaverAuth(a []any) (any, error) {
	n, err := mpcI(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	g, err := mpcRng(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	c, err := MpcSetupMac(n, g, MpcMacKeys)
	if err != nil {
		return nil, err
	}
	devs, err := mpcDevs(vecArg(a, 4))
	if err != nil {
		return nil, err
	}
	e, err := NewMpcSpdzEngine(c, devs)
	if err != nil {
		return nil, err
	}
	xv, err := mpcB(vecArg(a, 2))
	if err != nil {
		return nil, err
	}
	yv, err := mpcB(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	x, err := MpcAuthShare(xv, c, g)
	if err != nil {
		return nil, err
	}
	y, err := MpcAuthShare(yv, c, g)
	if err != nil {
		return nil, err
	}
	t, err := MpcGenAuthTriple(c, g)
	if err != nil {
		return nil, err
	}
	z, err := MpcBeaverMulAuth(x, y, t, c, e, "m")
	if err != nil {
		return nil, err
	}
	val := MpcAuthValue(z)
	out, err := e.Open(z, "out")
	if err != nil {
		return nil, err
	}
	if err := e.MacCheck(g); err != nil {
		return nil, err
	}
	return map[string]any{"z": mpcSVOut(z), "val": val.String(), "out": out.String(), "opens": e.OpenCount()}, nil
}

func mpcMacResiduals(a []any) (any, error) {
	p, err := mpcB(vecArg(a, 0))
	if err != nil {
		return nil, err
	}
	alphas, err := mpcBAA(vecArg(a, 1))
	if err != nil {
		return nil, err
	}
	var opened []MpcOpenedValue
	ol, _ := vecArg(a, 2).([]any)
	for _, o := range ol {
		m, ok := o.(map[string]any)
		if !ok {
			return nil, errors.New("not an object")
		}
		v, err := mpcB(m["value"])
		if err != nil {
			return nil, err
		}
		ms, err := mpcBAA(m["macShares"])
		if err != nil {
			return nil, err
		}
		opened = append(opened, MpcOpenedValue{Value: v, MacShares: ms})
	}
	ch, err := mpcBAA(vecArg(a, 3))
	if err != nil {
		return nil, err
	}
	return mpcLL(MpcMacResiduals(p, alphas, opened, ch)), nil
}

func TestMpcVectors(t *testing.T) {
	replayVectors(t, "ref-mpc.json.gz", map[string]vecFn{
		"mod":  func(a []any) (any, error) { return mpcOne(a, MpcMod) },
		"fneg": func(a []any) (any, error) { return mpcOne(a, MpcFNeg) },
		"fadd": func(a []any) (any, error) { return mpcTwo(a, MpcFAdd) },
		"fsub": func(a []any) (any, error) { return mpcTwo(a, MpcFSub) },
		"fmul": func(a []any) (any, error) { return mpcTwo(a, MpcFMul) },
		"fieldRng": func(a []any) (any, error) {
			g, err := mpcRng(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			n, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			out := []any{}
			for i := 0; i < n; i++ {
				out = append(out, g.Next().String())
			}
			return out, nil
		},
		"fieldRngDefault": func(a []any) (any, error) {
			g := NewMpcFieldRng(nil)
			n, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			out := []any{}
			for i := 0; i < n; i++ {
				out = append(out, g.Next().String())
			}
			return out, nil
		},
		"share": func(a []any) (any, error) {
			x, err := mpcB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			n, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			s, err := MpcShare(x, n, g)
			return mpcL(s), err
		},
		"reconstruct": func(a []any) (any, error) {
			sh, err := mpcBA(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			r, err := MpcReconstruct(sh)
			if err != nil {
				return nil, err
			}
			return r.String(), nil
		},
		"shareConstant": func(a []any) (any, error) {
			c, err := mpcB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			n, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			s, err := MpcShareConstant(c, n)
			return mpcL(s), err
		},
		"sv": mpcSVOp,
		"gf": mpcGfOp,
		"encBits": func(a []any) (any, error) {
			s, err := mpcI(vecArg(a, 0))
			return MpcEncBits(s), err
		},
		"makeGadget": func(a []any) (any, error) {
			s, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			gad, err := MpcMakeGadget(s, g, vecArg(a, 2) == true)
			return mpcL(gad), err
		},
		"plainShare": func(a []any) (any, error) {
			x, err := mpcB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			e := MpcPlainShare(x)
			return map[string]any{"value": e.Value.String(), "bits": mpcIL(e.Bits)}, nil
		},
		"plainGadget": func(a []any) (any, error) { return mpcL(MpcPlainGadget()), nil },
		"randomBits": func(a []any) (any, error) {
			m, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			if m < 0 {
				return nil, errors.New("negative length")
			}
			return mpcIL(MpcRandomBits(m, g)), nil
		},
		"sampleEnc": func(a []any) (any, error) {
			s, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			gad, err := MpcMakeGadget(s, g, true)
			if err != nil {
				return nil, err
			}
			e := MpcSampleEnc(gad, g)
			return map[string]any{"gadget": mpcL(gad), "e": map[string]any{"value": e.Value.String(), "bits": mpcIL(e.Bits)}}, nil
		},
		"encValue": func(a []any) (any, error) {
			g, err := mpcBA(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			bits, err := mpcIA(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			v, err := MpcEncValue(g, bits)
			if err != nil {
				return nil, err
			}
			return v.String(), nil
		},
		"genTriple": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			tr, err := MpcGenTriple(n, g)
			if err != nil {
				return nil, err
			}
			return map[string]any{"a": mpcL(tr.A), "b": mpcL(tr.B), "c": mpcL(tr.C)}, nil
		},
		"beaverMul": func(a []any) (any, error) {
			var p [5][]*big.Int
			for i := range p {
				var err error
				if p[i], err = mpcBA(vecArg(a, i)); err != nil {
					return nil, err
				}
			}
			var op []MpcOpenedMsg
			z, err := MpcBeaverMul(p[0], p[1], &MpcTriple{p[2], p[3], p[4]}, &op)
			if err != nil {
				return nil, err
			}
			return map[string]any{"z": mpcL(z), "opened": mpcOpenedOut(op)}, nil
		},
		"thermometerEncode": func(a []any) (any, error) {
			v, ok := jsNum(vecArg(a, 0))
			if !ok {
				return nil, errors.New("not a number")
			}
			m, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			bits, err := MpcThermometerEncode(v, m)
			return mpcIL(bits), err
		},
		"thermometerDecode": func(a []any) (any, error) {
			l, _ := vecArg(a, 0).([]any)
			c := 0
			for _, b := range l {
				if f, ok := jsNum(b); ok && f == 1 {
					c++
				}
			}
			return c, nil
		},
		"quantizeR": func(a []any) (any, error) {
			r, ok := jsNum(vecArg(a, 0))
			if !ok {
				return nil, errors.New("not a number")
			}
			q, err := mpcI(vecArg(a, 1))
			return MpcQuantizeR(r, q), err
		},
		"composeClear": func(a []any) (any, error) {
			vs, err := mpcVectors(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			q, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			d, err := MpcComposeClear(vs, q)
			return mpcDecision(d), err
		},
		"assertDecisionVectors": func(a []any) (any, error) {
			vs, err := mpcVectors(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			q, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return true, MpcAssertDecisionVectors(vs, q)
		},
		"composeSecure": func(a []any) (any, error) {
			vs, err := mpcVectors(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			q, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			seed, err := mpcB(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			r, err := MpcComposeSecure(vs, &q, seed)
			if err != nil {
				return nil, err
			}
			sh := []any{}
			for _, s := range r.Sharings {
				sh = append(sh, map[string]any{"label": s.Label, "party": s.Party, "secret": s.Secret.String(), "shares": mpcL(s.Shares)})
			}
			return map[string]any{"composed": mpcDecision(r.Composed), "parties": r.Parties, "Q": r.Q, "multiplications": r.Multiplications,
				"opened": mpcOpenedOut(r.Opened), "sharings": sh, "heldShares0": mpcL(r.Views[0].HeldShares), "viewsLen": len(r.Views)}, nil
		},
		"setupMac": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			k, err := mpcI(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			c, err := MpcSetupMac(n, g, k)
			if err != nil {
				return nil, err
			}
			return mpcCtxOut(c), nil
		},
		"macSoundnessBits": func(a []any) (any, error) {
			k, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			p := MpcPrime
			if len(a) > 1 {
				if p, err = mpcB(a[1]); err != nil {
					return nil, err
				}
			}
			return jsNumber(MpcMacSoundnessBits(k, p)), nil
		},
		"authShare": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			c, err := MpcSetupMac(n, g, MpcMacKeys)
			if err != nil {
				return nil, err
			}
			s, err := mpcB(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			sv, err := MpcAuthShare(s, c, g)
			if err != nil {
				return nil, err
			}
			return map[string]any{"ctx": mpcCtxOut(c), "sv": mpcSVOut(sv)}, nil
		},
		"authConstant": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			c, err := MpcSetupMac(n, g, MpcMacKeys)
			if err != nil {
				return nil, err
			}
			k, err := mpcB(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return mpcSVOut(MpcAuthConstant(k, c)), nil
		},
		"authOp": mpcAuthOp,
		"genAuthTriple": func(a []any) (any, error) {
			n, err := mpcI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := mpcRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			c, err := MpcSetupMac(n, g, MpcMacKeys)
			if err != nil {
				return nil, err
			}
			tr, err := MpcGenAuthTriple(c, g)
			if err != nil {
				return nil, err
			}
			return mpcTripleOut(*tr), nil
		},
		"genTripleWithPartners": func(a []any) (any, error) {
			if len(a) == 2 {
				n, err := mpcI(a[0])
				if err != nil {
					return nil, err
				}
				g, err := mpcRng(a[1])
				if err != nil {
					return nil, err
				}
				c, err := MpcSetupMac(n, g, MpcMacKeys)
				if err != nil {
					return nil, err
				}
				t, err := MpcGenTripleWithPartners(c, g, MpcSacrificeParts, nil)
				if err != nil {
					return nil, err
				}
				return mpcPartnered(t), nil
			}
			g, err := mpcRng(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			c, err := MpcSetupMac(2, g, MpcMacKeys)
			if err != nil {
				return nil, err
			}
			p, err := mpcI(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			f, err := mpcFault(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			t, err := MpcGenTripleWithPartners(c, g, p, f)
			if err != nil {
				return nil, err
			}
			return mpcPartnered(t), nil
		},
		"sacrifice":    mpcSacrifice,
		"engineRun":    mpcEngineRun,
		"macResiduals": mpcMacResiduals,
		"beaverAuth":   mpcBeaverAuth,
		"composeSecureMalicious": func(a []any) (any, error) {
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
		},
	})
}
