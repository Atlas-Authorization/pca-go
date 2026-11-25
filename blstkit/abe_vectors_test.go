package blstkit

import (
	"crypto/sha512"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"testing"
)

// The scheme-arithmetic cases carry {"$seed": label}: every fixed scalar is sha512("abe-oracle/" + label + name) mod r (1 for 0).
func abeSc(label string) *big.Int {
	d := sha512.Sum512([]byte("abe-oracle/" + label))
	v := new(big.Int).Mod(new(big.Int).SetBytes(d[:]), BbsR)
	if v.Sign() == 0 {
		return big.NewInt(1)
	}
	return v
}

func anyStrs(v any) []string {
	l := vecList(v)
	out := make([]string, len(l))
	for i, x := range l {
		out[i], _ = x.(string)
	}
	return out
}

func abeOpts(v any) AbeCapabilityOpts {
	o := vecObj(v)
	var opts AbeCapabilityOpts
	if c, ok := o["chain"]; ok {
		opts.HaveChain = true
		opts.Chain = vecList(c)
	}
	if p, ok := o["principal"].(string); ok {
		opts.Principal = &p
	}
	if pins := vecObj(o["pqPins"]); pins != nil {
		opts.PqPins = map[string]string{}
		for k, x := range pins {
			if s, ok := x.(string); ok {
				opts.PqPins[k] = s
			}
		}
	}
	return opts
}

func abeFame(a []any) (any, error) {
	sp := vecObj(a[2])
	label, _ := sp["$seed"].(string)
	// the committed corpus carries a seed label; the CI-generated one the fixed scalars themselves (hex)
	pick := func(name string, i int) *big.Int {
		if label != "" {
			return abeSc(label + name)
		}
		return unhexScalar(vecList(sp[name])[i].(string))
	}
	attrs := anyStrs(a[1])
	tree, why := abeNormalizePolicy(a[0])
	if why != "" {
		return nil, errors.New(why)
	}
	short := func(name string, i int) *big.Int {
		if label != "" {
			return abeSc(label + name + strconv.Itoa(i+1))
		}
		return pick(name, i)
	}
	mpk, msk, err := fameSetup([2]*big.Int{short("a", 0), short("a", 1)}, [2]*big.Int{short("b", 0), short("b", 1)},
		[3]*big.Int{short("d", 0), short("d", 1), short("d", 2)})
	if err != nil {
		return nil, err
	}
	sigmas := make([]*big.Int, len(attrs))
	for i := range sigmas {
		if label != "" {
			sigmas[i] = abeSc(label + "sg" + strconv.Itoa(i))
		} else {
			sigmas[i] = pick("sigma", i)
		}
	}
	sigmaP := abeSc(label + "sgp")
	if label == "" {
		sigmaP = unhexScalar(sp["sigmaPrime"].(string))
	}
	key, err := fameKeygen(msk, attrs, [2]*big.Int{short("r", 0), short("r", 1)}, sigmas, sigmaP)
	if err != nil {
		return nil, err
	}
	ct, k, err := fameEncrypt(mpk, tree, [2]*big.Int{short("s", 0), short("s", 1)})
	if err != nil {
		return nil, err
	}
	var dec any
	if d, ok := fameDecrypt(key, tree, ct); ok {
		dec = d
	}
	g1l := func(x abeG1x3) []any { return []any{g1Bytes(x[0]), g1Bytes(x[1]), g1Bytes(x[2])} }
	g2l := func(x abeG2x3) []any { return []any{g2Bytes(x[0]), g2Bytes(x[1]), g2Bytes(x[2])} }
	keyAttrs := map[string]any{}
	for n, c := range key.attrs {
		keyAttrs[n] = g1l(c)
	}
	rows := make([]any, len(ct.rows))
	for i, r := range ct.rows {
		rows[i] = g1l(r)
	}
	return map[string]any{
		"h": []any{g2Bytes(mpk.h1), g2Bytes(mpk.h2)}, "t": []any{mpk.t1, mpk.t2}, "mskg": g1l(msk.g),
		"k0": g2l(key.k0), "kp": g1l(key.kp), "key": keyAttrs, "ct0": g2l(ct.ct0), "rows": rows, "k": k, "dec": dec,
	}, nil
}

func optBytes(b []byte, ok bool) (any, error) {
	if !ok {
		return nil, nil
	}
	return b, nil
}

func TestAbeMatchesReference(t *testing.T) {
	fns := abeResolving(map[string]vecFn{
		"fame":        abeFame,
		"gtIsElement": func(a []any) (any, error) { return gtIsElement(vecBytes(a[0])), nil },
		"gtPow": func(a []any) (any, error) {
			b, ok := gtPow(vecBytes(a[0]), unhexScalar(a[1].(string)).FillBytes(make([]byte, 32)))
			if !ok {
				return nil, errors.New("gtPow refused")
			}
			return b, nil
		},
		"gtMul": func(a []any) (any, error) {
			b, ok := gtMul(vecBytes(a[0]), vecBytes(a[1]))
			if !ok {
				return nil, errors.New("gtMul refused")
			}
			return b, nil
		},
		"pairingProduct": func(a []any) (any, error) {
			b, ok := gtPairing(vecByteList(a[0]), vecByteList(a[1]))
			if !ok {
				return nil, errors.New("pairingProduct refused")
			}
			return b, nil
		},
		"normalizePolicy": func(a []any) (any, error) {
			tree, why := AbeNormalizePolicy(a[0])
			if why != "" {
				return map[string]any{"ok": false, "reason": why}, nil
			}
			return map[string]any{"ok": true, "tree": tree}, nil
		},
		"satisfies":        func(a []any) (any, error) { return AbeSatisfies(vecObj(a[0]), anyStrs(a[1])), nil },
		"policyAttributes": func(a []any) (any, error) { return AbePolicyAttributes(vecObj(a[0])), nil },
		"parseCiphertext":  func(a []any) (any, error) { return AbeParseCiphertext(a[0]), nil },
		"decrypt": func(a []any) (any, error) {
			pt, ok := AbeDecrypt(a[0], a[1])
			return optBytes(pt, ok)
		},
		"decryptText": func(a []any) (any, error) {
			s, ok := AbeDecryptText(a[0], a[1])
			if !ok {
				return nil, nil
			}
			return s, nil
		},
		"decryptWithCapability": func(a []any) (any, error) {
			p, ok, why := AbeDecryptWithCapability(a[0], a[1])
			if !ok {
				return map[string]any{"ok": false, "reason": why}, nil
			}
			return map[string]any{"ok": true, "payload": p}, nil
		},
		"encryptAccepts": func(a []any) (any, error) {
			if _, err := AbeEncryptForPolicy(a[0], a[1], []byte("x")); err != nil {
				return nil, err
			}
			return true, nil
		},
		"keygenForAttributes": func(a []any) (any, error) {
			_, names, err := abeIssue(a[0], anyStrs(a[1]))
			if err != nil {
				return nil, err
			}
			return names, nil
		},
		"keygenForCapability": func(a []any) (any, error) {
			key, names, err := abeIssueCapability(a[0], vecObj(a[1]), anyStrs(a[2]), abeOpts(a[3]))
			if err != nil {
				return nil, err
			}
			var holder any
			if h, ok := key["holder"].(string); ok {
				holder = h
			}
			return map[string]any{"holder": holder, "attrs": names}, nil
		},
		"capabilityAttributes": func(a []any) (any, error) {
			return AbeCapabilityAttributes(vecObj(a[0]), abeOpts(a[1])), nil
		},
	})
	replay(t, "ref-abe.json.gz", fns)
	replaySecretGen(t, "ref-abe.json.gz", func(t *testing.T, p string) { replay(t, p, fns) })
}

func TestAbeRoundTrip(t *testing.T) {
	mpk, msk, err := AbeSetup()
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{"allOf": []any{map[string]any{"attr": "a"}, map[string]any{"attr": "b"}}}
	ct, err := AbeEncryptForPolicy(mpk, policy, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	both, err := AbeKeygenForAttributes(msk, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	one, err := AbeKeygenForAttributes(msk, []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if pt, ok := AbeDecrypt(both, ct); !ok || string(pt) != "hello" {
		t.Fatalf("a key holding both attributes must decrypt: %v %q", ok, pt)
	}
	if _, ok := AbeDecrypt(one, ct); ok {
		t.Fatal("a key missing an attribute must not decrypt")
	}
	names := AbePolicyAttributes(normTreeForTest(t, policy))
	if !sort.StringsAreSorted(names) {
		t.Fatal("policy attributes are sorted")
	}
}

// normTreeForTest normalises policy for a test.
func normTreeForTest(t *testing.T, policy any) map[string]any {
	t.Helper()
	tree, why := AbeNormalizePolicy(policy)
	if why != "" {
		t.Fatal(why)
	}
	return tree
}

// abeResolving wraps every entry point so key recipes in the arguments are derived before the call.
func abeResolving(fns map[string]vecFn) map[string]vecFn {
	out := make(map[string]vecFn, len(fns))
	for name, f := range fns {
		f := f
		out[name] = func(a []any) (any, error) { return f(abeResolve(a).([]any)) }
	}
	return out
}
