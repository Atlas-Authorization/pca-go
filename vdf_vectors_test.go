package pca

// Replays the Wesolowski VDF / PCA timelock corpus. Big integers cross as decimal strings; bytes as {"$bytes": b64u}. A reference
// throw requires an error. Not replayed: calibrateSteps (wall clock) and the insecureDevSetup registry.

import (
	"errors"
	"math"
	"math/big"
	"testing"
)

func vdfBig(v any) (*big.Int, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("bigint arg")
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, errors.New("bad bigint")
	}
	return n, nil
}

func vdfBigs(args []any, idx ...int) ([]*big.Int, error) {
	out := make([]*big.Int, len(idx))
	for i, k := range idx {
		n, err := vdfBig(vecArg(args, k))
		if err != nil {
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}

func vdfNum(v any) float64 {
	f, ok := jsNum(v)
	if !ok {
		return math.NaN()
	}
	return f
}

func vdfVerdictOut(v VdfVerdict) any {
	if v.OK {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": v.Reason}
}

// vdfVerifyArgs reads (x, y, pi, T, N); a non-integer where the reference needs a bigint is the malformed-input verdict.
func vdfVerifyArgs(args []any, canonical bool) (any, error) {
	var b [4]*big.Int
	for i, k := range []int{0, 1, 2, 4} {
		b[i], _ = vdfBig(vecArg(args, k))
	}
	t := vdfNum(vecArg(args, 3))
	if canonical {
		return vdfVerdictOut(VdfVerifyCanonicalDetailed(b[0], b[1], b[2], t, b[3])), nil
	}
	return vdfVerdictOut(VdfVerifyDetailed(b[0], b[1], b[2], t, b[3])), nil
}

func vdfOpts(v any) (steps float64, n *big.Int, beacon []byte, allow bool, err error) {
	o := vecObj(v)
	if o == nil {
		return 0, nil, nil, false, errors.New("options")
	}
	n, err = vdfBig(o["N"])
	if err != nil {
		return
	}
	bs, ok := o["beacon"].(string)
	if !ok {
		return 0, nil, nil, false, errors.New("beacon")
	}
	return vdfNum(o["steps"]), n, vdfUtf8(bs), o["allowInsecureDevModulus"] == true, nil
}

func TestVdfReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-vdf.json.gz", map[string]vecFn{
		"isProbablePrime": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0)
			if err != nil {
				return nil, err
			}
			return VdfIsProbablePrime(b[0]), nil
		},
		"isMillerRabinProbablePrime": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0)
			if err != nil {
				return nil, err
			}
			return VdfIsMillerRabinProbablePrime(b[0]), nil
		},
		"isStrongLucasProbablePrime": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0)
			if err != nil {
				return nil, err
			}
			return VdfIsStrongLucasProbablePrime(b[0]), nil
		},
		"hashToPrime": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0, 1, 3)
			if err != nil {
				return nil, err
			}
			bits := float64(VdfChallengePrimeBits)
			if len(a) > 4 && a[4] != nil {
				bits = vdfNum(a[4])
			}
			p, err := VdfHashToPrime(b[0], b[1], vdfNum(vecArg(a, 2)), b[2], bits)
			if err != nil {
				return nil, err
			}
			return p.String(), nil
		},
		"modpow": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0, 1, 2)
			if err != nil {
				return nil, err
			}
			r, err := VdfModpow(b[0], b[1], b[2])
			if err != nil {
				return nil, err
			}
			return r.String(), nil
		},
		"gcd": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0, 1)
			if err != nil {
				return nil, err
			}
			return VdfGcd(b[0], b[1]).String(), nil
		},
		"canonicalVdfOutput": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0, 1)
			if err != nil {
				return nil, err
			}
			return VdfCanonicalOutput(b[0], b[1]).String(), nil
		},
		"bigIntToBytes": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0)
			if err != nil {
				return nil, err
			}
			out, err := VdfBigIntToBytes(b[0])
			if err != nil {
				return nil, err
			}
			return oprfOut(out), nil
		},
		"bytesRoundTrip": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			raw, err := b64.DecodeString(s)
			if err != nil {
				return nil, err
			}
			out, err := VdfBigIntToBytes(VdfBytesToBigInt(raw))
			if err != nil {
				return nil, err
			}
			return oprfOut(out), nil
		},
		"sequentialSquare": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0, 2)
			if err != nil {
				return nil, err
			}
			r, err := VdfSequentialSquare(b[0], vdfNum(vecArg(a, 1)), b[1])
			if err != nil {
				return nil, err
			}
			return r.String(), nil
		},
		"vdfEval": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0, 2)
			if err != nil {
				return nil, err
			}
			y, pi, err := VdfEval(b[0], vdfNum(vecArg(a, 1)), b[1])
			if err != nil {
				return nil, err
			}
			return map[string]any{"y": y.String(), "pi": pi.String()}, nil
		},
		"vdfEvalCanonical": func(a []any) (any, error) {
			b, err := vdfBigs(a, 0, 2)
			if err != nil {
				return nil, err
			}
			y, pi, err := VdfEvalCanonical(b[0], vdfNum(vecArg(a, 1)), b[1])
			if err != nil {
				return nil, err
			}
			return map[string]any{"y": y.String(), "pi": pi.String()}, nil
		},
		"vdfVerifyDetailed":          func(a []any) (any, error) { return vdfVerifyArgs(a, false) },
		"vdfVerifyCanonicalDetailed": func(a []any) (any, error) { return vdfVerifyArgs(a, true) },
		"checkProductionModulus": func(a []any) (any, error) {
			n, err := vdfBig(vecArg(a, 0))
			if err != nil {
				return map[string]any{"ok": false, "reason": "modulus is not a bigint"}, nil
			}
			ok, why := VdfCheckProductionModulus(n)
			return vdfVerdictOut(VdfVerdict{OK: ok, Reason: why}), nil
		},
		"deriveTimelockInput": func(a []any) (any, error) {
			n, err := vdfBig(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			bs, ok := vecArg(a, 2).(string)
			if !ok {
				return nil, errors.New("beacon")
			}
			x, err := VdfDeriveTimelockInput(vecArg(a, 0), n, vdfUtf8(bs))
			if err != nil {
				return nil, err
			}
			return x.String(), nil
		},
		"requireTimelock": func(a []any) (any, error) {
			steps, n, beacon, allow, err := vdfOpts(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			r, err := VdfRequireTimelock(vecArg(a, 0), steps, n, beacon, allow)
			if err != nil {
				return nil, err
			}
			return map[string]any{"kind": "vdf-timelock", "x": r.X.String(), "steps": jsNumber(float64(r.Steps)), "N": r.N.String(),
				"actionDigest": r.ActionDigest}, nil
		},
		"proveTimelockElapsed": func(a []any) (any, error) {
			n, err := vdfBig(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			o := vecObj(vecArg(a, 3))
			bs, ok := o["beacon"].(string)
			if !ok {
				return nil, errors.New("beacon")
			}
			p, err := VdfProveTimelockElapsed(vecArg(a, 0), vdfNum(vecArg(a, 1)), n, vdfUtf8(bs), o["allowInsecureDevModulus"] == true)
			if err != nil {
				return nil, err
			}
			return map[string]any{"kind": "vdf-timelock-proof", "y": p.Y.String(), "pi": p.Pi.String(), "steps": jsNumber(float64(p.Steps))}, nil
		},
		"verifyTimelock": func(a []any) (any, error) {
			steps, n, beacon, allow, err := vdfOpts(vecArg(a, 2))
			if err != nil {
				return false, nil
			}
			pm := vecObj(vecArg(a, 1))
			if pm == nil || pm["kind"] != "vdf-timelock-proof" {
				return false, nil
			}
			ps, ok := vdfSafeInt(vdfNum(pm["steps"]))
			y, errY := vdfBig(pm["y"])
			pi, errPi := vdfBig(pm["pi"])
			if !ok || errY != nil || errPi != nil {
				return false, nil
			}
			return VdfVerifyTimelock(vecArg(a, 0), &VdfTimelockProof{Y: y, Pi: pi, Steps: ps}, steps, n, beacon, allow), nil
		},
	})
}
