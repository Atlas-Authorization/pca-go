package pca

// Replays the OPRF / VOPRF / POPRF corpus (RFC 9497 ristretto255-SHA512 and the private revocation / rate-limit layer). Bytes cross
// as {"$bytes": b64u}; a reference throw requires an error. Keys derive from fixed seed labels in the corpus generator (the test
// re-derives the one extra key the lying-evaluator cases need).

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sort"
	"testing"
)

func oprfB(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return nil, false
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func oprfOut(b []byte) any {
	if b == nil {
		return nil
	}
	return map[string]any{"$bytes": b64.EncodeToString(b)}
}

// oprfReq reads a required bytes argument (anything else is the reference TypeError); oprfOpt an optional one (null = absent).
func oprfReq(args []any, i int) ([]byte, error) {
	b, ok := oprfB(vecArg(args, i))
	if !ok {
		return nil, errors.New("expected bytes")
	}
	return b, nil
}

func oprfOpt(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	b, ok := oprfB(v)
	if !ok {
		return nil, errors.New("expected bytes")
	}
	return b, nil
}

func oprfModeArg(args []any, i int) (string, error) {
	s, ok := vecArg(args, i).(string)
	if !ok {
		return "", errors.New("mode must be a string")
	}
	return s, nil
}

func oprfSeed(label string) []byte {
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	return d[:]
}

func oprfStr(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", errors.New("must be a string")
	}
	return s, nil
}

func oprfEvalFor(sk []byte, mode, lie string) (OprfBlindEvaluator, error) {
	useSk := sk
	if lie == "wrong-key" {
		k, _, err := OprfDeriveKeyPair(oprfSeed("ref-oprf/key-poprf"), []byte("k"), "poprf")
		if err != nil {
			return nil, err
		}
		useSk = k
	}
	real, err := OprfMakeRevocationEvaluator(useSk, mode)
	if err != nil {
		return nil, err
	}
	return func(b []byte) (OprfEvaluated, error) {
		res, err := real(b)
		if lie == "no-proof" {
			res.Proof = nil
		}
		return res, err
	}, nil
}

func TestOprfReferenceVectors(t *testing.T) {
	fns := vecSeeded(map[string]vecFn{
		"deriveKeyPair": func(a []any) (any, error) {
			seed, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			info, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			mode, err := oprfModeArg(a, 2)
			if err != nil {
				return nil, err
			}
			sk, pk, err := OprfDeriveKeyPair(seed, info, mode)
			if err != nil {
				return nil, err
			}
			return map[string]any{"secretKey": oprfOut(sk), "publicKey": oprfOut(pk)}, nil
		},
		"publicKeyFor": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			pk, err := OprfPublicKeyFor(sk)
			return oprfOut(pk), err
		},
		"deserializeScalar": func(a []any) (any, error) {
			b, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			n, err := OprfDeserializeScalar(b)
			if err != nil {
				return nil, err
			}
			return n.String(), nil
		},
		"serializeScalar": func(a []any) (any, error) {
			s, err := oprfStr(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			n, ok := new(big.Int).SetString(s, 10)
			if !ok {
				return nil, errors.New("bad bigint")
			}
			return oprfOut(OprfSerializeScalar(n)), nil
		},
		"hashToGroup": func(a []any) (any, error) {
			in, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			mode, err := oprfModeArg(a, 1)
			if err != nil {
				return nil, err
			}
			b, err := OprfHashToGroup(in, mode)
			return oprfOut(b), err
		},
		"deserializeElement": func(a []any) (any, error) {
			b, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			out, err := OprfDeserializeElement(b)
			return oprfOut(out), err
		},
		"blind": func(a []any) (any, error) {
			in, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			mode, err := oprfModeArg(a, 1)
			if err != nil {
				return nil, err
			}
			fixed, err := oprfOpt(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			bl, be, err := OprfBlind(in, mode, fixed)
			if err != nil {
				return nil, err
			}
			return map[string]any{"blind": oprfOut(bl), "blindedElement": oprfOut(be)}, nil
		},
		"blindEvaluate": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			be, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			mode, err := oprfModeArg(a, 2)
			if err != nil {
				return nil, err
			}
			pk, err := oprfOpt(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			if mode == "voprf" && len(a) > 3 && a[3] == nil { // the reference reads an explicit null key as a key (only undefined is absent)
				return nil, errors.New("DeserializeElement: expected a Uint8Array")
			}
			pr, err := oprfOpt(vecArg(a, 4))
			if err != nil {
				return nil, err
			}
			ev, proof, err := OprfBlindEvaluate(sk, be, mode, pk, pr)
			if err != nil {
				return nil, err
			}
			out := map[string]any{"evaluatedElement": oprfOut(ev)}
			if proof != nil {
				out["proof"] = oprfOut(proof)
			}
			return out, nil
		},
		"finalize": func(a []any) (any, error) {
			in, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			bl, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			ev, err := oprfReq(a, 2)
			if err != nil {
				return nil, err
			}
			mode, err := oprfModeArg(a, 3)
			if err != nil {
				return nil, err
			}
			opts := vecObj(vecArg(a, 4))
			proof, err := oprfOpt(opts["proof"])
			if err != nil {
				return nil, err
			}
			pk, err := oprfOpt(opts["publicKey"])
			if err != nil {
				return nil, err
			}
			be, err := oprfOpt(opts["blindedElement"])
			if err != nil {
				return nil, err
			}
			out, err := OprfFinalize(in, bl, ev, mode, proof, pk, be)
			return oprfOut(out), err
		},
		"evaluate": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			in, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			mode, err := oprfModeArg(a, 2)
			if err != nil {
				return nil, err
			}
			out, err := OprfEvaluate(sk, in, mode)
			return oprfOut(out), err
		},
		"blindPoprf": func(a []any) (any, error) {
			in, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			info, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			pk, err := oprfReq(a, 2)
			if err != nil {
				return nil, err
			}
			fixed, err := oprfOpt(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			bl, be, tk, err := OprfBlindPoprf(in, info, pk, fixed)
			if err != nil {
				return nil, err
			}
			return map[string]any{"blind": oprfOut(bl), "blindedElement": oprfOut(be), "tweakedKey": oprfOut(tk)}, nil
		},
		"blindEvaluatePoprf": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			be, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			info, err := oprfReq(a, 2)
			if err != nil {
				return nil, err
			}
			pr, err := oprfOpt(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			ev, proof, err := OprfBlindEvaluatePoprf(sk, be, info, pr)
			if err != nil {
				return nil, err
			}
			return map[string]any{"evaluatedElement": oprfOut(ev), "proof": oprfOut(proof)}, nil
		},
		"finalizePoprf": func(a []any) (any, error) {
			in, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			bl, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			ev, err := oprfReq(a, 2)
			if err != nil {
				return nil, err
			}
			info, err := oprfReq(a, 3)
			if err != nil {
				return nil, err
			}
			opts := vecObj(vecArg(a, 4))
			proof, err := oprfOpt(opts["proof"])
			if err != nil {
				return nil, err
			}
			be, err := oprfOpt(opts["blindedElement"])
			if err != nil {
				return nil, err
			}
			tk, err := oprfOpt(opts["tweakedKey"])
			if err != nil {
				return nil, err
			}
			out, err := OprfFinalizePoprf(in, bl, ev, info, proof, be, tk)
			return oprfOut(out), err
		},
		"evaluatePoprf": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			in, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			info, err := oprfReq(a, 2)
			if err != nil {
				return nil, err
			}
			out, err := OprfEvaluatePoprf(sk, in, info)
			return oprfOut(out), err
		},
		"toHex": func(a []any) (any, error) {
			b, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			return OprfToHex(b), nil
		},
		"bytesEqual": func(a []any) (any, error) {
			x, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			y, err := oprfReq(a, 1)
			if err != nil {
				return nil, err
			}
			return OprfBytesEqual(x, y), nil
		},
		"buildRevocationSet": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			ids, err := oprfIDs(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			mode, err := oprfModeArg(a, 2)
			if err != nil {
				return nil, err
			}
			set, err := OprfBuildRevocationSet(sk, ids, mode)
			if err != nil {
				return nil, err
			}
			outs := make([]string, 0, len(set.Outputs))
			for k := range set.Outputs {
				outs = append(outs, k)
			}
			sort.Strings(outs)
			list := make([]any, len(outs))
			for i, s := range outs {
				list[i] = s
			}
			res := map[string]any{"outputs": list, "mode": set.Mode}
			// the oracle's repeated-id case reports only the outputs and the mode
			dup := false
			seen := map[string]bool{}
			for _, id := range ids {
				dup = dup || seen[id]
				seen[id] = true
			}
			if set.PublicKey != nil && !dup {
				res["publicKey"] = oprfOut(set.PublicKey)
			}
			return res, nil
		},
		"isRevokedPrivate": func(a []any) (any, error) {
			id, err := oprfStr(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			op := vecObj(vecArg(a, 1))
			sk, err := oprfReq([]any{op["sk"]}, 0)
			if err != nil {
				return nil, err
			}
			ids, err := oprfIDs(op["revoked"])
			if err != nil {
				return nil, err
			}
			mode := vecStr(op, "mode")
			set, err := OprfBuildRevocationSet(sk, ids, mode)
			if err != nil {
				return nil, err
			}
			ev, err := oprfEvalFor(sk, mode, vecStr(op, "lie"))
			if err != nil {
				return nil, err
			}
			return OprfIsRevokedPrivate(id, ev, set)
		},
		"rateToken": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			id, err := oprfStr(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			w, err := oprfStr(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			out, err := OprfRateToken(sk, id, w)
			return oprfOut(out), err
		},
		"rateTokenHex": func(a []any) (any, error) {
			sk, err := oprfReq(a, 0)
			if err != nil {
				return nil, err
			}
			id, err := oprfStr(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			w, err := oprfStr(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return OprfRateTokenHex(sk, id, w)
		},
		"privateRateToken": func(a []any) (any, error) {
			id, err := oprfStr(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			w, err := oprfStr(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			op := vecObj(vecArg(a, 2))
			sk, err := oprfReq([]any{op["sk"]}, 0)
			if err != nil {
				return nil, err
			}
			pk, err := oprfOpt(op["pk"])
			if err != nil {
				return nil, err
			}
			if pk == nil {
				if pk, err = OprfPublicKeyFor(sk); err != nil {
					return nil, err
				}
			}
			out, err := OprfPrivateRateToken(id, w, OprfMakeRateEvaluator(sk), pk)
			return oprfOut(out), err
		},
		"rateCounter": func(a []any) (any, error) {
			lf, ok := jsNum(vecArg(a, 0))
			if !ok || lf != float64(int(lf)) {
				return nil, errors.New("limit must be a positive integer")
			}
			c, err := NewOprfRateCounter(int(lf))
			if err != nil {
				return nil, err
			}
			steps, _ := vecArg(a, 1).([]any)
			out := []any{}
			for _, s := range steps {
				st, _ := s.([]any)
				switch st[0] {
				case "hit":
					tok, err := oprfReq(st, 1)
					if err != nil {
						return nil, err
					}
					n, allowed := c.Hit(tok)
					out = append(out, map[string]any{"count": jsNumber(float64(n)), "allowed": allowed})
				case "count":
					tok, err := oprfReq(st, 1)
					if err != nil {
						return nil, err
					}
					out = append(out, jsNumber(float64(c.Count(tok))))
				default:
					c.Reset()
					out = append(out, nil)
				}
			}
			return out, nil
		},
	})
	replayVectors(t, "ref-oprf.json.gz", fns)
	replaySecretGen(t, "ref-oprf.json.gz", func(t *testing.T, p string) { replayVectors(t, p, fns) })
}

func oprfIDs(v any) ([]string, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("ids must be a list")
	}
	out := make([]string, len(l))
	for i, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, errors.New("capability id must be a string")
		}
		out[i] = s
	}
	return out, nil
}
