package pca

// Replays the reference oracle of key rotation (testdata/ref-rotate.json.gz). Keys cross the corpus as base64url Ed25519 seeds;
// a revokedAt within two minutes of the wall clock compares as "<now>".

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

// rotSeed maps a corpus seed to a key pair: null = no key (the call refuses), a seed of the wrong size refuses here (the
// reference refuses it when deriving the public key).
func rotSeed(v any) (*KeyPair, error) {
	if v == nil {
		return nil, nil
	}
	s, _ := v.(string)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return KeyPairFromSeed(b)
}

func rotOpts(m map[string]any) RotateOptions {
	var o RotateOptions
	if s, ok := m["reason"].(string); ok {
		o.Reason = &s
	}
	if x, has := m["now"]; has {
		f, ok := jsNum(x)
		if !ok {
			f = math.NaN()
		}
		o.Now = &f
	}
	return o
}

func rotChain(v any) ([]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("chain must be an array")
	}
	return l, nil
}

func rotOut(r any, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return vecRevNow(vecJSON(r)), nil
}

type rotSink struct {
	reg          *RevocationRegistry
	failAt       float64
	failUnrevoke bool
	calls        float64
}

func (s *rotSink) Revoke(in map[string]any) (RevocationEntry, error) {
	s.calls++
	if s.calls == s.failAt {
		return nil, errBoom
	}
	return s.reg.Revoke(in)
}

func (s *rotSink) Unrevoke(k any) (bool, error) {
	if s.failUnrevoke {
		return false, errBoom
	}
	return s.reg.Unrevoke(k)
}

func (s *rotSink) Lookup(kind, value string) (RevocationEntry, error) {
	return s.reg.Lookup(kind, value)
}

func TestRotateVectors(t *testing.T) {
	reissue := func(fn func([]any, string, *KeyPair, *KeyPair, RotateOptions) (any, error)) vecFn {
		return func(a []any) (any, error) {
			chain, err := rotChain(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			holder, ok := vecArg(a, 1).(string)
			if !ok {
				return nil, errors.New("holder must be a string")
			}
			op := vecObj(vecArg(a, 2))
			nk, err := rotSeed(op["newSeed"])
			if err != nil {
				return nil, err
			}
			ak, err := rotSeed(op["ancestorSeed"])
			if err != nil {
				return nil, err
			}
			return rotOut(fn(chain, holder, nk, ak, rotOpts(op)))
		}
	}
	replayVectors(t, "ref-rotate.json.gz", vecSeeded(map[string]vecFn{
		"rotateAgentKey": func(a []any) (any, error) {
			chain, err := rotChain(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			op := vecObj(vecArg(a, 1))
			ok, err := rotSeed(op["oldSeed"])
			if err != nil {
				return nil, err
			}
			nk, err := rotSeed(op["newSeed"])
			if err != nil {
				return nil, err
			}
			return rotOut(RotateAgentKey(chain, ok, nk, rotOpts(op)))
		},
		"rotatePrincipalKey": func(a []any) (any, error) {
			op := vecObj(vecArg(a, 0))
			cv := op["chain"]
			if cv == nil {
				cv = []any{}
				if jsTruthy(op["oldRoot"]) {
					cv = []any{op["oldRoot"]}
				}
			}
			chain, err := rotChain(cv)
			if err != nil {
				return nil, err
			}
			ok, err := rotSeed(op["oldSeed"])
			if err != nil {
				return nil, err
			}
			nk, err := rotSeed(op["newSeed"])
			if err != nil {
				return nil, err
			}
			var hs []*KeyPair
			if l, isL := op["holderSeeds"].([]any); isL {
				for _, s := range l {
					k, err := rotSeed(s)
					if err != nil {
						return nil, err
					}
					hs = append(hs, k)
				}
			}
			return rotOut(RotatePrincipalKey(chain, ok, nk, hs, rotOpts(op)))
		},
		"revokeAndReissueSubtree": reissue(func(c []any, h string, n, an *KeyPair, o RotateOptions) (any, error) {
			return RevokeAndReissueSubtree(c, h, n, an, o)
		}),
		"compromisedKeyFlow": reissue(func(c []any, h string, n, an *KeyPair, o RotateOptions) (any, error) {
			return CompromisedKeyFlow(c, h, n, an, o)
		}),
		"applyRotationScenario": func(a []any) (any, error) {
			spec := vecObj(vecArg(a, 0))
			recs := rsList(spec["records"])
			if r := vecObj(spec["records"]); r != nil {
				recs = []any{r}
			}
			for _, r := range recs {
				if n, ok := vecObj(r)["revokedAt"].(json.Number); ok && n == "-0" {
					// DELIBERATE: the native is stricter than the reference here. The reference stores a -0 revokedAt as 0; the native's
					// strict profile refuses a negative zero in a record. The refusal and its exact text are asserted, not skipped silently.
					txt, _ := json.Marshal(spec["records"])
					const tail = `"revokedAt":-0`
					want := fmt.Sprintf("strict JSON: negative zero is not allowed (at offset %d)", strings.Index(string(txt), tail)+len(tail))
					_, err := ApplyRotation(&rotSink{reg: NewRevocationRegistry(NewMemoryRevocationStore())}, spec["records"], spec["reissued"])
					if err == nil || err.Error() != want {
						t.Errorf("a -0 revokedAt must be refused with %q, got %v", want, err)
					}
					return nil, vecSkip("negative-zero revokedAt: native refusal asserted above (stricter than the reference on purpose)")
				}
			}
			reg := NewRevocationRegistry(NewMemoryRevocationStore())
			pre, _ := spec["pre"].([]any)
			for _, id := range pre {
				if _, err := reg.Revoke(map[string]any{"kind": "cap", "value": id, "reason": "pre", "revokedAt": jsNumber(vecOracleNow())}); err != nil {
					return nil, err
				}
			}
			sink := &rotSink{reg: reg}
			sink.failAt, _ = jsNum(spec["failAt"])
			sink.failUnrevoke = jsTruthy(spec["failUnrevoke"])
			var result any = map[string]any{"$err": true}
			if ids, err := ApplyRotation(sink, spec["records"], spec["reissued"]); err == nil {
				result = ids
			}
			list, err := reg.List()
			if err != nil {
				return nil, err
			}
			return map[string]any{"result": vecJSON(result), "list": vecRevNow(vecJSON(list))}, nil
		},
	}))
}
