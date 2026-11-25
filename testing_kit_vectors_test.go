package pca

// Replays the testing-kit reference corpus: the acceptance constants and route mapping, the fake verifier and its assertion
// helpers, the tamper helper and the in-memory state store. The adapter acceptance matrix harness is per-adapter and is not
// replayable as vectors.

import (
	"errors"
	"testing"
)

func tkTestOpts(v any) FakeVerifyOptions {
	m := vecObj(v)
	o := FakeVerifyOptions{Now: int64(connTestFloat(m["now"], 0))}
	if a, ok := m["audience"].(string); ok {
		o.Audience = &a
	}
	if g, ok := m["grant"].(map[string]any); ok {
		o.Grant = g
	}
	return o
}

func tkTestMutation(m map[string]any) func(rec map[string]any) error {
	return func(rec map[string]any) error {
		op, _ := m["op"].(string)
		if op == "none" {
			return nil
		}
		path := sliceOf(m["path"])
		var cur any = rec
		for _, k := range path[:len(path)-1] {
			key, _ := k.(string)
			cm, ok := cur.(map[string]any)
			if !ok {
				return errors.New("cannot read properties of undefined")
			}
			cur = cm[key]
		}
		cm, ok := cur.(map[string]any)
		if !ok {
			return errors.New("cannot set properties of undefined")
		}
		last, _ := path[len(path)-1].(string)
		if op == "set" {
			cm[last] = m["value"]
		} else {
			delete(cm, last)
		}
		return nil
	}
}

func TestTestingKitReferenceVectors(t *testing.T) {
	allow := func(f func(any, FakeVerifyOptions) (Verdict, error)) vecFn {
		return func(args []any) (any, error) {
			v, err := f(vecArg(args, 0), tkTestOpts(vecArg(args, 1)))
			if err != nil {
				return nil, err
			}
			return v.Allow, nil
		}
	}
	replayVectors(t, "ref-testing.json.gz", map[string]vecFn{
		"consts": func(args []any) (any, error) {
			return map[string]any{"aud": AdapterAcceptanceAudience, "expected": AdapterAcceptanceExpected()}, nil
		},
		"acceptanceOperation": func(args []any) (any, error) { return AcceptanceOperation(vecObj(vecArg(args, 0))) },
		"fakeVerifyAllow":     allow(FakeVerify),
		"expectVerifies":      allow(ExpectVerifies),
		"expectDenied":        allow(ExpectDenied),
		"tamper": func(args []any) (any, error) {
			enc, _ := vecArg(args, 0).(string)
			return Tamper(enc, tkTestMutation(vecObj(vecArg(args, 1))))
		},
		"memorySession": func(args []any) (any, error) {
			s := NewMemoryTestStateStore()
			out := []any{}
			for _, oi := range sliceOf(vecArg(args, 0)) {
				op := sliceOf(oi)
				key, _ := op[1].(string)
				if op[0] == "put" {
					s.Put(key, op[2])
				} else {
					out = append(out, s.Get(key))
				}
			}
			return out, nil
		},
	})
}
