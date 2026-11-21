package blstkit

import (
	"testing"
)

// registerAll registers every {pk, pop} pair; nil when any fails (the reference result is then {"registerFailed": true}).
func registerAll(v any) []*RegisteredKey {
	var out []*RegisteredKey
	for _, k := range vecList(v) {
		m := vecObj(k)
		r, err := RegisterKey(vecBytes(m["pk"]), vecBytes(m["pop"]))
		if err != nil {
			return nil
		}
		out = append(out, r)
	}
	if out == nil {
		out = []*RegisteredKey{}
	}
	return out
}

// registryOf registers pairs until the first failure and keeps what it has (the reference harness does the same).
func registryOf(v any) *KeyRegistry {
	reg := NewKeyRegistry()
	for _, k := range vecList(v) {
		m := vecObj(k)
		if _, err := reg.Register(vecBytes(m["pk"]), vecBytes(m["pop"])); err != nil {
			break
		}
	}
	return reg
}

var registerFailed = map[string]any{"registerFailed": true}

func bytesRes(b []byte, err error) (any, error) { return b, err }

func capMap(v any) map[string]any { return vecObj(v) }

func TestAggsigMatchesReference(t *testing.T) {
	replay(t, "ref-aggsig.json.gz", map[string]vecFn{
		"publicKeyOf": func(a []any) (any, error) { return bytesRes(PublicKeyOf(vecSecret(a[0]))) },
		"sign":        func(a []any) (any, error) { return bytesRes(Sign(vecSecret(a[0]), vecBytes(a[1]))) },
		"popProve":    func(a []any) (any, error) { return bytesRes(PopProve(vecSecret(a[0]))) },
		"verify":      func(a []any) (any, error) { return Verify(vecBytes(a[0]), vecBytes(a[1]), vecBytes(a[2])), nil },
		"keyValidate": func(a []any) (any, error) { return KeyValidate(vecBytes(a[0])), nil },
		"registerKey": func(a []any) (any, error) {
			if _, err := RegisterKey(vecBytes(a[0]), vecBytes(a[1])); err != nil {
				return map[string]any{"ok": false, "reason": err.Error()}, nil
			}
			return map[string]any{"ok": true}, nil
		},
		"aggregate": func(a []any) (any, error) { return bytesRes(Aggregate(vecByteList(a[0]))) },
		"aggregateVerify": func(a []any) (any, error) {
			ks := registerAll(a[0])
			if ks == nil {
				return registerFailed, nil
			}
			return AggregateVerify(ks, vecByteList(a[1]), vecBytes(a[2])), nil
		},
		"fastAggregateVerify": func(a []any) (any, error) {
			ks := registerAll(a[0])
			if ks == nil {
				return registerFailed, nil
			}
			return FastAggregateVerify(ks, vecBytes(a[1]), vecBytes(a[2])), nil
		},
		"mintBlsRoot": func(a []any) (any, error) {
			c, err := MintBlsRoot(vecSecret(a[0]), a[1].(string), a[2].(string), vecList(a[3]))
			return c, err
		},
		"chainDelegate": func(a []any) (any, error) {
			return BlsDelegate(capMap(a[0]), a[1].(string), vecList(a[2]), vecSecret(a[3]))
		},
		"chainAttenuate": func(a []any) (any, error) {
			return BlsAttenuate(capMap(a[0]), vecList(a[1]), vecSecret(a[2]))
		},
		"capHash":                  func(a []any) (any, error) { return CapHash(capMap(a[0])) },
		"aggregateChainSignatures": func(a []any) (any, error) { return bytesRes(AggregateChainSignatures(vecList(a[0]))) },
		"verifyAggregatedChain": func(a []any) (any, error) {
			var root *string
			if s, ok := vecArgAt(a, 3).(string); ok {
				root = &s
			}
			r := VerifyAggregatedChain(vecList(a[0]), vecBytes(a[1]), registryOf(a[2]), root)
			if r.Ok {
				return map[string]any{"ok": true}, nil
			}
			return map[string]any{"ok": false, "reason": r.Reason}, nil
		},
		"cosignTreeHead": func(a []any) (any, error) { return CosignTreeHead(vecObj(a[0]), vecSecret(a[1])) },
		"verifyWitnessCosignature": func(a []any) (any, error) {
			return VerifyWitnessCosignature(vecObj(a[0]), vecObj(a[1])), nil
		},
		"aggregateWitnessCosignatures": func(a []any) (any, error) { return bytesRes(AggregateWitnessCosignatures(vecList(a[0]))) },
		"verifyAggregatedWitnessCosignatures": func(a []any) (any, error) {
			ks := registerAll(a[1])
			if ks == nil {
				return registerFailed, nil
			}
			return VerifyAggregatedWitnessCosignatures(vecObj(a[0]), ks, vecBytes(a[2])), nil
		},
	})
}

func vecArgAt(a []any, i int) any {
	if i < len(a) {
		return a[i]
	}
	return nil
}

func TestUnregisteredKeysAreRefused(t *testing.T) {
	if AggregateVerify([]*RegisteredKey{{}}, [][]byte{{1}}, make([]byte, SignatureLength)) {
		t.Fatal("a zero RegisteredKey must not verify")
	}
	if FastAggregateVerify([]*RegisteredKey{nil}, []byte{1}, make([]byte, SignatureLength)) {
		t.Fatal("a nil key must not verify")
	}
}
