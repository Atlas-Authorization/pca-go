package pca

import (
	"encoding/json"
	"errors"
	"testing"
)

// Replay of the liveness beacons against the reference (ref-beacons), every case: constants, issuing under ed25519, ml-dsa-65 and
// the hybrid (keys from seed labels, deterministic), the signed message, the beacon reference, verification with every reason,
// monotonic acceptance, the frozen check and the durable acceptor as op scripts over one fresh in-memory store (faults and junk
// slots included). The option that accepts an unpinned post-quantum key is not ported: the case that the reference accepts only
// through it is asserted REFUSED, with the count asserted.

// beaconFailKv is an AtomicKV whose next Update fails when armed.
type beaconFailKv struct {
	AtomicKV
	armed bool
}

func (k *beaconFailKv) Update(key string, fn func(prev []byte) []byte) error {
	if k.armed {
		k.armed = false
		return errors.New("boom")
	}
	return k.AtomicKV.Update(key, fn)
}

func beaconAcceptorScript(ops []any) []any {
	kv := &beaconFailKv{AtomicKV: NewMemoryAtomicKV()}
	acc, _ := NewBeaconAcceptor(kv)
	out := make([]any, len(ops))
	for i, o := range ops {
		op, _ := o.([]any)
		switch name, _ := vecArg(op, 0).(string); name {
		case "accept":
			check, _ := vecArg(op, 2).(map[string]any)
			v := acc.AcceptValue(vecArg(op, 1), check)
			out[i] = beaconVerdictJSON(v)
		case "raw":
			if bm, ok := vecArg(op, 1).(map[string]any); ok {
				b, _ := json.Marshal(scJSONNull(vecArg(op, 2)))
				_ = kv.AtomicKV.Update(beaconSeqKey(bm), func([]byte) []byte { return b })
			}
		case "fail":
			kv.armed = true
		default:
			out[i] = map[string]any{"$err": "op"}
		}
	}
	return out
}

func beaconVerdictJSON(v BeaconVerdict) map[string]any {
	if v.OK {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": v.Reason}
}

func TestLivenessBeaconsMatchTheReference(t *testing.T) {
	unbound := 0
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"GLOBAL_SCOPE": GlobalScope, "BEACON_EPOCH_MS": jsNumber(BeaconEpochMs), "BEACON_MAX_VALIDITY_MS": jsNumber(BeaconMaxValidity), "BEACON_CLOCK_SKEW_MS": jsNumber(BeaconClockSkewMs)}, nil
		},
		"issueLivenessBeacon": func(a []any) (any, error) {
			a = scDecode(vecResolveSeeds(a)).([]any)
			o, _ := a[0].(map[string]any)
			secret, ok := qvBytes(o["issuerSecret"])
			if !ok {
				return nil, errors.New("issuerSecret is bytes")
			}
			key, err := KeyPairFromSeed(secret)
			if err != nil {
				return nil, err
			}
			var suite *SuiteOpts
			if sm, ok := o["suite"].(map[string]any); ok {
				alg, _ := sm["alg"].(string)
				suite = &SuiteOpts{Alg: alg}
				if seed, ok := qvBytes(sm["pqSeed"]); ok {
					if suite.Pq, err = GeneratePqKeyPairFromSeed("ML-DSA-65", seed); err != nil {
						return nil, err
					}
				}
			}
			return IssueLivenessBeaconValue(o, key, suite)
		},
		"livenessBeaconMessage": func(a []any) (any, error) {
			b, _ := scDecode(vecArg(a, 0)).(map[string]any)
			m, err := LivenessBeaconMessage(b)
			if err != nil {
				return nil, err
			}
			return vecBytesOut(m), nil
		},
		"beaconRef": func(a []any) (any, error) {
			b, ok := scDecode(vecArg(a, 0)).(map[string]any)
			if !ok {
				return nil, errors.New("not a beacon")
			}
			return BeaconRef(b)
		},
		"verifyLivenessBeacon": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			check, _ := vecArg(a, 1).(map[string]any)
			v := VerifyLivenessBeaconValue(vecArg(a, 0), check)
			if check["allowUnboundPq"] == true && !v.OK && v.Reason == "bad signature" {
				unbound++
				return map[string]any{"unboundRefused": true}, nil
			}
			return beaconVerdictJSON(v), nil
		},
		"acceptBeacon": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			return beaconVerdictJSON(AcceptBeaconValue(vecArg(a, 0), vecArg(a, 1))), nil
		},
		"isFrozenLiveness": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			check, _ := vecArg(a, 1).(map[string]any)
			return IsFrozenLivenessValue(vecArg(a, 0), check)
		},
		"acceptor": func(a []any) (any, error) { return beaconAcceptorScript(rsList(scDecode(vecArg(a, 0)))), nil },
		"ctor": func(a []any) (any, error) {
			// "ok" is a memory kv, an object whose update is a function is a kv; null, {} and {update: 5} are not
			var kv AtomicKV
			switch s := vecArg(a, 0).(type) {
			case string:
				kv = NewMemoryAtomicKV()
			case map[string]any:
				if s["update"] == "fn" {
					kv = NewMemoryAtomicKV()
				}
			}
			_, err := NewBeaconAcceptor(kv)
			return map[string]any{"built": err == nil}, nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		"verifyLivenessBeacon": func(want, got any) bool {
			if vecObj(got)["unboundRefused"] == true {
				return vecObj(want)["ok"] == true // accepted by the reference only through the legacy option
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-beacons.json.gz", 174, fns, cmp, nil)
	if unbound != 1 {
		t.Fatalf("%d unpinned-key cases were refused, 1 is expected", unbound)
	}
}
