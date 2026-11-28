package pca

import (
	"errors"
	"math"
	"testing"
)

// Replay of the guardian high-availability module against the reference (ref-ha), every case: liveness, quorum, degradation, signer
// selection and failover, set validation, the fence guard and, as op scripts over one fresh in-memory store, the leader lease with
// its store faults, corrupt records, the fenced signer and the raw compare-and-swap. A reference throw requires a refusal.

// scEncode is the corpus form of a decoded value: a non-finite number in the {"$num"} form, deeply.
func scEncode(v any) any {
	switch t := v.(type) {
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return scNumOut(t)
		}
		return jsNumber(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = scEncode(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = scEncode(x)
		}
		return a
	}
	return v
}

// scJSONNull is JSON.stringify of a value: a non-finite number is null.
func scJSONNull(v any) any {
	switch t := v.(type) {
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil
		}
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = scJSONNull(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = scJSONNull(x)
		}
		return a
	}
	return v
}

// haStore is the scenario store: a KvLeaseStore over an in-memory kv with a settable clock and injectable faults.
type haStore struct {
	kv      *MemoryDurableKv
	inner   *KvLeaseStore
	clock   float64
	fault   string
	loseCas bool
}

func newHaStore() *haStore {
	s := &haStore{kv: CreateMemoryDurableKv()}
	s.inner = NewKvLeaseStore(s.kv, "", func() float64 { return s.clock })
	return s
}

func (s *haStore) Read() (map[string]any, error) {
	if s.fault == "read" {
		return nil, errors.New("boom")
	}
	return s.inner.Read()
}

func (s *haStore) Now() (float64, error) {
	if s.fault == "now" {
		return 0, errors.New("boom")
	}
	return s.clock, nil
}

func (s *haStore) Cas(expected, next map[string]any) (bool, error) {
	if s.fault == "cas" {
		return false, errors.New("boom")
	}
	if s.loseCas {
		s.loseCas = false
		return false, nil
	}
	return s.inner.Cas(expected, next)
}

// haOpts reads lease options: ttlMs and skewMs (an absent or null skew is the default), a missing ttl is NaN (invalid).
func haOpts(v any) (ttl, skew float64) {
	m, _ := v.(map[string]any)
	skew = DefaultGuardianLeaseSkewMs
	if s, has := m["skewMs"]; has && s != nil {
		skew = jsF(s)
	}
	return jsF(m["ttlMs"]), skew
}

func haLeaseScript(ops []any) []any {
	st := newHaStore()
	refs := map[string]map[string]any{}
	// leaseOf: a remembered ref or a literal record; a number is present but no lease (an empty record)
	leaseOf := func(v any) map[string]any {
		switch t := v.(type) {
		case string:
			return refs[t]
		case map[string]any:
			return t
		case nil:
			return nil
		}
		return map[string]any{}
	}
	skewOf := func(v any) float64 {
		if v == nil {
			return DefaultGuardianLeaseSkewMs
		}
		return jsF(v)
	}
	out := make([]any, len(ops))
	for i, o := range ops {
		op, _ := o.([]any)
		name, _ := vecArg(op, 0).(string)
		switch name {
		case "clock":
			st.clock = jsF(vecArg(op, 1))
		case "fault":
			switch k, _ := vecArg(op, 1).(string); k {
			case "loseCas":
				st.loseCas = true
			case "none":
				st.fault, st.loseCas = "", false
			default:
				st.fault = k
			}
		case "raw":
			_ = st.kv.Set("ha/lease", scJSONNull(vecArg(op, 1)))
		case "read":
			r, err := st.Read()
			switch {
			case err != nil:
				out[i] = map[string]any{"$err": err.Error()}
			case r != nil:
				out[i] = r
			}
		case "acquire":
			holder, _ := vecArg(op, 2).(string)
			ttl, skew := haOpts(vecArg(op, 3))
			res := GuardianAcquireLease(st, holder, ttl, skew)
			if res["ok"] == true {
				ref, _ := vecArg(op, 1).(string)
				refs[ref], _ = res["lease"].(map[string]any)
			}
			out[i] = res
		case "renew":
			ttl, skew := haOpts(vecArg(op, 2))
			out[i] = GuardianRenewLease(st, leaseOf(vecArg(op, 1)), ttl, skew)
		case "release":
			res := GuardianReleaseLease(st, leaseOf(vecArg(op, 1)))
			if ref, isStr := vecArg(op, 1).(string); isStr && res["ok"] == true {
				refs[ref], _ = res["lease"].(map[string]any)
			}
			out[i] = res
		case "fence":
			out[i] = AssertFence(st, leaseOf(vecArg(op, 1)), skewOf(vecArg(op, 2)))
		case "signer":
			advance, throws := jsF(vecArg(op, 3)), vecArg(op, 4) == true
			sign := func() (any, error) {
				st.clock += advance
				if throws {
					return nil, errors.New("sign")
				}
				return "signed", nil
			}
			res, err := FencedSigner(st, func() map[string]any { return leaseOf(vecArg(op, 1)) }, sign, skewOf(vecArg(op, 2)))()
			var fe *FenceError
			switch {
			case err == nil:
				out[i] = map[string]any{"ok": true, "result": res.Result, "epoch": jsNumber(res.Epoch)}
			case errors.As(err, &fe):
				out[i] = map[string]any{"ok": false, "reason": fe.Reason}
			default:
				out[i] = map[string]any{"ok": false, "error": "sign"}
			}
		default:
			out[i] = map[string]any{"$err": "bad op"}
		}
	}
	return out
}

func TestHighAvailabilityMatchesTheReference(t *testing.T) {
	setNowOpts := func(a []any) (any, float64, map[string]any) {
		a = scDecode(a).([]any)
		return vecArg(a, 0), jsF(vecArg(a, 1)), vecObj(vecArg(a, 2))
	}
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"MAX_LEASE_TTL_MS": jsNumber(MaxGuardianLeaseTtlMs), "DEFAULT_LEASE_SKEW_MS": jsNumber(DefaultGuardianLeaseSkewMs)}, nil
		},
		"liveGuardians": func(a []any) (any, error) {
			set, now, opts := setNowOpts(a)
			return scEncode(LiveGuardians(set, now, opts)), nil
		},
		"quorumStatus": func(a []any) (any, error) {
			set, now, opts := setNowOpts(a)
			return scEncode(QuorumStatus(set, now, opts)), nil
		},
		"degradeMode": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			return DegradeMode(vecArg(a, 0), vecObj(vecArg(a, 1)))
		},
		"selectSigners": func(a []any) (any, error) {
			set, now, opts := setNowOpts(a)
			ids, err := SelectSigners(set, now, opts)
			return scEncode(ids), err
		},
		"failoverPlan": func(a []any) (any, error) {
			set, now, opts := setNowOpts(a)
			primary, standbys, err := FailoverPlan(set, now, opts)
			if err != nil {
				return nil, err
			}
			return scEncode(map[string]any{"primary": primary, "standbys": standbys}), nil
		},
		"validateGuardianSet": func(a []any) (any, error) {
			if r := ValidateGuardianSet(scDecode(vecArg(a, 0))); r != "" {
				return r, nil
			}
			return nil, nil
		},
		"fenceGuard": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			g := CreateFenceGuard(jsF(vecArg(a, 0)))
			admits := []any{}
			for _, e := range rsList(vecArg(a, 1)) {
				admits = append(admits, g.Admit(jsF(e)))
			}
			return map[string]any{"admits": admits, "highest": jsNumber(float64(g.Highest()))}, nil
		},
		"lease": func(a []any) (any, error) { return haLeaseScript(rsList(scDecode(vecArg(a, 0)))), nil },
		"kvCas": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			st := newHaStore()
			if prev := vecArg(a, 0); prev != nil || (len(a) > 1 && a[1] != nil) { // a null prev against a non-null expectation is a stored null
				if err := st.kv.Set("ha/lease", scJSONNull(prev)); err != nil {
					return nil, err
				}
			}
			expected, _ := vecArg(a, 1).(map[string]any)
			ok, err := st.inner.Cas(expected, vecObj(vecArg(a, 2)))
			if err != nil {
				return nil, err
			}
			out := map[string]any{"ok": ok}
			if v, has, _ := st.kv.Get("ha/lease"); has {
				out["stored"] = v
			}
			return out, nil
		},
	}
	replayAll(t, "ref-ha.json.gz", 753, fns, nil, nil)
}
