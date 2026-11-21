package pca

import (
	"regexp"
	"unicode/utf16"
)

// Durable forms of the allowlist high-water mark and of the accepted MAA key sets, over a DurableStateKv (OpenDurableState or
// CreateMemoryDurableKv).

var alDigestRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// alHighWater is a stored high-water mark {version, digest}; ok is false for anything malformed.
func alHighWater(x any) (version int64, digest string, ok bool) {
	m, isMap := x.(map[string]any)
	if !isMap || !jsIsInt(m["version"]) {
		return 0, "", false
	}
	f, _ := jsNum(m["version"])
	d, isStr := m["digest"].(string)
	if !isStr || !alDigestRe.MatchString(d) {
		return 0, "", false
	}
	return int64(f), d, true
}

// VerifyAllowlistDurable is VerifyAllowlistManifest with the rollback high-water mark kept in kv under "allowlist/<issuer>": the
// stored {version, digest} is the LastSeen pair (any LastSeen value in o is ignored), and an accepted manifest is recorded with an
// atomic, append-only update (a stored version at or above ours is kept). A manifest is accepted only when the record now stored is
// exactly its version and digest: a newer one accepted concurrently is `rollback`, the same version with another body is `conflict`,
// corrupt stored state is `malformed`, and a store error is `malformed` (nothing unpersisted is ever accepted). Deleting the state
// resets the mark, which is what the transparency anchor (VerifyAllowlistAnchored) covers.
func VerifyAllowlistDurable(manifest any, o VerifyAllowlistOptions, kv DurableStateKv) AllowlistResult {
	fail := func(code, reason string) AllowlistResult { return AllowlistResult{Code: code, Reason: reason} }
	if kv == nil {
		return fail("malformed", "durable verification needs a store")
	}
	m, _ := manifest.(map[string]any)
	issuer, isStr := m["issuer"].(string)
	if !isStr || len(utf16.Encode([]rune(issuer))) > 200 {
		return fail("malformed", "issuer must be a string")
	}
	key := "allowlist/" + issuer
	raw, has, err := kv.Get(key)
	if err != nil {
		return fail("malformed", err.Error())
	}
	o.LastSeenVersion, o.LastSeenDigest = nil, nil
	if has {
		pv, pd, ok := alHighWater(raw)
		if !ok {
			return fail("malformed", "persisted allowlist high-water mark is corrupt")
		}
		o.LastSeenVersion, o.LastSeenDigest = &pv, &pd
	}
	v := VerifyAllowlistManifest(manifest, o)
	if !v.OK {
		return v
	}
	stored, sok, err := kv.Update(key, func(cur any, ok bool) (any, bool) {
		if ok {
			cv, _, valid := alHighWater(cur)
			if !valid || cv >= v.Version { // corrupt stays corrupt; a stored version at or above ours is kept as is
				return nil, false
			}
		}
		return map[string]any{"version": v.Version, "digest": v.Digest}, true
	})
	if err != nil {
		return fail("malformed", err.Error())
	}
	// the decision reads only the record now stored, whether or not the store ran the updater
	sv, sd, valid := int64(0), "", false
	if sok {
		sv, sd, valid = alHighWater(stored)
	}
	switch {
	case !valid || sv > v.Version:
		return fail("rollback", "a newer manifest was accepted concurrently")
	case sv == v.Version && sd != v.Digest:
		return fail("conflict", "same version as the stored high-water mark but a different body")
	case sv < v.Version: // the store did not record our acceptance
		return fail("rollback", "a newer manifest was accepted concurrently")
	}
	return v
}

type durableMaaKeyStateStore struct{ kv DurableStateKv }

// DurableMaaKeyStateStore persists the accepted MAA key sets in durable state under "maa-keys/<issuer>". Writes are atomic
// read-modify-write and monotone in FetchedAtMs: a stale writer never moves the stored state backwards. A corrupt stored record is
// returned as it is, so GetTrustAnchors fails closed (corrupt-state).
func DurableMaaKeyStateStore(kv DurableStateKv) MaaKeyStateStore { return durableMaaKeyStateStore{kv} }

func (s durableMaaKeyStateStore) Get(issuer string) (any, bool, error) {
	return s.kv.Get("maa-keys/" + issuer)
}

func (s durableMaaKeyStateStore) Set(issuer string, state MaaKeyState) error {
	_, _, err := s.kv.Update("maa-keys/"+issuer, func(prev any, ok bool) (any, bool) {
		if ok {
			if p := parseMaaKeyState(prev, issuer); p != nil && p.FetchedAtMs > state.FetchedAtMs {
				return nil, false
			}
		}
		return maaStateAsAny(state), true
	})
	return err
}
