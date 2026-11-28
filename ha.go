package pca

import (
	"errors"
	"math"
	"sort"
	"time"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

// Guardian high-availability control logic: which guardians are live, whether a co-sign quorum is available, how to degrade when it
// is lost (read-only or halt, never fail open), who to ask and in which failover order, and a durable, FENCED leader lease: at most
// one holder at a time, a strictly increasing fencing epoch a stale ex-leader cannot get around, store-side expiry, and "no leader"
// whenever the store errs. Process deployment and health probing remain the operator's job.
//
// Guarantees: lease safety holds if the store's compare-and-swap is linearizable and the holder's clock error stays under the skew.
// Not guaranteed: availability, and protection of a downstream that never checks the fencing epoch (check it with a FenceGuard).
// Nothing here fails open: losing quorum or the lease restricts authority, never widens it.
//
// A guardian set is its decoded JSON object, {guardians: [{id, healthy, lastSeen, weight?}], quorum}: every shape is answered, a
// malformed one counts as down.

// haCollator orders guardian ids as `localeCompare` does (the CLDR root collation; JavaScript's default is the runtime locale).
var haCollator = collate.New(language.Und)

const haDefaultStaleMs = 30_000

func haGuardiansOf(set any) ([]any, bool) {
	m, ok := set.(map[string]any)
	if !ok {
		return nil, false
	}
	l, ok := m["guardians"].([]any)
	return l, ok
}

// LiveGuardians returns the guardians that are flagged healthy AND have a fresh heartbeat at now, in set order. Opts may carry
// `staleMs` (default 30000). It fails closed: a malformed set, a non-finite clock or stale window, a non-finite or FUTURE-dated
// heartbeat and a non-boolean `healthy` all count as down.
func LiveGuardians(set any, now float64, opts map[string]any) []any {
	staleMs := float64(haDefaultStaleMs)
	if v, has := opts["staleMs"]; has && v != nil {
		staleMs = jsF(v)
	}
	list, ok := haGuardiansOf(set)
	if ok {
		for _, g := range list {
			if _, isObj := safetyObj(g); !isObj {
				ok = false
			}
		}
	}
	if math.IsNaN(now) || math.IsInf(now, 0) || math.IsNaN(staleMs) || math.IsInf(staleMs, 0) || staleMs < 0 || !ok {
		return []any{}
	}
	out := []any{}
	for _, g := range list {
		m, isMap := g.(map[string]any)
		if !isMap || m["healthy"] != true {
			continue
		}
		seen, isNum := jsNum(m["lastSeen"])
		if isNum && !math.IsNaN(seen) && !math.IsInf(seen, 0) && seen <= now && now-seen <= staleMs {
			out = append(out, g)
		}
	}
	return out
}

func haWeightOf(g any) float64 {
	m, _ := g.(map[string]any)
	if w, ok := jsNum(m["weight"]); ok && !math.IsNaN(w) && !math.IsInf(w, 0) {
		return w
	}
	return 0
}

// QuorumStatus is {total, live, quorum, available, degraded}: available means a co-sign quorum is reachable right now, degraded
// that some guardians are live but below quorum. `quorum` is the set's own value (absent when the set has none).
func QuorumStatus(set any, now float64, opts map[string]any) map[string]any {
	live := len(LiveGuardians(set, now, opts))
	m, _ := set.(map[string]any)
	list, _ := haGuardiansOf(set)
	q, hasQ := m["quorum"]
	out := map[string]any{"total": jsNumber(float64(len(list))), "live": jsNumber(float64(live))}
	if hasQ {
		out["quorum"] = q
	}
	qf, isNum := jsNum(q)
	out["available"] = isNum && jsIsInteger(qf) && qf >= 1 && float64(live) >= qf
	qc := math.NaN()
	if hasQ {
		qc = jsToNumber(q)
	}
	out["degraded"] = live > 0 && float64(live) < qc
	return out
}

// DegradeMode is the degradation mode a quorum status implies: "normal" when a quorum is available, else "read-only" (reversible
// automatic actions only, no new co-signed authority) while some guardian is live, else "halt". A policy that sets allowReadOnly
// to false (exactly) goes straight to "halt". It never fails open. A status that is not an object is an error.
func DegradeMode(status any, policy map[string]any) (string, error) {
	s, ok := status.(map[string]any)
	if !ok {
		return "", errors.New("degradeMode: the status is not an object")
	}
	if jsTruthy(s["available"]) {
		return "normal", nil
	}
	if jsToNumber(s["live"]) > 0 && policy["allowReadOnly"] != false {
		return "read-only", nil
	}
	return "halt", nil
}

// haOrdered sorts the live guardians by preference: weight descending, then the freshest heartbeat, then id (as localeCompare).
func haOrdered(live []any) ([]any, error) {
	out := append([]any(nil), live...)
	var cmpErr error
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].(map[string]any), out[j].(map[string]any)
		if d := haWeightOf(b) - haWeightOf(a); d != 0 && !math.IsNaN(d) {
			return d < 0
		}
		la, _ := jsNum(a["lastSeen"])
		lb, _ := jsNum(b["lastSeen"])
		if d := lb - la; d != 0 && !math.IsNaN(d) {
			return d < 0
		}
		ia, ok1 := a["id"].(string)
		ib, ok2 := b["id"].(string)
		if !ok1 || !ok2 {
			cmpErr = errors.New("Cannot read properties of undefined (reading 'localeCompare')")
			return false
		}
		return haCollator.CompareString(ia, ib) < 0
	})
	return out, cmpErr
}

// SelectSigners selects the guardians to ask for a co-sign: the `quorum` freshest, highest-weight live guardians (their ids), or
// none when a quorum is not available (never attempt a co-sign below quorum). A set that is null is an error.
func SelectSigners(set any, now float64, opts map[string]any) ([]any, error) {
	live := LiveGuardians(set, now, opts)
	if set == nil {
		return nil, errors.New("Cannot read properties of null (reading 'quorum')")
	}
	m, _ := set.(map[string]any)
	q, isNum := jsNum(m["quorum"])
	if !isNum || !jsIsInteger(q) || q < 1 || float64(len(live)) < q {
		return []any{}, nil
	}
	ordered, err := haOrdered(live)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, g := range ordered[:int(q)] {
		out = append(out, g.(map[string]any)["id"])
	}
	return out, nil
}

// FailoverPlan is a primary (the preferred live guardian, or nil when none is live) and the remaining live guardians as ordered
// standbys, for the single-signer fast path with the quorum as the backstop.
func FailoverPlan(set any, now float64, opts map[string]any) (primary any, standbys []any, err error) {
	ordered, err := haOrdered(LiveGuardians(set, now, opts))
	if err != nil {
		return nil, nil, err
	}
	standbys = []any{}
	for i, g := range ordered {
		id := g.(map[string]any)["id"]
		if i == 0 {
			primary = id
			continue
		}
		standbys = append(standbys, id)
	}
	return primary, standbys, nil
}

// ValidateGuardianSet returns why a guardian set is malformed (quorum in range, unique non-empty ids), or "".
func ValidateGuardianSet(set any) string {
	m, isObj := safetyObj(set)
	if !isObj {
		return "guardian set is not an object"
	}
	list, ok := m["guardians"].([]any)
	if !ok || len(list) == 0 {
		return "guardian set is empty"
	}
	q, isNum := jsNum(m["quorum"])
	if !isNum || !jsIsInteger(q) || q < 1 {
		return "quorum must be an integer ≥ 1"
	}
	if q > float64(len(list)) {
		return "quorum exceeds guardian count"
	}
	ids := map[string]bool{}
	for _, g := range list {
		gm, isObj := safetyObj(g)
		id, isStr := gm["id"].(string)
		if !isObj || !isStr || id == "" {
			return "guardian id must be a non-empty string"
		}
		ids[id] = true
	}
	if len(ids) != len(list) {
		return "duplicate guardian ids"
	}
	return ""
}

// ---- durable, fenced leader lease -------------------------------------------------------------------------
//
// The lease itself (GuardianAcquireLease, GuardianRenewLease, GuardianReleaseLease over a LeaseStore, with DefaultGuardianLeaseSkewMs
// and MaxGuardianLeaseTtlMs) lives with the store conformance profile; this adds the fence that guards its epoch, the fenced signer,
// the resource-side guard and the reference store over a durable key-value store.

// AssertFence reports whether this exact (holder, epoch) token is still the leader, with its safe window open, per the store:
// {ok: true} or {ok: false, reason} with reason "stale", "expired" or "store-error". Any error answers no. A nil token, or a skew
// that is not a finite number from 0, is "stale" without a store read. Pass DefaultGuardianLeaseSkewMs for the default skew.
func AssertFence(store LeaseStore, token map[string]any, skewMs float64) map[string]any {
	refuse := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if token == nil || math.IsNaN(skewMs) || math.IsInf(skewMs, 0) || skewMs < 0 {
		return refuse("stale")
	}
	cur, now, err := leaseSnapshot(store)
	if err != nil {
		return refuse("store-error")
	}
	if cur == nil || cur["holder"] != token["holder"] || !leaseSameEpoch(cur, token) {
		return refuse("stale")
	}
	if exp, _ := leaseNum(cur["expiresAt"]); exp-skewMs > now {
		return map[string]any{"ok": true}
	}
	return refuse("expired")
}

// FenceError is a refusal of the fenced signer: Reason is "stale", "expired", "store-error" or "no-lease".
type FenceError struct{ Reason string }

func (e *FenceError) Error() string { return "fenced: " + e.Reason }

// FencedSigned is the result of a fenced signature and the epoch it was made under.
type FencedSigned struct {
	Result any
	Epoch  float64
}

// FencedSigner wraps a co-sign function so it only runs while the caller is the fenced leader (getLease returns nil for none). The
// fence is checked before AND after the signature: a leader that lost the lease mid-signature gets a *FenceError and the
// signature is discarded. Check-then-sign is inherently racy, so the downstream must also admit the epoch with a FenceGuard. An
// error of sign is returned as is.
func FencedSigner(store LeaseStore, getLease func() map[string]any, sign func() (any, error), skewMs float64) func() (FencedSigned, error) {
	return func() (FencedSigned, error) {
		lease := getLease()
		if lease == nil {
			return FencedSigned{}, &FenceError{"no-lease"}
		}
		if pre := AssertFence(store, lease, skewMs); pre["ok"] != true {
			return FencedSigned{}, &FenceError{pre["reason"].(string)}
		}
		result, err := sign()
		if err != nil {
			return FencedSigned{}, err
		}
		if post := AssertFence(store, lease, skewMs); post["ok"] != true {
			return FencedSigned{}, &FenceError{post["reason"].(string)}
		}
		epoch, _ := leaseNum(lease["epoch"])
		return FencedSigned{Result: result, Epoch: epoch}, nil
	}
}

// FenceGuard is resource-side fencing: it remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write).
type FenceGuard struct{ hi int64 }

// CreateFenceGuard starts a guard at initial (a non-positive or unsafe value starts at 0).
func CreateFenceGuard(initial float64) *FenceGuard {
	g := &FenceGuard{}
	if initial > 0 && initial <= maxSafeInt && initial == math.Trunc(initial) {
		g.hi = int64(initial)
	}
	return g
}

// Admit admits an epoch from 1 that is not below the highest seen, and remembers it.
func (g *FenceGuard) Admit(epoch float64) bool {
	if math.IsNaN(epoch) || epoch != math.Trunc(epoch) || epoch > maxSafeInt || epoch < 1 || epoch < float64(g.hi) {
		return false
	}
	g.hi = int64(epoch)
	return true
}

// Highest is the highest epoch admitted so far.
func (g *FenceGuard) Highest() int64 { return g.hi }

// KvLeaseStore is the reference LeaseStore over any DurableStateKv (its Update is the atomic compare-and-swap). With a durable
// state it survives restarts. A stored record that is not well formed is an error ("corrupt lease state"), never "no lease".
type KvLeaseStore struct {
	kv  DurableStateKv
	key string
	now func() float64
}

// NewKvLeaseStore builds the store: key "" is "ha/lease"; now nil is the wall clock in epoch milliseconds.
func NewKvLeaseStore(kv DurableStateKv, key string, now func() float64) *KvLeaseStore {
	if key == "" {
		key = "ha/lease"
	}
	if now == nil {
		now = func() float64 { return float64(time.Now().UnixMilli()) }
	}
	return &KvLeaseStore{kv: kv, key: key, now: now}
}

// Read implements LeaseStore.
func (s *KvLeaseStore) Read() (map[string]any, error) {
	v, ok, err := s.kv.Get(s.key)
	if err != nil || !ok {
		return nil, err
	}
	m, _ := v.(map[string]any)
	if !leaseValid(m) {
		return nil, errors.New("corrupt lease state")
	}
	return m, nil
}

// leaseSame is the reference's record equality: holder, epoch and expiry.
func leaseSame(a, b map[string]any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ae, aok := leaseNum(a["epoch"])
	be, bok := leaseNum(b["epoch"])
	ax, axok := leaseNum(a["expiresAt"])
	bx, bxok := leaseNum(b["expiresAt"])
	ah, ahok := a["holder"].(string)
	bh, bhok := b["holder"].(string)
	return ahok && bhok && ah == bh && aok && bok && ae == be && axok && bxok && ax == bx
}

// Cas implements LeaseStore: it replaces the record iff the stored one equals expected (nil: none) and next does not lower the epoch.
func (s *KvLeaseStore) Cas(expected, next map[string]any) (bool, error) {
	if !leaseValid(next) {
		return false, errors.New("invalid lease record")
	}
	matched := false
	_, _, err := s.kv.Update(s.key, func(prev any, ok bool) (any, bool) {
		var p map[string]any
		if ok {
			p, _ = prev.(map[string]any)
			if !leaseValid(p) {
				return nil, false
			}
		}
		if !leaseSame(p, expected) {
			return nil, false
		}
		if pe, _ := leaseNum(p["epoch"]); p != nil {
			if ne, _ := leaseNum(next["epoch"]); ne < pe {
				return nil, false
			}
		}
		matched = true
		return next, true
	})
	return matched, err
}

// Now implements LeaseStore.
func (s *KvLeaseStore) Now() (float64, error) { return s.now(), nil }
