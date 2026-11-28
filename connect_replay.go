package pca

// One-time-use guard for a verified PCActn and its reference in-memory store: the anti-replay primitives the token vault spends an
// action with. The store contract is ConsumeOnce(key, retainUntilMs, nowMs) -> first-time?, plus an optional per-stream counter
// (Advance); both return an error when they cannot decide, and the guard turns every such failure into a denial. Run the guard
// only AFTER the PCActn verified.

import (
	"errors"
	"math"
)

const (
	// ConnectReplayMaxComponentLen bounds the grant and holder components of a replay key (UTF-8 bytes).
	ConnectReplayMaxComponentLen = 512
	// PcactnMaxLifetimeMs is the longest iat..exp window the guard accepts (1 h).
	PcactnMaxLifetimeMs = 3_600_000
	// PcactnMaxSkewMs caps the clock-skew allowance.
	PcactnMaxSkewMs = 60_000

	replayMaxAudLen   = 256
	replayMaxNonceLen = 128
	replayMaxSafe     = 9007199254740991.0
)

// PcactnReplayStore decides whether a key was already consumed.
type PcactnReplayStore interface {
	ConsumeOnce(key string, retainUntilMs, nowMs float64) (bool, error)
}

// PcactnCounterStore advances a per-stream counter, returning false when the counter is not above the last accepted one.
type PcactnCounterStore interface {
	Advance(streamKey string, counter float64) (bool, error)
}

// PcactnReplayVerdict is the guard's answer: OK, or a Code ("malformed", "audience", "not_yet_valid", "expired", "replay",
// "store_unavailable") and Reason.
type PcactnReplayVerdict struct {
	OK           bool
	Code, Reason string
}

func replaySafeInt(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f) && math.Abs(f) <= replayMaxSafe
}

func replaySafeNonNeg(v any) (float64, bool) {
	f, ok := jsNum(v)
	if !ok || !replaySafeInt(f) || f < 0 || (f == 0 && math.Signbit(f)) {
		return 0, false
	}
	return f, true
}

// GuardPcactnReplay decides whether a (signature-verified) PCActn may be accepted ONCE. aud is the verifier's audience; now the
// verifier clock (epoch ms); clockSkewMs nil = the maximum; counters may be nil. Never fails: every failure is a denial.
func GuardPcactnReplay(store PcactnReplayStore, p map[string]any, aud string, now float64, clockSkewMs *float64, requireNonce bool, counters PcactnCounterStore) PcactnReplayVerdict {
	deny := func(code, reason string) PcactnReplayVerdict { return PcactnReplayVerdict{Code: code, Reason: reason} }
	skew := float64(PcactnMaxSkewMs)
	if clockSkewMs != nil && !math.IsNaN(*clockSkewMs) && !math.IsInf(*clockSkewMs, 0) && *clockSkewMs >= 0 {
		skew = math.Min(*clockSkewMs, PcactnMaxSkewMs)
	}
	objOK := p != nil
	var leaf map[string]any
	if chain, ok := p["cap_chain"].([]any); ok && len(chain) > 0 {
		leaf, _ = chain[len(chain)-1].(map[string]any)
	}
	holder, holderOK := "", false
	if leaf != nil {
		holder, holderOK = leaf["holder"].(string)
	}
	grant, grantOK := p["grant_ref"].(string)
	leafOK := leaf != nil && holderOK && grantOK
	compsOK := leafOK
	if leafOK {
		for _, c := range []string{grant, holder} {
			if len(c) == 0 || len(c) > ConnectReplayMaxComponentLen {
				compsOK = false
			}
		}
	}
	nonceV, hasNonce := p["nonce"]
	nonce, nonceStr := nonceV.(string)
	nonceOK := hasNonce && nonceStr && len(nonce) != 0 && len(nonce) <= replayMaxNonceLen
	nowOK := replaySafeInt(now)
	audOK := len(aud) != 0 && len(aud) <= replayMaxAudLen
	pAud, pAudOK := p["aud"].(string)
	audMatches := objOK && pAudOK && pAud == aud
	iat, iatOK := replaySafeNonNeg(p["iat"])
	exp, expOK := replaySafeNonNeg(p["exp"])
	counter, counterOK := replaySafeNonNeg(p["counter"])
	sk := math.Floor(skew)
	windowOK := iatOK && expOK && exp > iat && exp-iat <= PcactnMaxLifetimeMs
	code := ""
	switch {
	case !nowOK || !audOK || !objOK:
		code = "malformed"
	case !audMatches:
		code = "audience"
	case !windowOK:
		code = "malformed"
	case iat > now+sk:
		code = "not_yet_valid"
	case now > exp:
		code = "expired"
	case !leafOK || !compsOK || !counterOK:
		code = "malformed"
	}
	if code != "" {
		switch {
		case code == "audience":
			return deny(code, "the PCActn is for another audience")
		case code == "not_yet_valid":
			return deny(code, "iat is in the future beyond the clock-skew allowance")
		case code == "expired":
			return deny(code, "the PCActn has expired")
		case !nowOK:
			return deny(code, "verifier clock is not an integer epoch-ms")
		case !audOK:
			return deny(code, "verifier audience is invalid")
		case !objOK:
			return deny(code, "not a PCActn")
		case !windowOK:
			return deny(code, "iat / exp are not a valid bounded window")
		case !leafOK:
			return deny(code, "no leaf holder / grant")
		case !compsOK:
			return deny(code, "grant / holder is not a bounded string")
		}
		return deny(code, "counter is not a non-negative safe integer")
	}
	if exp+math.Ceil(skew) > replayMaxSafe {
		return deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)")
	}
	retainUntil := exp + skew
	if hasNonce {
		if !nonceOK {
			return deny("malformed", "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes")
		}
		key, err := ReplayKey("pca-nonce/v1", aud, grant, holder, nonce)
		if err != nil {
			return deny("store_unavailable", "replay store failed closed: "+err.Error())
		}
		consumed, err := store.ConsumeOnce(key, retainUntil, now)
		if err != nil {
			return deny("store_unavailable", "replay store failed closed: "+err.Error())
		}
		if !consumed {
			return deny("replay", "nonce already consumed")
		}
	} else if requireNonce {
		return deny("malformed", "a nonce is required")
	}
	if counters != nil {
		key, err := ReplayKey("pca-counter/v1", aud, grant, holder)
		if err != nil {
			return deny("store_unavailable", "replay store failed closed: "+err.Error())
		}
		advanced, err := counters.Advance(key, counter)
		if err != nil {
			return deny("store_unavailable", "replay store failed closed: "+err.Error())
		}
		if !advanced {
			return deny("replay", "counter is not greater than the last accepted")
		}
	}
	return PcactnReplayVerdict{OK: true}
}

// InMemoryPcactnReplayStore is the reference store: correct only for a single verifier process whose lifetime covers the action
// lifetime. It is not safe for concurrent use without external locking.
type InMemoryPcactnReplayStore struct {
	seen    map[string]float64
	streams map[string]float64
	max     int
}

// NewInMemoryPcactnReplayStore returns a store holding at most maxEntries live keys (<= 0: 100000).
func NewInMemoryPcactnReplayStore(maxEntries int) *InMemoryPcactnReplayStore {
	if maxEntries <= 0 {
		maxEntries = 100_000
	}
	return &InMemoryPcactnReplayStore{seen: map[string]float64{}, streams: map[string]float64{}, max: maxEntries}
}

// Size is the number of retained keys.
func (s *InMemoryPcactnReplayStore) Size() int { return len(s.seen) }

// Prune drops every key retained only until before nowMs and returns how many.
func (s *InMemoryPcactnReplayStore) Prune(nowMs float64) int {
	n := 0
	for k, until := range s.seen {
		if until < nowMs {
			delete(s.seen, k)
			n++
		}
	}
	return n
}

// ConsumeOnce records key until retainUntilMs; false when it was already live.
func (s *InMemoryPcactnReplayStore) ConsumeOnce(key string, retainUntilMs, nowMs float64) (bool, error) {
	fin := func(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
	if key == "" || !fin(retainUntilMs) || !fin(nowMs) || retainUntilMs < nowMs {
		return false, errors.New("consumeOnce: invalid key or retention horizon")
	}
	until, had := s.seen[key]
	if had && until >= nowMs {
		return false, nil
	}
	if !had && len(s.seen) >= s.max {
		s.Prune(nowMs)
		if len(s.seen) >= s.max {
			return false, errors.New("replay store full of live entries")
		}
	}
	s.seen[key] = math.Max(retainUntilMs, until)
	return true, nil
}

// Advance records counter for the stream; false unless it is above the last accepted one.
func (s *InMemoryPcactnReplayStore) Advance(streamKey string, counter float64) (bool, error) {
	if streamKey == "" || math.IsNaN(counter) || counter < 0 || !replaySafeInt(counter) {
		return false, errors.New("advance: invalid stream or counter")
	}
	if last, ok := s.streams[streamKey]; ok && !(counter > last) {
		return false, nil
	}
	s.streams[streamKey] = counter
	return true, nil
}
