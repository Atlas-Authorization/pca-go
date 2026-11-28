package pca

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
)

// Dead-man liveness beacons v2: an issuer (the grant's principal, or the operator / guardian) signs short-lived beacons; authority is live
// only while a valid beacon covers the current moment, and the PCActn binds one through its signed `freshness.beacon_ref`
// (= BeaconRef). Fail closed: an absent, stale, unpinned-issuer, wrong-scope or replayed beacon is frozen. A beacon is a map with
// json.Number integers (as parsed from JSON, or as IssueLivenessBeacon returns it).

const (
	GlobalScope        = "*"
	livenessDomain     = "atlas-pca/beacon/v2\x00"
	BeaconEpochMs      = 60_000
	BeaconMaxValidity  = 60 * 60_000 // HARD ceiling on not_after - issued_at, ms
	BeaconClockSkewMs  = 30_000
	maxSafeBeaconInt   = 9007199254740991
	beaconStateRefused = "beacon state unavailable"
)

// BeaconVerdict is a beacon decision: OK, or the refusal Reason.
type BeaconVerdict struct {
	OK     bool
	Reason string
}

// IssueLivenessBeacon signs a beacon (Ed25519 by default; pass suite for another). scope "" is GlobalScope; validityMs 0 is 5 epochs.
func IssueLivenessBeacon(issuer *KeyPair, instance, scope string, seq, issuedAt, validityMs int64, suite *SuiteOpts) (map[string]any, error) {
	if validityMs == 0 {
		validityMs = 5 * BeaconEpochMs
	}
	if scope == "" {
		scope = GlobalScope
	}
	if seq < 0 || seq > maxSafeBeaconInt {
		return nil, errors.New("issueLivenessBeacon: seq must be a non-negative integer")
	}
	if issuedAt < 0 || issuedAt > maxSafeBeaconInt {
		return nil, errors.New("issueLivenessBeacon: issuedAt must be an integer")
	}
	if validityMs <= 0 || validityMs > BeaconMaxValidity {
		return nil, fmt.Errorf("issueLivenessBeacon: validity must be in (0, %d] ms", int64(BeaconMaxValidity))
	}
	return SignArtifact(livenessDomain, map[string]any{"v": 2, "instance": instance, "scope": scope, "epoch": issuedAt / BeaconEpochMs, "seq": seq,
		"issued_at": issuedAt, "not_after": issuedAt + validityMs, "issuer": issuer.Public}, issuer, suite)
}

// BeaconRef is the stable reference to a beacon: what the PCActn commits in `freshness.beacon_ref`.
func BeaconRef(b map[string]any) (string, error) { return HashCanonical(b) }

func beaconMsg(b map[string]any) ([]byte, bool) {
	body := map[string]any{}
	for _, k := range []string{"v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer"} {
		if v, has := b[k]; has {
			body[k] = v
		}
	}
	alg, algP := b["alg"]
	pq, pqP := b["pq_pk"]
	bound, ok := bindSuiteFields(body, alg, algP, pq, pqP)
	if !ok {
		return nil, false
	}
	cb, err := canonBytes(bound)
	if err != nil {
		return nil, false
	}
	return append([]byte(livenessDomain), cb...), true
}

// VerifyLivenessBeacon: signature, pinned issuer, instance and scope binding (scope "" = not checked), the HARD maximum validity and the
// freshness window. pqPins is the server's issuer -> pq_pk pins for a post-quantum suite. Never panics.
func VerifyLivenessBeacon(b map[string]any, issuers []string, now int64, instance, scope string, pqPins map[string]string) (v BeaconVerdict) {
	bad := BeaconVerdict{Reason: "malformed beacon"}
	defer func() {
		if recover() != nil {
			v = bad
		}
	}()
	if b == nil {
		return bad
	}
	if ver, ok := safeInt(b["v"]); !ok || ver != 2 {
		return bad
	}
	alg, algP := b["alg"]
	if _, ok := resolveSigAlg(alg, algP); !ok {
		return bad
	}
	if inst, isStr := b["instance"].(string); !isStr || inst != instance {
		return BeaconVerdict{Reason: "wrong instance"}
	}
	issuer, _ := b["issuer"].(string)
	if !slices.Contains(issuers, issuer) {
		return BeaconVerdict{Reason: "issuer not pinned"}
	}
	msg, ok := beaconMsg(b)
	if !ok || !verifyPinnedSuite(alg, algP, issuer, b["pq_pk"], msg, b["sig"], b["pq_sig"], pqPins) {
		return BeaconVerdict{Reason: "bad signature"}
	}
	epoch, e1 := safeInt(b["epoch"])
	seq, e2 := safeInt(b["seq"])
	iat, e3 := safeInt(b["issued_at"])
	nafter, e4 := safeInt(b["not_after"])
	if !(e1 && e2 && e3 && e4) || seq < 0 {
		return BeaconVerdict{Reason: "malformed window"}
	}
	if nafter <= iat || nafter-iat > BeaconMaxValidity {
		return BeaconVerdict{Reason: "validity exceeds the hard maximum"}
	}
	if epoch != int64(math.Floor(float64(iat)/BeaconEpochMs)) {
		return BeaconVerdict{Reason: "epoch does not match issued_at"}
	}
	if now+BeaconClockSkewMs < iat {
		return BeaconVerdict{Reason: "not yet valid"}
	}
	if now > nafter {
		return BeaconVerdict{Reason: "expired"}
	}
	if sc, _ := b["scope"].(string); scope != "" && sc != GlobalScope && sc != scope {
		return BeaconVerdict{Reason: "scope not covered"}
	}
	return BeaconVerdict{OK: true}
}

// AcceptBeacon is the monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher seq. prev is the previously
// accepted seq (nil: none). Total: a malformed beacon is refused.
func AcceptBeacon(prev *int64, next map[string]any) BeaconVerdict {
	seq, ok := safeInt(next["seq"])
	if !ok || seq < 0 || seq > maxSafeBeaconInt {
		return BeaconVerdict{Reason: "malformed beacon"}
	}
	if prev != nil && !(seq > *prev) {
		return BeaconVerdict{Reason: fmt.Sprintf("replayed beacon: seq %d <= %d", seq, *prev)}
	}
	return BeaconVerdict{OK: true}
}

// IsFrozenLiveness: frozen unless at least one beacon verifies for (instance, scope, now). Absence is a freeze.
func IsFrozenLiveness(beacons []map[string]any, issuers []string, now int64, instance, scope string, pqPins map[string]string) bool {
	for _, b := range beacons {
		if VerifyLivenessBeacon(b, issuers, now, instance, scope, pqPins).OK {
			return false
		}
	}
	return true
}

// BeaconAcceptor is durable replay protection: the highest accepted seq per (instance, scope, issuer) in an atomic kv, under one atomic
// read-modify-write. FAIL CLOSED: when the store cannot decide, the beacon is refused with `beacon state unavailable`.
type BeaconAcceptor struct{ kv AtomicKV }

// NewBeaconAcceptor requires a kv (a process-local one forgets a beacon on restart).
func NewBeaconAcceptor(kv AtomicKV) (*BeaconAcceptor, error) {
	if kv == nil {
		return nil, errors.New("createBeaconAcceptor: a DurableKv is required")
	}
	return &BeaconAcceptor{kv: kv}, nil
}

func beaconSeqKey(b map[string]any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode([]any{b["instance"], b["scope"], b["issuer"]})
	return "beacon-seq/v1/" + string(bytes.TrimRight(buf.Bytes(), "\n"))
}

// Accept verifies b, then records its seq iff STRICTLY above the highest already accepted for the same (instance, scope, issuer).
func (a *BeaconAcceptor) Accept(b map[string]any, issuers []string, now int64, instance, scope string, pqPins map[string]string) (v BeaconVerdict) {
	if v = VerifyLivenessBeacon(b, issuers, now, instance, scope, pqPins); !v.OK {
		return v
	}
	defer func() {
		if recover() != nil {
			v = BeaconVerdict{Reason: beaconStateRefused}
		}
	}()
	seq, _ := safeInt(b["seq"])
	var replayOf int64 = -1
	junk := false
	err := a.kv.Update(beaconSeqKey(b), func(prev []byte) []byte {
		replayOf, junk = -1, false
		if prev != nil {
			p, perr := strconv.ParseInt(string(prev), 10, 64)
			if perr != nil || p < 0 || p > maxSafeBeaconInt || strconv.FormatInt(p, 10) != string(prev) {
				junk = true
				return nil
			}
			if !(seq > p) {
				replayOf = p
				return nil
			}
		}
		return []byte(strconv.FormatInt(seq, 10))
	})
	if err != nil || junk {
		return BeaconVerdict{Reason: beaconStateRefused}
	}
	if replayOf >= 0 {
		return BeaconVerdict{Reason: fmt.Sprintf("replayed beacon: seq %d <= %d", seq, replayOf)}
	}
	return BeaconVerdict{OK: true}
}

// BeaconDecision is the beacon-check decision: rejected | replayed | unbound | pass | not-enforced.
func BeaconDecision(present, ok, replayed, refBinds bool) string {
	switch {
	case !present:
		return "not-enforced"
	case !ok:
		return "rejected"
	case replayed:
		return "replayed"
	case refBinds:
		return "pass"
	}
	return "unbound"
}
