package pca

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// The liveness beacon functions over decoded JSON values, with the reference's own number and member semantics: a beacon member that
// is missing has no canonical form (the signed message and the beacon reference refuse it), an integer test accepts any integral
// finite number, a clock that is not a number never satisfies an ordering. The typed entry points of beacon.go cover the usual
// case (integers in int64); these answer for every shape a beacon on the wire can take.

var beaconBodyMembers = []string{"v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer"}

var errBeaconUndefined = errors.New("canonicalize: unsupported type undefined")

// LivenessBeaconMessage is the unsigned body a principal signs client-side: the beacon domain followed by the canonical form of
// {v, instance, scope, epoch, seq, issued_at, not_after, issuer} (and alg, pq_pk for a non-Ed25519 suite). A body member that is
// missing, or a value with no canonical form, is an error.
func LivenessBeaconMessage(b map[string]any) ([]byte, error) {
	body := make(map[string]any, len(beaconBodyMembers)+2)
	for _, k := range beaconBodyMembers {
		v, has := b[k]
		if !has {
			return nil, errBeaconUndefined
		}
		body[k] = v
	}
	alg, algP := b["alg"]
	pq, pqP := b["pq_pk"]
	bound, ok := bindSuiteFields(body, alg, algP, pq, pqP)
	if !ok {
		return nil, errBeaconUndefined
	}
	cb, err := canonBytes(bound)
	if err != nil {
		return nil, err
	}
	return append([]byte(livenessDomain), cb...), nil
}

func beaconInteger(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f)
}

// IssueLivenessBeaconValue is IssueLivenessBeacon over decoded values: args = {instance, scope?, seq, issuedAt, validityMs?}. An
// absent or null scope is "*" and an absent or null validityMs is five epochs.
func IssueLivenessBeaconValue(args map[string]any, issuer *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	validity := any(jsNumber(5 * BeaconEpochMs))
	if v := args["validityMs"]; v != nil {
		validity = v
	}
	seq, ok := beaconInteger(args["seq"])
	if !ok || seq < 0 {
		return nil, errors.New("issueLivenessBeacon: seq must be a non-negative integer")
	}
	issuedAt, ok := beaconInteger(args["issuedAt"])
	if !ok || issuedAt < 0 {
		return nil, errors.New("issueLivenessBeacon: issuedAt must be an integer")
	}
	vf, ok := beaconInteger(validity)
	if !ok || vf <= 0 || vf > BeaconMaxValidity {
		return nil, fmt.Errorf("issueLivenessBeacon: validity must be in (0, %d] ms", int64(BeaconMaxValidity))
	}
	scope := args["scope"]
	if scope == nil {
		scope = GlobalScope
	}
	pqPk, hasPq := SuitePqPublicKey(suite)
	body := map[string]any{"v": jsNumber(2), "scope": scope, "epoch": jsNumber(math.Floor(issuedAt / BeaconEpochMs)), "seq": args["seq"],
		"issued_at": args["issuedAt"], "not_after": jsNumber(issuedAt + vf), "issuer": issuer.Public}
	if inst, has := args["instance"]; has {
		body["instance"] = inst
	}
	body, ok = bindSuiteFields(body, suite.alg(), true, pqPk, hasPq)
	if !ok {
		return nil, errors.New("issueLivenessBeacon: the suite needs a post-quantum key pair")
	}
	msg, err := LivenessBeaconMessage(body)
	if err != nil {
		return nil, err
	}
	fields, err := SignSuiteArtifact(suite, issuer, msg)
	if err != nil {
		return nil, err
	}
	for k, v := range fields {
		body[k] = v
	}
	return body, nil
}

// VerifyLivenessBeaconValue verifies a beacon (a decoded value) against a check {issuers, now, instance, scope?, pqPins?}: the
// signature under a pinned issuer, instance and scope binding, the hard maximum validity and the freshness window. It never
// panics: anything unexpected is "malformed beacon". A clock that is not a number never fails an ordering (as the reference's
// comparisons with NaN); the option that accepts an unpinned post-quantum key is not read.
func VerifyLivenessBeaconValue(b any, check map[string]any) (v BeaconVerdict) {
	bad := BeaconVerdict{Reason: "malformed beacon"}
	defer func() {
		if recover() != nil {
			v = bad
		}
	}()
	bm, ok := b.(map[string]any)
	if !ok || !jsStrictEq(bm["v"], jsNumber(2)) {
		return bad
	}
	alg, algP := bm["alg"]
	if _, ok := resolveSigAlg(alg, algP); !ok {
		return bad
	}
	inst, hasInst := bm["instance"]
	want, hasWant := check["instance"]
	if hasInst != hasWant || (hasInst && !jsStrictEq(inst, want)) {
		return BeaconVerdict{Reason: "wrong instance"}
	}
	issuer, hasIssuer := bm["issuer"]
	pinned := false
	switch iss := check["issuers"].(type) {
	case []any:
		for _, x := range iss {
			if hasIssuer && jsStrictEq(x, issuer) {
				pinned = true
			}
		}
	case string: // String.prototype.includes: a substring test on the coerced issuer
		pinned = strings.Contains(iss, func() string {
			if !hasIssuer {
				return "undefined"
			}
			return jsValueString(issuer)
		}())
	default:
		return bad // `issuers.includes` is not a function
	}
	if !pinned {
		return BeaconVerdict{Reason: "issuer not pinned"}
	}
	msg, err := LivenessBeaconMessage(bm)
	if err != nil {
		return bad
	}
	var pins map[string]string
	if p, isMap := check["pqPins"].(map[string]any); isMap {
		pins = map[string]string{}
		for k, x := range p {
			pins[k], _ = x.(string)
		}
	}
	issuerStr, _ := issuer.(string)
	if !verifyPinnedSuite(alg, algP, issuerStr, bm["pq_pk"], msg, bm["sig"], bm["pq_sig"], pins) {
		return BeaconVerdict{Reason: "bad signature"}
	}
	epoch, e1 := beaconInteger(bm["epoch"])
	seq, e2 := beaconInteger(bm["seq"])
	iat, e3 := beaconInteger(bm["issued_at"])
	nafter, e4 := beaconInteger(bm["not_after"])
	if !(e1 && e2 && e3 && e4) || seq < 0 {
		return BeaconVerdict{Reason: "malformed window"}
	}
	if nafter <= iat || nafter-iat > BeaconMaxValidity {
		return BeaconVerdict{Reason: "validity exceeds the hard maximum"}
	}
	if epoch != math.Floor(iat/BeaconEpochMs) {
		return BeaconVerdict{Reason: "epoch does not match issued_at"}
	}
	now := jsToNumber(check["now"])
	if _, has := check["now"]; !has {
		now = math.NaN()
	}
	if now+BeaconClockSkewMs < iat {
		return BeaconVerdict{Reason: "not yet valid"}
	}
	if !(now <= nafter) { // NaN (a missing or non-numeric clock) is expired
		return BeaconVerdict{Reason: "expired"}
	}
	if scope, has := check["scope"]; has && !jsStrictEq(bm["scope"], GlobalScope) && !jsStrictEq(bm["scope"], scope) {
		return BeaconVerdict{Reason: "scope not covered"}
	}
	return BeaconVerdict{OK: true}
}

// AcceptBeaconValue is the monotonic acceptance over values: next replaces prev only with a STRICTLY higher seq (a prev that is
// absent, null or otherwise falsy accepts any well-formed beacon). A next that is no object with a safe-integer seq from 0
// (negative zero refused) is "malformed beacon".
func AcceptBeaconValue(prev, next any) BeaconVerdict {
	nm, ok := next.(map[string]any)
	if !ok || !jsIsInt(nm["seq"]) {
		return BeaconVerdict{Reason: "malformed beacon"}
	}
	seq, _ := jsNum(nm["seq"])
	if seq < 0 {
		return BeaconVerdict{Reason: "malformed beacon"}
	}
	if !jsTruthy(prev) {
		return BeaconVerdict{OK: true}
	}
	pm, _ := prev.(map[string]any)
	pv, has := pm["seq"]
	ps := math.NaN()
	if has {
		ps = jsToNumber(pv)
	}
	if !(seq > ps) {
		return BeaconVerdict{Reason: "replayed beacon: seq " + jsNumberString(seq) + " <= " + jsMemberString(pm, "seq")}
	}
	return BeaconVerdict{OK: true}
}

// IsFrozenLivenessValue: frozen unless at least one beacon verifies for the check; absence is a freeze. A beacons value that is not
// a list is an error.
func IsFrozenLivenessValue(beacons any, check map[string]any) (bool, error) {
	l, ok := beacons.([]any)
	if !ok {
		return false, errors.New("beacons.some is not a function")
	}
	for _, b := range l {
		if VerifyLivenessBeaconValue(b, check).OK {
			return false, nil
		}
	}
	return true, nil
}

// AcceptValue verifies b against the check (VerifyLivenessBeaconValue) and records its seq iff STRICTLY above the highest accepted
// for the same (instance, scope, issuer), in one atomic read-modify-write. FAIL CLOSED: a store that errors or holds a malformed
// value refuses the beacon with `beacon state unavailable`.
func (a *BeaconAcceptor) AcceptValue(b any, check map[string]any) (v BeaconVerdict) {
	if v = VerifyLivenessBeaconValue(b, check); !v.OK {
		return v
	}
	defer func() {
		if recover() != nil {
			v = BeaconVerdict{Reason: beaconStateRefused}
		}
	}()
	bm := b.(map[string]any)
	f, _ := jsNum(bm["seq"])
	seq := int64(f)
	var replayOf int64 = -1
	junk := false
	err := a.kv.Update(beaconSeqKey(bm), func(prev []byte) []byte {
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
