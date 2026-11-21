package pca

// Trusted-setup bookkeeping for the Groth16 circuits (pure: no file or process access).
//
// A verifying key is only as trustworthy as the ceremony that made it. This file answers one question: "was this key produced by
// a multi-party ceremony we can check?". The answer is "multi-party" only when the caller supplies a transcript, pins its SHA-256
// (published out of band by the ceremony coordinator), the transcript is well-formed (at least two distinct contributions chained
// from the initial key, a public random beacon applied last) and names exactly this verifying key. Everything else is
// "single-party". The cryptographic check of the contributions themselves is the ceremony tool's; nothing here claims more than
// the pinned transcript says.
//
// Values are parsed JSON (map[string]any, []any, string, bool, nil, json.Number), read with the reference's rules: a member that
// is absent and a member that is null are different things.

import (
	"encoding/hex"
	"errors"
	"math"
	"strings"
)

// zkUndef is the reference's `undefined`: what reading an absent member or an index past the end gives.
type zkUndef struct{}

var zkUndefined any = zkUndef{}

// zkProp is `v[k]` for a parsed JSON value: the member of an object, undefined for an absent member or any other value.
func zkProp(v any, k string) any {
	if m, ok := v.(map[string]any); ok {
		if x, has := m[k]; has {
			return x
		}
	}
	return zkUndefined
}

// zkIdx is `a[i]`: undefined past the end.
func zkIdx(a []any, i int) any {
	if i >= 0 && i < len(a) {
		return a[i]
	}
	return zkUndefined
}

// zkEq is `===` (undefined equals only undefined; containers are never equal).
func zkEq(a, b any) bool {
	_, ua := a.(zkUndef)
	_, ub := b.(zkUndef)
	if ua || ub {
		return ua && ub
	}
	return jsStrictEq(a, b)
}

// zkIs reports v === s.
func zkIs(v any, s string) bool {
	x, ok := v.(string)
	return ok && x == s
}

func zkTruthy(v any) bool {
	if _, u := v.(zkUndef); u {
		return false
	}
	return jsTruthy(v)
}

// zkString is String(v).
func zkString(v any) string {
	if _, u := v.(zkUndef); u {
		return "undefined"
	}
	return jsValueString(v)
}

func zkIsHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// zkIsHex64 reports a lower-case SHA-256 in hex.
func zkIsHex64(s string) bool { return len(s) == 64 && zkIsHex(s) }

// zkIsObject is `v && typeof v === "object"`: a JSON object or array.
func zkIsObject(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

// VkID is the id of a verifying key: "vk_" + the SHA-256 (hex) of its canonical JSON. A new setup always yields a new id.
func VkID(vkey any) (string, error) {
	b, err := canonBytes(vkey)
	if err != nil {
		return "", err
	}
	return "vk_" + hex.EncodeToString(sha(b)), nil
}

// CircuitProvenance records what a verifying key was built from. args is {circuit, sourceSha256, r1csSha256, vkey}: the circuit
// id, the SHA-256 of its source set (the circuit version, see CircuitVersion), the SHA-256 of the compiled constraint system and the
// key. The result is {circuit, sourceSha256, r1csSha256, vkId}. A ceremony transcript's r1csSha256 must equal the one here for the
// key to be the one that was built. It errors on an empty circuit id, a hash that is not a lower-case SHA-256 or a missing key.
func CircuitProvenance(args map[string]any) (map[string]any, error) {
	if args == nil {
		return nil, errors.New("circuitProvenance: arguments are required")
	}
	if !zkIsHex64(zkString(zkProp(args, "sourceSha256"))) || !zkIsHex64(zkString(zkProp(args, "r1csSha256"))) || zkIs(args["circuit"], "") {
		return nil, errors.New("circuitProvenance: bad circuit id or hash")
	}
	vkey, has := args["vkey"]
	if !has {
		return nil, errors.New("circuitProvenance: a verifying key is required")
	}
	id, err := VkID(vkey)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"sourceSha256": args["sourceSha256"], "r1csSha256": args["r1csSha256"], "vkId": id}
	if c, has := args["circuit"]; has {
		out["circuit"] = c
	}
	return out, nil
}

// CheckCircuitProvenance returns the first reason prov does not describe expect.vkey built from the expected sources and constraint
// system, or "" when it does. expect is {circuit, sourceSha256, r1csSha256?, vkey}; without r1csSha256 the record's own constraint
// system hash only has to be well-formed. The error is for an expectation without a usable key, never a verdict.
func CheckCircuitProvenance(prov any, expect map[string]any) (string, error) {
	if !zkIsObject(prov) {
		return "not a provenance record", nil
	}
	if !zkEq(zkProp(prov, "circuit"), zkProp(expect, "circuit")) {
		return "record is for another circuit", nil
	}
	if !zkEq(zkProp(prov, "sourceSha256"), zkProp(expect, "sourceSha256")) {
		return "circuit sources differ from the pinned version", nil
	}
	r1, isStr := zkProp(prov, "r1csSha256").(string)
	if want, pinned := expect["r1csSha256"]; !isStr || !zkIsHex64(r1) || (pinned && !zkEq(r1, want)) {
		return "constraint system differs", nil
	}
	vkey, has := expect["vkey"]
	if !has {
		return "", errors.New("checkCircuitProvenance: the expectation carries no verifying key")
	}
	id, err := VkID(vkey)
	if err != nil {
		return "", err
	}
	if !zkIs(zkProp(prov, "vkId"), id) {
		return "verifying key is not the recorded one", nil
	}
	return "", nil
}

// TranscriptSha256 is the SHA-256 (hex) of the canonical JSON of a ceremony transcript: the value the coordinator publishes and a
// verifier pins.
func TranscriptSha256(transcript any) (string, error) {
	b, err := canonBytes(transcript)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sha(b)), nil
}

// CheckTranscript returns the first problem with a ceremony transcript, or "" when it is well-formed. It fails closed on any odd
// shape. A transcript is {version: 1, circuit, curve: "bn128" | "bls12-381", r1csSha256, ptauSha256, initZkeySha256,
// minContributions, contributions: [{index, name, prevZkeySha256, zkeySha256}], beacon: {hashHex, iterationsExp, prevZkeySha256,
// zkeySha256}, finalZkeySha256, vkId}. opts (nil for none) may pin circuit and r1csSha256 and raise minContributions; the minimum
// is never below two.
func CheckTranscript(transcript any, opts map[string]any) string {
	x := transcript
	if f, isNum := jsNum(zkProp(x, "version")); !zkIsObject(x) || !isNum || f != 1 {
		return "not a version-1 transcript"
	}
	circuit, isStr := zkProp(x, "circuit").(string)
	if !isStr || circuit == "" {
		return "no circuit id"
	}
	if want, pinned := opts["circuit"]; pinned && !zkEq(circuit, want) {
		return "transcript is for another circuit"
	}
	if curve := zkProp(x, "curve"); !zkIs(curve, "bn128") && !zkIs(curve, "bls12-381") {
		return "unknown curve"
	}
	for _, k := range []string{"r1csSha256", "ptauSha256", "initZkeySha256"} {
		if !zkIsHex64(zkString(zkProp(x, k))) {
			return k + " is not a SHA-256"
		}
	}
	if want, pinned := opts["r1csSha256"]; pinned && !zkEq(zkProp(x, "r1csSha256"), want) {
		return "transcript is for a different constraint system"
	}
	optMin, ownMin := 2.0, 2.0
	if v := opts["minContributions"]; v != nil {
		optMin = jsToNumber(v)
	}
	if v := zkProp(x, "minContributions"); jsIsSafeInteger(v) {
		ownMin = jsF(v)
	}
	need := math.Max(2, math.Max(optMin, ownMin)) // NaN (a pin that is not a number) compares false below, as in the reference
	cs, isList := zkProp(x, "contributions").([]any)
	if !isList || float64(len(cs)) < need {
		return "fewer than " + jsNumberString(need) + " contributions"
	}
	names, keys := map[string]bool{}, map[string]bool{}
	prev := zkProp(x, "initZkeySha256")
	for i, c := range cs {
		at := "contribution " + jsNumberString(float64(i))
		index, isNum := jsNum(zkProp(c, "index"))
		name, isStr := zkProp(c, "name").(string)
		if !zkTruthy(c) || !isNum || index != float64(i) || math.Signbit(index) || !isStr || name == "" {
			return at + " is malformed"
		}
		key := zkProp(c, "zkeySha256")
		if !zkIsHex64(zkString(key)) || !zkEq(zkProp(c, "prevZkeySha256"), prev) {
			return at + " does not chain from the previous key"
		}
		keyStr, keyIsStr := key.(string) // a key that is not a string never equals another one
		if names[name] || (keyIsStr && keys[keyStr]) {
			return at + " repeats a name or key"
		}
		names[name] = true
		if keyIsStr {
			keys[keyStr] = true
		}
		prev = key
	}
	b := zkProp(x, "beacon")
	exp := zkProp(b, "iterationsExp")
	if !zkTruthy(b) || !zkIsHex64(zkString(zkProp(b, "hashHex"))) || !jsIsSafeInteger(exp) || jsF(exp) < 10 || jsF(exp) > 63 {
		return "no valid random beacon"
	}
	if !zkEq(zkProp(b, "prevZkeySha256"), prev) || !zkIsHex64(zkString(zkProp(b, "zkeySha256"))) {
		return "beacon is not applied after the last contribution"
	}
	if !zkEq(zkProp(x, "finalZkeySha256"), zkProp(b, "zkeySha256")) {
		return "final key is not the beacon output"
	}
	if id, isStr := zkProp(x, "vkId").(string); !isStr || len(id) != 67 || !strings.HasPrefix(id, "vk_") || !zkIsHex(id[3:]) {
		return "no verifying-key id"
	}
	return ""
}

// The two answers of CeremonyOf.
const (
	CeremonySingleParty = "single-party"
	CeremonyMultiParty  = "multi-party"
)

// CeremonyOf is "multi-party" only when evidence ({transcript, sha256, r1csSha256?, circuit?}) pins the transcript's hash, the
// transcript is well-formed and it names vkey. Anything else, a fault included, is "single-party".
func CeremonyOf(vkey any, evidence any) (kind string) {
	defer func() {
		if recover() != nil {
			kind = CeremonySingleParty
		}
	}()
	if !zkTruthy(vkey) || !zkTruthy(evidence) {
		return CeremonySingleParty
	}
	t := zkProp(evidence, "transcript")
	opts := map[string]any{}
	for _, k := range []string{"r1csSha256", "circuit"} {
		if v := zkProp(evidence, k); v != zkUndefined {
			opts[k] = v
		}
	}
	if CheckTranscript(t, opts) != "" {
		return CeremonySingleParty
	}
	digest, err := TranscriptSha256(t)
	if err != nil || !zkIs(zkProp(evidence, "sha256"), digest) {
		return CeremonySingleParty
	}
	id, err := VkID(vkey)
	if err != nil || !zkIs(zkProp(t, "vkId"), id) {
		return CeremonySingleParty
	}
	return CeremonyMultiParty
}
