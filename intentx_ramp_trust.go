package pca

// The trust ramp over a learner (start narrow, widen only through confirmed behaviour, veto on every negative runtime signal,
// freeze widening on drift) and the signed runtime observations that feed it.

import (
	"crypto/ed25519"
	"encoding/base64"
	"math"
)

const ixObsSigDomain = "atlas-pca/intent-obs/v1\x00"

var ixObsSources = []string{"runtime", "witness", "elicitation", "import"}

func ixObsBody(o map[string]any) map[string]any {
	b := map[string]any{}
	for _, k := range []string{"v", "map_digest", "verb", "values", "y", "source", "observed_at", "pcactn_digest", "signer"} {
		if v, ok := o[k]; ok {
			b[k] = ixClone(v)
		}
	}
	return b
}

// ixObsShapeError is "" when the observation is well-formed.
func ixObsShapeError(ov any) string {
	o, ok := ov.(map[string]any)
	if !ok || !jsStrictEq(o["v"], 1.0) {
		return "not an intent observation v1"
	}
	if !ixIsB32(o["map_digest"]) {
		return "map_digest is not canonical base64url (32 bytes)"
	}
	if s, ok := o["verb"].(string); !ok || s == "" {
		return "verb must be a non-empty string"
	}
	vals, ok := o["values"].(map[string]any)
	if ok {
		for _, x := range vals {
			if _, isS := x.(string); isS {
				continue
			}
			if f, isN := jsNum(x); !(isN && !math.IsNaN(f) && !math.IsInf(f, 0)) {
				ok = false
			}
		}
	}
	if !ok {
		return "values must map paths to numbers or strings"
	}
	if y, isN := jsNum(o["y"]); !isN || (y != 0 && y != 1) {
		return "y must be 0 or 1"
	}
	src, _ := o["source"].(string)
	if ixIndexOf(ixObsSources, src) < 0 {
		return "unknown observation source"
	}
	if at, _ := jsNum(o["observed_at"]); !jsIsInt(o["observed_at"]) || at < 0 {
		return "observed_at must be a non-negative safe integer"
	}
	if d, has := o["pcactn_digest"]; has && !ixIsB32(d) {
		return "pcactn_digest is not canonical base64url (32 bytes)"
	}
	if !ixIsB32(o["signer"]) {
		return "signer is not canonical base64url (32 bytes)"
	}
	return ""
}

func ixObsMessage(body map[string]any) ([]byte, bool) {
	b, ok := ixStrictCanon(body)
	if !ok {
		return nil, false
	}
	return append([]byte(ixObsSigDomain), b...), true
}

// IntentSignObservation signs a runtime observation with an Ed25519 seed (the signer is the key of the seed).
func IntentSignObservation(o map[string]any, seedB64 string) (map[string]any, error) {
	r, err := ixTry(func() any { return ixSignObservation(o, seedB64) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func ixSignObservation(o map[string]any, seedB64 string) map[string]any {
	seed, ok := DecodeB64uStrict(seedB64, 32)
	if !ok {
		ixFail("secret key must be a 32-byte seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	withS := ixCopyMap(o)
	withS["v"] = 1.0
	withS["signer"] = base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	body := ixObsBody(withS)
	if bad := ixObsShapeError(body); bad != "" {
		ixFail("signIntentObservation: %s", bad)
	}
	msg, ok := ixObsMessage(body)
	if !ok {
		ixFail("observation is not canonicalizable")
	}
	out := ixCopyMap(body)
	out["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return out
}

// IntentVerifyObservation verifies a signed observation (shape, signer, suite signature; a PQ key must be pinned via opts.pqPins).
func IntentVerifyObservation(ov any, opts map[string]any) map[string]any {
	fail := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if bad := ixObsShapeError(ov); bad != "" {
		return fail(bad)
	}
	o := ov.(map[string]any)
	if es := opts["expectedSigner"]; es != nil && o["signer"] != es {
		return fail("signer mismatch")
	}
	alg, algP := o["alg"]
	pqPk, pqPkP := o["pq_pk"]
	_, pqSigP := o["pq_sig"]
	if algP && !suiteSupported(alg, true) {
		return fail("unknown signature suite")
	}
	if (!algP || alg == "ed25519") && (pqPkP || pqSigP) {
		return fail("an ed25519 artifact must not carry pq_pk / pq_sig")
	}
	body, ok := bindSuiteFields(ixObsBody(o), alg, algP, pqPk, pqPkP)
	if !ok {
		return fail("malformed intent observation: canonicalize: unsupported type undefined")
	}
	msg, ok := ixObsMessage(body)
	if !ok {
		return fail("malformed intent observation: the observation is not canonicalizable")
	}
	if !verifyPinnedSuite(alg, algP, ixS(o["signer"]), pqPk, msg, o["sig"], o["pq_sig"], ixPqPins(opts)) {
		return fail("bad signature")
	}
	return map[string]any{"ok": true}
}

// IntentTrustRamp keeps a learner's grant narrow until confirmed behaviour widens it.
type IntentTrustRamp struct {
	l      *IntentLearner
	drift  *IntentDriftDetector
	queued []any
	log    []any
}

// NewIntentTrustRamp builds a ramp; drift carries the optional rho0, rho1 and h.
func NewIntentTrustRamp(l *IntentLearner, drift map[string]any) (*IntentTrustRamp, error) {
	d, err := ixNewDrift(drift)
	if err != nil {
		return nil, err
	}
	return &IntentTrustRamp{l: l, drift: d}, nil
}

// Learner is the ramped learner.
func (r *IntentTrustRamp) Learner() *IntentLearner { return r.l }

// Frozen is true while a drift alarm stands: widening is frozen.
func (r *IntentTrustRamp) Frozen() bool { return r.drift.State().Alarm }

// Pending are positive signals held back by a freeze (released only by Rebase).
func (r *IntentTrustRamp) Pending() []any { return append([]any{}, r.queued...) }

// Log is every recorded signal.
func (r *IntentTrustRamp) Log() []any { return append([]any{}, r.log...) }

// Drift is the drift detector.
func (r *IntentTrustRamp) Drift() *IntentDriftDetector { return r.drift }

func (r *IntentTrustRamp) grantSize() float64 {
	n := 0.0
	for _, cv := range r.l.Cells() {
		if ixM(cv)["inGrant"] == true {
			n++
		}
	}
	return n
}

// Record feeds one runtime signal about outcome o.
func (r *IntentTrustRamp) Record(o map[string]any, signal string) (rec map[string]any, err error) {
	v, err := ixTry(func() any { return r.record(o, signal) })
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

func (r *IntentTrustRamp) record(o map[string]any, signal string) map[string]any {
	y := float64(IntentSignalLabel(signal))
	wasInGrant := r.l.AdmitsOutcome(o)
	before := r.grantSize()
	drift := r.drift.State()
	if wasInGrant {
		drift = r.drift.Update(y == 0)
	}
	applied := true
	if y == 1 && r.Frozen() {
		r.queued = append(r.queued, map[string]any{"o": o, "signal": signal})
		applied = false
	} else {
		r.l.observe(o, y, "runtime", nil)
	}
	rec := map[string]any{"signal": signal, "y": y, "wasInGrant": wasInGrant, "before": before, "after": r.grantSize(), "applied": applied, "drift": drift.toJSON()}
	r.log = append(r.log, rec)
	return rec
}

// RecordObservation records a SIGNED runtime observation: the signature must verify, the signer must be trusted and the
// observation must be about this map. ctx: mapDigest, trustedSigners, verify (options of IntentVerifyObservation).
func (r *IntentTrustRamp) RecordObservation(obs any, ctx map[string]any) (map[string]any, error) {
	v, err := ixTry(func() any {
		fail := func(why string) map[string]any { return map[string]any{"ok": false, "reason": why} }
		vr := IntentVerifyObservation(obs, ixM(ctx["verify"]))
		if vr["ok"] != true {
			return fail(ixS(vr["reason"]))
		}
		o := ixM(obs)
		trusted := false
		for _, s := range ixL(ctx["trustedSigners"]) {
			if s == o["signer"] {
				trusted = true
			}
		}
		if !trusted {
			return fail("untrusted observation signer")
		}
		if o["map_digest"] != ctx["mapDigest"] {
			return fail("observation is about a different map")
		}
		if o["source"] != "runtime" {
			return fail("only runtime observations feed the ramp")
		}
		sig := "postcondition-violation"
		if o["y"] == 1.0 {
			sig = "principal-confirm"
		}
		return map[string]any{"ok": true, "record": r.record(map[string]any{"verb": o["verb"], "values": o["values"]}, sig)}
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

// Rebase re-bases on a new, signed intent statement (the only way to clear an alarm); queued positive signals are discarded.
func (r *IntentTrustRamp) Rebase(next *IntentLearner) {
	r.l, r.queued = next, nil
	r.drift.Reset()
}
