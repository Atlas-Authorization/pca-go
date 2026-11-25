package pca

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"testing"
)

// Replay of the PUF attestation root against the reference (ref-attest-puf), every case: the correction bound, the simulated PUF, the
// fuzzy extractor (enrolment and reproduction), the TPM endorsement-key provider over a recording runner, enrolment, the attestor,
// the enrolment registry, the verifier and its construction. A reference throw requires a refusal. The typed Go API cannot hold a
// non-integer repetition factor: the two cases that pass one compute the bound as the reference does, before the call (counted).

func pufDecodeB64u(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	return DecodeB64uStrict(s, -1)
}

// pufInt is a JS number that is a positive-or-zero safe integer, else -1 (a value the typed API refuses with the reference's text).
func pufInt(v any) int {
	if f, ok := attSafeInt(v); ok && f >= 0 && f < 1<<31 {
		return int(f)
	}
	return -1
}

func pufSimulated(spec map[string]any) (PufProvider, error) {
	seed, ok := pufDecodeB64u(spec["seed"])
	if !ok {
		return nil, errors.New("the simulated PUF seed is base64url")
	}
	var flip []int
	for _, x := range rsList(spec["flip"]) {
		if f, ok := jsNum(x); ok && f == math.Trunc(f) && math.Abs(f) < 1<<31 {
			flip = append(flip, int(f))
		}
	}
	n := pufInt(spec["length"])
	if n < 0 {
		return nil, errors.New("length")
	}
	return NewSimulatedPuf(rsStr(spec["id"]), seed, n, flip), nil
}

func pufHelperOf(v any) FuzzyExtractorHelper {
	m := vecObj(v)
	h := FuzzyExtractorHelper{Rep: pufInt(m["rep"]), MessageBits: pufInt(m["messageBits"]), N: pufInt(m["n"])}
	h.Sketch, _ = m["sketch"].(string)
	h.Salt, _ = m["salt"].(string)
	if m["rep"] == nil {
		h.Rep = 0
	}
	return h
}

func pufEnrollmentOf(v any) PufEnrollment {
	m := vecObj(v)
	e := PufEnrollment{ProviderID: rsStr(m["providerId"]), Challenge: rsStr(m["challenge"]), Alg: rsStr(m["alg"]), PublicKey: rsStr(m["publicKey"]),
		Helper: pufHelperOf(m["helper"]), HelperCommitment: rsStr(m["helperCommitment"])}
	if f, ok := attSafeInt(m["notAfter"]); ok {
		n := int64(f)
		e.NotAfter = &n
	}
	return e
}

func pufEnrollmentOut(e PufEnrollment) map[string]any {
	out := map[string]any{"providerId": e.ProviderID, "challenge": e.Challenge, "alg": e.Alg, "publicKey": e.PublicKey, "helper": e.Helper.wire(),
		"helperCommitment": e.HelperCommitment}
	if e.NotAfter != nil {
		out["notAfter"] = jsNumber(float64(*e.NotAfter))
	}
	return out
}

func pufKeySha(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])
}

// pufRand is the randomBytes callback of a case: its first call gives r1 (cut to n), its second r2.
func pufRand(v any) func(n int) ([]byte, error) {
	rs := rsList(v)
	i := 0
	return func(n int) ([]byte, error) {
		b, _ := qvBytes(vecArg(rs, i))
		i++
		if len(b) < n {
			return nil, errors.New("the randomness is too short")
		}
		return b[:n], nil
	}
}

func pufWrap(v any, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "value": v}, nil
}

func pufUnwrap(want any) any {
	if m := vecObj(want); m != nil && m["ok"] == true && m["value"] != nil && len(m) == 2 {
		return m["value"]
	}
	return want
}

func TestPufAttestationMatchesTheReference(t *testing.T) {
	fractional := 0
	enrollOpts := func(v any) EnrollPufOptions {
		m := vecObj(v)
		return EnrollPufOptions{FuzzyExtractorParams: FuzzyExtractorParams{Rep: pufInt(m["rep"]), MessageBits: pufInt(m["messageBits"])}, Alg: rsStr(m["alg"])}
	}
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"PUF_EXTRACT_INFO": PufExtractInfo, "PUF_ATTEST_DOMAIN": PufAttestDomain, "PUF_KEY_BYTES": jsNumber(PufKeyBytes), "TPM_EK_PUF_DOMAIN": TpmEkPufDomain}, nil
		},
		"repetitionCorrectionBound": func(a []any) (any, error) {
			f, _ := jsNum(scDecode(vecArg(a, 0)))
			if f != math.Trunc(f) { // a fractional factor is no int
				fractional++
				return jsNumber(math.Floor((f - 1) / 2)), nil
			}
			return jsNumber(float64(RepetitionCorrectionBound(int(f)))), nil
		},
		"simulatedPufResponse": func(a []any) (any, error) {
			p, err := pufSimulated(vecObj(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			ch, _ := qvBytes(vecArg(a, 1))
			bits, err := p.Response(ch)
			if err != nil {
				return nil, err
			}
			return vecBytesOut(bits), nil
		},
		"fuzzyEnroll": func(a []any) (any, error) {
			bits, _ := qvBytes(vecArg(a, 0))
			pm := vecObj(vecArg(a, 1))
			key, h, err := FuzzyEnroll(bits, FuzzyExtractorParams{Rep: pufInt(pm["rep"]), MessageBits: pufInt(pm["messageBits"])}, pufRand(vecArg(a, 2)))
			if err != nil {
				return nil, err
			}
			return map[string]any{"keySha256": pufKeySha(key), "helper": h.wire()}, nil
		},
		"fuzzyReproduce": func(a []any) (any, error) {
			bits, _ := qvBytes(vecArg(a, 0))
			hm := vecObj(vecArg(a, 1))
			if hm == nil {
				return nil, errors.New("fuzzyReproduce: malformed helper params")
			}
			if _, ok := hm["sketch"].(string); !ok {
				return nil, errors.New("fuzzyReproduce: helper data missing sketch or salt")
			}
			if _, ok := hm["salt"].(string); !ok {
				return nil, errors.New("fuzzyReproduce: helper data missing sketch or salt")
			}
			key, err := FuzzyReproduce(bits, pufHelperOf(hm))
			if err != nil {
				return nil, err
			}
			return pufWrap(map[string]any{"keySha256": pufKeySha(key)}, nil)
		},
		"tpmEk": func(a []any) (any, error) {
			sc := vecObj(vecArg(a, 0))
			om := vecObj(sc["opts"])
			calls := []any{}
			runSpec := sc["run"]
			o := TpmEkPufOptions{ID: rsStr(om["id"]), Length: pufInt(om["length"]), Tool: rsStr(om["tool"]), EkHandle: rsStr(om["ekHandle"])}
			if o.Length < 1 {
				o.Length = 0
			}
			if l, ok := om["args"].([]any); ok {
				o.Args = []string{}
				for _, x := range l {
					o.Args = append(o.Args, rsStr(x))
				}
			}
			if v, present := om["minEkBytes"]; present && v != nil {
				if f, ok := attSafeInt(v); ok && f >= 1 {
					o.MinEkBytes = int(f)
				} else {
					o.MinEkBytes = -1
				}
			}
			o.Run = func(cmd string, args []string) *TpmCommandResult {
				as := make([]any, len(args))
				for i, x := range args {
					as[i] = x
				}
				calls = append(calls, []any{cmd, as})
				if s, ok := runSpec.(string); ok && s == "undefined" {
					return nil
				}
				rm := vecObj(runSpec)
				if msg, ok := rm["$throws"].(string); ok {
					panic(msg)
				}
				res := &TpmCommandResult{Stderr: rsStr(rm["stderr"]), Error: rsStr(rm["error"])}
				res.Stdout, _ = qvBytes(rm["stdout"])
				if f, ok := attSafeInt(rm["status"]); ok {
					st := int(f)
					res.Status = &st
				}
				return res
			}
			fail := func(err error) (any, error) {
				return map[string]any{"ok": false, "error": err.Error(), "calls": calls}, nil
			}
			p, err := NewTpmEkPufProvider(o)
			if err != nil {
				return fail(err)
			}
			var out []byte
			if sc["op"] == "readEkPublic" {
				out, err = p.ReadEkPublic()
			} else {
				ch := pufDefaultChallenge()
				if b, ok := qvBytes(sc["challenge"]); ok {
					ch = b
				}
				out, err = p.Response(ch)
			}
			if err != nil {
				return fail(err)
			}
			return map[string]any{"ok": true, "value": vecBytesOut(out), "calls": calls}, nil
		},
		"enrollPuf": func(a []any) (any, error) {
			p, err := pufSimulated(vecObj(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			ch, _ := qvBytes(vecArg(a, 1))
			o := enrollOpts(vecArg(a, 2))
			o.RandomBytes = pufRand(vecArg(a, 3))
			e, err := EnrollPuf(p, ch, o)
			if err != nil {
				return nil, err
			}
			return pufWrap(pufEnrollmentOut(*e), nil)
		},
		"pufAttest": func(a []any) (any, error) {
			p, err := pufSimulated(vecObj(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			att, err := CreatePufAttestor(p, pufEnrollmentOf(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			cm := vecObj(scDecode(vecArg(a, 2)))
			c := PufClaims{Measurement: rsStr(cm["measurement"]), WeightsDigest: rsStr(cm["weights_digest"]), HolderPub: rsStr(cm["holder_pub"]),
				GrantRef: rsStr(cm["grant_ref"]), Nonce: rsStr(cm["nonce"]), Epoch: math.NaN()}
			if f, ok := jsNum(cm["epoch"]); ok {
				c.Epoch = f
			}
			st, err := att.Attest(c)
			return pufWrap(st, err)
		},
		"registry": func(a []any) (any, error) {
			sc := vecObj(vecArg(a, 0))
			reg := NewPufEnrollmentRegistry()
			valid := func(v any) bool { m := vecObj(v); _, ok := m["providerId"].(string); return ok }
			for _, x := range rsList(sc["enrollments"]) {
				if valid(x) {
					reg.Register(pufEnrollmentOf(x))
				}
			}
			out := []any{}
			for _, op := range rsList(sc["ops"]) {
				m := vecObj(op)
				switch {
				case pufHas(m, "register"):
					if valid(m["register"]) {
						reg.Register(pufEnrollmentOf(m["register"]))
					}
					out = append(out, nil)
				case pufHas(m, "lookup"):
					if e, ok := reg.Lookup(rsStr(m["lookup"])); ok {
						out = append(out, pufEnrollmentOut(e))
					} else {
						out = append(out, nil)
					}
				case pufHas(m, "revoke"):
					reg.Revoke(rsStr(m["revoke"]))
					out = append(out, nil)
				default:
					out = append(out, reg.IsRevoked(rsStr(m["isRevoked"])))
				}
			}
			return pufWrap(out, nil)
		},
		"buildVerifier": func(a []any) (any, error) {
			sc := vecObj(vecArg(a, 0))
			o := PufVerifierOptions{Policy: PufPolicy{Measurements: attStrings(vecObj(sc["policy"])["measurements"])}}
			if sc["noResolveEnrollment"] != true {
				o.ResolveEnrollment = func(string, map[string]any, map[string]any) (PufEnrollment, bool) { return PufEnrollment{}, false }
			}
			_, err := CreatePufVerifier(o)
			return pufWrap(map[string]any{"built": true}, err)
		},
		"verifyPuf": func(a []any) (any, error) {
			sc := vecObj(scDecode(vecArg(a, 0)))
			cfg := vecObj(sc["config"])
			pol := vecObj(cfg["policy"])
			o := PufVerifierOptions{Policy: PufPolicy{Measurements: attStrings(pol["measurements"]), WeightsMeasurements: attStrings(pol["weightsMeasurements"])}}
			if pol["identity"] == "custom" {
				o.Policy.DeriveIdentity = func(st map[string]any, e PufEnrollment) MeasuredIdentity {
					return MeasuredIdentity{ModelID: "m-custom", WeightsDigest: rsStr(st["weights_digest"]), WeightsMeasured: true, RuntimeMeasurement: rsStr(st["measurement"]), Operator: e.ProviderID}
				}
			}
			o.RequirePq = cfg["requirePq"] == true
			byID := map[string]PufEnrollment{}
			for _, x := range rsList(sc["enrollments"]) {
				e := pufEnrollmentOf(x)
				byID[e.ProviderID] = e
			}
			if cfg["noResolveEnrollment"] != true {
				o.ResolveEnrollment = func(id string, _, _ map[string]any) (PufEnrollment, bool) { e, ok := byID[id]; return e, ok }
			}
			if cfg["noEvidenceSeam"] != true {
				st := vecObj(sc["evidence"])
				o.ResolveEvidence = func(_, _ map[string]any) map[string]any { return st }
			}
			if rl, ok := sc["revoked"].([]any); ok {
				revoked := attStrings(rl)
				o.IsRevoked = func(id string) bool { return slices.Contains(revoked, id) }
			}
			v, err := CreatePufVerifier(o)
			if err != nil {
				return nil, err
			}
			in := vecObj(sc["input"])
			var exp ExpectedAttestationBinding
			if in["expected"] != nil {
				exp = attExpected(in["expected"])
			}
			now, _ := jsNum(in["nowMs"])
			return v.VerifyHardware(map[string]any{}, map[string]any{}, int64(now), exp).Wire(), nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		"fuzzyEnroll": func(want, got any) bool { return baseCanon(pufUnwrap(want)) == baseCanon(got) },
	}
	replayAll(t, "ref-attest-puf.json.gz", 278, vecSeeded(fns), cmp, map[string]bool{"enrollPuf": true})
	if fractional != 2 {
		t.Fatalf("%d fractional factors were computed before the call, 2 are expected", fractional)
	}
}

func pufHas(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// pufDefaultChallenge is the challenge of the cases that carry none: the reference's own sha256("attest-puf-oracle-randomness/challenge").
func pufDefaultChallenge() []byte {
	h := sha256.Sum256([]byte("attest-puf-oracle-randomness/challenge"))
	return h[:]
}
