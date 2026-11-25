package pca

// Entry points for the EAT corpus cases that need key material: the AMD delegation, the post-quantum co-signature, admission
// evidence and the running-image digest. Seeds are {"$seed": label} (sha256("atlas-pca-conformance/" + label)) or, in the
// generated secret corpus, base64url bytes.

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

func eatTestSeedBytes(v any) []byte {
	switch t := v.(type) {
	case string:
		b, _ := base64.RawURLEncoding.DecodeString(t)
		return b
	case map[string]any:
		if label, ok := t["$seed"].(string); ok {
			d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			return d[:]
		}
	}
	return nil
}

var eatTestPqFamily = map[string]string{"ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87", "slh-dsa-sha2-128f": "SLH-DSA-SHA2-128f", "slh-dsa-sha2-256s": "SLH-DSA-SHA2-256s"}

func eatTestCoSign(a []any) (any, error) {
	op := vecObj(vecArg(a, 1))
	key := vecObj(op["key"])
	o := EatCoSignOptions{}
	if s, ok := op["suite"].(string); ok {
		o.Suite = s
	}
	if n, ok := jsNum(op["now"]); ok {
		o.Now = n
	}
	if e, ok := key["ed"]; ok {
		o.EdSecret = eatTestSeedBytes(e)
	}
	if pq := vecObj(key["pq"]); pq != nil {
		fam, ok := eatTestPqFamily[jsAnyString(pq["prim"])]
		if !ok {
			return nil, errors.New("unknown pq family")
		}
		kp, err := GeneratePqKeyPairFromSeed(fam, eatTestSeedBytes(pq["seed"]))
		if err != nil {
			return nil, err
		}
		o.Pq = kp
	}
	return EatCoSignAttestation(vecArg(a, 0), o)
}

// eatTestAmdOpts turns the {"$bytes"} report of an amd option into bytes.
func eatTestAmdOpts(opts map[string]any) map[string]any {
	amd, ok := opts["amd"].(map[string]any)
	if !ok {
		return opts
	}
	c := make(map[string]any, len(amd))
	for k, v := range amd {
		c[k] = v
	}
	if m, ok := c["rawReport"].(map[string]any); ok {
		if _, has := m["$bytes"]; has {
			c["rawReport"] = vcBytes(m)
		}
	}
	eatTestCertBytes(c)
	out := make(map[string]any, len(opts))
	for k, v := range opts {
		out[k] = v
	}
	out["amd"] = c
	return out
}

func eatTestVerifyAmd(a []any) (any, error) {
	b := vcBytes(vecArg(a, 0))
	opts := map[string]any{}
	for k, v := range vecObj(vecArg(a, 1)) {
		opts[k] = v
	}
	eatTestCertBytes(opts)
	r := EatVerifyAmdAttestation(b, opts)
	out := map[string]any{}
	for _, k := range []string{"ok", "hardwareRoot", "reason", "evidence", "measured"} {
		if v, ok := r[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}

func eatTestAdmission(a []any) (any, error) {
	opts := vecObj(vecArg(a, 1))
	k, err := eatTestVerifyKey(opts["verifyKey"])
	if err != nil {
		return map[string]any{"ok": false, "bound": false, "reason": "Error"}, nil
	}
	rest := map[string]any{}
	for kk, v := range opts {
		if kk != "verifyKey" {
			rest[kk] = v
		}
	}
	return EatAdmissionEvidence(vecArg(a, 0), k, eatTestAmdOpts(rest)), nil
}

func eatTestRuntimeDigest(a []any) (any, error) {
	o := vecObj(vecArg(a, 1))
	r, err := EatRuntimeDigestFromEat(vecArg(a, 0), vecStr(o, "slot"), vecStr(o, "alg"))
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, nil
	}
	return r, nil
}

// eatTestStricter accepts a refusal where the reference of the corpus is more lenient: a clock skew that is not a finite number
// and a minimum tier other than affirming / affirming-hw-rooted are refused by the current reference too, the vectors predate it.
func eatTestStricter(want, got any) bool {
	if baseCanon(want) == baseCanon(got) {
		return true
	}
	g := vecObj(got)
	return g["ok"] == false && (g["reason"] == "invalid minTier" || eatReasonsMention(g, "clockSkewMs"))
}

func eatReasonsMention(g map[string]any, s string) bool {
	rs, _ := g["reasons"].([]any)
	for _, r := range rs {
		if x, ok := r.(string); ok && strings.Contains(x, s) {
			return true
		}
	}
	return false
}

// eatTestCertBytes turns a certificate given as {"$bytes"} (DER) into bytes, in place.
func eatTestCertBytes(m map[string]any) {
	for _, k := range []string{"vcek", "ask", "ark"} {
		if x, ok := m[k].(map[string]any); ok {
			if _, has := x["$bytes"]; has {
				m[k] = vcBytes(x)
			}
		}
	}
}
