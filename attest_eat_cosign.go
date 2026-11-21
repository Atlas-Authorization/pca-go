package pca

// Post-quantum co-signature of a verified attestation verdict. After the classical AMD SEV-SNP hardware root has been verified,
// the verdict's security-relevant fields (tier, trustworthy bit, measured identity, nonce and iat freshness anchor, issuer,
// co-sign time) are bound under an ML-DSA-65 signature by default (or a hybrid, nested-hybrid or category-5 suite). This does not
// make AMD's root post-quantum: it makes the recorded verdict forward-secure against a later break of the classical root. A
// classical-only suite is refused.
//
// The signed bytes are utf8(JSON(obj)) over a fixed field order with a domain-separating typ and every optional field emitted
// explicitly (its value or null).

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// EatPqCosignDomain is the domain-separating typ of the co-signed verdict.
const EatPqCosignDomain = "atlas-pca/attest-cosign/v1"

// EatIsPqCoSignSuite reports whether x names one of the accepted post-quantum suites (not ed25519, an unknown name or a non-string).
func EatIsPqCoSignSuite(x any) bool {
	s, ok := x.(string)
	return ok && eatInStrings(EatPqCosignSuites, s)
}

func eatPut(o eatOrdered, src any, k string) eatOrdered {
	if v, present := eatGet(src, k); present { // a JavaScript undefined member is absent from JSON.stringify
		return append(o, eatKV{k, v})
	}
	return o
}

func eatStrOrNull(v any) any {
	if s, ok := v.(string); ok {
		return s
	}
	return nil
}

func eatCanonicalMeasured(m any, present bool) any {
	if !present {
		return nil
	}
	o := eatOrdered{}
	o = eatPut(o, m, "model_id")
	o = eatPut(o, m, "weights_digest")
	wm, _ := eatGet(m, "weights_measured")
	if b, ok := wm.(bool); ok {
		o = append(o, eatKV{"weights_measured", b})
	} else {
		o = append(o, eatKV{"weights_measured", nil})
	}
	o = eatPut(o, m, "runtime_measurement")
	o = eatPut(o, m, "operator")
	sp, _ := eatGet(m, "system_prompt_digest")
	tm, _ := eatGet(m, "tool_manifest_digest")
	return append(o, eatKV{"system_prompt_digest", eatStrOrNull(sp)}, eatKV{"tool_manifest_digest", eatStrOrNull(tm)})
}

// EatCanonicalVerdictBytes are the canonical, deterministic bytes the co-signature is computed over (fixed field order, null for
// every absent optional).
func EatCanonicalVerdictBytes(verdict any, cosignedAt any) ([]byte, error) {
	c := eatOrdered{{"typ", EatPqCosignDomain}}
	c = eatPut(c, verdict, "tier")
	tw, _ := eatGet(verdict, "trustworthy")
	c = append(c, eatKV{"trustworthy", tw == true})
	meas, _ := eatGet(verdict, "measurement")
	measured, hasMeasured := eatGet(verdict, "measured")
	if hasMeasured && measured == nil { // measured.model_id on null throws
		return nil, errors.New("Cannot read properties of null (reading 'model_id')")
	}
	nonce, _ := eatGet(verdict, "nonce")
	iat, _ := eatGet(verdict, "iat")
	issuer, _ := eatGet(verdict, "issuer")
	var iatV any
	if f, ok := eatFinite(iat); ok {
		iatV = jsNumber(f)
	}
	c = append(c, eatKV{"measurement", eatStrOrNull(meas)}, eatKV{"measured", eatCanonicalMeasured(measured, hasMeasured)},
		eatKV{"nonce", eatStrOrNull(nonce)}, eatKV{"iat", iatV}, eatKV{"issuer", eatStrOrNull(issuer)}, eatKV{"cosignedAt", cosignedAt})
	var sb strings.Builder
	if err := eatStringify(&sb, c); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// EatVerdictFromAppraisal is an attestation verdict from an Appraise result plus the EAT claims (tier, trustworthy, measured
// identity and launch measurement, nonce, iat, issuer).
func EatVerdictFromAppraisal(result, claims any) map[string]any {
	v := map[string]any{}
	if t, present := eatGet(result, "tier"); present {
		v["tier"] = t
	}
	if t, present := eatGet(result, "trustworthy"); present {
		v["trustworthy"] = t
	}
	measured, present := eatGet(claims, "measured")
	if present {
		v["measured"] = measured
	}
	var measurement any
	if rm, ok := eatMember(measured, "runtime_measurement").(string); ok && rm != "" {
		measurement = rm
	} else if sev, ok := eatGet(claims, "sevsnp"); ok && sev != nil {
		measurement = eatMember(sev, "measurement")
	}
	if s, ok := measurement.(string); ok && s != "" {
		v["measurement"] = s
	}
	if n, ok := eatMember(claims, "eat_nonce").(string); ok {
		v["nonce"] = n
	}
	if iat, ok := eatGet(claims, "iat"); ok {
		if f, fin := eatFinite(iat); fin {
			v["iat"] = jsNumber(f)
		}
	}
	if iss, ok := eatMember(claims, "iss").(string); ok {
		v["issuer"] = iss
	}
	return v
}

// EatCoSignOptions are the options of EatCoSignAttestation.
type EatCoSignOptions struct {
	// Suite is a post-quantum co-sign suite; empty means ml-dsa-65.
	Suite string
	// EdSecret is the 32-byte Ed25519 seed of a hybrid suite.
	EdSecret []byte
	// Pq is the post-quantum key pair of the suite's family.
	Pq *PqKeyPair
	// Now is the co-sign time in epoch milliseconds; zero means the clock.
	Now float64
}

// EatCoSignAttestation co-signs a verified verdict under a post-quantum suite (default ml-dsa-65). Call it AFTER the classical
// hardware check passed. It fails closed on misconfiguration: a classical-only or unknown suite, or missing key material for the
// suite, is an error.
func EatCoSignAttestation(verdict any, o EatCoSignOptions) (map[string]any, error) {
	suite := o.Suite
	if suite == "" {
		suite = EatDefaultPqCosignSuite
	}
	if !EatIsPqCoSignSuite(suite) {
		return nil, fmt.Errorf("coSignAttestation: '%s' is not an accepted post-quantum co-sign suite", suite)
	}
	if o.Pq == nil {
		return nil, fmt.Errorf("coSignAttestation: suite '%s' requires post-quantum key material", suite)
	}
	cosignedAt := o.Now
	if cosignedAt == 0 {
		cosignedAt = float64(time.Now().UnixMilli())
	}
	msg, err := EatCanonicalVerdictBytes(verdict, jsNumber(cosignedAt))
	if err != nil {
		return nil, err
	}
	signerPub := map[string]any{"pq": o.Pq.Public}
	var ed *KeyPair
	if strings.HasPrefix(suite, "hybrid") {
		if len(o.EdSecret) != 32 {
			return nil, fmt.Errorf("coSignAttestation: hybrid suite '%s' requires edSecret", suite)
		}
		if ed, err = KeyPairFromSeed(o.EdSecret); err != nil {
			return nil, err
		}
		signerPub["ed"] = ed.Public
	}
	sig, pqSig, err := SignWithSuite(&SuiteOpts{Alg: suite, Pq: o.Pq}, ed, msg)
	if err != nil {
		return nil, fmt.Errorf("coSignAttestation: suite '%s' requires matching key material: %w", suite, err)
	}
	cosig := map[string]any{"cosignedAt": jsNumber(cosignedAt), "sig": sig}
	if pqSig != "" {
		cosig["pq_sig"] = pqSig
	}
	return map[string]any{"verdict": verdict, "cosig": cosig, "suite": suite, "signer_pub": signerPub}, nil
}

func eatParseSignerPub(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	pq, ok := m["pq"].(string)
	if !ok || pq == "" {
		return nil
	}
	out := map[string]any{"pq": pq}
	if ed, ok := m["ed"].(string); ok && ed != "" {
		out["ed"] = ed
	}
	return out
}

func eatSignerMatches(expected any, got map[string]any) bool {
	expPq, isStr := expected.(string)
	if expected == nil { // `expected.pq` on null throws; the caller turns it into a fail-closed verification error
		panic("Cannot read properties of null (reading 'pq')")
	}
	if !isStr {
		expPq, _ = eatMember(expected, "pq").(string)
	}
	gotPq, _ := got["pq"].(string)
	if expPq == "" || !eatStrEq(expPq, gotPq) {
		return false
	}
	if !isStr {
		if expEd, ok := eatMember(expected, "ed").(string); ok {
			gotEd, ok := got["ed"].(string)
			if !ok || !eatStrEq(expEd, gotEd) {
				return false
			}
		}
	}
	return true
}

// EatVerifyCoSignedAttestation verifies a co-signed attestation: it recomputes the canonical bytes from the artifact's own verdict
// and co-sign time and checks the post-quantum signature under the embedded signer key. It fails closed (a result with a reason,
// never a panic) on a malformed artifact, a classical-only or unknown suite, a tampered verdict field, a wrong key, an
// expectedSigner mismatch, a co-signature older than maxAgeMs, or a suite this runtime cannot verify. Without expectedSigner it
// proves only that the signature matches the key EMBEDDED in the artifact. opts: now, expectedSigner (a pq string or {pq, ed?}),
// maxAgeMs.
func EatVerifyCoSignedAttestation(cosigned any, opts map[string]any) (res map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			res = map[string]any{"ok": false, "reason": "co-signature verification error (fail closed): " + jsAnyString(r)}
		}
	}()
	refuse := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	c, ok := cosigned.(map[string]any)
	if !ok {
		return refuse("co-signed attestation is not an object")
	}
	verdict, isV := c["verdict"].(map[string]any)
	if _, tierOK := verdict["tier"].(string); !isV || !tierOK {
		return refuse("verdict is missing or has a non-string tier / non-boolean trustworthy")
	}
	if _, twOK := verdict["trustworthy"].(bool); !twOK {
		return refuse("verdict is missing or has a non-string tier / non-boolean trustworthy")
	}
	cosig, isC := c["cosig"].(map[string]any)
	at, atOK := eatFinite(cosig["cosignedAt"])
	if _, sigOK := cosig["sig"].(string); !isC || !atOK || !sigOK {
		return refuse("cosig is missing or has a non-numeric cosignedAt / non-string sig")
	}
	suiteV, hasSuite := c["suite"]
	if !EatIsPqCoSignSuite(suiteV) {
		return refuse("suite '" + jsAnyStringIf(suiteV, hasSuite) + "' is not an accepted post-quantum co-sign suite")
	}
	suite := suiteV.(string)
	signer := eatParseSignerPub(c["signer_pub"])
	if signer == nil {
		return refuse("signer_pub is missing or has no post-quantum public key")
	}
	now := float64(time.Now().UnixMilli())
	if f, ok := eatFinite(opts["now"]); ok {
		now = f
	}
	age := now - at
	partial := func(ok bool, reason string) map[string]any {
		out := map[string]any{"ok": ok, "suite": suite, "verdict": verdict, "signer_pub": signer, "cosignedAt": jsNumber(at), "ageMs": jsNumber(age)}
		if reason != "" {
			out["reason"] = reason
		}
		return out
	}
	if exp, present := opts["expectedSigner"]; present && !eatSignerMatches(exp, signer) {
		return partial(false, "co-signer public key does not match the expected signer")
	}
	if mv, present := opts["maxAgeMs"]; present {
		max, fin := eatFinite(mv)
		if !fin || max <= 0 {
			return partial(false, "invalid maxAgeMs")
		}
		if at > now {
			return partial(false, "co-sign timestamp is in the future")
		}
		if age > max {
			return partial(false, "co-signature is stale (older than maxAgeMs)")
		}
	}
	msg, err := EatCanonicalVerdictBytes(verdict, cosig["cosignedAt"])
	if err != nil {
		return refuse("co-signature verification error (fail closed): " + err.Error())
	}
	su, avail := resolveSigAlg(suite, true)
	if !avail {
		return partial(false, "unsupported_suite: "+suite)
	}
	var ed string
	if su.hasEd25519 {
		ed, _ = signer["ed"].(string)
	}
	pqSig, hasPqSig := cosig["pq_sig"]
	if !hasPqSig {
		pqSig = nil
	}
	if !verifyLeafSuite(suite, true, ed, callerVouchedPqKey(signer["pq"]), msg, cosig["sig"], pqSig) {
		return partial(false, "post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)")
	}
	return partial(true, "")
}

func jsAnyStringIf(v any, present bool) string {
	if !present {
		return "undefined"
	}
	return jsAnyString(v)
}
