package pca

// The pure, scheme-independent parts of the homomorphic risk gate: risk-input transformation and fixed-point quantization, the
// public gate policy, the risk claim binding read from a signed action, the plaintext reference verdict, and the origin layer
// (signed claims, replay guard, verdict attestation). Values are parsed JSON (json.Number, maps, slices); a number that is not
// finite is the fail-closed worst case, as in the reference.
//
// NOT here: the BFV evaluation itself (key generation, encryption of the risk inputs, the homomorphic weighted sum and slack,
// decryption of the verdict). The reference runs it on Microsoft SEAL; no vetted Go binding for SEAL exists, and a lattice
// scheme on another library would not interoperate with the reference's ciphertexts. The signed-claim layer is scheme
// independent: a Go verifier can check a claim produced by the reference and attest a verdict over a ciphertext it never opens.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
	"unicode/utf16"
)

const (
	FhePolyModulusDegree = 8192
	FhePlainModulusBits  = 30
	FhePlainModulus      = 1073692673
	FheSignedBound       = FhePlainModulus / 2
	FheDefaultScale      = 1000
	FheRiskDim           = 6
)

var fheInputFields = []string{"semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"}

func fheFinite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }

func fheClamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func fheUnit(x, worst float64) float64 {
	if fheFinite(x) {
		return fheClamp01(x)
	}
	return worst
}

func fheWt(x float64) float64 {
	if fheFinite(x) && x > 0 {
		return x
	}
	return 0
}

// fheField reads member k of v as a number: reading a member of null/undefined throws in the reference; anything else that
// is not an object has no such member (NaN).
func fheField(v any, k string) (float64, error) {
	if v == nil {
		return 0, errors.New("cannot read a member of null or undefined")
	}
	if m, ok := v.(map[string]any); ok {
		return jsF(m[k]), nil
	}
	return math.NaN(), nil
}

func fheFields(v any, keys ...string) ([]float64, error) {
	out := make([]float64, len(keys))
	for i, k := range keys {
		f, err := fheField(v, k)
		if err != nil {
			return nil, err
		}
		out[i] = f
	}
	return out, nil
}

// FheTransformedInputs is [d, 1 - rev, bl, taint, 1 - conf, age], each through unit with the worst case of the risk score.
func FheTransformedInputs(inputs any) ([]float64, error) {
	f, err := fheFields(inputs, fheInputFields...)
	if err != nil {
		return nil, err
	}
	return []float64{fheUnit(f[0], 1), 1 - fheUnit(f[1], 0), fheUnit(f[2], 1), fheUnit(f[3], 1), 1 - fheUnit(f[4], 0), fheUnit(f[5], 1)}, nil
}

// FheWeightVector is the weight vector of the risk score in canonical order with its clamp applied.
func FheWeightVector(w any) ([]float64, error) {
	f, err := fheFields(w, "alpha", "beta", "gamma", "delta", "epsilon", "zeta")
	if err != nil {
		return nil, err
	}
	for i := range f {
		f[i] = fheWt(f[i])
	}
	return f, nil
}

// fheRound is JavaScript Math.round (ties toward +infinity).
func fheRound(x float64) float64 {
	if !fheFinite(x) {
		return x
	}
	f := math.Floor(x)
	if x-f >= 0.5 {
		return f + 1
	}
	return f
}

func fheRequireScale(s float64) error {
	if !fheFinite(s) || s != math.Trunc(s) || s <= 0 {
		return errors.New("scale must be a positive integer")
	}
	return nil
}

// FheQuantizeRiskInputs is round(x_i * scale) for each transformed input: the integer vector the agent encrypts.
func FheQuantizeRiskInputs(inputs any, scale float64) ([]float64, error) {
	if err := fheRequireScale(scale); err != nil {
		return nil, err
	}
	t, err := FheTransformedInputs(inputs)
	if err != nil {
		return nil, err
	}
	for i := range t {
		t[i] = fheRound(float64(t[i] * scale)) // rounded product: no fused multiply-subtract in the rounding
	}
	return t, nil
}

// FheNumbers is the JSON value of a float vector.
func FheNumbers(a []float64) []any {
	out := make([]any, len(a))
	for i, f := range a {
		out[i] = jsNumber(f)
	}
	return out
}

// FheRiskPolicy is the public gate policy from a risk policy {weights, kappa} and the trust budget B at fixed-point scale S:
// weights round(w_i S), kappa-weighted weights round(kappa w_i S), budget round(B S^2). It refuses a policy whose scaled values
// could overflow the signed plain-modulus range (a wrap would silently corrupt the verdict).
func FheRiskPolicy(core any, budget any, scale float64) (map[string]any, error) {
	if err := fheRequireScale(scale); err != nil {
		return nil, err
	}
	b := jsF(budget)
	if !(fheFinite(b) && b >= 0) {
		return nil, errors.New("budget must be finite and >= 0")
	}
	kappa, err := fheField(core, "kappa")
	if err != nil {
		return nil, err
	}
	if !(fheFinite(kappa) && kappa > 0) {
		return nil, errors.New("policy.kappa must be finite and > 0")
	}
	cm, _ := core.(map[string]any)
	w, err := FheWeightVector(cm["weights"])
	if err != nil {
		return nil, err
	}
	ws, kws := make([]float64, len(w)), make([]float64, len(w))
	var sumW, sumK float64
	for i := range w {
		ws[i] = fheRound(w[i] * scale)
		kws[i] = fheRound(kappa * w[i] * scale)
		sumW += ws[i]
		sumK += kws[i]
	}
	budgetScaled := fheRound(b * scale * scale)
	if math.Max(math.Max(sumW*scale, sumK*scale), budgetScaled) >= FheSignedBound {
		return nil, errors.New("policy/scale overflow the plain modulus: lower the scale or the weights/budget")
	}
	return map[string]any{"scale": jsNumber(scale), "dim": jsNumber(FheRiskDim), "weightsScaled": FheNumbers(ws),
		"kappaWeightsScaled": FheNumbers(kws), "budgetScaled": jsNumber(budgetScaled), "kappa": jsNumber(kappa)}, nil
}

// FheRiskInputsFromPCActn reads the six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field
// is left out (non-finite when read, so the transform maps it to its fail-closed worst case).
func FheRiskInputsFromPCActn(p any) (map[string]any, error) {
	pm, _ := p.(map[string]any)
	rc := pm["risk_claim"]
	if rc == nil {
		return nil, errors.New("cannot read inputs of an action without a risk claim")
	}
	rcm, _ := rc.(map[string]any)
	src := rcm["inputs"]
	if src == nil {
		return nil, errors.New("cannot read a member of null or undefined")
	}
	sm, _ := src.(map[string]any)
	out := map[string]any{}
	for _, k := range fheInputFields {
		if _, ok := jsNum(sm[k]); ok {
			out[k] = sm[k]
		}
	}
	return out, nil
}

// FheBindingFromPCActn is the replay binding of a signed action: audience, action digest, counter and the optional nonce.
func FheBindingFromPCActn(p any) (map[string]any, error) {
	pm, _ := p.(map[string]any)
	act := pm["action"]
	if act == nil {
		return nil, errors.New("cannot read params_digest of an action without an action")
	}
	am, _ := act.(map[string]any)
	out := map[string]any{"aud": pm["aud"], "actionRef": am["params_digest"], "counter": pm["counter"]}
	if n, ok := pm["nonce"]; ok {
		out["nonce"] = n
	}
	return out, nil
}

// FhePlaintextVerdict is the plaintext reference verdict: r = risk score, admit iff kappa-cost(r) <= budget.
func FhePlaintextVerdict(inputs, core any, budget any) (map[string]any, error) {
	cm, _ := core.(map[string]any)
	if core == nil {
		return nil, errors.New("cannot read a member of null or undefined")
	}
	w, err := FheWeightVector(cm["weights"])
	if err != nil {
		return nil, err
	}
	t, err := FheTransformedInputs(inputs)
	if err != nil {
		return nil, err
	}
	var sum float64
	for i := range w {
		sum += float64(w[i] * t[i]) // no fused multiply-add: the reference rounds each product
	}
	r := fheClamp01(sum)
	kappa := jsF(cm["kappa"])
	k := 0.0
	if fheFinite(kappa) && kappa > 0 {
		k = kappa
	}
	cost := k * fheClamp01(r)
	return map[string]any{"r": jsNumber(r), "admit": fheFinite(jsF(budget)) && cost <= jsF(budget)}, nil // a budget that is not finite admits nothing
}

// ---- origin: signed claims, replay guard, verdict attestation ------------------------------------------------------------

const (
	fheClaimDomain   = "atlas-pca-fhe/signed-claim/v1\x00"
	fheVerdictDomain = "atlas-pca-fhe/verdict-attestation/v1\x00"
	fheNonceBytes    = 16
	fheMaxContextLen = 512
)

func fheBytesDigest(s string) string {
	h := sha256.Sum256([]byte(s))
	return b64.EncodeToString(h[:])
}

func fhePrefixed(domain string, body any) ([]byte, error) {
	c, err := Canonicalize(body)
	if err != nil {
		return nil, err
	}
	return []byte(domain + c), nil
}

func fheClaimStatement(claim map[string]any, context, nonce, signer string) ([]byte, error) {
	policy, err := HashCanonical(claim["policy"])
	if err != nil {
		return nil, err
	}
	enc, _ := claim["encInputs"].(string)
	return fhePrefixed(fheClaimDomain, map[string]any{"v": jsNumber(1), "context": context, "nonce": nonce, "signer": signer,
		"binding": claim["binding"], "policy": policy, "enc_inputs": fheBytesDigest(enc)})
}

// FheSignedClaimDigest is the content digest of a signed claim (what the key holder's attestation commits to).
func FheSignedClaimDigest(signed any) (string, error) { return HashCanonical(signed) }

func fheKey(secret []byte) (ed25519.PrivateKey, string, error) {
	if len(secret) != 32 {
		return nil, "", errors.New("signing key must be a 32-byte Ed25519 secret key")
	}
	k := ed25519.NewKeyFromSeed(secret)
	return k, b64.EncodeToString(k.Public().(ed25519.PublicKey)), nil
}

// FheSignRiskClaim signs an encrypted risk claim {binding, encInputs, policy} with the caller's one-time nonce (16 random
// bytes; an all-zero nonce is refused as an RNG failure).
func FheSignRiskClaim(claim map[string]any, signerSecretKey []byte, context string, nonce []byte) (map[string]any, error) {
	if n := len(utf16.Encode([]rune(context))); n == 0 || n > fheMaxContextLen {
		return nil, errors.New("context must be a non-empty string of at most 512 characters")
	}
	zero := true
	for _, b := range nonce {
		if b != 0 {
			zero = false
		}
	}
	if len(nonce) != fheNonceBytes || zero {
		return nil, errors.New("signRiskClaim: random source returned all zeros (RNG failure)")
	}
	priv, signer, err := fheKey(signerSecretKey)
	if err != nil {
		return nil, err
	}
	n := b64.EncodeToString(nonce)
	stmt, err := fheClaimStatement(claim, context, n, signer)
	if err != nil {
		return nil, err
	}
	return map[string]any{"claim": claim, "context": context, "nonce": n, "signer": signer, "sig": b64.EncodeToString(ed25519.Sign(priv, stmt))}, nil
}

// FheNonceGuard is a bounded set of nonces already seen; Claim is false when the key was seen or the window is full.
type FheNonceGuard func(key string) bool

// FheMemoryNonceGuard builds an in-memory guard holding at most maxEntries keys.
func FheMemoryNonceGuard(maxEntries int) FheNonceGuard {
	seen := map[string]bool{}
	return func(key string) bool {
		if seen[key] || len(seen) >= maxEntries {
			return false
		}
		seen[key] = true
		return true
	}
}

// FheClaimExpectations is what the verifier expects: trusted encryptor keys, the grant context, the action binding, the gate
// policy and the replay guard.
type FheClaimExpectations struct {
	TrustedSigners []string
	Context        string
	Binding        any
	Policy         any
	Nonces         FheNonceGuard
}

func fheContains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func fheIsObject(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func fheSameHash(a, b any) bool {
	ha, e1 := HashCanonical(a)
	hb, e2 := HashCanonical(b)
	return e1 == nil && e2 == nil && ha == hb
}

// FheVerifySignedRiskClaim verifies a signed claim; it never panics (a malformed or hostile input is a not-ok result
// {ok:false, reason}). On success {ok:true, claim, digest}.
func FheVerifySignedRiskClaim(s any, exp FheClaimExpectations) map[string]any {
	fail := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	c, ok := s.(map[string]any)
	if !ok {
		return fail("claim is not signed: malformed envelope")
	}
	claim, _ := c["claim"].(map[string]any)
	context, ok1 := c["context"].(string)
	nonce, ok2 := c["nonce"].(string)
	signer, ok3 := c["signer"].(string)
	sig, ok4 := c["sig"].(string)
	_, ok5 := claim["encInputs"].(string)
	if !(ok1 && ok2 && ok3 && ok4 && claim != nil && ok5 && fheIsObject(claim["binding"]) && fheIsObject(claim["policy"])) {
		return fail("claim is not signed: malformed envelope")
	}
	if _, ok := DecodeB64uStrict(nonce, fheNonceBytes); !ok {
		return fail("malformed nonce")
	}
	signerBytes, okS := DecodeB64uStrict(signer, 32)
	sigBytes, okG := DecodeB64uStrict(sig, 64)
	if !okS || !okG {
		return fail("malformed signer key or signature")
	}
	if !fheContains(exp.TrustedSigners, signer) {
		return fail("signer is not a trusted encryptor")
	}
	stmt, err := fheClaimStatement(claim, context, nonce, signer)
	if err != nil {
		return fail("claim could not be verified (malformed)")
	}
	if !VerifyStrict(signerBytes, stmt, sigBytes) {
		return fail("signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)")
	}
	if context != exp.Context {
		return fail("context mismatch: claim was signed for a different grant/policy")
	}
	if !fheSameHash(claim["binding"], exp.Binding) {
		return fail("binding mismatch: claim is bound to a different action")
	}
	if !fheSameHash(claim["policy"], exp.Policy) {
		return fail("policy mismatch: claim was signed for a different gate policy")
	}
	if exp.Nonces == nil || !exp.Nonces(signer+":"+nonce) {
		return fail("replay: nonce already used (or the replay window is full)")
	}
	digest, err := FheSignedClaimDigest(s)
	if err != nil {
		return fail("claim could not be verified (malformed)")
	}
	return map[string]any{"ok": true, "claim": claim, "digest": digest}
}

func fheVerdictStatement(claimDigest string, gateDigest any, admit bool, holder string) ([]byte, error) {
	return fhePrefixed(fheVerdictDomain, map[string]any{"v": jsNumber(1), "claim": claimDigest, "gate": gateDigest, "admit": admit, "holder": holder})
}

// FheAttestVerdict is the key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output
// {encRiskRaw, encSlack}.
func FheAttestVerdict(holderSecretKey []byte, signed any, gate map[string]any, admit bool) (map[string]any, error) {
	raw, _ := gate["encRiskRaw"].(string)
	slack, _ := gate["encSlack"].(string)
	gd := map[string]any{"encRiskRaw": fheBytesDigest(raw), "encSlack": fheBytesDigest(slack)}
	cd, err := FheSignedClaimDigest(signed)
	if err != nil {
		return nil, err
	}
	priv, holder, err := fheKey(holderSecretKey)
	if err != nil {
		return nil, err
	}
	stmt, err := fheVerdictStatement(cd, gd, admit, holder)
	if err != nil {
		return nil, err
	}
	return map[string]any{"claimDigest": cd, "gateDigest": gd, "admit": admit, "holder": holder, "sig": b64.EncodeToString(ed25519.Sign(priv, stmt))}, nil
}

// FheVerifyVerdictAttestation verifies an attestation: trusted holder, signature, the expected claim digest and (when gate is
// non-nil) the expected gate output. Returns {ok:true, admit} or {ok:false, reason}.
func FheVerifyVerdictAttestation(a any, trustedHolders []string, claimDigest string, gate map[string]any) map[string]any {
	fail := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	x, ok := a.(map[string]any)
	if !ok {
		return fail("malformed attestation")
	}
	gd, _ := x["gateDigest"].(map[string]any)
	cd, ok1 := x["claimDigest"].(string)
	holderS, ok2 := x["holder"].(string)
	sigS, ok3 := x["sig"].(string)
	admit, ok4 := x["admit"].(bool)
	gRaw, ok5 := gd["encRiskRaw"].(string)
	gSlack, ok6 := gd["encSlack"].(string)
	if !(ok1 && ok2 && ok3 && ok4 && gd != nil && ok5 && ok6) {
		return fail("malformed attestation")
	}
	if !fheContains(trustedHolders, holderS) {
		return fail("attestation holder is not trusted")
	}
	holder, okH := DecodeB64uStrict(holderS, 32)
	sig, okG := DecodeB64uStrict(sigS, 64)
	if !okH || !okG {
		return fail("malformed holder key or signature")
	}
	stmt, err := fheVerdictStatement(cd, gd, admit, holderS)
	if err != nil {
		return fail("attestation could not be verified (malformed)")
	}
	if !VerifyStrict(holder, stmt, sig) {
		return fail("attestation signature does not verify")
	}
	if cd != claimDigest {
		return fail("attestation is for a different claim")
	}
	if gate != nil {
		raw, _ := gate["encRiskRaw"].(string)
		slack, _ := gate["encSlack"].(string)
		if gRaw != fheBytesDigest(raw) || gSlack != fheBytesDigest(slack) {
			return fail("attestation is for a different gate output")
		}
	}
	return map[string]any{"ok": true, "admit": admit}
}
